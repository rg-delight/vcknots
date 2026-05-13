#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = path.dirname(scriptPath);
const oidfRoot = path.resolve(scriptDir, "..");
const vcknotsRoot = path.resolve(oidfRoot, "../..");
const defaultSuiteDir = path.resolve(vcknotsRoot, "../openid-conformance-suite");
const suiteDir = path.resolve(process.env.OIDF_CONFORMANCE_SUITE_DIR ?? defaultSuiteDir);
const suiteOrigin = trimTrailingSlash(
  process.env.CONFORMANCE_SERVER ?? "https://localhost.emobix.co.uk:8443",
);
const composeProject = process.env.OIDF_COMPOSE_PROJECT ?? "vcknots-oidf-conformance";
const composeFile = path.join(oidfRoot, "docker-compose-prebuilt-named-volume.yml");
const moduleTimeoutMs = Number(process.env.OIDF_MODULE_TIMEOUT_MS ?? 120_000);
const walletInvocationTimeoutMs = Number(process.env.OIDF_WALLET_INVOCATION_TIMEOUT_MS ?? 30_000);
const moduleLimit = optionalPositiveInteger(process.env.OIDF_MODULE_LIMIT);
const moduleFilter = process.env.OIDF_MODULE_FILTER;
const placeholderFulfillmentTimeoutMs = Number(
  process.env.OIDF_PLACEHOLDER_FULFILLMENT_TIMEOUT_MS ?? 10_000,
);
const placeholderImage =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADElEQVR42mN89+4dAAX8AqGd7mOmAAAAAElFTkSuQmCC";

const defaultHarnessOrigin = trimTrailingSlash(
  process.env.VCKNOTS_OIDF_HARNESS_ORIGIN ??
    process.env.VCKNOTS_HAIP_HARNESS_ORIGIN ??
    "http://127.0.0.1:9080",
);

const targets = {
  "vci-wallet-final": {
    role: "wallet",
    protocol: "oid4vci",
    suite: "final",
    planName: "oid4vci-1_0-wallet-test-plan",
    config: "vci-wallet-test-config.json",
    variant: {
      credential_format: "sd_jwt_vc",
      fapi_profile: "vci",
      vci_grant_type: "authorization_code",
      vci_authorization_code_flow_variant: "issuer_initiated",
      vci_credential_offer_variant: "by_value",
      authorization_request_type: "simple",
      client_auth_type: "client_attestation",
      sender_constrain: "dpop",
      fapi_request_method: "unsigned",
      vci_credential_issuance_mode: "immediate",
      vci_credential_encryption: "plain",
    },
    overrideConfig(config) {
      config.vci ??= {};
      config.vci.credential_offer_endpoint =
        process.env.VCKNOTS_OIDF_WALLET_CREDENTIAL_OFFER_ENDPOINT ??
        process.env.VCKNOTS_HAIP_WALLET_CREDENTIAL_OFFER_ENDPOINT ??
        `${defaultHarnessOrigin}/oidf/vci/credential-offer`;
    },
  },
  "vci-wallet-haip": {
    role: "wallet",
    protocol: "oid4vci",
    suite: "haip",
    planName: "oid4vci-1_0-wallet-haip-test-plan",
    config: "vci-wallet-test-config.json",
    variant: {
      credential_format: "sd_jwt_vc",
      vci_authorization_code_flow_variant: "issuer_initiated",
      vci_credential_offer_variant: "by_value",
    },
    overrideConfig(config) {
      config.vci ??= {};
      config.vci.credential_offer_endpoint =
        process.env.VCKNOTS_HAIP_WALLET_CREDENTIAL_OFFER_ENDPOINT ??
        `${defaultHarnessOrigin}/oidf/vci/credential-offer`;
    },
  },
  "vci-issuer-haip": {
    role: "issuer",
    protocol: "oid4vci",
    suite: "haip",
    planName: "oid4vci-1_0-issuer-haip-test-plan",
    config: "vci-issuer-test-config-client_attestation-client-auth-dpop.json",
    variant: {
      credential_format: "sd_jwt_vc",
      vci_authorization_code_flow_variant: "wallet_initiated",
    },
    overrideConfig(config) {
      config.vci ??= {};
      config.vci.credential_issuer_url =
        process.env.VCKNOTS_HAIP_ISSUER_BASE_URL ?? `${defaultHarnessOrigin}/oidf/vci/issuer`;
    },
  },
  "vp-wallet-haip": {
    role: "wallet",
    protocol: "oid4vp",
    suite: "haip",
    planName: "oid4vp-1final-wallet-haip-test-plan",
    config: "vp-wallet-test-config-dcql-sdjwt.json",
    variant: {
      credential_format: "sd_jwt_vc",
      response_mode: "direct_post.jwt",
    },
    overrideConfig(config) {
      config.server ??= {};
      config.server.authorization_endpoint =
        process.env.VCKNOTS_HAIP_WALLET_AUTHORIZATION_ENDPOINT ??
        `${defaultHarnessOrigin}/oidf/vp/authorize`;
    },
  },
  "vp-wallet-final": {
    role: "wallet",
    protocol: "oid4vp",
    suite: "final",
    planName: "oid4vp-1final-wallet-test-plan",
    config: "vp-wallet-test-config-dcql-sdjwt.json",
    variant: {
      vp_profile: "plain_vp",
      credential_format: "sd_jwt_vc",
      response_mode: "direct_post.jwt",
      request_method: "request_uri_signed",
      client_id_prefix: "x509_hash",
    },
    overrideConfig(config) {
      config.server ??= {};
      config.server.authorization_endpoint =
        process.env.VCKNOTS_OIDF_WALLET_AUTHORIZATION_ENDPOINT ??
        process.env.VCKNOTS_HAIP_WALLET_AUTHORIZATION_ENDPOINT ??
        `${defaultHarnessOrigin}/oidf/vp/authorize`;
    },
  },
  "vp-verifier-haip": {
    role: "verifier",
    protocol: "oid4vp",
    suite: "haip",
    planName: "oid4vp-1final-verifier-haip-test-plan",
    config: "vp-verifier-test-config.json",
    variant: {
      credential_format: "sd_jwt_vc",
      response_mode: "direct_post.jwt",
    },
    overrideConfig(config) {
      config.server ??= {};
      config.server.authorization_endpoint =
        process.env.VCKNOTS_HAIP_VERIFIER_AUTHORIZATION_ENDPOINT ??
        `${defaultHarnessOrigin}/oidf/vp/verifier/authorize`;
    },
  },
};

const targetNames = Object.keys(targets);
const targetGroups = {
  haip: targetNames.filter((name) => targets[name].suite === "haip"),
  walletFinal: ["vci-wallet-final", "vci-wallet-haip", "vp-wallet-final", "vp-wallet-haip"],
  all: targetNames,
};
const command = process.argv[2] ?? "help";
const targetName = process.argv[3];

try {
  if (command === "help" || command === "--help" || command === "-h") {
    printHelp();
  } else if (command === "list-targets") {
    console.log(JSON.stringify({ targets: targetNames, groups: targetGroups }, null, 2));
  } else if (command === "start-suite") {
    startSuite();
    await waitForSuite();
    console.log(JSON.stringify({ ok: true, suiteOrigin }, null, 2));
  } else if (command === "create-plan") {
    const name = requireTargetName(targetName);
    startSuite();
    await waitForSuite();
    const result = await createPlanArtifact(name);
    console.log(JSON.stringify(result.summary, null, 2));
  } else if (command === "run-target") {
    const name = requireTargetName(targetName);
    startSuite();
    await waitForSuite();
    const result = await runTarget(name);
    console.log(JSON.stringify(result.summary, null, 2));
    process.exitCode = result.exitCode;
  } else if (command === "run-all-haip") {
    startSuite();
    await waitForSuite();
    const summary = await runTargetGroup(targetGroups.haip);
    console.log(JSON.stringify(summary, null, 2));
    process.exitCode = summary.ok ? 0 : 1;
  } else if (command === "run-all-wallet-final") {
    startSuite();
    await waitForSuite();
    const summary = await runTargetGroup(targetGroups.walletFinal);
    console.log(JSON.stringify(summary, null, 2));
    process.exitCode = summary.ok ? 0 : 1;
  } else if (command === "run-all") {
    startSuite();
    await waitForSuite();
    const summary = await runTargetGroup(targetGroups.all);
    console.log(JSON.stringify(summary, null, 2));
    process.exitCode = summary.ok ? 0 : 1;
  } else {
    fail(`Unknown command ${command}. Run with --help for usage.`);
  }
} catch (error) {
  fail(error instanceof Error ? error.stack ?? error.message : String(error));
}

async function runTargetGroup(names) {
  const results = [];
  for (const name of names) {
    results.push(await runTarget(name));
  }
  return {
    ok: results.every((result) => result.exitCode === 0),
    suiteOrigin,
    targets: results.map((result) => result.summary),
  };
}

async function createPlanArtifact(name) {
  const target = targets[name];
  const artifactDir = await createArtifactDir(name);
  const config = await buildConfig(target);
  await writeJson(path.join(artifactDir, "run-config.json"), {
    suiteOrigin,
    suiteDir,
    targetName: name,
    role: target.role,
    protocol: target.protocol,
    suite: target.suite,
    planName: target.planName,
    variant: target.variant,
    config,
  });

  try {
    const plan = await createPlan(target, config);
    await writeJson(path.join(artifactDir, "plan.json"), plan);
    const classification = classifyTarget({
      plan,
      moduleResults: [],
      error: undefined,
      timedOut: false,
    });
    await writeJson(path.join(artifactDir, "classification.json"), classification);
    return {
      artifactDir,
      plan,
      summary: {
        ok: true,
        targetName: name,
        artifactDir,
        moduleCount: plan.modules?.length ?? 0,
        classification: classification.classification,
      },
      exitCode: 0,
    };
  } catch (error) {
    const classification = classifyTarget({
      plan: undefined,
      moduleResults: [],
      error,
      timedOut: false,
    });
    await writeJson(path.join(artifactDir, "runner-error.json"), serializeError(error));
    await writeJson(path.join(artifactDir, "classification.json"), classification);
    return {
      artifactDir,
      plan: undefined,
      summary: {
        ok: false,
        targetName: name,
        artifactDir,
        classification: classification.classification,
        reason: classification.reason,
      },
      exitCode: 1,
    };
  }
}

async function runTarget(name) {
  const target = targets[name];
  const artifactDir = await createArtifactDir(name);
  const config = await buildConfig(target);
  await writeJson(path.join(artifactDir, "run-config.json"), {
    suiteOrigin,
    suiteDir,
    targetName: name,
    role: target.role,
    protocol: target.protocol,
    suite: target.suite,
    planName: target.planName,
    variant: target.variant,
    moduleTimeoutMs,
    moduleLimit,
    moduleFilter,
    config,
  });

  try {
    const plan = await createPlan(target, config);
    await writeJson(path.join(artifactDir, "plan.json"), plan);

    const planModules = selectModules(plan.modules ?? []);
    await writeJson(path.join(artifactDir, "selected-modules.json"), planModules);

    const moduleResults = [];
    for (const [index, planModule] of planModules.entries()) {
      const moduleResult = await runModule({
        artifactDir,
        index: index + 1,
        target,
        plan,
        planModule,
      });
      moduleResults.push(moduleResult);
    }

    const classification = classifyTarget({
      plan,
      moduleResults,
      error: undefined,
      timedOut: moduleResults.some((result) => result.timedOut),
    });
    await writeJson(path.join(artifactDir, "classification.json"), classification);

    return {
      artifactDir,
      summary: {
        ok: classification.classification === "passed",
        targetName: name,
        artifactDir,
        selectedModuleCount: planModules.length,
        moduleResultCounts: countBy(moduleResults.map((result) => result.classification)),
        classification: classification.classification,
        reason: classification.reason,
      },
      exitCode: classification.classification === "suite_or_environment_issue" ? 1 : 0,
    };
  } catch (error) {
    const classification = classifyTarget({
      plan: undefined,
      moduleResults: [],
      error,
      timedOut: false,
    });
    await writeJson(path.join(artifactDir, "runner-error.json"), serializeError(error));
    await writeJson(path.join(artifactDir, "classification.json"), classification);
    return {
      artifactDir,
      summary: {
        ok: false,
        targetName: name,
        artifactDir,
        classification: classification.classification,
        reason: classification.reason,
      },
      exitCode: 1,
    };
  }
}

async function runModule({ artifactDir, index, target, plan, planModule }) {
  const moduleName = planModule.testModule;
  const filePrefix = `${String(index).padStart(3, "0")}-${sanitizeFileName(moduleName)}`;
  const runnerModule = await suiteFetch("/api/runner", {
    method: "POST",
    searchParams: {
      test: moduleName,
      plan: plan.id,
      ...(planModule.variant ? { variant: JSON.stringify(planModule.variant) } : {}),
    },
  });
  await writeJson(path.join(artifactDir, `${filePrefix}-module.json`), runnerModule);

  const walletInvocation = await driveWalletInvocationIfNeeded({ target, moduleId: runnerModule.id });
  await writeJson(path.join(artifactDir, `${filePrefix}-wallet-invocation.json`), walletInvocation);

  const placeholderFulfillment = await fulfillReviewPlaceholdersIfNeeded({
    target,
    moduleId: runnerModule.id,
  });
  await writeJson(
    path.join(artifactDir, `${filePrefix}-placeholder-fulfillment.json`),
    placeholderFulfillment,
  );

  const info = await waitForModule(runnerModule.id);
  const logs = await getModuleLogs(runnerModule.id);
  await writeJson(path.join(artifactDir, `${filePrefix}-info.json`), info);
  await writeJson(path.join(artifactDir, `${filePrefix}-log.json`), logs);

  const classification = classifyModule({ target, planModule, runnerModule, info, logs });
  await writeJson(path.join(artifactDir, `${filePrefix}-classification.json`), classification);
  return {
    moduleName,
    moduleId: runnerModule.id,
    timedOut: Boolean(info.runnerTimedOut),
    classification: classification.classification,
    reason: classification.reason,
  };
}

async function fulfillReviewPlaceholdersIfNeeded({ target, moduleId }) {
  if (target.role !== "wallet") {
    return {
      attempted: false,
      reason: "Target is not a wallet target.",
    };
  }

  const deadline = Date.now() + placeholderFulfillmentTimeoutMs;
  const uploaded = [];
  let lastPlaceholderCount = 0;
  while (Date.now() < deadline) {
    const logs = await getModuleLogs(moduleId);
    const placeholders = extractReviewPlaceholders(logs);
    lastPlaceholderCount = placeholders.length;
    const remaining = placeholders.filter((placeholder) => !uploaded.includes(placeholder));
    if (remaining.length > 0) {
      for (const placeholder of remaining) {
        await uploadPlaceholderImage(moduleId, placeholder);
        uploaded.push(placeholder);
      }
      return {
        attempted: true,
        uploaded,
      };
    }

    const info = await suiteFetch(`/api/info/${moduleId}`);
    if (info.status === "FINISHED" || info.result === "FAILED" || info.test?.result === "FAILED") {
      return {
        attempted: false,
        reason: "Module finished or failed before a REVIEW placeholder appeared.",
        lastPlaceholderCount,
      };
    }
    await delay(500);
  }

  return {
    attempted: false,
    reason: "No REVIEW placeholder appeared before timeout.",
    timeoutMs: placeholderFulfillmentTimeoutMs,
    lastPlaceholderCount,
  };
}

async function driveWalletInvocationIfNeeded({ target, moduleId }) {
  if (target.role !== "wallet") {
    return {
      invoked: false,
      reason: "Target is not a wallet target.",
    };
  }

  const deadline = Date.now() + walletInvocationTimeoutMs;
  let lastHintCount = 0;
  while (Date.now() < deadline) {
    const logs = await getModuleLogs(moduleId);
    const concreteUrls = extractConcreteWalletInvocationUrls(logs);
    lastHintCount = concreteUrls.length;
    const concreteUrl = concreteUrls.find((candidate) => !candidate.includes("*"));
    const url =
      concreteUrls.find(
        (candidate) => !candidate.includes("*") && candidate.includes("request_uri_method=post"),
      ) ?? concreteUrl;
    if (url) {
      try {
        const response = await fetch(url, { redirect: "follow" });
        const body = await response.text();
        return {
          invoked: true,
          url,
          status: response.status,
          ok: response.ok,
          body: body.slice(0, 2000),
        };
      } catch (error) {
        return {
          invoked: false,
          url,
          error: serializeError(error),
        };
      }
    }
    await delay(1_000);
  }

  return {
    invoked: false,
    reason: "No concrete wallet invocation URL appeared in suite logs before timeout.",
    timeoutMs: walletInvocationTimeoutMs,
    lastHintCount,
  };
}

function startSuite() {
  const result = spawnSync(
    "docker",
    ["compose", "-p", composeProject, "-f", composeFile, "up", "-d"],
    {
      cwd: vcknotsRoot,
      env: { ...process.env, BASE_URL: suiteOrigin },
      stdio: "inherit",
    },
  );
  if (result.status !== 0) {
    fail("OIDF conformance suite Docker stack failed to start.");
  }
}

async function waitForSuite() {
  const deadline = Date.now() + Number(process.env.OIDF_SUITE_READY_TIMEOUT_MS ?? 180_000);
  let lastError = "";
  while (Date.now() < deadline) {
    try {
      await suiteFetch("/api/runner/available");
      return;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
      await delay(2_000);
    }
  }
  fail(`OIDF suite did not become ready at ${suiteOrigin}: ${lastError}`);
}

async function buildConfig(target) {
  const configPath = path.join(suiteDir, "scripts/test-configs-rp-against-op", target.config);
  let text = await readFile(configPath, "utf8");

  const certsDir = path.join(suiteDir, "scripts/certs-keys");
  for (const certFile of [
    "vp-server-jwk.json",
    "vp-signing-jwk.json",
    "vp-signing-ca-jwk.json",
    "vp-signing-jwk-2.json",
    "vp-signing-ca.crt",
    "uk-client-transport.crt",
  ]) {
    try {
      text = text.replaceAll(
        `{${certFile}}`,
        (await readFile(path.join(certsDir, certFile), "utf8")).trim(),
      );
    } catch {
      // Not every config uses every placeholder.
    }
  }

  text = text
    .replaceAll("{BASEURL}", `${suiteOrigin}/`)
    .replaceAll("{LOCALBASEURL}", `${suiteOrigin}/`)
    .replaceAll("{HOSTNAME}", new URL(suiteOrigin).hostname)
    .replaceAll("{BASEURLMTLS}", `${suiteOrigin}/`);

  const config = JSON.parse(text);
  config.alias = `vcknots-${target.planName}-${Date.now()}`.replaceAll(/[^A-Za-z0-9._-]/g, "-");
  config.description = `VCKnots OIDF runner for ${target.planName}`;
  target.overrideConfig?.(config);
  if (target.suite === "haip") {
    const credentialTrustAnchorPem = (
      await readFile(path.join(certsDir, "vp-signing-ca.crt"), "utf8")
    ).trim();
    config.credential ??= {};
    config.credential.trust_anchor_pem = credentialTrustAnchorPem;
    config.credential.status_list_trust_anchor_pem = credentialTrustAnchorPem;
  }
  return config;
}

async function createPlan(target, config) {
  return suiteFetch("/api/plan", {
    method: "POST",
    searchParams: {
      planName: target.planName,
      variant: JSON.stringify(target.variant),
    },
    body: JSON.stringify(config),
  });
}

function selectModules(planModules) {
  let selected = planModules;
  if (moduleFilter) {
    selected = selected.filter(({ testModule }) => testModule.includes(moduleFilter));
  }
  if (moduleLimit != null) {
    selected = selected.slice(0, moduleLimit);
  }
  return selected;
}

async function waitForModule(moduleId) {
  const deadline = Date.now() + moduleTimeoutMs;
  let latest;
  while (Date.now() < deadline) {
    latest = await suiteFetch(`/api/info/${moduleId}`);
    if (latest.status === "FINISHED") {
      return latest;
    }
    await delay(1_000);
  }
  return {
    ...(latest ?? {}),
    runnerTimedOut: true,
    runnerTimeoutMs: moduleTimeoutMs,
  };
}

async function getModuleLogs(moduleId) {
  try {
    return await suiteFetch(`/api/log/${moduleId}`);
  } catch (error) {
    return { error: serializeError(error) };
  }
}

function classifyTarget({ plan, moduleResults, error, timedOut }) {
  if (error) {
    return {
      classification: "suite_or_environment_issue",
      reason: error instanceof Error ? error.message : String(error),
    };
  }
  if (!plan) {
    return {
      classification: "suite_or_environment_issue",
      reason: "No OIDF plan was created.",
    };
  }
  if (moduleResults.length === 0) {
    return {
      classification: "plan_created",
      reason: "OIDF plan was created; no modules were started in this command.",
    };
  }
  const counts = countBy(moduleResults.map((result) => result.classification));
  if (counts.failed) {
    return {
      classification: "failed",
      reason: "At least one OIDF module finished with a failing result.",
      counts,
    };
  }
  if (counts.harness_gap || timedOut) {
    return {
      classification: "harness_gap",
      reason: "At least one OIDF module is waiting for a VCKnots harness or timed out before completion.",
      counts,
    };
  }
  if (counts.review_required) {
    return {
      classification: "review_required",
      reason: "At least one OIDF module finished in REVIEW after screenshot evidence was uploaded.",
      counts,
    };
  }
  if (counts.unsupported_capability) {
    return {
      classification: "unsupported_capability",
      reason: "At least one OIDF module reached a known unsupported capability.",
      counts,
    };
  }
  if (counts.passed === moduleResults.length) {
    return {
      classification: "passed",
      reason: "Every selected OIDF module reported PASSED.",
      counts,
    };
  }
  return {
    classification: "suite_or_environment_issue",
    reason: "Module results did not fit a known classification.",
    counts,
  };
}

function classifyModule({ target, planModule, runnerModule, info, logs }) {
  const result = info.result ?? info.test?.result;
  const logText = JSON.stringify(logs);
  if (result === "PASSED") {
    return { classification: "passed", reason: "OIDF module result is PASSED." };
  }
  if (result === "FAILED") {
    return { classification: "failed", reason: "OIDF module result is FAILED." };
  }
  if (result === "WARNING") {
    return { classification: "failed", reason: "OIDF module finished with WARNING result." };
  }
  if (result === "REVIEW") {
    return {
      classification: "review_required",
      reason: "OIDF module finished in REVIEW after screenshot evidence was uploaded.",
    };
  }
  if (isMissingHarnessEvidence(logText)) {
    return {
      classification: "harness_gap",
      reason: `Module ${planModule.testModule} reached the suite but needs a VCKnots ${target.role} harness that is intentionally not implemented in this milestone.`,
      invocation: extractInvocationHints(logText),
      moduleUrl: runnerModule.url,
    };
  }
  if (info.runnerTimedOut || info.status === "WAITING" || info.status === "RUNNING") {
    return {
      classification: "harness_gap",
      reason: `Module ${planModule.testModule} is waiting for ${target.role} ${target.protocol} behavior that is intentionally not implemented in this milestone.`,
      invocation: extractInvocationHints(logText),
      moduleUrl: runnerModule.url,
    };
  }
  if (/unsupported|not supported|not implemented/i.test(logText)) {
    return {
      classification: "unsupported_capability",
      reason: "Suite logs mention unsupported or unimplemented behavior.",
    };
  }
  return {
    classification: "suite_or_environment_issue",
    reason: `Module ended with status ${info.status ?? "unknown"} and result ${result ?? "unknown"}.`,
  };
}

function isMissingHarnessEvidence(logText) {
  return (
    /127\.0\.0\.1:9080/i.test(logText) ||
    /Connection refused/i.test(logText) ||
    /redirect_to_authorization_endpoint/i.test(logText) ||
    /credential_offer_redirect_url/i.test(logText)
  );
}

function extractInvocationHints(logText) {
  const hints = [];
  for (const pattern of [
    /openid4vp:\/\/[^"\\\s]+/g,
    /openid-credential-offer:\/\/[^"\\\s]+/g,
    /https:\/\/[^"\\\s]+\/credential_offer[^"\\\s]*/g,
    /https:\/\/[^"\\\s]+\/authorize[^"\\\s]*/g,
  ]) {
    for (const match of logText.matchAll(pattern)) {
      hints.push(match[0]);
    }
  }
  return [...new Set(hints)].slice(0, 10);
}

function extractConcreteWalletInvocationUrls(logs) {
  const urls = [];
  const visit = (value, key = "") => {
    if (typeof value === "string") {
      const isInvocationField =
        key === "redirect_to_authorization_endpoint" ||
        key === "credential_offer_redirect_url" ||
        key === "redirect_to";
      const hasRequiredWalletParams =
        (/\/oidf\/vp\/authorize/i.test(value) && value.includes("request_uri=")) ||
        (/\/oidf\/vci\/credential-offer/i.test(value) && value.includes("credential_offer"));
      if (isInvocationField && /^https?:\/\/[^*\s"]+$/i.test(value) && hasRequiredWalletParams) {
        urls.push(value);
      }
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        visit(item, key);
      }
      return;
    }
    if (value && typeof value === "object") {
      for (const [childKey, item] of Object.entries(value)) {
        visit(item, childKey);
      }
    }
  };
  visit(logs);
  return [...new Set(urls)];
}

function extractReviewPlaceholders(logs) {
  const placeholders = [];
  const visit = (value) => {
    if (Array.isArray(value)) {
      for (const item of value) {
        visit(item);
      }
      return;
    }
    if (!value || typeof value !== "object") {
      return;
    }
    if (value.result === "REVIEW" && typeof value.upload === "string" && value.upload.length > 0) {
      placeholders.push(value.upload);
    }
    for (const item of Object.values(value)) {
      visit(item);
    }
  };
  visit(logs);
  return [...new Set(placeholders)];
}

async function uploadPlaceholderImage(moduleId, placeholder) {
  await suiteFetchRaw(`/api/log/${moduleId}/images/${placeholder}`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "text/plain",
    },
    body: placeholderImage,
  });
}

async function suiteFetch(pathname, options = {}) {
  const { text } = await suiteFetchRaw(pathname, {
    method: options.method,
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
    searchParams: options.searchParams,
    body: options.body,
  });
  return text ? JSON.parse(text) : {};
}

async function suiteFetchRaw(pathname, options = {}) {
  const url = new URL(pathname, suiteOrigin);
  for (const [key, value] of Object.entries(options.searchParams ?? {})) {
    url.searchParams.set(key, value);
  }

  const response = await fetch(url, {
    method: options.method ?? "GET",
    headers: options.headers ?? { Accept: "application/json" },
    body: options.body,
  });
  const text = await response.text();

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}: ${text}`);
  }
  return { response, text };
}

async function createArtifactDir(targetName) {
  const artifactDir = path.join(
    oidfRoot,
    "artifacts",
    targetName,
    new Date().toISOString().replaceAll(/[:.]/g, "-"),
  );
  await mkdir(artifactDir, { recursive: true });
  return artifactDir;
}

async function writeJson(file, value) {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

function countBy(values) {
  return values.reduce((counts, value) => {
    counts[value] = (counts[value] ?? 0) + 1;
    return counts;
  }, {});
}

function trimTrailingSlash(value) {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

function optionalPositiveInteger(value) {
  if (!value) {
    return undefined;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    fail(`Expected a positive integer, got ${value}`);
  }
  return parsed;
}

function sanitizeFileName(value) {
  return value.replaceAll(/[^A-Za-z0-9._-]/g, "-").slice(0, 160);
}

function serializeError(error) {
  if (error instanceof Error) {
    return { name: error.name, message: error.message, stack: error.stack };
  }
  return { message: String(error) };
}

function requireTargetName(name) {
  if (!name || !targets[name]) {
    fail(`Expected target name. Known targets: ${targetNames.join(", ")}`);
  }
  return name;
}

function printHelp() {
  console.log(`Usage:
  node conformance/oidf/scripts/create-plan-spike.mjs list-targets
  node conformance/oidf/scripts/create-plan-spike.mjs start-suite
  node conformance/oidf/scripts/create-plan-spike.mjs create-plan <target>
  node conformance/oidf/scripts/create-plan-spike.mjs run-target <target>
  node conformance/oidf/scripts/create-plan-spike.mjs run-all-haip
  node conformance/oidf/scripts/create-plan-spike.mjs run-all-wallet-final
  node conformance/oidf/scripts/create-plan-spike.mjs run-all

Targets:
  ${targetNames.join("\n  ")}

Useful environment:
  OIDF_MODULE_TIMEOUT_MS=15000
  OIDF_MODULE_LIMIT=1
  OIDF_MODULE_FILTER=happy-flow
  VCKNOTS_OIDF_HARNESS_ORIGIN=http://127.0.0.1:9080
  VCKNOTS_HAIP_HARNESS_ORIGIN=http://127.0.0.1:9080
`);
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
