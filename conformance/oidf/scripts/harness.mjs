#!/usr/bin/env node

import { execFile } from "node:child_process";
import http from "node:http";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = path.dirname(scriptPath);
const oidfRoot = path.resolve(scriptDir, "..");
const vcknotsRoot = path.resolve(oidfRoot, "../..");
const walletRoot = path.join(vcknotsRoot, "wallet");
const defaultSuiteDir = path.resolve(vcknotsRoot, "../openid-conformance-suite");
const suiteDir = path.resolve(process.env.OIDF_CONFORMANCE_SUITE_DIR ?? defaultSuiteDir);
const execFileAsync = promisify(execFile);

const host = process.env.VCKNOTS_OIDF_HARNESS_HOST ?? "127.0.0.1";
const port = Number(process.env.VCKNOTS_OIDF_HARNESS_PORT ?? "9080");

const server = http.createServer(async (request, response) => {
  try {
    const requestUrl = new URL(request.url ?? "/", `http://${request.headers.host ?? `${host}:${port}`}`);
    if (request.method === "GET" && requestUrl.pathname === "/health") {
      return sendJson(response, 200, { ok: true });
    }
    if (request.method === "GET" && requestUrl.pathname === "/oidf/vp/authorize") {
      const result = await handleVpAuthorize(requestUrl);
      return sendHtml(response, result.status, result.body);
    }
    if (request.method === "GET" && requestUrl.pathname === "/oidf/vci/credential-offer") {
      const result = await handleVciCredentialOffer(requestUrl);
      return sendHtml(response, result.status, result.body);
    }
    return sendJson(response, 404, { error: "not_found", path: requestUrl.pathname });
  } catch (error) {
    console.error("[harness] request failed", error);
    return sendJson(response, 500, {
      error: "harness_error",
      message: error instanceof Error ? error.message : String(error),
    });
  }
});

server.listen(port, host, () => {
  console.log(`[harness] listening on http://${host}:${port}`);
});

async function handleVpAuthorize(requestUrl) {
  console.log(`[harness] VP authorize request=${requestUrl}`);
  let result;
  try {
    result = await runWalletAPI("vp-authorize", [
      "--authorize-url",
      requestUrl.toString(),
      "--suite-dir",
      suiteDir,
    ]);
  } catch (error) {
    const message = error?.stderr?.trim() || (error instanceof Error ? error.message : String(error));
    if (message.includes("wallet rejected request:")) {
      console.log(`[harness] ${message}`);
      return { status: 400, body: message };
    }
    throw error;
  }
  const parsed = JSON.parse(result);
  const suiteBody = parsed.suite_response_body ?? "";
  await openRedirectUriIfReturned(suiteBody);

  console.log("[harness] completed VP presentation through wallet API");
  return { status: 200, body: "The response has been sent to the server for processing" };
}

async function handleVciCredentialOffer(requestUrl) {
  const result = await runWalletAPI("vci-receive", [
    "--offer-url",
    requestUrl.toString(),
    "--suite-dir",
    suiteDir,
    "--conformance-server",
    suiteOrigin(),
  ]);
  console.log(`[harness] completed VCI issuance through wallet API: ${result.trim()}`);
  return { status: 200, body: "The response has been sent to the server for processing" };
}

async function runWalletAPI(command, args) {
  const { stdout, stderr } = await execFileAsync("go", ["run", "./cmd/oidf-harness-api", command, ...args], {
    cwd: walletRoot,
    env: {
      ...process.env,
      MISE_TRUSTED_CONFIG_PATHS: walletRoot,
    },
    maxBuffer: 1024 * 1024,
  });
  if (stderr.trim().length > 0) {
    console.error(`[harness] wallet API ${command} stderr: ${stderr.trim()}`);
  }
  return stdout;
}

async function openRedirectUriIfReturned(suiteBody) {
  let parsed;
  try {
    parsed = JSON.parse(suiteBody);
  } catch {
    return;
  }
  if (typeof parsed.redirect_uri !== "string") {
    return;
  }
  console.log(`[harness] opening redirect_uri from direct_post response: ${parsed.redirect_uri}`);
  const redirectUrl = new URL(parsed.redirect_uri);
  const response = await fetch(parsed.redirect_uri, {
    headers: { accept: "text/html,application/xhtml+xml,application/json,*/*" },
  });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`redirect_uri returned ${response.status}`);
  }
  const implicitSubmitUrl = extractImplicitSubmitUrl(body);
  if (implicitSubmitUrl) {
    console.log(`[harness] submitting redirect_uri fragment to ${implicitSubmitUrl}`);
    const submitResponse = await fetch(implicitSubmitUrl, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: redirectUrl.hash,
    });
    await submitResponse.text();
    if (!submitResponse.ok) {
      throw new Error(`implicit fragment submission returned ${submitResponse.status}`);
    }
  } else {
    console.log("[harness] redirect_uri response did not contain an implicit submit URL");
  }
}

function extractImplicitSubmitUrl(html) {
  const direct = html.match(/https:\/\/[^"'\\\s]+\/implicit\/[A-Za-z0-9]+/)?.[0];
  if (direct) {
    return direct;
  }
  const escaped = html.match(/"(https:\\\/\\\/[^"]+\\\/implicit\\\/[A-Za-z0-9]+)"/)?.[1];
  if (escaped) {
    return escaped.replaceAll("\\/", "/");
  }
  return undefined;
}

function suiteOrigin() {
  return trimTrailingSlash(process.env.CONFORMANCE_SERVER ?? "https://localhost.emobix.co.uk:8443");
}

function trimTrailingSlash(value) {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

function sendJson(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

function sendHtml(response, status, body) {
  response.writeHead(status, { "content-type": "text/html; charset=utf-8" });
  response.end(`<!doctype html><html><body><p id="submission_complete">${escapeHtml(body)}</p></body></html>`);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
