# VCKnots OIDF Conformance Spike

This directory is a first harness home for running VCKnots-focused OpenID Foundation conformance experiments before integrating Final 1.0 or HAIP behavior into a wallet application.

The harness starts the OIDF conformance suite with Docker named volumes, creates HAIP test plans through the suite API, can start suite modules, and saves artifacts under `conformance/oidf/artifacts`. It intentionally does not depend on the NICE wallet app, BetterAuth, a database, or UI routes.

## Why this lives in VCKnots

VCKnots should prove its protocol, cryptographic, and wire-format behavior before a downstream app wraps it in app-specific state and UX. The downstream wallet can still own durable state, login, credential storage, and user consent, but this harness keeps the first conformance failures attributable to VCKnots, the harness, unsupported capabilities, or suite/environment setup.

## Current scope

The current script is a suite/API smoke test and red-test runner, not a conformance pass claim. It verifies that the local OIDF suite can start, that the HAIP plans can be created from the pinned suite configuration files, and that modules can be invoked with bounded timeouts for TDD.

The HAIP targets are:

- `vci-wallet-haip`: `oid4vci-1_0-wallet-haip-test-plan`
- `vci-issuer-haip`: `oid4vci-1_0-issuer-haip-test-plan`
- `vp-wallet-haip`: `oid4vp-1final-wallet-haip-test-plan`
- `vp-verifier-haip`: `oid4vp-1final-verifier-haip-test-plan`

The HAIP targets expose the expected VCKnots gaps. OpenID4VCI HAIP requires authorization code flow, DPoP, client or wallet attestation, key attestation, and Final-era nonce and encryption behavior. OpenID4VP HAIP requires encrypted responses such as `direct_post.jwt`, Final client identifier handling such as `x509_hash`, and DCQL-oriented requests.

## Prerequisites

- Docker with Compose support.
- Node.js 22 or newer.
- A checked-out OIDF conformance suite source tree. In the NICE repository this is available as the sibling directory `../openid-conformance-suite` next to this VCKnots submodule. In a standalone VCKnots clone, set `OIDF_CONFORMANCE_SUITE_DIR` to the suite checkout.

Do not use the upstream `docker-compose-prebuilt.yml` directly from the suite checkout for local repository work. That file can bind-mount MongoDB data into the suite repository and create root-owned files. This directory uses `docker-compose-prebuilt-named-volume.yml` to keep MongoDB state in a Docker named volume.

## Commands

From the VCKnots repository root:

    node conformance/oidf/scripts/create-plan-spike.mjs list-targets

Start the local suite only:

    node conformance/oidf/scripts/create-plan-spike.mjs start-suite

Create a VP HAIP wallet plan and save artifacts:

    node conformance/oidf/scripts/create-plan-spike.mjs create-plan vp-wallet-haip

Create every HAIP plan one at a time:

    node conformance/oidf/scripts/create-plan-spike.mjs create-plan vci-wallet-haip
    node conformance/oidf/scripts/create-plan-spike.mjs create-plan vci-issuer-haip
    node conformance/oidf/scripts/create-plan-spike.mjs create-plan vp-wallet-haip
    node conformance/oidf/scripts/create-plan-spike.mjs create-plan vp-verifier-haip

Run one HAIP target. This starts every selected module for the target and writes per-module `*-module.json`, `*-info.json`, `*-log.json`, and `*-classification.json` files:

    node conformance/oidf/scripts/create-plan-spike.mjs run-target vp-wallet-haip

Run all four HAIP targets:

    node conformance/oidf/scripts/create-plan-spike.mjs run-all-haip

For a quick red smoke run while no VCKnots HAIP harness exists yet, limit each target to one module and use a short timeout:

    OIDF_MODULE_LIMIT=1 OIDF_MODULE_TIMEOUT_MS=15000 node conformance/oidf/scripts/create-plan-spike.mjs run-all-haip

Useful environment variables:

- `CONFORMANCE_SERVER`: suite base URL, default `https://localhost.emobix.co.uk:8443`.
- `OIDF_CONFORMANCE_SUITE_DIR`: path to the OIDF suite checkout.
- `OIDF_COMPOSE_PROJECT`: Docker Compose project name, default `vcknots-oidf-conformance`.
- `OIDF_CONFORMANCE_HTTPS_PORT`: host HTTPS port for the suite, default `8443`.
- `OIDF_SUITE_READY_TIMEOUT_MS`: suite readiness timeout, default `180000`.
- `OIDF_MODULE_TIMEOUT_MS`: per-module timeout, default `120000`.
- `OIDF_MODULE_LIMIT`: optional number of modules to run from each created plan.
- `OIDF_MODULE_FILTER`: optional substring filter for module names.
- `VCKNOTS_HAIP_HARNESS_ORIGIN`: default future harness origin, default `http://127.0.0.1:9080`.
- `VCKNOTS_HAIP_WALLET_CREDENTIAL_OFFER_ENDPOINT`: VCI wallet entrypoint override.
- `VCKNOTS_HAIP_WALLET_AUTHORIZATION_ENDPOINT`: VP wallet entrypoint override.
- `VCKNOTS_HAIP_ISSUER_BASE_URL`: VCI issuer under test override.
- `VCKNOTS_HAIP_VERIFIER_AUTHORIZATION_ENDPOINT`: VP verifier authorization endpoint override.

## Artifact classification

The runner writes a `classification.json` for each target. Current red results are expected.

- `plan_created`: the suite accepted the plan and variant, but no module was started.
- `passed`: every selected module reported `PASSED`.
- `failed`: at least one selected module reported `FAILED`.
- `harness_gap`: a module is waiting for a VCKnots HAIP wallet, issuer, or verifier HTTP behavior that this milestone intentionally does not implement.
- `unsupported_capability`: logs point to a known unsupported HAIP capability.
- `suite_or_environment_issue`: Docker, TLS, suite API, plan creation, or an unexpected module state blocked meaningful protocol testing.

## Next harness milestones

The next useful step is to add very thin VCKnots HTTP harnesses beside this script. For VP wallet tests, that harness should expose an authorization endpoint, accept the suite-generated `openid4vp` request, call VCKnots request parsing and presentation code with request-scoped fixture credentials and keys, and post the result back to the suite. For VCI wallet tests, it should expose a credential-offer entrypoint and call VCKnots receive utilities with request-scoped keys. For issuer and verifier tests, it should expose only the HTTP surfaces that the OIDF suite expects, backed by VCKnots APIs as they are implemented.

Keep the failure classification explicit:

- `vcknots_implementation_defect`: VCKnots protocol, crypto, or wire behavior is wrong.
- `harness_gap`: the HTTP or browser-driving wrapper is missing behavior.
- `unsupported_capability`: the selected suite variant requires a capability not implemented yet.
- `suite_or_environment_issue`: Docker, TLS, port, or suite API prevented a meaningful protocol result.
