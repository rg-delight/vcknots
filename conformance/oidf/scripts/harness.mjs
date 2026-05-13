#!/usr/bin/env node

import { createHash, randomBytes, randomUUID, X509Certificate } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = path.dirname(scriptPath);
const oidfRoot = path.resolve(scriptDir, "..");
const vcknotsRoot = path.resolve(oidfRoot, "../..");
const defaultSuiteDir = path.resolve(vcknotsRoot, "../openid-conformance-suite");
const suiteDir = path.resolve(process.env.OIDF_CONFORMANCE_SUITE_DIR ?? defaultSuiteDir);
const requireFromIssuerVerifier = createRequire(path.join(vcknotsRoot, "issuer+verifier/package.json"));

const { SDJwtInstance } = requireFromIssuerVerifier("@sd-jwt/core");
const { ES256, digest, generateSalt } = requireFromIssuerVerifier("@sd-jwt/crypto-nodejs");
const jose = requireFromIssuerVerifier("jose");

const host = process.env.VCKNOTS_OIDF_HARNESS_HOST ?? "127.0.0.1";
const port = Number(process.env.VCKNOTS_OIDF_HARNESS_PORT ?? "9080");

const holderKeyPair = await ES256.generateKeyPair();
const issuerKeyPair = await ES256.generateKeyPair();
const haipCredentialSigningJwk = await readJson(
  path.join(suiteDir, "scripts/certs-keys/vp-signing-jwk.json"),
);
const haipCredentialX5c = Array.isArray(haipCredentialSigningJwk.x5c)
  ? haipCredentialSigningJwk.x5c
  : [];
const vciIssuerHarnessConfig = await readJson(
  path.join(suiteDir, "scripts/test-configs-rp-against-op/vci-issuer-test-config-client_attestation-client-auth-dpop.json"),
);
const vciClientId = vciIssuerHarnessConfig.client.client_id;
const vciRedirectUri = `${suiteOrigin()}/test/a/oidf-vci-issuer-test/callback`;
const vciClientJwk = vciIssuerHarnessConfig.client.jwks.keys[0];
const vciClientAttesterJwk = vciIssuerHarnessConfig.vci.client_attester_keys_jwks.keys[0];
const vciCredentialResponseEncryptionKeyPair = await jose.generateKeyPair("ECDH-ES", {
  crv: "P-256",
  extractable: true,
});
const vciCredentialResponseEncryptionPrivateJwk = await jose.exportJWK(
  vciCredentialResponseEncryptionKeyPair.privateKey,
);
const vciCredentialResponseEncryptionPublicJwk = {
  ...(await jose.exportJWK(vciCredentialResponseEncryptionKeyPair.publicKey)),
  alg: "ECDH-ES",
  use: "enc",
  kid: "vcknots-vci-credential-response-enc",
};
const holderPublicJwk = publicOnlyJwk(holderKeyPair.publicKey);
const fixtureClaims = {
  given_name: "TARO",
  family_name: "TEST",
  birthdate: "2000-03-03",
};
const fixtureVct = "urn:eudi:pid:1";

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
    if (error instanceof WalletRejectionError) {
      console.log(`[harness] wallet rejected request: ${error.message}`);
      return sendHtml(response, 400, error.message);
    }
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
  const requestUri = requiredParam(requestUrl, "request_uri");
  const outerClientId = requiredParam(requestUrl, "client_id");

  console.log(`[harness] VP authorize request_uri=${requestUri}`);
  const requestObject = await fetchRequestObject(requestUri, requestUrl.searchParams.get("request_uri_method"));
  const { payload } = await verifyRequestObject(requestObject, outerClientId);
  validateOuterClientId(outerClientId);

  const clientId = stringClaim(payload, "client_id");
  if (clientId !== outerClientId) {
    rejectRequest(`outer client_id does not match request object client_id: ${outerClientId} != ${clientId}`);
  }
  const responseUri = stringClaim(payload, "response_uri");
  const haip = isHaipRequest(requestUri, responseUri);
  const nonce = stringClaim(payload, "nonce");
  const responseMode = stringClaim(payload, "response_mode");
  if (responseMode !== "direct_post.jwt") {
    rejectRequest(`unsupported response_mode ${responseMode}`);
  }
  if (typeof payload.redirect_uri === "string") {
    rejectRequest("direct_post.jwt request contains redirect_uri");
  }
  if (!new URL(responseUri).pathname.endsWith("/responseuri")) {
    rejectRequest(`response_uri is not the configured direct-post endpoint: ${responseUri}`);
  }
  validateTransactionData(payload.transaction_data);

  const dcql = objectClaim(payload, "dcql_query");
  const credentialIds = resolveSatisfiableDcqlCredentialIds(dcql);
  if (credentialIds.length === 0) {
    rejectRequest("DCQL query cannot be satisfied by the harness fixture credential");
  }
  const vpToken = {};
  for (const credentialId of credentialIds) {
    vpToken[credentialId] = [
      await createPresentedSdJwt({
        vct: resolveSingleVct(dcql, credentialId),
        requestedClaims: resolveRequestedClaimNames(dcql, credentialId),
        audience: clientId,
        nonce,
        haip,
      }),
    ];
  }

  const authzResponse = {
    vp_token: vpToken,
  };
  if (typeof payload.state === "string") {
    authzResponse.state = payload.state;
  }

  const encryptedResponse = await encryptAuthorizationResponse(authzResponse, payload);
  const suiteResponse = await fetch(responseUri, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ response: encryptedResponse }),
  });
  const suiteBody = await suiteResponse.text();
  if (!suiteResponse.ok) {
    throw new Error(`suite response_uri returned ${suiteResponse.status}: ${suiteBody}`);
  }
  await openRedirectUriIfReturned(suiteBody);

  console.log(`[harness] posted encrypted VP response to ${responseUri}`);
  return { status: 200, body: "The response has been sent to the server for processing" };
}

async function handleVciCredentialOffer(requestUrl) {
  const credentialOffer = JSON.parse(requiredParam(requestUrl, "credential_offer"));
  const credentialIssuer = stringProperty(credentialOffer, "credential_issuer");
  const credentialConfigurationId = Array.isArray(credentialOffer.credential_configuration_ids)
    ? credentialOffer.credential_configuration_ids[0]
    : undefined;
  if (typeof credentialConfigurationId !== "string" || credentialConfigurationId.length === 0) {
    rejectRequest("credential_offer does not contain a credential_configuration_id");
  }

  console.log(`[harness] VCI credential offer issuer=${credentialIssuer}`);
  const issuerMetadata = await fetchJson(wellKnownUrl(credentialIssuer, "openid-credential-issuer"));
  const authorizationServerIssuer = Array.isArray(issuerMetadata.authorization_servers)
    ? issuerMetadata.authorization_servers[0]
    : credentialIssuer;
  const authorizationServerMetadata = await fetchJson(
    wellKnownUrl(authorizationServerIssuer, "oauth-authorization-server"),
  );

  const attestationChallenge = await fetchClientAttestationChallengeIfAdvertised(
    authorizationServerMetadata.challenge_endpoint,
  );
  const clientAttestation = await createClientAttestation();

  const codeVerifier = randomBase64Url(32);
  const state = randomBase64Url(16);
  const codeChallenge = base64url(createHash("sha256").update(codeVerifier).digest());
  const credentialConfiguration =
    issuerMetadata.credential_configurations_supported?.[credentialConfigurationId];
  const scope = typeof credentialConfiguration?.scope === "string"
    ? credentialConfiguration.scope
    : credentialConfigurationId;

  const parEndpoint = stringProperty(authorizationServerMetadata, "pushed_authorization_request_endpoint");
  const authorizationEndpoint = stringProperty(authorizationServerMetadata, "authorization_endpoint");
  const tokenEndpoint = stringProperty(authorizationServerMetadata, "token_endpoint");
  const credentialEndpoint = stringProperty(issuerMetadata, "credential_endpoint");
  const nonceEndpoint = stringProperty(issuerMetadata, "nonce_endpoint");
  const deferredCredentialEndpoint = stringProperty(issuerMetadata, "deferred_credential_endpoint");

  const parParams = new URLSearchParams({
    response_type: "code",
    client_id: vciClientId,
    redirect_uri: vciRedirectUri,
    scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
  const issuerState = credentialOffer.grants?.authorization_code?.issuer_state;
  if (typeof issuerState === "string") {
    parParams.set("issuer_state", issuerState);
  }

  const parResponse = await fetchWithClientAttestation(parEndpoint, {
    method: "POST",
    body: parParams,
    clientAttestation,
    attestationChallenge,
    authorizationServerIssuer,
    contentType: "application/x-www-form-urlencoded",
  });
  const parBody = await readJsonResponse(parResponse, "PAR");
  const requestUri = stringProperty(parBody, "request_uri");

  const authorizationUrl = new URL(authorizationEndpoint);
  authorizationUrl.searchParams.set("client_id", vciClientId);
  authorizationUrl.searchParams.set("request_uri", requestUri);
  const authorizationResponse = await fetch(authorizationUrl, { redirect: "manual" });
  const authorizationLocation = authorizationResponse.headers.get("location");
  if (!authorizationLocation) {
    throw new Error(`authorization endpoint did not redirect: ${authorizationResponse.status} ${await authorizationResponse.text()}`);
  }
  const authorizationRedirect = new URL(authorizationLocation, authorizationEndpoint);
  assertReturnedState(authorizationRedirect, state);
  const code = requiredParam(authorizationRedirect, "code");

  const tokenParams = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: vciRedirectUri,
    code_verifier: codeVerifier,
    client_id: vciClientId,
  });
  const tokenResponse = await fetchWithClientAttestationAndDpopRetry(tokenEndpoint, {
    method: "POST",
    body: tokenParams,
    clientAttestation,
    attestationChallenge,
    authorizationServerIssuer,
    contentType: "application/x-www-form-urlencoded",
  });
  const tokenBody = await readJsonResponse(tokenResponse, "token");
  const accessToken = stringProperty(tokenBody, "access_token");

  const nonceResponse = await fetch(nonceEndpoint, { method: "POST" });
  const nonceBody = await readJsonResponse(nonceResponse, "nonce");
  const credentialNonce = stringProperty(nonceBody, "c_nonce");
  const proofJwt = await createCredentialRequestJwtProof({
    audience: credentialIssuer,
    nonce: credentialNonce,
  });

  let credentialBody = await postVciCredentialRequest({
    endpoint: credentialEndpoint,
    issuerMetadata,
    accessToken,
    label: "credential",
    requestBody: {
      credential_configuration_id: credentialConfigurationId,
      proofs: {
        jwt: [proofJwt],
      },
    },
  });
  if (typeof credentialBody.transaction_id === "string") {
    credentialBody = await postVciCredentialRequest({
      endpoint: deferredCredentialEndpoint,
      issuerMetadata,
      accessToken,
      label: "deferred credential",
      requestBody: {
        transaction_id: credentialBody.transaction_id,
      },
    });
  }
  if (typeof credentialBody.notification_id === "string" && typeof issuerMetadata.notification_endpoint === "string") {
    await sendCredentialAcceptedNotification({
      notificationEndpoint: issuerMetadata.notification_endpoint,
      accessToken,
      notificationId: credentialBody.notification_id,
    });
  }

  console.log(`[harness] completed VCI issuance for ${credentialConfigurationId}`);
  return { status: 200, body: "The response has been sent to the server for processing" };
}

async function fetchRequestObject(requestUri, requestUriMethod) {
  const usePost = requestUriMethod?.toLowerCase() === "post";
  const response = await fetch(requestUri, {
    method: usePost ? "POST" : "GET",
    headers: {
      accept: "application/oauth-authz-req+jwt, application/jwt, text/plain, */*",
      ...(usePost ? { "content-type": "application/x-www-form-urlencoded" } : {}),
    },
    body: usePost ? new URLSearchParams({ wallet_metadata: "{}" }) : undefined,
  });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`request_uri fetch failed: ${response.status} ${body}`);
  }
  return body.trim();
}

async function verifyRequestObject(requestObject, expectedClientId) {
  const header = jose.decodeProtectedHeader(requestObject);
  if (!Array.isArray(header.x5c) || header.x5c.length === 0) {
    throw new Error("signed request object is missing x5c header");
  }

  const leafDer = Buffer.from(header.x5c[0], "base64");
  if (expectedClientId.startsWith("x509_hash:")) {
    const expectedHash = expectedClientId.slice("x509_hash:".length);
    const actualHash = base64url(createHash("sha256").update(leafDer).digest());
    if (expectedHash !== actualHash) {
      rejectRequest(`x509_hash client_id mismatch: expected ${expectedHash}, got ${actualHash}`);
    }
  }

  const cert = new X509Certificate(leafDer);
  try {
    return await jose.jwtVerify(requestObject, cert.publicKey, {
      audience: "https://self-issued.me/v2",
    });
  } catch (error) {
    rejectRequest(`request object verification failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function createPresentedSdJwt({ vct, requestedClaims, audience, nonce, haip }) {
  const signingJwk = haip ? haipCredentialSigningJwk : issuerKeyPair.privateKey;
  const signer = await ES256.getSigner(signingJwk);
  const sdJwt = new SDJwtInstance({
    signer,
    signAlg: ES256.alg,
    hasher: digest,
    hashAlg: "sha-256",
    saltGenerator: () => generateSalt(8),
  });
  const now = Math.floor(Date.now() / 1000);
  const credentialPayload = {
    iss: "https://issuer.example.test",
    vct,
    cnf: { jwk: holderPublicJwk },
    iat: now,
    nbf: now,
    exp: now + 3600,
    ...fixtureClaims,
  };
  const disclosureFrame = {
    _sd: ["given_name", "family_name", "birthdate"],
  };
  const issued = await sdJwt.issue(credentialPayload, disclosureFrame, {
    header: createCredentialHeader(haip),
  });

  const presentationFrame = Object.fromEntries(requestedClaims.map((name) => [name, true]));
  const sdJwtWithDisclosures = await sdJwt.present(issued, presentationFrame);
  const kbJwt = await createKeyBindingJwt(sdJwtWithDisclosures, audience, nonce);
  return `${sdJwtWithDisclosures}${kbJwt}`;
}

function createCredentialHeader(haip) {
  if (!haip) {
    return { typ: "dc+sd-jwt", kid: "vcknots-oidf-harness-issuer" };
  }
  if (haipCredentialX5c.length === 0) {
    throw new Error("HAIP credential signing JWK is missing x5c");
  }
  return {
    typ: "dc+sd-jwt",
    x5c: haipCredentialX5c,
  };
}

function isHaipRequest(...values) {
  return values.some((value) => typeof value === "string" && value.includes("wallet-haip-test-plan"));
}

async function createKeyBindingJwt(sdJwtWithDisclosures, audience, nonce) {
  const key = await jose.importJWK(holderKeyPair.privateKey, "ES256");
  const sdHash = base64url(createHash("sha256").update(sdJwtWithDisclosures, "ascii").digest());
  return new jose.SignJWT({
    aud: audience,
    iat: Math.floor(Date.now() / 1000),
    nonce,
    sd_hash: sdHash,
  })
    .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
    .sign(key);
}

async function encryptAuthorizationResponse(authzResponse, requestPayload) {
  const clientMetadata = objectClaim(requestPayload, "client_metadata");
  const jwks = objectClaim(clientMetadata, "jwks");
  const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
  const encryptionJwk = keys.find((key) => key.use === "enc") ?? keys[0];
  if (!encryptionJwk) {
    throw new Error("client_metadata.jwks does not contain an encryption key");
  }

  const alg = typeof encryptionJwk.alg === "string" ? encryptionJwk.alg : "ECDH-ES";
  const encValues = Array.isArray(clientMetadata.encrypted_response_enc_values_supported)
    ? clientMetadata.encrypted_response_enc_values_supported
    : [];
  const enc = typeof encValues[0] === "string" ? encValues[0] : "A128GCM";
  const key = await jose.importJWK(encryptionJwk, alg);
  const payload = new TextEncoder().encode(JSON.stringify(authzResponse));

  return new jose.CompactEncrypt(payload)
    .setProtectedHeader({
      alg,
      enc,
      ...(typeof encryptionJwk.kid === "string" ? { kid: encryptionJwk.kid } : {}),
      cty: "json",
    })
    .encrypt(key);
}

async function fetchClientAttestationChallengeIfAdvertised(challengeEndpoint) {
  if (typeof challengeEndpoint !== "string" || challengeEndpoint.length === 0) {
    return undefined;
  }
  const response = await fetch(challengeEndpoint, { method: "POST" });
  const body = await readJsonResponse(response, "client attestation challenge");
  return typeof body.attestation_challenge === "string" ? body.attestation_challenge : undefined;
}

async function createClientAttestation() {
  const clientInstancePublicJwk = {
    ...publicOnlyJwk(vciClientJwk),
    kid: vciClientJwk.kid,
    alg: "ES256",
    use: "sig",
  };
  const now = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({
    iss: "https://client-attester.example.org/",
    sub: vciClientId,
    iat: now,
    nbf: now,
    exp: now + 300,
    cnf: {
      jwk: clientInstancePublicJwk,
    },
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "oauth-client-attestation+jwt",
      x5c: vciClientAttesterJwk.x5c,
      kid: vciClientAttesterJwk.kid,
    })
    .sign(await jose.importJWK(vciClientAttesterJwk, "ES256"));
}

async function createClientAttestationPop({ authorizationServerIssuer, attestationChallenge }) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: vciClientId,
    iat: now,
    nbf: now,
    exp: now + 300,
    aud: authorizationServerIssuer,
    jti: randomUUID(),
  };
  if (typeof attestationChallenge === "string") {
    payload.challenge = attestationChallenge;
  }
  return new jose.SignJWT(payload)
    .setProtectedHeader({
      alg: "ES256",
      typ: "oauth-client-attestation-pop+jwt",
      kid: vciClientJwk.kid,
    })
    .sign(await jose.importJWK(vciClientJwk, "ES256"));
}

async function createDpopProof({ method, url, nonce, accessToken }) {
  const publicJwk = {
    ...publicOnlyJwk(vciClientJwk),
    kid: vciClientJwk.kid,
    alg: "ES256",
    use: "sig",
  };
  const payload = {
    htm: method.toUpperCase(),
    htu: dpopHtu(url),
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
  };
  if (nonce) {
    payload.nonce = nonce;
  }
  if (accessToken) {
    payload.ath = base64url(createHash("sha256").update(accessToken).digest());
  }
  return new jose.SignJWT(payload)
    .setProtectedHeader({
      alg: "ES256",
      typ: "dpop+jwt",
      jwk: publicJwk,
    })
    .sign(await jose.importJWK(vciClientJwk, "ES256"));
}

async function createCredentialRequestJwtProof({ audience, nonce }) {
  const now = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({
    aud: audience,
    iat: now,
    nonce,
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "openid4vci-proof+jwt",
      jwk: publicOnlyJwk(holderKeyPair.publicKey),
    })
    .sign(await jose.importJWK(holderKeyPair.privateKey, "ES256"));
}

async function fetchWithClientAttestation(url, {
  method,
  body,
  clientAttestation,
  attestationChallenge,
  authorizationServerIssuer,
  contentType,
}) {
  const pop = await createClientAttestationPop({ authorizationServerIssuer, attestationChallenge });
  return fetch(url, {
    method,
    headers: {
      accept: "application/json",
      "content-type": contentType,
      "oauth-client-attestation": clientAttestation,
      "oauth-client-attestation-pop": pop,
    },
    body,
  });
}

async function fetchWithClientAttestationAndDpopRetry(url, options) {
  let dpopNonce;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const pop = await createClientAttestationPop({
      authorizationServerIssuer: options.authorizationServerIssuer,
      attestationChallenge: options.attestationChallenge,
    });
    const dpop = await createDpopProof({
      method: options.method,
      url,
      nonce: dpopNonce,
    });
    const response = await fetch(url, {
      method: options.method,
      headers: {
        accept: "application/json",
        "content-type": options.contentType,
        dpop,
        "oauth-client-attestation": options.clientAttestation,
        "oauth-client-attestation-pop": pop,
      },
      body: options.body,
    });
    if (response.ok || !isDpopNonceError(response)) {
      return response;
    }
    dpopNonce = response.headers.get("dpop-nonce");
    await response.text();
  }
  throw new Error(`DPoP nonce retry exhausted for ${url}`);
}

async function fetchWithDpopRetry(url, { method, body, contentType, accessToken }) {
  let dpopNonce;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const dpop = await createDpopProof({
      method,
      url,
      nonce: dpopNonce,
      accessToken,
    });
    const response = await fetch(url, {
      method,
      headers: {
        accept: "application/json",
        authorization: `DPoP ${accessToken}`,
        "content-type": contentType,
        dpop,
      },
      body,
    });
    if (response.ok || !isDpopNonceError(response)) {
      return response;
    }
    dpopNonce = response.headers.get("dpop-nonce");
    await response.text();
  }
  throw new Error(`DPoP nonce retry exhausted for ${url}`);
}

async function postVciCredentialRequest({ endpoint, issuerMetadata, accessToken, requestBody, label }) {
  const bodyWithEncryption = addCredentialResponseEncryptionIfSupported(requestBody, issuerMetadata);
  const { body, contentType } = await encodeCredentialRequest(bodyWithEncryption, issuerMetadata);
  const response = await fetchWithDpopRetry(endpoint, {
    method: "POST",
    accessToken,
    body,
    contentType,
  });
  return readCredentialResponse(response, label);
}

function addCredentialResponseEncryptionIfSupported(requestBody, issuerMetadata) {
  if (!issuerMetadata.credential_response_encryption) {
    return requestBody;
  }
  const encValues = issuerMetadata.credential_response_encryption.enc_values_supported;
  return {
    ...requestBody,
    credential_response_encryption: {
      jwk: vciCredentialResponseEncryptionPublicJwk,
      enc: Array.isArray(encValues) && typeof encValues[0] === "string" ? encValues[0] : "A128GCM",
    },
  };
}

async function encodeCredentialRequest(requestBody, issuerMetadata) {
  const requestEncryption = issuerMetadata.credential_request_encryption;
  if (!requestEncryption) {
    return {
      body: JSON.stringify(requestBody),
      contentType: "application/json",
    };
  }
  const encryptionJwk = requestEncryption.jwks?.keys?.[0];
  if (!encryptionJwk) {
    throw new Error("credential_request_encryption metadata does not contain a jwk");
  }
  const alg = typeof encryptionJwk.alg === "string" ? encryptionJwk.alg : "ECDH-ES";
  const encValues = Array.isArray(requestEncryption.enc_values_supported)
    ? requestEncryption.enc_values_supported
    : [];
  const enc = typeof encValues[0] === "string" ? encValues[0] : "A128GCM";
  const payload = new TextEncoder().encode(JSON.stringify(requestBody));
  const key = await jose.importJWK(encryptionJwk, alg);
  const jwe = await new jose.CompactEncrypt(payload)
    .setProtectedHeader({
      alg,
      enc,
      ...(typeof encryptionJwk.kid === "string" ? { kid: encryptionJwk.kid } : {}),
      cty: "json",
    })
    .encrypt(key);
  return {
    body: jwe,
    contentType: "application/jwt",
  };
}

async function readCredentialResponse(response, label) {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.toLowerCase().includes("application/jwt")) {
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`${label} endpoint returned ${response.status}: ${text}`);
    }
    const key = await jose.importJWK(vciCredentialResponseEncryptionPrivateJwk, "ECDH-ES");
    const { plaintext } = await jose.compactDecrypt(text, key);
    return JSON.parse(new TextDecoder().decode(plaintext));
  }
  return readJsonResponse(response, label);
}

async function sendCredentialAcceptedNotification({ notificationEndpoint, accessToken, notificationId }) {
  const response = await fetchWithDpopRetry(notificationEndpoint, {
    method: "POST",
    accessToken,
    contentType: "application/json",
    body: JSON.stringify({
      notification_id: notificationId,
      event: "credential_accepted",
    }),
  });
  if (!response.ok) {
    throw new Error(`notification endpoint returned ${response.status}: ${await response.text()}`);
  }
  await response.text();
}

function isDpopNonceError(response) {
  return (response.status === 400 || response.status === 401) && response.headers.has("dpop-nonce");
}

async function readJsonResponse(response, label) {
  const text = await response.text();
  let parsed;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`${label} endpoint returned non-JSON ${response.status}: ${text}`);
  }
  if (!response.ok) {
    throw new Error(`${label} endpoint returned ${response.status}: ${text}`);
  }
  return parsed;
}

async function fetchJson(url) {
  const response = await fetch(url, { headers: { accept: "application/json" } });
  return readJsonResponse(response, url);
}

function wellKnownUrl(issuer, wellKnownTypePath) {
  const issuerUrl = new URL(issuer);
  return `${issuerUrl.origin}/.well-known/${wellKnownTypePath}${issuerUrl.pathname}`;
}

function dpopHtu(url) {
  const parsed = new URL(url);
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString();
}

function resolveSatisfiableDcqlCredentialIds(dcql) {
  if (!Array.isArray(dcql.credentials)) {
    throw new Error("DCQL credentials must be an array");
  }
  const satisfiableIds = dcql.credentials.filter(isCredentialSatisfiable).map((credential) => credential.id);
  if (!Array.isArray(dcql.credential_sets)) {
    return satisfiableIds;
  }

  const selected = new Set();
  for (const credentialSet of dcql.credential_sets) {
    const required = credentialSet.required !== false;
    const options = Array.isArray(credentialSet.options) ? credentialSet.options : [];
    const matchingOption = options.find((option) =>
      Array.isArray(option) && option.every((credentialId) => satisfiableIds.includes(credentialId)),
    );
    if (matchingOption) {
      for (const credentialId of matchingOption) {
        selected.add(credentialId);
      }
    } else if (required) {
      rejectRequest("required DCQL credential_set cannot be satisfied by the harness fixture credential");
    }
  }
  return [...selected];
}

function isCredentialSatisfiable(credential) {
  if (!credential || typeof credential.id !== "string" || credential.format !== "dc+sd-jwt") {
    return false;
  }
  const values = credential.meta?.vct_values;
  if (Array.isArray(values) && !values.includes(fixtureVct)) {
    return false;
  }
  return resolveRequestedClaimNames({ credentials: [credential] }, credential.id).every((claim) =>
    Object.hasOwn(fixtureClaims, claim),
  );
}

function resolveSingleVct(dcql, credentialId) {
  const credential = dcql.credentials.find((entry) => entry.id === credentialId);
  const values = credential?.meta?.vct_values;
  if (Array.isArray(values) && typeof values[0] === "string") {
    return values[0];
  }
  return "urn:eudi:pid:1";
}

function resolveRequestedClaimNames(dcql, credentialId) {
  const credential = dcql.credentials.find((entry) => entry.id === credentialId);
  const claims = Array.isArray(credential?.claims) ? credential.claims : [];
  return claims
    .map((claim) => (Array.isArray(claim.path) && claim.path.length === 1 ? claim.path[0] : undefined))
    .filter((claim) => typeof claim === "string");
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

function validateOuterClientId(clientId) {
  if (!clientId.startsWith("x509_hash:")) {
    rejectRequest(`unsupported client_id prefix in ${clientId}`);
  }
}

function validateTransactionData(transactionData) {
  if (transactionData == null) {
    return;
  }
  const entries = Array.isArray(transactionData) ? transactionData : [transactionData];
  for (const entry of entries) {
    const decodedEntry = decodeTransactionDataEntry(entry);
    const type = decodedEntry?.type;
    if (typeof type === "string" && type !== "qes_authorization") {
      rejectRequest(`unsupported transaction_data type ${type}`);
    }
  }
}

function decodeTransactionDataEntry(entry) {
  if (typeof entry !== "string") {
    return entry;
  }
  try {
    return JSON.parse(Buffer.from(entry, "base64url").toString("utf8"));
  } catch {
    rejectRequest("transaction_data entry is not valid base64url JSON");
  }
}

function rejectRequest(message) {
  throw new WalletRejectionError(message);
}

class WalletRejectionError extends Error {}

function requiredParam(url, name) {
  const value = url.searchParams.get(name);
  if (!value) {
    throw new Error(`missing required query parameter ${name}`);
  }
  return value;
}

function stringClaim(payload, name) {
  const value = payload[name];
  if (typeof value !== "string" || value.length === 0) {
    rejectRequest(`request object claim ${name} must be a string`);
  }
  return value;
}

function stringProperty(payload, name) {
  const value = payload?.[name];
  if (typeof value !== "string" || value.length === 0) {
    rejectRequest(`property ${name} must be a string`);
  }
  return value;
}

function objectClaim(payload, name) {
  const value = payload[name];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    rejectRequest(`request object claim ${name} must be an object`);
  }
  return value;
}

function publicOnlyJwk(jwk) {
  const { d: _d, key_ops: _keyOps, ext: _ext, ...publicJwk } = jwk;
  return publicJwk;
}

function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function randomBase64Url(byteLength) {
  return base64url(randomBytes(byteLength));
}

function suiteOrigin() {
  return trimTrailingSlash(process.env.CONFORMANCE_SERVER ?? "https://localhost.emobix.co.uk:8443");
}

function trimTrailingSlash(value) {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

function assertReturnedState(url, expectedState) {
  const error = url.searchParams.get("error");
  if (error) {
    throw new Error(`authorization endpoint returned ${error}: ${url.searchParams.get("error_description") ?? ""}`);
  }
  const actualState = url.searchParams.get("state");
  if (actualState !== expectedState) {
    throw new Error(`authorization response state mismatch: ${actualState} != ${expectedState}`);
  }
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
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
