# Public Wallet API driver

This independent Go module calls the public Wallet APIs. It accepts one JSON
operation on stdin and returns one JSON result on stdout. A protocol error exits
with code 1; invalid command/configuration input exits with code 2.

The driver supports an initial SD-JWT VC pre-authorized issuance path, the
OpenID4VCI 1.0 Final authorization code flow, persistent credential listing, the
public presentation method, and OpenID4VP 1.0 over the W3C Digital Credentials
API. mdoc and remote attestation providers are subsequent work. This
software-JWK configuration makes no hardware protection claim.

## Configure and run

Use Go 1.26.6 for the repository validation environment. From this directory:

```sh
go build -o official_driver .
```

Provide separate EC signing JWK files for the holder, DPoP and client keys.
The key files must contain private components, and the client public JWK must be
registered with the issuer. Do not use production keys for tests. Use explicit
absolute paths in the configuration.

### Configuration fields

| Field | Type | Default | Effect |
| --- | --- | --- | --- |
| `stateDirectory` | string | required | Directory for the bbolt credential store. |
| `clientId` | string | required | OAuth2 `client_id` used at the issuer token endpoint. |
| `holderKeyFile` | string | required | Private JWK used as the credential holder key. |
| `dpopKeyFile` | string | required | Private JWK used for DPoP proofs. |
| `clientKeyFile` | string | required | Private JWK used for `private_key_jwt` client authentication. |
| `tlsCAFiles` | []string | `[]` | Extra PEM roots added to system roots for TLS. Also used for CRL fetches (issuer and Request Object). |
| `profile` | string | `""` | Protocol policy: `""`/`"final"`/`"haip"` → `profile.Profile`. Applied to `wallet.Config.Profile` and to both constructed plugins, which must match. Unknown values are rejected. |
| `verifierCAFiles` | []string | `[]` | PEM trust anchors for signed Request Objects → `RequestObjectValidation.TrustAnchors`. Every CERTIFICATE block is parsed; a file with none is rejected. When empty, `RequestObjectValidation` stays nil and X.509 Request Objects are rejected (fail-closed). |
| `verifierAllowUnadvertisedRevocation` | bool | `false` | → `RequestObjectValidation.AllowUnadvertisedRevocation`. Requires `verifierCAFiles`. |
| `walletAudience` | []string | `[]` | → `RequestObjectValidation.WalletAudience`. Requires `verifierCAFiles`. |
| `issuerCAFiles` | []string | `[]` | PEM issuer trust anchors for credential `x5c` chains → `IssuerX509TrustOptions.TrustAnchors`. Same parsing and rejection rules as `verifierCAFiles`. |
| `issuerAllowUnadvertisedRevocation` | bool | `false` | → `IssuerX509TrustOptions.AllowUnadvertisedRevocation`. Requires `issuerCAFiles`. |
| `issuerJWKSFiles` | []string | `[]` | JWKS files (`{"keys":[...]}`) of public issuer keys for credentials without an `x5c` header. Non-empty sets `CredentialAcceptancePolicy.ResolveIssuerKeys`, which returns all operator-chosen keys; the library matches `kid`. Private keys are rejected. |
| `requireHolderBinding` | bool | `false` | → `CredentialAcceptancePolicy.RequireHolderBinding`; credentials without `cnf` are rejected. |
| `redirectUri` | string | `""` | Wallet's registered redirect URI for the authorization code flow. Required by `receive-code` and `receive-code-wallet-initiated`. |
| `authorizationRequestType` | string | `""` | → `OID4VCIFinalReceiveRequest.AuthorizationRequestType`. Selects how `receive-code`/`receive-code-wallet-initiated` request the Credential Configuration (OpenID4VCI 1.0 §5.1.1/§5.1.2): `""` uses `scope` when the configuration advertises one and `authorization_details` otherwise; `"scope"` requires an advertised scope (error before PAR otherwise); `"authorization_details"` sends `[{"type":"openid_credential","credential_configuration_id":...}]` and no scope. Under HAIP only `scope` is accepted, because HAIP §4.1/§4.2 require the Wallet to communicate the Credential Type with `scope`; an explicit `"authorization_details"` is rejected. |
| `attesterKeyFile` | string | `""` | Private JWK for a test-only `wallet.StaticClientAttester` → `wallet.Config.ClientAttestation`. Must be set together with `attesterIssuer`. The JWK's `x5c` chain, when present, becomes the client attestation header chain. |
| `attesterIssuer` | string | `""` | `iss` of the static client attester. Must be set together with `attesterKeyFile`. |
| `keyAttesterKeyFile` | string | `""` | Private JWK for a test-only `wallet.StaticKeyAttester` → `wallet.Config.KeyAttestation`. Must be set together with `keyAttesterIssuer`. |
| `keyAttesterIssuer` | string | `""` | `iss` of the static key attester. Must be set together with `keyAttesterKeyFile`. |
| `includeKeyAttestation` | bool | `false` | → `OID4VCIFinalReceiveRequest.IncludeKeyAttestation`; requests an OpenID4VCI Appendix D key attestation even when the issuer does not require one. |
| `deferredPollAttempts` | int | `10` | → `OID4VCIFinalReceiveRequest.DeferredPollAttempts`. Zero or negative selects the default of 10. |
| `credentialResponseEncryption` | bool | `false` | When true, the authorization code operations generate an ephemeral P-256 key per run and pass it as `CredentialResponseEncryptionKey`, so the issuer encrypts the credential response. |
| `followRedirect` | bool | `true` | When true (or absent), `present` opens a returned `redirect_uri` like a same-device browser: HTTP GET with the TLS-configured client, `Accept: text/html,*/*`, `User-Agent: official_driver`, a 15 s timeout, and at most 5 followed redirects. Set `false` to return the URI without opening it. |

`wallet.Config.CredentialAcceptance` is always set, because the OpenID4VCI 1.0
Final and HAIP issuance paths refuse to store a credential without it. With
`issuerCAFiles` or `issuerJWKSFiles` the policy authenticates the issuer key;
with neither, the driver sets `CredentialAcceptancePolicy.UnverifiedIssuer`, so
a run against an arbitrary test issuer keeps working and says so in one
greppable place. `requireHolderBinding` applies in both cases.

The TLS-configured HTTP client is passed as `IssuerX509TrustOptions.HTTPClient`
and as `RequestObjectValidationOptions.CRL.HTTPClient`, so CRL fetches honour
`tlsCAFiles`. Unknown profile values and inconsistent options (for example an
`*AllowUnadvertisedRevocation` flag without its CA files, or `walletAudience`
without `verifierCAFiles`) are rejected at compose time before any operation runs.
An attester key and its issuer, and a key-attester key and its issuer, must each
be set together, and `receive-code` without `redirectUri` is rejected.

`StaticClientAttester` and `StaticKeyAttester` self-issue attestations with a
locally held attester key. They exist for tests and single-operator deployments
only: a static attester is test-only evidence and must not be treated as a
production attestation, because the wallet holds the attester's private key
instead of obtaining attestations from a remote attester. A production
deployment splits the wallet and the attester so the wallet never holds the
attester's private key.

Example configuration:

```json
{
  "stateDirectory": "/path/to/isolated-wallet-state",
  "tlsCAFiles": ["/path/to/test-transport-ca.pem"],
  "verifierCAFiles": ["/path/to/verifier-trust-anchor.pem"],
  "verifierAllowUnadvertisedRevocation": false,
  "walletAudience": ["https://self-issued.me/v2"],
  "issuerCAFiles": ["/path/to/issuer-trust-anchor.pem"],
  "issuerAllowUnadvertisedRevocation": false,
  "issuerJWKSFiles": ["/path/to/issuer-jwks.json"],
  "requireHolderBinding": true,
  "profile": "final",
  "holderKeyFile": "/path/to/holder.jwk",
  "dpopKeyFile": "/path/to/dpop.jwk",
  "clientKeyFile": "/path/to/client.jwk",
  "clientId": "registered-wallet-client",
  "redirectUri": "https://wallet.example/callback",
  "authorizationRequestType": "",
  "attesterKeyFile": "/path/to/attester.jwk",
  "attesterIssuer": "https://attester.example",
  "keyAttesterKeyFile": "/path/to/key-attester.jwk",
  "keyAttesterIssuer": "https://attester.example",
  "includeKeyAttestation": false,
  "deferredPollAttempts": 10,
  "credentialResponseEncryption": false
}
```

Transport verification uses system roots plus `tlsCAFiles`. The example does not
disable TLS or X.509 checks; the library remains responsible for enforcing each
protocol's trust requirements. Credentials use the library's bbolt local storage
plugin.

### Operations and output

```sh
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"public-keys"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"receive-preauth","uri":"openid-credential-offer://?credential_offer=...","txCode":"issuer-supplied-code"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"receive-code","uri":"openid-credential-offer://?credential_offer_uri=..."}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"receive-code-wallet-initiated","credentialIssuer":"https://issuer.example/","credentialConfigurationId":"eudi_pid"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"list"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"present","uri":"openid4vp://?client_id=...&request_uri=..."}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"present-dcapi","dcapiRequest":{"protocol":"openid4vp-v1-unsigned","data":{"response_type":"vp_token","response_mode":"dc_api.jwt","nonce":"...","client_metadata":{...},"dcql_query":{...}}},"origin":"https://localhost:33513"}
JSON
```

`receive-preauth` returns the saved `credentialId` plus the library's
`verification` record for that credential. `receive-code` runs the OpenID4VCI 1.0
Final authorization code flow from the offer URI (`credential_offer_uri` is
resolved), using `clientId`, `redirectUri`, `holderKeyFile` and `clientKeyFile`,
and returns `credentialIds`, a `verification` array in credential order, plus
`notificationId` and `transactionId`; `pending` is `true` when the issuer left the
issuance pending after the deferred polls. The driver sets
`OID4VCIFinalReceiveRequest.AllowSelfDrivenAuthorization`, so the library drives
the authorization endpoint itself: the same TLS client fetches it without
following redirects and expects a 302 `code` response, and no browser emulation
is added here. A wallet with a user does the opposite — it calls
`BeginOID4VCIFinalAuthorization`, opens the returned `authorization_url` in the
system browser and hands the redirect to `ResumeOID4VCIFinalAuthorization`. `present` returns `redirectUri` plus `redirectFollowed`
(whether the driver opened it) and `redirectStatus` (the final HTTP status, `0`
when not opened). `list` returns `credentialIds` and `total`. Existing fields
keep their names. Protocol errors from `receive-code` propagate unchanged; the
driver never retries or repairs them.

`receive-code-wallet-initiated` runs the same OpenID4VCI 1.0 authorization code
flow without a Credential Offer (OpenID4VCI 1.0 §5: "The Wallet can also start
the issuance without a Credential Offer"). It takes `credentialIssuer` and
`credentialConfigurationId` instead of `uri`, obtains the Credential Issuer
metadata itself, requests that Credential Configuration with `scope` or
`authorization_details` (§5.1.1/§5.1.2), and sends no `issuer_state`. The output
is identical to `receive-code`, including `pending`.

`present-dcapi` answers a W3C Digital Credentials API invocation instead of a
launch URI. `dcapiRequest` is the platform request entry (`protocol` plus the
protocol `data` object) and `origin` is the platform-authenticated calling
origin; the origin is never read from `data`. All three protocols are accepted:
`openid4vp-v1-unsigned`, `openid4vp-v1-signed` and
`openid4vp-v1-multisigned`. The result is the `DCAPIResponse` object the runner
submits to the verifier: `{"protocol":<same protocol>,"data":{"vp_token":{...}}}`
for `dc_api`, or `{"protocol":...,"data":{"response":"<JWE compact>"}}` for
`dc_api.jwt`. The driver makes no HTTP call. The Key Binding JWT `aud` is
`origin:<origin>` (OID4VP 1.0 Appendix A.4), not the request `client_id`.

Each invocation is a new process, so listing and presenting use the persisted
credential. Use the issuer/verifier's complete launch URI unchanged. The driver
does not repair queries, issue its own credentials, retry protocol failures, or
construct presentation responses. When `followRedirect` is enabled and the
verifier returns a `redirect_uri`, the driver opens it as the same-device browser
would (HAIP §5.1, OpenID4VP §8.2); the fragment is never transmitted. A non-2xx/3xx
final status is reported as an error naming the status.

### additionalHolderKeys

`additionalHolderKeys` (integer, default 0) makes the authorization code
operations send that many
extra proofs with ephemeral P-256 keys so an issuer that advertises
`batch_credential_issuance` returns several credentials (OpenID4VCI 1.0 §14.6).
The ephemeral keys are discarded after the run; the resulting credentials are
stored but cannot be presented later. Use it only for batch controls.
