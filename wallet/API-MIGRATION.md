# Wallet API migration from the NICE fork

This integration incorporates upstream `f0c7c53dac3cb7d7df535ef775635f14d4b6d124`
into the NICE fork based on `5b363598aae9b6677a88c3b74d0b6d65e687ed31`.
Passing regression tests is not evidence of complete Final or HAIP conformance.

| Previous fork API | Integrated API |
| --- | --- |
| `FetchAccessToken(type, endpoint, request)` | `FetchAccessToken(type, endpoint, authzCode, txCode, ...TokenRequestOption)` |
| Structured `FetchNonce(endpoint)` | `FetchNonceResponse(endpoint)`; upstream `FetchNonce(type, endpoint)` returns `*string` |
| `CredentialPresentationRequest.DCQLQuery` | `CredentialPresentationRequest.DcqlQuery` with one canonical JSON field |
| Draft `Oid4vpPresenter.ParsePresentationRequest(uri)` | `ParseDraft24PresentationRequest(uri)` |
| Draft `NewRequestBuilder()` | `NewDraft24RequestBuilder()` |
| Draft `Oid4vpPresenter.Present(..., submission, request) error` | `PresentDraft24(..., submission, request) (redirectURI, error)` |
| Draft `Wallet.PresentCredential(uri, key, options) error` | `PresentDraft24Credential(uri, key, options) error` |
| Final `Present` / `PresentCredential` | Upstream signatures return `(redirectURI, error)` and use DCQL response objects |

`ParsePresentationRequest` and `NewRequestBuilder` now follow the upstream
Final path and reject Presentation Exchange parameters. Draft24 supports both
Presentation Exchange and DCQL request syntax; accepting a query does not
imply every query feature is implemented. `PresentDraft24` submits a
Presentation Exchange response with a string VP token and a
`presentation_submission`. Final `Present` submits an object keyed by DCQL
credential query ID. Use the response operation matching the request profile
and query syntax.

`DCQLQuery`, `DCQLCredentialQuery`, and `DCQLCredentialSet` are aliases of the
upstream DCQL model. Credential query `Meta` is now a JSON object
(`map[string]any`), not the old `DCQLCredentialMeta` struct. The existing
selection API remains available in `dcql_selection.go`; this integration does
not add support for all DCQL claims, values, or constraints.

Built-in dispatchers snapshot the environment's local HTTP allowance when
constructed. Set development configuration before constructing a Wallet.
Direct plugin and builder callers use `AllowHTTP` / `WithHTTPAllowed` and an
injected `HTTPClient`; changing process environment later does not change a
plugin's policy. Token POSTs retain redirect refusal even with an injected
client. The receiver's default client has a 15-second timeout; presenter
operations using its default client have a 30-second timeout.

The legacy root Draft flow retains the fork's single-credential selection and
descriptor generation limitations. Applications with their own selected
credentials and input descriptor mapping use `PresentDraft24`. This integration
does not claim to fix the root automatic selection, untrusted issuer storage,
all request-object trust paths, or the Final retry/nonce contracts. These are
tracked separately by the Final/HAIP roadmap and require independent behavior
tests.

The explicit Draft24 JARM operation preserves the legacy fork's JSON-string
`presentation_submission` inside the encrypted payload. This historical double
encoding is retained for compatibility, not claimed as normative conformance.
The NICE sidecar's regular single-format presentations already build an object
in their own response path. Final response objects are unaffected.

## Final Request Object authentication

`ParsePresentationRequest` and `NewRequestBuilder` now authenticate signed
Request Objects for the `x509_san_dns` and `x509_hash` Client Identifier
Prefixes (OpenID4VP 1.0 §5.10) instead of only checking the signature against
the first `x5c` certificate. The chain must reach a trust anchor configured by
the relying party through `Oid4vpPresenter.X509TrustChainRoots` or
`Oid4vpPresenter.RequestObjectValidation` (`RequestObjectValidationOptions`:
explicit `TrustAnchors` or `RootCAs`, optional EKU policy, CRL revocation with
`AllowUnadvertisedRevocation`, `WalletAudience`, clock and `SigningAlgorithms`).
Configure the roots in exactly one of those places. `x509_hash` binds the leaf
certificate hash only and does not require a DNS SAN (HAIP §5); `x509_san_dns`
binds the SAN and the `response_uri` (direct_post modes) or `redirect_uri`.
`aud`, `exp` and `nbf` are validated; `iss` is ignored (§5).

Final plain query-parameter requests that use an X.509 prefix are rejected with
`invalid_request` because those prefixes require a signed Request Object.
`InsecureSkipX509Verify` no longer applies to the Final path; explicit test
anchors must be configured instead. The Draft24 entrypoints
(`ParseDraft24PresentationRequest`, `NewDraft24RequestBuilder`) keep the
previous behaviour, including `InsecureSkipX509Verify`.

The verification result is exposed as
`CredentialPresentationRequest.RequestObjectVerification` (client ID,
certificate SHA-256 fingerprints, revocation counters). It is produced only by
the library and never read from request data. The new
`common/x509.VerifySigningCertificateChain` and `common/x509.NewCRLChecker`
are the shared signing-certificate path and CRL primitives; issuer-side
callers are expected to move to them in a later change.

## Credential acceptance before storage

`ReceiveCredential` and `ReceiveOID4VCIFinalCredential` now verify a credential
before saving it (`credential_acceptance.go`). Without a policy the minimum
rules apply: the credential must parse, the issuer JWT must carry a supported
`alg` and (for SD-JWT VC) a `dc+sd-jwt` / `vc+sd-jwt` `typ`, and a `cnf.jwk`
that does not match the holder key used for the credential request proof is
rejected. A Final response that contains one unverifiable credential stores
nothing.

`Config.CredentialAcceptance` (`CredentialAcceptancePolicy`) adds issuer
authentication: `IssuerX509` verifies the `x5c` chain with the shared
`common/x509` signing-chain and CRL primitives (explicit anchors or a root
pool, optional EKU policy, `AllowUnadvertisedRevocation`, optional
`RequireIssuerDNSBinding` as an ecosystem policy rather than an SD-JWT VC §3.5
requirement); `ResolveIssuerKeys` supplies keys through a mechanism the caller chose
(JWKS, DID or a static registry); when `IssuerX509` is not configured it is
used even for credentials that carry `x5c`, and the chain is then not
consulted. A credential with `x5c` and neither mechanism configured is
rejected. With a policy the
signature, `exp` / `nbf` and SD-JWT disclosure integrity (every disclosure
referenced exactly once by an `_sd` or `...` digest) are also checked.
`SavedCredential.Verification` records the key, certificate fingerprints and
revocation counters. `VerifyCredential` previously returned true only when
verification errored; it now returns true only on success.

## Explicit Final / HAIP profile

Package `profile` defines `profile.Final` (default) and `profile.HAIP`.
`wallet.Config.Profile` selects the policy for the root Wallet; the built-in
`oid4vci.Oid4vciReceiver.Profile` and `oid4vp.Oid4vpPresenter.Profile` carry
the same value for direct plugin use. A Wallet constructed with caller-injected
dispatchers fails when a registered plugin that implements `profile.Carrier`
reports a different profile, so the root policy cannot be bypassed through a
lower-level API. The Draft entrypoints ignore the profile.

Under HAIP the Final paths additionally reject: `AllowHTTP` /
`InsecureSkipX509Verify`; access tokens that are not DPoP-bound; credential
configurations without a `scope` or with a format other than `dc+sd-jwt` /
`mso_mdoc`; issuers that advertise cryptographic binding without a
`nonce_endpoint`; issuance without any configured OAuth client authentication
(client attestation or `ClientAuth`); SD-JWT VCs without an `x5c` header or
whose `x5c` includes a configured trust anchor; presentation requests whose
client identifier prefix is not `x509_hash`, that were not delivered by
`request_uri`, whose response mode is not `direct_post.jwt`, or whose DCQL
formats are not `dc+sd-jwt` / `mso_mdoc`; response encryption other than
ECDH-ES with A128GCM or A256GCM; and a missing KB-JWT for an SD-JWT VC that
carries `cnf` even when the verifier set
`require_cryptographic_holder_binding` to false. Each constraint is covered by
a Final-accepts / HAIP-rejects test pair. HAIP obligations of the other party
that the Wallet cannot observe (for example "Verifiers MUST list both A128GCM
and A256GCM") are not turned into rejections.

## OpenID4VCI 1.0 Final issuance path

`ReceiveOID4VCIFinalCredential` now resolves offers by reference
(`ResolveCredentialOffer`, `credential_offer_uri`), requires the fetched
`credential_issuer` to equal the offer value exactly, selects the authorization
server from the grant's `authorization_server` hint (which must be listed) and
checks the authorization server metadata `issuer` (RFC 8414 §3.3); the
authorization response must come back on the registered `redirect_uri`,
error redirects surface as `AuthorizationResponseError`, `iss` is validated
when present and required when advertised or under HAIP (RFC 9207), and an
expired PAR `request_uri` is not used. The Nonce Endpoint is optional (§7);
token-response `credential_identifiers` are used when present (§6.2);
`invalid_nonce` triggers one re-proof through
`PostCredentialEndpointWithNonceRetry` (§8.3.1); credential endpoint failures
are `receiver/types.CredentialEndpointError` values usable with `errors.Is`.
Credential response encryption follows §8.2 (`jwk`, `enc`, optional `zip`, no
`alg`), fails closed when `encryption_required` is set without a key, and
rejects a plaintext response after encryption was requested. Batch issuance
sends one proof per holder key (`AdditionalHolderKeys`, bounded by
`batch_credential_issuance.batch_size`) and verifies each credential against
its own key. Deferred issuance polls with `interval` up to
`DeferredPollAttempts`, otherwise returns a pending result that
`ResumeOID4VCIFinalDeferredCredential` can continue in another process.
`credential_accepted` is sent only after storage succeeded,
`credential_failure` on verification or storage failure, and
`NotifyOID4VCIFinalCredentialDeleted` sends `credential_deleted`.

## Attestation providers

`Config.ClientAttestation` (`ClientAttestationProvider`) and
`Config.KeyAttestation` (`KeyAttestationProvider`) let the caller supply
attestations from a remote attester. The library never handles the attester's
private key. `ClientAttestationProvider` is called once per issuance with the
selected authorization server identifier and must return a compact JWS with typ
`oauth-client-attestation+jwt`, `sub` = `ClientID` and `cnf.jwk` = the wallet
instance key; `KeyAttestationProvider` is called with the holder keys and
`c_nonce` and must return a `key_attestation+jwt` whose `attested_keys` contain
every holder key.

Before use the wallet validates the provider result without verifying the
attester signature: typ, `sub`, RFC 7638 `cnf.jwk` thumbprint, and future `exp`
(respecting an earlier `ClientAttestation.ExpiresAt`). Under HAIP the header
must also carry a non-self-signed `x5c` leaf (client attestation §4.4.1, key
attestation §4.5.1). Failures are returned before PAR.

`OID4VCIFinalReceiveRequest.AttesterKey` / `AttesterIssuer` remain as a
deprecated fallback: when set and no `ClientAttestationProvider` is configured
they are wrapped into a `StaticClientAttester` for that request. New code
should configure a provider instead. `StaticClientAttester` and
`StaticKeyAttester` self-issue for tests and single-operator deployments only.

When the selected credential configuration advertises
`proof_types_supported.jwt.key_attestations_required`, a `KeyAttestationProvider`
is required before PAR; under HAIP a missing provider names HAIP §4.5.1. A
configured provider is otherwise only used when
`OID4VCIFinalReceiveRequest.IncludeKeyAttestation` is set. The key attestation
is attached to each `proofs.jwt` entry as the Appendix D `key_attestation`
protected-header parameter via `CreateCredentialRequestJWTProofWithKeyAttestation`
(the original `CreateCredentialRequestJWTProof` keeps its signature).

## Final request validation and private_key_jwt at PAR

The Final OpenID4VP parser now rejects `response_type` values other than
`vp_token`, a request carrying both `request` and `request_uri`, a
`request_uri_method` that is not exactly `get` or `post` or that appears
without `request_uri`, `transaction_data` entries that are not base64url JSON
objects with a supported `type` and known `credential_ids`, and malformed
`meta` (`vct_values`, `doctype_value`). A colon-less `client_id` is treated as
a pre-registered client (OpenID4VP 1.0 §5.9.2) instead of a format error; HAIP
still requires `x509_hash`. `Oid4vpPresenter.SupportedTransactionDataTypes`
lists the transaction data types the application understands; with an empty
list every `transaction_data` request is rejected with
`invalid_transaction_data`. Encryption keys in `client_metadata.jwks` must
carry `alg` (§8.3); keys without it are skipped. Error responses for
`direct_post.jwt` are encrypted when the verifier metadata allows it and sent
in plaintext only as the §8.3.1 fallback. The new error codes are
`invalid_request_uri_method`, `invalid_transaction_data`,
`wallet_unavailable` and `invalid_client`.

`ReceiveOID4VCIFinalCredential` sends `client_assertion` /
`client_assertion_type` at the PAR endpoint and, freshly per attempt, at the
token endpoint when `ClientAuth.Method` is `private_key_jwt` (RFC 9126 §2,
RFC 7523, HAIP §4.3). `PushedAuthorizationRequest` and
`AuthorizationCodeTokenRequest` carry the assertion fields;
`AuthorizationCodeTokenRequest.ClientAssertionFactory` produces a new
assertion for each retry.
