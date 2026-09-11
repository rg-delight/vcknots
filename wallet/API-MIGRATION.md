# Wallet API migration

This document lists the API changes the OpenID4VCI / OpenID4VP Final and HAIP
support introduced, and how a caller written against the previous API moves to
the current one. Passing regression tests is not evidence of complete Final or
HAIP conformance.

| Previous API | Current API |
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

The legacy root Draft flow retains its single-credential selection and
descriptor generation limitations. Applications with their own selected
credentials and input descriptor mapping use `PresentDraft24`. This integration
does not claim to fix the root automatic selection, untrusted issuer storage,
all request-object trust paths, or the Final retry/nonce contracts. These are
tracked separately by the Final/HAIP roadmap and require independent behavior
tests.

The explicit Draft24 JARM operation preserves the legacy JSON-string
`presentation_submission` inside the encrypted payload. This historical double
encoding is retained for compatibility, not claimed as normative conformance.
A caller that builds single-format presentations in its own response path is
unaffected, as are Final response objects.

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
`PostCredentialEndpointWithNonceRetryForToken` (§8.3.1); credential endpoint
failures
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

## Final receiver plugin contract: transport and signer

`receiver/types.OID4VCIFinalReceiver` mixed the HTTP exchanges of the Final
flow with the wallet's private-key operations, so a plugin could not be written
without also owning the wallet's keys. It is now split:

| Interface | What it covers |
| --- | --- |
| `OID4VCIFinalTransport` | the Draft 13 `Receiver`, plus `PushAuthorizationRequest`, `ExchangeAuthorizationCodeWithDpopAndAttestationRetry`, `FetchClientAttestationChallenge`, `FetchNonceResponse`, `PostCredentialEndpointWithNonceRetryForToken`, `SendCredentialNotificationWithDpopRetryForToken`, `EncodeCredentialRequest`, `DecodeCredentialResponse` |
| `OID4VCIFinalSigner` | `CreateDpopProof`, `CreateCredentialRequestJWTProofWithOptions`, `CreateClientAttestationPop` |
| `OID4VCIFinalReceiver` | both of the above; **deprecated**, kept so existing implementations and callers still compile |

The bundled `oid4vci.Oid4vciReceiver` satisfies all three: it embeds
`receiver/oid4vcisign.Default`, the software implementation of the signer, which
any third-party transport plugin can embed for the same behaviour.

`Config.OID4VCISigner` selects the signer, so a wallet can keep its keys in a
hardware module or a remote signing service and still use the bundled
transport. When it is nil the receiver plugin signs if it implements
`OID4VCIFinalSigner`, and `oid4vcisign.Default` signs otherwise; a wallet that
configures nothing behaves exactly as before.
`ReceivingDispatcher.OID4VCIFinalTransport` resolves the transport capability
and accepts a plugin that does not sign; `OID4VCIFinalReceiver` still resolves
the compound capability and is deprecated.

Five methods left the interface and stay as concrete methods on
`oid4vci.Oid4vciReceiver` (and on `oid4vcisign.Default` for the signing ones),
because the wallet calls none of them. A caller that reached them through an
`OID4VCIFinalReceiver`-typed value now needs the concrete plugin type or its own
narrow interface:

| Removed from the interface | Replacement for a caller |
| --- | --- |
| `ExchangeAuthorizationCodeWithDpopRetry` | `ExchangeAuthorizationCodeWithDpopAndAttestationRetry` with a headers factory |
| `PostCredentialEndpointWithDpopRetry` | `PostCredentialEndpointWithNonceRetryForToken`, which carries the token's own authorization scheme |
| `PostCredentialEndpointWithNonceRetry`, `SendCredentialNotificationWithDpopRetry` | the `…ForToken` overloads: RFC 6750 §2.1 `Bearer` and RFC 9449 §7.1 `DPoP` are told apart by the token response, which the bare access token cannot express |
| `CreateCredentialRequestJWTProof`, `CreateCredentialRequestJWTProofWithKeyAttestation` | `CreateCredentialRequestJWTProofWithOptions` with `ProofOptions{Audience, Nonce, KeyAttestation}` |

`CreateClientAttestation` is not part of `OID4VCIFinalSigner` either. The wallet
never mints a Client Attestation: it is issued by the attester, and the wallet
obtains it from a `ClientAttestationProvider` (see below), so the library does
not hold the attester's private key. The method remains on
`oid4vcisign.Default` and on the bundled plugin for tests, examples and
single-operator deployments that act as their own attester.

## Attestation providers

`Config.ClientAttestation` (`ClientAttestationProvider`) and
`Config.KeyAttestation` (`KeyAttestationProvider`) let the caller supply
attestations from a remote attester. The library never handles the attester's
private key. `ClientAttestationProvider` is called once per issuance with the
selected authorization server identifier and must return a compact JWS with typ
`oauth-client-attestation+jwt`, `sub` = `ClientID` and `cnf.jwk` = the wallet
instance key; `KeyAttestationProvider` is called with the holder keys and
`c_nonce` and must return a `key-attestation+jwt` whose `attested_keys` contain
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
protected-header parameter through `ProofOptions.KeyAttestation` on
`CreateCredentialRequestJWTProofWithOptions`; the two older
`CreateCredentialRequestJWTProof…` overloads keep their signatures as concrete
methods.

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

## DCQL semantics: trusted authorities, nested paths, multiple, transaction data

This section records the DCQL semantics completed for the OID4VP 1.0 Final
presenter. The quoted sentences are the normative basis for each change.

### `trusted_authorities` and the `aki` query (OID4VP 1.0 §6.1.1, HAIP §5)

`CredentialQuery` now carries `TrustedAuthorities []TrustedAuthority`, where
`TrustedAuthority` is `{Type string; Values []string}`. The parser rejects a
non-array, an empty array, a non-object entry, an empty `type`, and a missing
or non-string `values` element with `invalid_request`.

OID4VP 1.0 §6.1: "Every Credential returned by the Wallet SHOULD match at least
one of the conditions present in the corresponding trusted_authorities array if
present." §6.4.2: "Credentials not matching the respective constraints
expressed within credentials MUST NOT be returned, i.e., they are treated as if
they would not exist in the Wallet." HAIP 1.0 §5: "The Authority Key Identifier
(aki)-based Trusted Authority Query (trusted_authorities) for DCQL ... MUST be
supported."

The `aki` value is the base64url encoding of the KeyIdentifier; per §6.1.1.1
"the raw byte representation of this element MUST match with the
AuthorityKeyIdentifier element of an X.509 certificate in the certificate chain
present in the Credential". `oid4vp.AuthorityKeyIdentifiersFromCredential`
extracts these from the issuer JWT header `x5c`, and `DCQLCredentialCandidate`
now exposes `AuthorityKeyIDs []string` for matching. A credential that matches
none of the entries is treated as absent.

The specification does not define behavior for an unimplemented `type` (it
lists `aki`, `etsi_tl` and `openid_federation`, while noting at the top of §6
that "Implementations MUST ignore any unknown properties"). This wallet can only
evaluate `aki`, so entries of any other `type` are ignored; a query whose
entries are all of an unknown type therefore places no constraint. Other types
can be added behind the same matcher later.

### Holder-binding-aware selection (OID4VP 1.0 §6.4.2, Appendix B.3)

`DCQLCredentialCandidate` gained `HolderBound *bool` (the issuer JWT `cnf`
claim). For `dc+sd-jwt` queries that require holder binding (the default), a
candidate explicitly marked unbound is excluded before selection so another
credential can satisfy the query. Appendix B.3: "SD-JWTs that do not support
Holder Binding (i.e., do not have a cnf Claim) cannot be returned in this
case." A nil flag means the caller did not evaluate holder binding and the
candidate is not excluded, preserving existing direct callers.

### `multiple` (OID4VP 1.0 §6.1, §8.1)

When `multiple` is true, `ResolveSatisfiableDCQLCredentials` returns every
matching candidate for the Query id, each presented separately in the
`vp_token` array. When false (the default) the first match is selected. §8.1:
"When multiple is omitted, or set to false, the array MUST contain only one
Presentation."

### Claims path pointers (OID4VP 1.0 §7)

`DCQLClaimQuery.Path` is now `[]any` and accepts strings, `null` and
non-negative integers. §7: "A string value indicates that the respective key is
to be selected, a null value indicates that all elements of the currently
selected array(s) are to be selected; and a non-negative integer indicates that
the respective index in an array is to be selected." Selection evaluates the
pointer over the decoded credential (`DCQLCredentialCandidate.ClaimObject`,
built for SD-JWT VC by the new `sdjwtvc.ReconstructClaimsObject`, which applies
all disclosures). A path that selects no element is unsatisfied, and `values`
restrictions apply to the selected elements.

The serializer's disclosure selector now resolves JSON-encoded nested paths and
returns only the disclosures needed to reveal the selected leaves, including
nested `_sd` object properties and `...` array elements. §6.4: "Wallets MUST
NOT send selectively disclosable claims that have not been selected according
to the rules below."

### Per-object `transaction_data_hashes_alg` (OID4VP 1.0 Appendix B.3.3.1)

The Final path no longer reads the top-level `transaction_data_hashes_alg`
parameter. For each `transaction_data` object the wallet selects the first
algorithm in its `transaction_data_hashes_alg` array that it supports
(sha-256/sha-384/sha-512), defaulting to sha-256 when the member is absent, and
sets `CredentialPresentationRequest.TransactionDataHashesAlg` accordingly.
Conflicting algorithms across objects are rejected with
`invalid_transaction_data`. Appendix B.3.3.1: "one of which MUST be used to
calculate hashes ... If this parameter is not present, a default value of
sha-256 MUST be used."

### Root configuration and submission

`wallet.Config` gained `SupportedTransactionDataTypes []string`, propagated to
the default OID4VP presenter exactly like `Profile`.
`Oid4vpPresenter.SetSupportedTransactionDataTypes` is the propagation hook.
`SubmitOID4VPFinalAuthorizationRequest` now builds transaction data through the
same `buildDCQLVPToken` path as `PresentCredentialWithOptions` instead of
refusing it.

### Error codes (OID4VP 1.0 §8.2, §8.5)

When no stored credential can satisfy the query the wallet returns
`*oid4vp.AuthorizationRequestError{Code: oid4vp.AccessDeniedError}`. §8.5:
"access_denied: The Wallet did not have the requested Credentials to satisfy
the Authorization Request." Request validation failures (missing
`response_type`/`client_id`/`redirect_uri`/`nonce`, a bad `response_uri`, and the
redirect_uri/response_uri exclusivity rule, now scoped to the direct_post
modes) return `AuthorizationRequestError{Code: invalid_request}`. §8.2: "If the
redirect_uri Authorization Request parameter is present when the Response Mode
is direct_post, the Wallet MUST return an invalid_request Authorization
Response error."

## OpenID4VP 1.0 over the W3C Digital Credentials API (Appendix A)

The presenter now parses and answers OpenID4VP 1.0 requests delivered through
the W3C Digital Credentials API (OID4VP 1.0 Appendix A). New public surface in
`presenter/plugins/oid4vp`:

- `OAuthAuthzReqResponseModeDCAPI` (`"dc_api"`) and
  `OAuthAuthzReqResponseModeDCAPIJWT` (`"dc_api.jwt"`).
- `DCAPIProtocolUnsigned`, `DCAPIProtocolSigned`, `DCAPIProtocolMultiSigned`.
- `DCAPIRequest{Protocol, Data}`, `DCAPIInvocation{Request, Origin}` and
  `DCAPIResponse{Protocol, Data}`.
- `(*Oid4vpPresenter).ParseDCAPIRequest(DCAPIInvocation)` and
  `(*Oid4vpPresenter).BuildDCAPIResponse(*CredentialPresentationRequest, vpToken)`.
- Root `(*Wallet).PresentCredentialToDCAPI(invocation, key, options...)` in
  `wallet_dcapi.go`, which reuses the existing DCQL selection/serialization
  machinery and makes no HTTP call.

The parsed request exposes `ResponseAudience` (`origin:<origin>`) and
`DCAPIProtocol`; the root overrides the Key Binding JWT audience with
`ResponseAudience` instead of `client_id`.

Spec rules implemented. A.2: "The client_id parameter MUST be omitted in
unsigned requests defined in Appendix A.3.1. The Wallet MUST ignore any
client_id parameter that is present in an unsigned request." The Wallet uses
`web-origin:<origin>` as the effective identifier. A.2: "The value of the
response_mode parameter MUST be dc_api when the response is not encrypted and
dc_api.jwt when the response is encrypted as defined in Section 8.3";
`response_uri`/`redirect_uri` MUST be absent. A.2: "expected_origins: REQUIRED
when signed requests defined in Appendix A.3.2 are used ... If the Origin does
not match any of the entries in expected_origins, the Wallet MUST return an
error", compared against the platform `Origin`, never the request. A.3.2: signed
requests are compact JWS with `typ: oauth-authz-req+jwt`, authenticated like a
Request Object (x5c chain to configured anchors, `client_id` from the protected
header or payload, x509_hash binding). A.3.2.2: multi-signed requests are JWS
JSON Serialization, each signature's protected header carries its own
`client_id`; the Wallet verifies at least one authenticatable signature and
records it in `RequestObjectVerification.ClientID`. A.4: "The audience for the
response (for example, the aud value in a Key Binding JWT) MUST be the Origin,
prefixed with origin:"; `dc_api.jwt` encrypts the response exactly like
`direct_post.jwt` (§8.3) with the same key selection, while `dc_api` returns the
plaintext `{"vp_token": {...}}`.

HAIP §5.2: "The Wallet MUST support the Response Mode dc_api.jwt" and "The
Wallet MUST support unsigned, signed, and multi-signed requests as defined in
Appendices A.3.1 and A.3.2". `enforceHAIPProfile` therefore accepts
`dc_api`/`dc_api.jwt` and all three request types instead of rejecting
`dc_api.jwt` and requiring `request_uri`; the x509_hash rule continues to apply
to the signed paths.

The `official_driver` adds `present-dcapi` with input
`{"operation":"present-dcapi","dcapiRequest":{"protocol":..,"data":..},"origin":"https://localhost:33513"}`
and returns the `DCAPIResponse` JSON for the runner to submit.

## HAIP request delivery attestation

An application that fetches a signed Request Object through `request_uri` at
admission time and later re-parses the stored JWT with `request=` cannot satisfy
`enforceHAIPProfile`'s "delivered by reference" check (`requestSource !=
"reference"`), even though HAIP §5.1 was honoured. The library cannot observe
the original delivery, so the caller attests it via the new
`RequestObjectValidationOptions.DeliveredByReference`. Set it only when the
application's own admission path recorded the `request_uri` fetch.

When `DeliveredByReference` is true and the builder's `requestSource` is
`"value"`, the HAIP §5.1 check treats the source as `"reference"` for that check
only; the `wallet_nonce` echo remains bound to an actual `request_uri` POST in
the same process, so the attestation never suppresses a nonce mismatch. The
attestation has no effect on the Final profile. The verification result
`CredentialPresentationRequest.RequestObjectVerification` now also records
`Delivery` (`"reference"`, `"value"`, or `"query"`, what the library observed)
and `DeliveryAttested` (true when the caller attestation was accepted for the
HAIP check).

## Wallet-initiated OpenID4VCI authorization code issuance

`OID4VCIFinalReceiveRequest` gained `CredentialIssuer *url.URL` and
`CredentialConfigurationID string`. OpenID4VCI 1.0 §5: "The Wallet can also
start the issuance without a Credential Offer." When `CredentialOffer` is nil
the caller names the Credential Issuer and the Credential Configuration; both
are required. The flow fetches the issuer metadata, checks it against the
requested issuer, selects the authorization server from
`authorization_servers[0]` (falling back to the credential issuer) because no
grant carries an `authorization_server` hint, sends no `issuer_state`, and
requests the configuration with `scope` or `authorization_details`
(§5.1.1/§5.1.2). Supplying `CredentialIssuer` or `CredentialConfigurationID`
together with a `CredentialOffer` is rejected before any HTTP request. The HAIP
client-authentication and profile validators apply unchanged.

The `official_driver` adds `receive-code-wallet-initiated` with input
`{"operation":"receive-code-wallet-initiated","credentialIssuer":"https://issuer.example/","credentialConfigurationId":"eudi_pid"}`
(no `uri`); its output is identical to `receive-code`.
