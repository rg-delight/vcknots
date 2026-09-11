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
requirement); `ResolveIssuerKeys` supplies keys for credentials without `x5c`
(JWKS, DID or a static registry chosen by the caller). With a policy the
signature, `exp` / `nbf` and SD-JWT disclosure integrity (every disclosure
referenced exactly once by an `_sd` or `...` digest) are also checked.
`SavedCredential.Verification` records the key, certificate fingerprints and
revocation counters. `VerifyCredential` previously returned true only when
verification errored; it now returns true only on success.
