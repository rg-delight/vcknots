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
