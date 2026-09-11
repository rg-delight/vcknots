# vcknots-wallet Local Server Integration Test and Conformance Test Sample

The independent [public Wallet API driver](official_driver/README.md) is used for
the new official-suite controls. It preserves received credentials between
processes and reports current API limitations explicitly.

This directory contains sample code that demonstrates two key testing scenarios for vcknots-wallet:

1. **Local server integration test mode**: Tests integration with a local vcknots server
2. **Conformance test mode**: Tests against external OpenID4VP conformance test services

Both modes are supported by the same program (`server_integration_sdjwt.go`) and are selected based on command-line arguments.
In local server integration test mode, the wallet obtains a credential through OpenID4VCI and then presents it through OpenID4VP.
Conformance test mode seeds a local credential and tests only the OpenID4VP presentation flow.

## Features Covered by the Samples

| Sample | OpenID4VCI credential issuance | OpenID4VP presentation | Key binding |
| --- | --- | --- | --- |
| `server_integration_jwtvc` | JWT-VC | JWT-VC | Not applicable |
| `server_integration_sdjwt` | SD-JWT VC (`dc+sd-jwt`) | Selective disclosure | Without KB-JWT |
| `server_integration_sdjwt+kbjwt` | SD-JWT VC (`dc+sd-jwt`) | Selective disclosure | With KB-JWT |

Regardless of the credential format shown above, every local server integration test mode sample uses `private_key_jwt` client authentication and DPoP.

## Supported protocols

This Go wallet implements OpenID4VCI 1.0 and OpenID4VP 1.0. HAIP 1.0 is available as an explicit profile: the zero value of `profile.Profile` normalizes to `profile.Final`, and `profile.HAIP` adds the HAIP constraints on top. The matrix lists behaviour found in the public API and its tests. `Partial` marks a feature whose interface exists but whose production integration is the caller's responsibility.

| Protocol / feature | Status | Public API entry point | Notes |
| --- | --- | --- | --- |
| OpenID4VCI 1.0 pre-authorized code | Implemented | `Wallet.ReceiveCredential` (`ReceiveCredentialRequest`) | Also the legacy Draft 13 entry point. The public driver exposes it as `receive-preauth`. |
| OpenID4VCI 1.0 authorization code with PAR / PKCE / DPoP / `private_key_jwt` / client attestation | Implemented | `Wallet.ReceiveOID4VCIFinalCredential` (`OID4VCIFinalReceiveRequest`) | Pushed Authorization Request is required; PKCE is always `S256`; DPoP is configured with `Config.DPoP` and `ClientKey`; `private_key_jwt` is used when the authorization server advertises it; attestation-based client authentication uses `Config.ClientAttestation`. |
| Deferred issuance | Implemented | `Wallet.ReceiveOID4VCIFinalCredential` (`DeferredPollAttempts`), `Wallet.ResumeOID4VCIFinalDeferredCredential` | Polls at the advertised interval and returns a pending result when the attempt budget is exhausted. The `OID4VCIFinalDeferredRequest` can resume in another process. |
| Notification endpoint | Implemented | `Wallet.NotifyOID4VCIFinalCredentialDeleted` (`OID4VCIFinalNotificationRequest`) | Sends `credential_deleted`. `credential_accepted` and `credential_failure` are sent internally by `storeAndNotifyOID4VCIFinalCredentials` only after storage has succeeded or failed. |
| Batch issuance | Implemented | `Wallet.ReceiveOID4VCIFinalCredential` (`AdditionalHolderKeys`) | Sends one proof per holder key, bounded by `batch_credential_issuance.batch_size`; each response credential is matched to its own key. |
| Credential response encryption | Implemented | `OID4VCIFinalReceiveRequest.CredentialResponseEncryptionKey` | OpenID4VCI 1.0 §8.2 (`jwk`, `enc`, optional `zip`, no `alg`). Fails closed when the issuer requires encryption and no key was supplied. |
| Key attestation | Partial | `Config.KeyAttestation` (`KeyAttestationProvider`), `StaticKeyAttester`, `OID4VCIFinalReceiveRequest.IncludeKeyAttestation` | Provider interface plus a test-only static attester. The library validates the provider JWT (`typ`, `attested_keys`, `exp`) but does not verify the attester's signature; a production attester or HSM is caller-supplied. |
| OpenID4VP 1.0 redirect flow (`x509_hash` / `x509_san_dns` / `redirect_uri` / pre-registered) | Implemented | `Wallet.PresentCredential`, `Wallet.PresentCredentialWithOptions`, `Oid4vpPresenter.ParsePresentationRequest` | All four client identifier forms are parsed by `parseOID4VPClientID`. Signed Request Objects are authenticated for `x509_san_dns` and `x509_hash` (`authenticateFinalRequestObject`); a colon-less identifier is a pre-registered client (OpenID4VP §5.9.2). HAIP requires `x509_hash`. |
| `request_uri` GET / POST with `wallet_nonce` | Implemented | `Oid4vpPresenter.ParsePresentationRequest`, `requestBuilder.WithRequestObjectURI`, `Oid4vpPresenter.RequestURINonce` | Both methods are accepted. A Final POST always carries a fresh `wallet_nonce` (32 random bytes) and optional `wallet_metadata`; the echo is exposed as `RequestObjectVerification.WalletNonce`. |
| DCQL `credential_sets` | Implemented | `Oid4vpPresenter.ParsePresentationRequest`, `ResolveSatisfiableDCQLCredentials` | `options` with `required`. All required queries must be satisfiable before any response is sent. |
| DCQL `claims` / `claim_sets` / `values` | Implemented | as above | Claim identifiers and `values` (string, integer or boolean) are validated; `claim_sets` selects one option. |
| DCQL `trusted_authorities` (`aki`) and `multiple` | Implemented | as above, `AuthorityKeyIdentifiersFromCredential` | Only the `aki` authority type is evaluated (HAIP §5); entries of other types are ignored. `multiple: true` returns every match. |
| DCQL nested / array claim paths | Implemented | `evaluateDCQLClaimPath`, `sdjwtvc.selectTopLevelDisclosures` | String keys, `null` (all array elements) and non-negative array indices (OID4VP §7). The `_sd` / `...` disclosures for the selected leaves only are emitted. |
| `direct_post` / `direct_post.jwt` | Implemented | `Wallet.PresentCredential`, `Oid4vpPresenter.PresentDCQL`, `Oid4vpPresenter.CreateEncryptedAuthorizationResponse` | Plain form POST for `direct_post`; ECDH-ES JWE for `direct_post.jwt`. Error responses are encrypted when the verifier metadata allows and otherwise sent in plaintext per §8.3.1. |
| `transaction_data` | Implemented | `Config.SupportedTransactionDataTypes`, `Oid4vpPresenter.SetSupportedTransactionDataTypes` | Each object is base64url-encoded JSON with known `credential_ids`; the hash is bound into the KB-JWT. With an empty list every `transaction_data` request is rejected with `invalid_transaction_data`. |
| W3C Digital Credentials API (`dc_api` / `dc_api.jwt`, unsigned / signed / multi-signed) | Implemented (protocol only) | `Wallet.PresentCredentialToDCAPI`, `Oid4vpPresenter.ParseDCAPIRequest`, `Oid4vpPresenter.BuildDCAPIResponse` | Accepts `openid4vp-v1-unsigned`, `-signed` and `-multisigned`. The caller supplies the platform-authenticated `origin`; there is no browser or OS integration in this library. |
| HAIP 1.0 profile switch | Implemented | `profile.HAIP`, `Config.Profile`, `Oid4vpPresenter.Profile`, `Oid4vciReceiver.Profile` | `profile.Final` is the default. The profile is propagated to every plugin; a caller-injected dispatcher whose plugin reports a different profile is rejected. |
| Draft 13 / Draft 24 legacy entry points | Implemented | `Wallet.ReceiveCredential`; `Wallet.PresentDraft24Credential`, `Oid4vpPresenter.ParseDraft24PresentationRequest`, `NewDraft24RequestBuilder`, `PresentDraft24` | The Draft paths keep their historical behaviour, including `InsecureSkipX509Verify`, and ignore the Final / HAIP profile. |
| Formats: SD-JWT VC (`dc+sd-jwt`, `vc+sd-jwt`) and `jwt_vc_json` | Implemented | `credential.SDJwtVC`, `credential.JwtVc`, the SD-JWT VC and JWT VC serializer plugins | Serialization and presentation for both. An SD-JWT VC issuer `typ` may be `dc+sd-jwt` or `vc+sd-jwt`. |
| Formats: ISO mdoc (`mso_mdoc`) | Not implemented | - | No mdoc / COSE / CBOR serializer exists. The HAIP format allow-list mentions `mso_mdoc`, but no presentation can be built. Out of scope for this integration. |

**Conformance evidence.** The public driver in `examples/official_driver` passed the official modules recorded in the Final / HAIP roadmap against a locally built copy of the OIDF conformance suite: the HAIP VCI plan `oid4vci-1_0-wallet-haip-test-plan` (credential-issuance, notification, client-attestation-challenge, deferred and batch modules) and the Final / HAIP VP plans `oid4vp-1final-wallet-test-plan` and `oid4vp-1final-wallet-haip-test-plan` over `direct_post.jwt`, `request_uri_signed`, `x509_hash` and the `dc_api.jwt` variant (unsigned, signed and multi-signed). This is a partial suite run, not a full profile conformance claim and not a certification; see the roadmap record for the exact module and variant list.

## Quick start

The runnable reference is the independent [public Wallet API driver](official_driver/README.md), which composes a `wallet.Wallet` with explicit trust and acceptance policy and then drives receive and present. The essential composition is:

```go
// Trust anchors for signed OID4VP Request Objects. Config has no direct
// verifier-trust field: inject a presenter plugin that carries
// RequestObjectValidation. With none, the library has no anchors and rejects
// every X.509 Request Object (fail-closed).
requestObjectValidation := &oid4vp.RequestObjectValidationOptions{
	TrustAnchors:                verifierAnchors, // []*x509.Certificate
	AllowUnadvertisedRevocation: false,
	WalletAudience:              []string{"https://self-issued.me/v2"},
}

// Issuer authentication before storage. With a nil policy only the library's
// minimum rules apply: the credential must parse, carry a supported alg and
// (for SD-JWT VC) a dc+sd-jwt / vc+sd-jwt typ, and a cnf that does not match
// the holder key is rejected.
acceptance := &wallet.CredentialAcceptancePolicy{
	IssuerX509:           &wallet.IssuerX509TrustOptions{TrustAnchors: issuerAnchors},
	RequireHolderBinding: true,
}

receiving, _ := receiver.NewReceivingDispatcher(receiver.WithPlugin(
	receiverTypes.Oid4vci,
	&oid4vci.Oid4vciReceiver{HTTPClient: httpClient, Profile: profile.HAIP},
))
presenting, _ := presenter.NewPresentationDispatcher(presenter.WithPlugin(
	presenter.Oid4vp,
	&oid4vp.Oid4vpPresenter{
		HTTPClient:              httpClient,
		RequestObjectValidation: requestObjectValidation,
		Profile:                 profile.HAIP,
	},
))

w, err := wallet.NewWalletWithConfig(wallet.Config{
	Receiver:                      receiving,
	Presenter:                     presenting,
	Profile:                       profile.HAIP, // profile.Final is the default
	CredentialAcceptance:          acceptance,
	SupportedTransactionDataTypes: []string{"payment"}, // empty rejects every transaction_data request
	DPoP:                          wallet.DPoPConfig{Enabled: true, Key: dpopKey},
	ClientAuth:                    wallet.ClientAuthConfig{Method: receiverTypes.PrivateKeyJwt, ClientID: clientID, Key: clientKey},
	ClientAttestation:             clientAttestation, // wallet.ClientAttestationProvider, or nil
	KeyAttestation:                keyAttestation,    // wallet.KeyAttestationProvider, or nil
})
```

Receive with the authorization-code flow, or with a pre-authorized code:

```go
offer, _ := w.ResolveCredentialOffer(offerURI) // offer by reference; ParseCredentialOfferURL for an inline offer
result, err := w.ReceiveOID4VCIFinalCredential(wallet.OID4VCIFinalReceiveRequest{
	CredentialOffer:                 offer,
	Type:                            receiverTypes.Oid4vci,
	ClientID:                        clientID,
	RedirectURI:                     redirectURI,
	HolderKey:                       holderKey,
	ClientKey:                       clientKey,
	CredentialResponseEncryptionKey: encryptionKey, // nil requests a plaintext response
	DeferredPollAttempts:            10,
})

saved, err := w.ReceiveCredential(wallet.ReceiveCredentialRequest{
	CredentialOffer: offer,
	Type:            receiverTypes.Oid4vci,
	Key:             holder,
	RequestedFormat: credential.SDJwtVC,
	TxCode:          txCode,
})
```

Present through a launch URI, or answer a W3C Digital Credentials API invocation:

```go
redirectURI, err := w.PresentCredential(requestURI, holderKey, nil)

response, err := w.PresentCredentialToDCAPI(
	oid4vp.DCAPIInvocation{
		Request: oid4vp.DCAPIRequest{Protocol: oid4vp.DCAPIProtocolSigned, Data: data},
		Origin:  origin, // platform-authenticated, never read from data
	},
	holderKey, nil,
)
```

Fail-closed defaults:
- No verifier trust anchors: `RequestObjectValidation` stays nil and every X.509 (signed) Request Object is rejected.
- Nil `CredentialAcceptance`: only the minimum rules run, and a Final response containing one unverifiable credential stores nothing.
- Empty `SupportedTransactionDataTypes`: every request carrying `transaction_data` is rejected.
- HAIP is not chosen by default: the zero `Config.Profile` normalizes to `profile.Final`.

## Security model

**What the library authenticates.** Signed OID4VP Request Objects are verified against the caller's X.509 anchors, with `aud` / `exp` / `nbf`, an optional EKU and CRL policy, and the `x509_san_dns` or `x509_hash` binding (`authenticateFinalRequestObject`, `verifyRequestObjectCertificateChain`). The outcome is exposed only in `CredentialPresentationRequest.RequestObjectVerification` and is never read from the request. Credentials are authenticated before storage by `verifyCredentialForAcceptance`, which checks the signature, `exp` / `nbf` and SD-JWT disclosure integrity. Attestations from providers are checked by `ValidateClientAttestation` / `validateKeyAttestation` for `typ`, `sub`, RFC 7638 `cnf.jwk`, `exp` and, under HAIP, a non-self-signed `x5c` leaf; the attester's own signature is not verified.

**What the application must keep.** Trust-anchor selection and distribution (`RequestObjectValidation.TrustAnchors` / `RootCAs`, `IssuerX509TrustOptions`); the inputs to the revocation policy (reachable CRLs, `AllowUnadvertisedRevocation`). The shared signing-chain path consults CRLs only and does not implement OCSP (`common/x509.NewCRLChecker` never follows OCSP). It also keeps consent and any ecosystem policy above the protocol; persistence and resumption of the protocol state the migration guide describes (deferred token and transaction identifiers, notification identifiers); and the platform-authenticated origin for DC API.

**Explicit escapes, for local development and tests only.** `AllowHTTP` (and the `VCKNOTS_WALLET_HTTP_ALLOWED` environment variable) permits plain HTTP endpoints and is rejected under HAIP. `InsecureSkipX509Verify` applies to the Draft24 entry points only; the Final path rejects it. `AllowUnadvertisedRevocation` keeps certificates without published CRL / OCSP information on the trust path and reports them separately, never as positively checked. `DeliveredByReference` is a caller attestation that a `request=` Request Object was originally fetched through `request_uri`, letting the request satisfy the HAIP §5.1 delivery check; set it only when the application's own admission path recorded the fetch.

See the [API migration guide](../API-MIGRATION.md) for the integrated API changes and the [public Wallet API driver](official_driver/README.md) for a complete configuration.

## Prerequisites

Local server integration test mode requires Node.js and pnpm in addition to Go.
Conformance test mode does not require the local Node.js server.

### 1. Install mise

The wallet package uses [mise](https://mise.jdx.dev/) for development environment management.
If mise is not installed, please install it first.

Example:
```bash
# macOS
brew install mise

# Install via curl
curl https://mise.jdx.dev/install.sh | sh
```

### 2. Set up the environment

Move to the project directory and set up the environment:

```bash
cd /path/to/vcknots/wallet
mise install
```

This automatically installs Go 1.26.6 and configures the necessary environment variables based on `mise.toml`.
If you prefer not to use mise, install Go 1.26.6 manually and set the `GOPRIVATE` environment variable:

```bash
export GOPRIVATE="github.com/trustknots/vcknots/wallet"
```

### 3. Install dependencies

Install Go module dependencies:

```bash
go mod download
```

## How to Run the Sample

`server_integration_sdjwt` is the sample that operates in two modes. The other two support the local server integration test mode only.

| Sample | Supported modes | Command-line arguments |
| --- | --- | --- |
| `server_integration_sdjwt` | Both modes | Positional OpenID4VP URI, `--credential-offer-uri`, `--tx-code` |
| `server_integration_jwtvc` | Local server integration test mode only | `--credential-offer-uri`, `--tx-code` |
| `server_integration_sdjwt+kbjwt` | Local server integration test mode only | None |

### Mode 1: Local Server Integration Test Mode (Recommended for First Run)

Tests integration with a local vcknots server.

#### Step 1: Start the Issuer, Authorization Server, and Verifier

The local server runs as **a single process** and provides all three roles together at `http://localhost:8080`. You do not need to start them separately.

| Role | Responsibility | Main endpoints |
| --- | --- | --- |
| Issuer | Issues credentials | `/configurations/:configuration/offer`, `/credentials`, `/.well-known/openid-credential-issuer`, `/.well-known/jwt-vc-issuer` |
| Authorization Server | Issues access tokens | `/token`, `/.well-known/oauth-authorization-server` |
| Verifier | Verifies presented credentials | `/request`, `/request-object`, `/request.jwt/:request-object-Id`, `/callback` |

Move to the repository root and start it:

```bash
# From the wallet directory, move to the vcknots root (/path/to/vcknots)
cd ../

# Install dependencies (if not done yet)
pnpm install

# Build the issuer+verifier module
pnpm -F @trustknots/vcknots build

# Build the server-core module
pnpm -F @trustknots/server-core build

# Build the server module
pnpm -F @trustknots/server build

# Start the server
pnpm -F @trustknots/server start
```

### Confirm the server is running

When the server starts, you should see output similar to:

```
> @trustknots/server@0.1.0 start /path/to/vcknots/server/single
> tsx src/example.ts

POST  /configurations/:configuration/offer
        [handler]
POST  /credentials
        [handler]
GET   /.well-known/openid-credential-issuer
        [handler]
GET   /.well-known/jwt-vc-issuer
        [handler]
POST  /token
        [handler]
GET   /.well-known/oauth-authorization-server
        [handler]
POST  /request
        [handler]
POST  /callback
        [handler]
POST  /request-object
        [handler]
GET   /request.jwt/:request-object-Id
        [handler]
Server is running on http://localhost:8080
Verifier metadata initialized for http://localhost:8080
Issuer metadata initialized
Authz metadata initialized
```

By default the server listens on `http://localhost:8080`.
The test scripts also use this URL.

#### Client authentication in local server integration test mode

The local server integration test mode samples use `private_key_jwt` for client authentication and enable DPoP. The token request therefore includes:

| Location | Name | Value |
| --- | --- | --- |
| Form parameter | `client_id` | `test-client-id` |
| Form parameter | `client_assertion_type` | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| Form parameter | `client_assertion` | An ES256-signed JWT |
| HTTP header | `DPoP` | A DPoP proof JWT (RFC 9449) |

The samples read this registration from `examples/config/`, which the wallet loads with the `wallet/clientconfig` package:

| File | Contents |
| --- | --- |
| `examples/config/wallet-clients.json` | Client metadata: `client_id`, `token_endpoint_auth_method`, `token_endpoint_auth_signing_alg`, `client_assertion_audience`, and the public `jwks` |
| `examples/config/client-private.sample.jwks.json` | The matching private JWK used to sign the `client_assertion` |

```go
clientAuth, err := clientconfig.Load(
	"../config/wallet-clients.json",
	clientconfig.WithClientID("test-client-id"),
	clientconfig.WithPrivateJWKFile("../config/client-private.sample.jwks.json"),
)
if err != nil {
	return err
}

w, err := wallet.NewWalletWithConfig(wallet.Config{ClientAuth: clientAuth})
```

The two files are kept apart on purpose. OpenID Connect Dynamic Client Registration 1.0 states that a `jwks` member MUST NOT contain private key values, so `wallet-clients.json` holds public keys only and can be handed to the authorization server as-is. `clientconfig.Load` rejects a `jwks` that carries a private key, and requires the private JWK file to be mode `0600`.

The public key in `examples/config/wallet-clients.json` is the one registered for `test-client-id` in `server/samples/oauth-clients.json`. The authorization server metadata in `server/samples/authorization_metadata.json` explicitly advertises both `private_key_jwt` and ES256; the wallet uses this authentication method only when both are advertised.

Configuring the wallet in Go is equally supported: `clientconfig.Load` returns a `wallet.ClientAuthConfig`, which you pass through `wallet.Config.ClientAuth` yourself. Keys that cannot be exported into a file, such as those held in an HSM or a secure enclave, are supplied with `clientconfig.WithKeyEntry`.

> ⚠️ **Warning**: The sample private key is committed so that the examples run straight after a clone, which is also why they pass `clientconfig.AllowInsecureFilePermissions()`. It is for this local sample only. In a real deployment generate a separate key, keep it out of the repository with mode `0600`, and register its public JWK with the authorization server.

#### Step 2: Run the integration test script (no arguments)

Open a new terminal, navigate to each test directory, and run the local server integration test mode script:

```bash
# JWT-VC integration test
cd /path/to/vcknots/wallet/examples/server_integration_jwtvc
go run server_integration_jwtvc.go

# SD-JWT integration test (without kb-jwt)
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go

# SD-JWT integration test (with kb-jwt)
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt+kbjwt
go run server_integration_sdjwt_kbjwt.go
```

Set `VCKNOTS_SERVER_URL` when the server is not running on `http://localhost:8080`:

```bash
VCKNOTS_SERVER_URL=http://localhost:18080 go run server_integration_sdjwt.go
```

To run against an offer URI created separately, pass it via `--credential-offer-uri`. If the offer requires a transaction code, also pass `--tx-code` (`--tx_code` is also accepted).

```bash
OFFER_URI='openid-credential-offer://?...'
go run server_integration_sdjwt.go --credential-offer-uri "$OFFER_URI" --tx-code 123456
```



### Step 3: Check the results

If everything works, you should see output similar to:

```
time=2025-11-27T14:03:25.066+09:00 level=INFO msg="Starting server integration check..."
time=2025-11-27T14:03:25.066+09:00 level=INFO msg="Fetching credential offer from server..."
time=2025-11-27T14:03:25.077+09:00 level=INFO msg="Received offer URL" url="openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A8080%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredential%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%220d6386e621c740d1a02771312039efeb%22%7D%7D%7D"
time=2025-11-27T14:03:25.077+09:00 level=INFO msg="Decoded offer" offer="{\"credential_issuer\":\"http://localhost:8080\",\"credential_configuration_ids\":[\"UniversityDegreeCredential\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"0d6386e621c740d1a02771312039efeb\"}}}"
time=2025-11-27T14:03:25.077+09:00 level=INFO msg="Parsed credential offer" issuer=http://localhost:8080 configs=[UniversityDegreeCredential] grants=1
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Successfully imported demo credential via controller.ReceiveCredential" entry_id=0909df8b-cecb-4432-a047-a1a9c2dfc720 raw_length=808
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="=== Received Credential Details ==="
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential Entry ID" id=0909df8b-cecb-4432-a047-a1a9c2dfc720
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential MimeType" mime_type=application/vc+jwt
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential Received At" received_at=2025-11-27T14:03:25.143+09:00
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential Raw Content" raw=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC92Yy83ZWE5MjI1YmMxZDM0ZmUxOWJkYmYwOWU4NjhkYjRmMSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJpc3N1YW5jZURhdGUiOiIyMDI1LTExLTI3VDA1OjAzOjI1LjE0MloiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSIsImdpdmVuX25hbWUiOiJ0ZXN0IiwiZmFtaWx5X25hbWUiOiJ0YXJvIiwiZGVncmVlIjoiNSIsImdwYSI6InRlc3QifX0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsInN1YiI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSJ9.Qd1dNQbpoRvpfkWF8m2z-EVvo8dZ3IM4gtlN2JTvoqnh8TDoXegh0OBC6gO6FwpODxf7m_IO_PhR1WnhztHC2Q
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Stored credentials" count=2 total=2
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Verifier Details" URL=http://localhost:8080
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Using received credential for presentation" credential_id=0909df8b-cecb-4432-a047-a1a9c2dfc720
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Decoding received credential JWT"
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Decoded credential" credential="map[iss:http://localhost:8080 sub:did:key:zDnaeYiwHNeMYaj21Wo9jPCowtnBrY8he8UCK8ZZN1mhhx8PM vc:map[@context:[https://www.w3.org/2018/credentials/v1] credentialSubject:map[degree:5 family_name:taro given_name:test gpa:test id:did:key:zDnaeYiwHNeMYaj21Wo9jPCowtnBrY8he8UCK8ZZN1mhhx8PM] id:http://localhost:8080/vc/7ea9225bc1d34fe19bdbf09e868db4f1 issuanceDate:2025-11-27T05:03:25.142Z issuer:http://localhost:8080 type:[VerifiableCredential UniversityDegreeCredential]]]"
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential analysis" types="[VerifiableCredential UniversityDegreeCredential]" subject_fields="[gpa id given_name family_name degree]"
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Generated presentation definition" json="{\n\t\t\"query\": {\n\t\t\t\"presentation_definition\": {\n\t\t\t\"id\": \"dynamic-presentation-UniversityDegreeCredential\",\n\t\t\t\"input_descriptors\": [\n\t\t\t{\n\t\t\t\t\"id\": \"credential-request\",\n\t\t\t\t\"name\": \"UniversityDegreeCredential\",\n\t\t\t\t\"purpose\": \"Verify credential\",\n\t\t\t\t\"format\": {\n\t\t\t\t\"jwt_vc_json\": {\n\t\t\t\t\t\"alg\": [\"ES256\"]\n\t\t\t\t}\n\t\t\t\t},\n\t\t\t\t\"constraints\": {\n\t\t\t\t\"fields\": [\n\t\t{\n\t\t\t\"path\": [\"$.type\"],\n\t\t\t\"filter\": {\n\t\t\t\t\"type\": \"array\",\n\t\t\t\t\"contains\": {\"const\": \"UniversityDegreeCredential\"}\n\t\t\t}\n\t\t},\n\t\t{\n\t\t\t\"path\": [\"$.credentialSubject.gpa\"],\n\t\t\t\"intent_to_retain\": false\n\t\t},\n\t\t{\n\t\t\t\"path\": [\"$.credentialSubject.given_name\"],\n\t\t\t\"intent_to_retain\": false\n\t\t},\n\t\t{\n\t\t\t\"path\": [\"$.credentialSubject.family_name\"],\n\t\t\t\"intent_to_retain\": false\n\t\t},\n\t\t{\n\t\t\t\"path\": [\"$.credentialSubject.degree\"],\n\t\t\t\"intent_to_retain\": false\n\t\t}\n\t]\n\t\t\t\t}\n\t\t\t}\n\t\t\t]\n\t\t}\n\t\t},\n\t\t\"state\": \"example-state\",\n\t\t\"base_url\": \"http://localhost:8080\",\n\t\t\"is_request_uri\": true,\n\t\t\"response_uri\": \"http://localhost:8080/callback\",\n\t\t\"client_id\": \"x509_san_dns:localhost\"\n\t}"
time=2025-11-27T14:03:25.155+09:00 level=INFO msg="Authorization RequestURI" status="200 OK" body="openid4vp://authorize?client_id=x509_san_dns%3Alocalhost&request_uri=http%3A%2F%2Flocalhost%3A8080%2Frequest.jwt%2F9855a937fda74c3f8de9d7f92537206e"
time=2025-11-27T14:03:25.155+09:00 level=INFO msg="Request URI is valid" scheme=openid4vp
time=2025-11-27T14:03:25.174+09:00 level=INFO msg="Credential presented successfully"
```

If `Credential presented successfully` appears, the sample succeeded.
Reaching this point also means that the authorization server accepted the client assertion and DPoP proof used to obtain the access token.

---

For SD-JWT VC, the public `PresentCredential` API follows the answered DCQL query's `require_cryptographic_holder_binding` value (default: `true`). Caller serialization options can require a KB-JWT when the query permits omission, but cannot disable a required proof. Credentials without a matching `cnf.jwk` are rejected before submission when binding is required.

### Mode 2: Conformance Test Mode (External URL)

Tests against external OpenID4VP conformance test services.
The conformance test URI can be obtained from the [OIDF Conformance Testing for OpenID for Verifiable Presentations](https://openid.net/certification/conformance-testing-for-openid-for-verifiable-presentations/) page.
Click the `Testing a wallet` button to proceed.

#### How to Run

```bash
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go "openid4vp://authorize?client_id=...&request_uri=..."
```

**Important**: Providing an OpenID4VP URI as an argument automatically uses Conformance Test mode.

#### Differences in Behavior

Conformance Test mode automatically applies the following settings:

- **Certificate Verification**: Uses system root certificate pool
- **Certificate Chain Verification Skip**: `InsecureSkipX509Verify: true` is automatically set, enabling communication with conformance test servers that use self-signed or non-standard certificates
- **Selected Claims**: Selects `given_name` and `family_name`
- **Key Binding**: Required (`RequireKeyBinding: true`)
- **Audience/Nonce**: Automatically extracted from the request URI
- **OID4VCI Client Authentication and DPoP**: Not configured; this mode tests the OpenID4VP presentation flow only

> ⚠️ **Warning**: `InsecureSkipX509Verify: true` should only be used in conformance tests and local development. **Never** use this in production environments.

---

## File Layout and Usage

### Integration Test Program

`server_integration_sdjwt/server_integration_sdjwt.go` operates in two modes:

**Mode 1: Local server integration test mode (no arguments)**
```bash
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go
VCKNOTS_SERVER_URL=http://localhost:18080 go run server_integration_sdjwt.go
go run server_integration_sdjwt.go --credential-offer-uri "$OFFER_URI" --tx-code 123456
```
- Tests integration with a local vcknots server
- Strict certificate verification (uses a specific certificate file)
- Server must be running on http://localhost:8080
- `--tx-code` is optional and is forwarded to the OpenID4VCI token request as `tx_code`
- `--credential-offer-uri` skips fetching a new offer and uses the provided OpenID4VCI offer URI

**Mode 2: Conformance test mode (with OpenID4VP URI argument)**
```bash
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go "openid4vp://authorize?..."
```
- Tests against external OpenID4VP conformance test services
- Uses system root certificate pool
- `InsecureSkipX509Verify: true` is automatically set (supports non-standard certificates)

### File Structure

```
examples/
├── common/                            # Shared sample setup (wallet construction, mock key)
├── config/
│   ├── wallet-clients.json            # Client authentication metadata (public keys only)
│   └── client-private.sample.jwks.json # Sample client_assertion signing key (local use only)
├── server_integration_jwtvc/
│   └── server_integration_jwtvc.go   # JWT-VC integration test
├── server_integration_sdjwt/
│   ├── server_integration_sdjwt.go   # SD-JWT integration test (without kb-jwt)
│   └── example_sd_jwt.txt            # Sample SD-JWT credential
├── server_integration_sdjwt+kbjwt/
│   ├── server_integration_sdjwt_kbjwt.go # SD-JWT integration test with kb-jwt
│   └── example_sd_jwt.txt                 # Sample SD-JWT credential
├── custom_dispatcher/                 # Example: custom dispatcher implementation
├── custom_plugin/                     # Example: custom plugin implementation
├── README.md                          # This file
└── README.ja.md                       # Japanese version
```

**Note**: The certificate file and SD-JWT sample file are loaded using relative paths from each test directory. By default:
- Certificate: `../../../server/samples/certificate-openid-test/certificate_openid.pem`
- SD-JWT sample: `example_sd_jwt.txt` (in server_integration_sdjwt/)

For KB-JWT verification, use the `server_integration_sdjwt+kbjwt` sample. It requests `dc+sd-jwt`, posts to `http://localhost:8080/callback-kbjwt`, and includes a fixed nonce plus KB-JWT audience matching `x509_san_dns:localhost`.

If you need to use a different certificate, set the `VCKNOTS_CERT_PATH` environment variable:

```bash
cd /path/to/vcknots/wallet/examples/server_integration_jwtvc
VCKNOTS_CERT_PATH=/path/to/custom/cert.pem go run server_integration_jwtvc.go
```

### DCQL presentation selection

`PresentCredential` and `BuildOID4VPFinalAuthorizationResponse` match each DCQL
query by credential format, `vct_values`, and requested claims. All required
queries must be satisfied before any response is sent. The response maps each
query ID to its own presentation array; `credential_sets` can express alternatives.
For SD-JWT VC, omitted `claims` means no selective disclosures. Plaintext claims
already in the issuer JWT remain present. Explicit `SelectedClaims` is a caller
limit, so requested claims outside that limit cause an error.

The current claim selector handles top-level string paths. General nested and
array paths remain unsupported. This does not establish full Final/HAIP
conformance, issuer authentication before storage, or platform DC API support.
The existing single-query `Oid4vpPresenter.Present` API remains available;
`PresentDCQL` adds submission of a complete map of query presentations. Custom
presenter plugins opt into that additional capability.

### Wallet Runtime Environment Variables

In addition to `VCKNOTS_CERT_PATH`, the wallet runtime behavior is controlled by environment variables defined in `wallet/env/env.go`.

| Variable | Default | Description |
| :---- | :---- | :---- |
| `VCKNOTS_WALLET_HTTP_ALLOWED` | `false` (unset/empty) | When set to `true`, HTTP endpoints are allowed for wallet HTTP calls (for local development/testing). A client assertion is the exception: it is sent over plain HTTP only to a loopback host, so `private_key_jwt` against a remote `http://` endpoint is refused even with this set. |
| `VCKNOTS_WALLET_DEBUG` | `false` (unset/empty) | Enables debug logging only. It does not relax the HTTPS requirement. |

Behavior summary:
- `IsHTTPAllowed()` becomes `true` only when `VCKNOTS_WALLET_HTTP_ALLOWED=true`.
- `VCKNOTS_WALLET_DEBUG=true` does not enable HTTP allowance; to use a local `http://` endpoint, set `VCKNOTS_WALLET_HTTP_ALLOWED=true` as well.
- If `VCKNOTS_WALLET_HTTP_ALLOWED` is unset (or not equal to `true`), `IsHTTPAllowed()` is `false`, and HTTPS-only validation remains active.

Example (local development only):

```bash
export VCKNOTS_WALLET_HTTP_ALLOWED=true
```

> ⚠️ **Security warning**: Do not enable `VCKNOTS_WALLET_HTTP_ALLOWED` in production. Keep HTTPS-only validation enabled.

---

## Troubleshooting

### `client_id` Validation Errors (Conformance Test Mode)

The conformance test suite intentionally sends malformed `client_id` values to test the wallet's validation logic.

- **Example errors**:
  - `invalid client_id: duplicate prefix detected` (e.g., `x509_san_dns:x509_san_dns:...`)
  - `SAN of the certificate and client_id did not match`
- These errors are **expected behavior** and indicate the wallet is correctly enforcing security checks.

### `x509: certificate is not standards compliant` Error

Conformance test servers may use self-signed or non-standard certificate structures for testing purposes.

- **When running local server integration test mode (no arguments)**: Check that the certificate file is correctly placed at `../../../server/samples/certificate-openid-test/certificate_openid.pem`, or specify it via `VCKNOTS_CERT_PATH`.
- **When running conformance test mode (with URI argument)**: `InsecureSkipX509Verify: true` is set automatically, so this error should not appear.
