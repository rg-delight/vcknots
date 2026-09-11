---
sidebar_position: 13
---

# How to Set Up and Use the Wallet Feature

This tutorial explains how to set up the VCKnots wallet library (a Go library), how to receive and present credentials with it, and what to consider before using it in production environments.

The wallet implements the OpenID for Verifiable Credentials specifications:

* **Receiving credentials (OID4VCI):** the wallet obtains a credential from an issuer using a credential offer and the pre-authorized code flow.
* **Presenting credentials (OID4VP):** the wallet responds to an `openid4vp://` authorization request and submits a Verifiable Presentation to a verifier.

Both **JWT-VC** (`application/vc+jwt`) and **SD-JWT VC** (`application/dc+sd-jwt`) are supported for receiving and presenting, including selective disclosure and Key Binding JWT for SD-JWT VC.

## Supported protocols and profiles

This wallet implements **OpenID4VCI 1.0** and **OpenID4VP 1.0**. **HAIP 1.0** is available as an explicit profile: the zero value of `profile.Profile` normalizes to `profile.Final`, and `profile.HAIP` adds the HAIP constraints on top. The Draft 13 and Draft 24 entry points remain supported with their historical behaviour. `Partial` marks a feature whose interface exists but whose production integration is the caller's responsibility.

| Protocol / feature | Status | Public API entry point | Notes |
| --- | --- | --- | --- |
| OpenID4VCI 1.0 pre-authorized code | Implemented | `Wallet.ReceiveCredential` (`ReceiveCredentialRequest`) | Also the legacy Draft 13 entry point. |
| OpenID4VCI 1.0 authorization code (PAR / PKCE / DPoP / `private_key_jwt` / client attestation) | Implemented | `Wallet.BeginOID4VCIFinalAuthorization` + `Wallet.ResumeOID4VCIFinalAuthorization`, or `Wallet.ReceiveOID4VCIFinalCredential` (`OID4VCIFinalReceiveRequest`) | PAR is used when the authorization server advertises one and is required only under HAIP (HAIP §4); PKCE is always `S256`; `private_key_jwt` is used when the authorization server advertises it; attestation-based client authentication uses `Config.ClientAttestation`. |
| Deferred issuance | Implemented | `Wallet.ReceiveOID4VCIFinalCredential` (`DeferredPollAttempts`), `Wallet.ResumeOID4VCIFinalDeferredCredential` | Polls at the advertised interval, capped at 60 seconds (`MaxDeferredInterval` overrides it) and cancellable through the `…Context` variants. Resumable in another process through `OID4VCIFinalDeferredRequest`. |
| Notification endpoint | Implemented | `Wallet.NotifyOID4VCIFinalCredentialDeleted` (`OID4VCIFinalNotificationRequest`) | Sends `credential_deleted`. `credential_accepted` and `credential_failure` are sent internally after storage has succeeded or failed. |
| Batch issuance | Implemented | `Wallet.ReceiveOID4VCIFinalCredential` (`AdditionalHolderKeys`) | One proof per holder key, bounded by `batch_credential_issuance.batch_size`. |
| Credential response encryption | Implemented | `OID4VCIFinalReceiveRequest.CredentialResponseEncryptionKey` | OpenID4VCI 1.0 §8.2 (`jwk`, `enc`, optional `zip`, no `alg`). Fails closed when the issuer requires encryption and no key was supplied. |
| Key attestation | Partial | `Config.KeyAttestation` (`KeyAttestationProvider`), `StaticKeyAttester`, `OID4VCIFinalReceiveRequest.IncludeKeyAttestation` | The library validates the provider JWT (`typ`, `attested_keys`, `exp`) but does not verify the attester's signature; a production attester or HSM is caller-supplied. |
| OpenID4VP 1.0 redirect flow (`x509_hash` / `x509_san_dns` / `redirect_uri` / pre-registered) | Implemented | `Wallet.PresentCredential`, `Wallet.PresentCredentialWithOptions`, `Oid4vpPresenter.ParsePresentationRequest` | Signed Request Objects are authenticated for `x509_san_dns` and `x509_hash`; a colon-less identifier is a pre-registered client (OpenID4VP §5.9.2). HAIP requires `x509_hash`. |
| `request_uri` GET / POST with `wallet_nonce` | Implemented | `Oid4vpPresenter.ParsePresentationRequest`, `requestBuilder.WithRequestObjectURI`, `Oid4vpPresenter.RequestURINonce` | A Final POST always carries a fresh `wallet_nonce` and optional `wallet_metadata`; the echo is exposed as `RequestObjectVerification.WalletNonce`. |
| DCQL (`credential_sets`, `claims`, `claim_sets`, `values`, nested / array claim paths, `trusted_authorities` with `aki`, `multiple`) | Implemented | `Oid4vpPresenter.ParsePresentationRequest`, `ResolveSatisfiableDCQLCredentials`, `AuthorityKeyIdentifiersFromCredential` | Only the `aki` authority type is evaluated (HAIP §5); entries of other types are ignored. `multiple: true` returns every match. |
| `direct_post` / `direct_post.jwt` | Implemented | `Wallet.PresentCredential`, `Oid4vpPresenter.PresentDCQL`, `Oid4vpPresenter.CreateEncryptedAuthorizationResponse` | Plain form POST for `direct_post`; ECDH-ES JWE for `direct_post.jwt`. Error responses are encrypted when the verifier metadata allows and otherwise sent in plaintext per §8.3.1. |
| `transaction_data` | Implemented | `Config.SupportedTransactionDataTypes`, `Oid4vpPresenter.SetSupportedTransactionDataTypes` | Each object is base64url-encoded JSON with known `credential_ids`; the hash is bound into the KB-JWT. With an empty list every `transaction_data` request is rejected with `invalid_transaction_data`. |
| W3C Digital Credentials API (`dc_api` / `dc_api.jwt`, unsigned / signed / multi-signed) | Implemented (protocol only) | `Wallet.PresentCredentialToDCAPI`, `Oid4vpPresenter.ParseDCAPIRequest`, `Oid4vpPresenter.BuildDCAPIResponse` | Accepts `openid4vp-v1-unsigned`, `-signed` and `-multisigned`. The caller supplies the platform-authenticated `origin`; there is no browser or OS integration in this library. |
| HAIP 1.0 profile switch | Implemented | `profile.HAIP`, `Config.Profile`, `Oid4vpPresenter.Profile`, `Oid4vciReceiver.Profile` | `profile.Final` is the default. The profile is propagated to every plugin; a caller-injected dispatcher whose plugin reports a different profile is rejected. |
| Draft 13 / Draft 24 legacy entry points | Implemented | `Wallet.ReceiveCredential`; `Wallet.PresentDraft24Credential`, `Oid4vpPresenter.ParseDraft24PresentationRequest`, `NewDraft24RequestBuilder`, `PresentDraft24` | The Draft paths keep their historical behaviour, including `InsecureSkipX509Verify`, and ignore the Final / HAIP profile. |
| Formats: SD-JWT VC (`dc+sd-jwt`, `vc+sd-jwt`) and `jwt_vc_json` | Implemented | `credential.SDJwtVC`, `credential.JwtVc`, the SD-JWT VC and JWT VC serializer plugins | Serialization and presentation for both. An SD-JWT VC issuer `typ` may be `dc+sd-jwt` or `vc+sd-jwt`. |

**Not implemented.** ISO mdoc (`mso_mdoc`): no mdoc / COSE / CBOR serializer exists, so no presentation can be built. The `verifier_attestation`, `openid_federation` and `decentralized_identifier` Client Identifier Prefixes are parsed but not authenticated by the Final path. Only the `aki` DCQL trust authority type is evaluated; `etsi_tl` and `openid_federation` entries are ignored (a query whose entries are all of an unknown type therefore places no constraint).

### Profiles (Final vs HAIP)

* **Final** is OpenID4VCI 1.0 / OpenID4VP 1.0 without additional constraints. It is the default: a zero `profile.Profile` (`""`) normalizes to `profile.Final`.
* **HAIP** is HAIP 1.0 constraints on top of Final, selected with `profile.HAIP` in `wallet.Config.Profile`, `oid4vci.Oid4vciReceiver.Profile` and `oid4vp.Oid4vpPresenter.Profile`.
* The root Wallet propagates its profile to every registered plugin. A caller-injected dispatcher whose plugin implements `profile.Carrier` and reports a different profile is rejected, so the root policy cannot be bypassed through a lower-level API.
* The Draft 13 / Draft 24 entry points ignore the profile.
* Under HAIP the Final paths additionally reject, among others: `AllowHTTP` and `InsecureSkipX509Verify`; access tokens that are not DPoP-bound; credential configurations without a `scope`; issuers that advertise cryptographic binding without a `nonce_endpoint`; issuance without any configured OAuth client authentication; presentation requests whose client identifier prefix is not `x509_hash`, whose response mode is not `direct_post.jwt` / `dc_api.jwt`, or whose DCQL formats are not `dc+sd-jwt` / `mso_mdoc`; response encryption other than ECDH-ES with A128GCM or A256GCM; and a missing KB-JWT for an SD-JWT VC that carries `cnf`. Each constraint is covered by a Final-accepts / HAIP-rejects test pair.

## 1. Prerequisites

* **Supported specifications:**
    - Receiving: [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) (pre-authorized code and authorization code), with HAIP 1.0 as an optional profile
    - Presenting: [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) with HAIP 1.0 as an optional profile; the earlier Draft 13 / Draft 24 flows are still supported
    - For the full implementation scope of each feature, see [VC Knots Coverage](./support-matrix.md).

### 1-1. Go Environment Requirements

* **Go version:** The vcknots/wallet library requires the Go version pinned in `wallet/mise.toml` (currently Go 1.26.5).
* **Development environment management (mise):**
    - We recommend using [mise](https://mise.jdx.dev/) to manage the development environment.
    - Running `mise install` in the `wallet` directory installs the required Go version and sets the necessary environment variables automatically.

```bash
# macOS
brew install mise

# Install via curl
curl https://mise.jdx.dev/install.sh | sh

# (From the root of the vcknots repository)
cd wallet
mise install
```

* **GOPRIVATE environment variable:**
    - If you are not using mise, set the following environment variable manually. Without it, `go mod download` fails.

```bash
export GOPRIVATE="github.com/trustknots/vcknots/wallet"
```

### 1-2. Requirements for the Sample Execution Environment (Issuer/Verifier Server)

The sample code in this tutorial (receiving and presenting credentials) assumes that counterpart services (an Issuer and a Verifier) are available. The Node.js-based sample server (`server/`) in this repository provides both.

Start the server before running any wallet sample code:

```bash
# From the root of the vcknots repository
pnpm install

# Build the issuer+verifier module, the server-core module, and the server module
pnpm -F @trustknots/vcknots build
pnpm -F @trustknots/server-core build
pnpm -F @trustknots/server build

# Start the server (listens on http://localhost:8080)
pnpm -F @trustknots/server start
```

The server exposes the endpoints used in this tutorial:

* `POST /configurations/:configurationId/offer` — creates a credential offer
* `POST /token`, `POST /nonce`, `POST /credentials` — OID4VCI token, nonce, and credential endpoints
* `POST /request`, `POST /request-object` — creates an OID4VP authorization request
* `POST /callback` — the verifier's response endpoint
* `GET /.well-known/openid-credential-issuer`, `GET /.well-known/oauth-authorization-server` — metadata endpoints

* **Allowing HTTP for local testing:** The wallet rejects non-HTTPS issuer and verifier endpoints by default. Because the local sample server runs on plain HTTP, enable HTTP explicitly when testing locally:

```bash
export VCKNOTS_WALLET_HTTP_ALLOWED=true
```

Alternatively, call `env.SetHTTPAllowed(true)` (package `github.com/trustknots/vcknots/wallet/env`) from your test code.

> ⚠️ **Security warning:** Do not enable `VCKNOTS_WALLET_HTTP_ALLOWED` in production. Keep HTTPS-only validation active.

## 2. Initial Setup

This section explains how to install the library dependencies and initialize the `Wallet` instance, which aggregates the core wallet features.

### 2-1. Installing Dependencies

After setting GOPRIVATE, run the following command in the `wallet` directory to download the dependencies listed in `go.mod` (such as `github.com/go-jose/go-jose/v4`, `go.etcd.io/bbolt`, `golang.org/x/crypto`, etc.).

```bash
go mod download
```

### 2-2. Initializing the Wallet

The library exposes its top-level API in the `github.com/trustknots/vcknots/wallet` package. The simplest way to create a wallet is `wallet.NewWallet()`, which initializes every dispatcher component with its default plugin implementation:

```go
import (
    "log"

    "github.com/trustknots/vcknots/wallet"
)

w, err := wallet.NewWallet()
if err != nil {
    log.Fatal(err)
}
```

Internally, the `Wallet` coordinates six dispatcher components, each responsible for one aspect of wallet functionality:

* `credstore.CredStoreDispatcher` — credential persistence (bbolt-backed local storage by default)
* `receiver.ReceivingDispatcher` — credential issuance protocols (OID4VCI)
* `presenter.PresentationDispatcher` — credential presentation protocols (OID4VP)
* `serializer.SerializationDispatcher` — credential serialization (JWT-VC, SD-JWT VC)
* `verifier.VerificationDispatcher` — cryptographic signature verification
* `idprof.IdentityProfileDispatcher` — DIDs and identity profiles (`did:key`)

When you need custom configuration (for example, to set the trust roots used for verifying OID4VP request objects), construct the dispatchers yourself and pass them to `wallet.NewWalletWithConfig`. Every dispatcher constructor returns an error, and any field left `nil` in `wallet.Config` falls back to its default implementation. The following code is the initialization used by the samples under `wallet/examples/`:

```go
package main

import (
    "crypto/x509"
    "fmt"
    "os"

    "github.com/trustknots/vcknots/wallet"
    "github.com/trustknots/vcknots/wallet/credstore"
    "github.com/trustknots/vcknots/wallet/idprof"
    "github.com/trustknots/vcknots/wallet/presenter"
    "github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
    "github.com/trustknots/vcknots/wallet/receiver"
    "github.com/trustknots/vcknots/wallet/serializer"
    "github.com/trustknots/vcknots/wallet/verifier"
)

func newWallet(certPath string) (*wallet.Wallet, error) {
    credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
    if err != nil {
        return nil, err
    }

    receiverDisp, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
    if err != nil {
        return nil, err
    }

    serializerDisp, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
    if err != nil {
        return nil, err
    }

    verifierDisp, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
    if err != nil {
        return nil, err
    }

    idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
    if err != nil {
        return nil, err
    }

    // Trust roots for verifying the x5c certificate chain of OID4VP request objects
    certFile, err := os.ReadFile(certPath)
    if err != nil {
        return nil, err
    }
    certPool := x509.NewCertPool()
    if !certPool.AppendCertsFromPEM(certFile) {
        return nil, fmt.Errorf("failed to parse certificate: %s", certPath)
    }

    oid4vpPresenter := &oid4vp.Oid4vpPresenter{
        X509TrustChainRoots: certPool,
    }
    presenterDisp, err := presenter.NewPresentationDispatcher(
        presenter.WithPlugin(presenter.Oid4vp, oid4vpPresenter),
    )
    if err != nil {
        return nil, err
    }

    return wallet.NewWalletWithConfig(wallet.Config{
        CredStore:  credStore,
        IDProfiler: idProf,
        Receiver:   receiverDisp,
        Serializer: serializerDisp,
        Verifier:   verifierDisp,
        Presenter:  presenterDisp,
    })
}
```

* **Storage location:** The default credential store persists credentials with `go.etcd.io/bbolt` to `<user config dir>/vcknots/wallet/.local_credstore.db` (for example `~/.config/vcknots/wallet/.local_credstore.db` on Linux, `~/Library/Application Support/vcknots/wallet/.local_credstore.db` on macOS).

## 3. Sample Implementation of Wallet Features

Using the `Wallet` instance, this section provides concrete Go code samples for the main wallet functions: key preparation, receiving credentials, and presenting credentials. These samples are based on `wallet/examples/server_integration_sdjwt/server_integration_sdjwt.go` and `wallet/examples/common/common.go`.

### 3-1. Preparing Test Keys (IKeyEntry Interface)

The main workflow methods (`ReceiveCredential`, `PresentCredential`) require the `IKeyEntry` interface for signing operations. This allows library users to swap out key management implementations (for example: in-memory, HSM, secure enclave).

The `IKeyEntry` interface is defined as follows:

```go
// IKeyEntry represents a key entry interface for signing operations.
type IKeyEntry interface {
    ID() string
    PublicKey() jose.JSONWebKey
    Sign(data []byte) ([]byte, error)
}
```

* **Signature format:** ECDSA implementations of `Sign` may return either DER-encoded ASN.1 signatures or raw IEEE P1363 (`R || S`) signatures. The library normalizes DER-encoded signatures to IEEE P1363 internally (via `JWKSigner`), so both formats work.

For this tutorial, we use an in-memory implementation equivalent to `MockKeyEntry` in `wallet/examples/common/common.go`:

```go
// MockKeyEntry is a test implementation of IKeyEntry.
type MockKeyEntry struct {
    id         string
    privateKey *ecdsa.PrivateKey
}

func NewMockKeyEntry() (*MockKeyEntry, error) {
    privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }
    return &MockKeyEntry{
        id:         "test-key-id-" + uuid.NewString(),
        privateKey: privKey,
    }, nil
}

func (m *MockKeyEntry) ID() string { return m.id }

func (m *MockKeyEntry) PublicKey() jose.JSONWebKey {
    return jose.JSONWebKey{
        Key:       &m.privateKey.PublicKey,
        Algorithm: "ES256", // P-256 curve
        Use:       "sig",
    }
}

// Sign performs SHA-256 hashing -> ECDSA signing -> IEEE P1363 serialization.
func (m *MockKeyEntry) Sign(payload []byte) ([]byte, error) {
    hash := sha256.Sum256(payload)
    r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
    if err != nil {
        return nil, err
    }

    const keySize = 32 // P-256: 256 bits / 8
    signature := make([]byte, 2*keySize)
    r.FillBytes(signature[:keySize])
    s.FillBytes(signature[keySize:])
    return signature, nil
}
```

### 3-2. Receiving a Credential (OID4VCI)

The wallet receives a credential by calling `ReceiveCredential` with a `CredentialOffer` obtained from the issuer. In a real deployment the offer URI comes from a QR code or deep link; with the local sample server you can create one via `POST /configurations/:configurationId/offer`.

The offer URI has the form `openid-credential-offer://?credential_offer=...`. Parse it into a `wallet.CredentialOffer` and pass it to `ReceiveCredential`:

```go
import (
    "encoding/json"
    "net/url"

    "github.com/trustknots/vcknots/wallet"
    "github.com/trustknots/vcknots/wallet/credential"
    "github.com/trustknots/vcknots/wallet/receiver"
)

func receiveSDJwtCredential(w *wallet.Wallet, key wallet.IKeyEntry, offerURI string) (*wallet.SavedCredential, error) {
    // 1. Parse the openid-credential-offer:// URI
    parsed, err := url.Parse(offerURI)
    if err != nil {
        return nil, err
    }

    var offerJSON struct {
        CredentialIssuer           string                                  `json:"credential_issuer"`
        CredentialConfigurationIDs []string                                `json:"credential_configuration_ids"`
        Grants                     map[string]*wallet.CredentialOfferGrant `json:"grants"`
    }
    if err := json.Unmarshal([]byte(parsed.Query().Get("credential_offer")), &offerJSON); err != nil {
        return nil, err
    }

    issuerURL, err := url.Parse(offerJSON.CredentialIssuer)
    if err != nil {
        return nil, err
    }

    offer := &wallet.CredentialOffer{
        CredentialIssuer:           issuerURL,
        CredentialConfigurationIDs: offerJSON.CredentialConfigurationIDs,
        Grants:                     offerJSON.Grants, // key: "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }

    // 2. Receive the credential via OID4VCI (pre-authorized code flow)
    return w.ReceiveCredential(wallet.ReceiveCredentialRequest{
        CredentialOffer: offer,
        Type:            receiver.Oid4vci,
        Key:             key,                 // used to sign the JWT proof (key binding)
        RequestedFormat: credential.SDJwtVC,  // "application/dc+sd-jwt"
    })
}
```

Notes on `ReceiveCredentialRequest`:

* **RequestedFormat:** Set `credential.SDJwtVC` to receive an SD-JWT VC, or `credential.JwtVc` for a JWT-VC. When omitted, the format is resolved from the issuer metadata for the first credential configuration ID (falling back to JWT-VC).
* **TxCode:** When the offer requires a transaction code, set `TxCode`; it is sent to the token endpoint as `tx_code`.
* **CachedIssuerMetadata:** When set, `ReceiveCredential` skips fetching the issuer metadata (see section 4).

`ReceiveCredential` fetches the issuer and authorization server metadata, obtains an access token with the pre-authorized code, generates a JWT proof signed with `Key`, requests the credential, and stores the result in the credential store. It returns a `*wallet.SavedCredential` containing both the parsed credential and its storage entry.

### 3-3. Presenting a Credential (OpenID4VP)

After receiving a request URI in the form `openid4vp://authorize?...` from the verifier (typically by scanning a QR code; with the local sample server, via `POST /request` or `POST /request-object`), call `PresentCredential`:

```go
import (
    "log"

    sdjwtvc "github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

func presentCredential(w *wallet.Wallet, key wallet.IKeyEntry, oid4vpURI string) error {
    // Options for SD-JWT VC presentations: selective disclosure and Key Binding JWT
    options := &sdjwtvc.SdJwtVcPresentationOptions{
        SelectedClaims:    []string{"given_name", "family_name"},
        RequireKeyBinding: true,
    }

    redirectURI, err := w.PresentCredential(oid4vpURI, key, options)
    if err != nil {
        return err
    }
    if redirectURI != "" {
        log.Printf("Verifier requested redirect: %s\n", redirectURI)
    }
    return nil
}
```

`PresentCredential` parses the OID4VP request (including JAR request objects referenced by `request_uri`, whose signatures are verified against `X509TrustChainRoots`), selects the most recently received credential from the store (matching against the presentation definition is not performed yet), serializes and signs the Verifiable Presentation with `key`, and posts it to the verifier's `response_uri` (`response_mode=direct_post`). The wallet does not send anything to `redirect_uri`; when the verifier's response contains a `redirect_uri`, it is returned to the caller as the return value, or empty when there is none.

* **Presentation options:** The third argument accepts a format-specific options value. For SD-JWT VC, `sdjwtvc.SdJwtVcPresentationOptions` controls which claims are disclosed (`SelectedClaims`) and whether a Key Binding JWT is attached (`RequireKeyBinding`). The KB-JWT audience and nonce are filled automatically from the OID4VP request (`client_id` and `nonce`), as are `transaction_data` hashes when the request contains transaction data. Pass `nil` to use the default options for the credential's format (for JWT-VC presentations, `nil` is typical).
* **Redirect handling:** Use `PresentCredentialWithOptions` with `&wallet.PresentCredentialOptions{OnRedirect: func(uri string) error {...}}` when you want a callback invoked with the verifier's redirect URI.

### 3-4. Referencing Saved Credentials

Credentials saved via `ReceiveCredential` can be listed with `GetCredentialEntries`, which supports pagination (`Offset`, `Limit`) and filtering with a Go function (`Filter`). A single entry can be fetched by ID with `GetCredentialEntry`.

```go
func listSavedCredentials(w *wallet.Wallet) ([]*wallet.SavedCredential, error) {
    limit := 10
    entries, total, err := w.GetCredentialEntries(wallet.GetCredentialEntriesRequest{
        Offset: 0,
        Limit:  &limit,
        Filter: func(sc *wallet.SavedCredential) bool {
            return true // Example: return sc.Entry.MimeType == string(credential.SDJwtVC)
        },
    })
    if err != nil {
        return nil, err
    }

    log.Printf("Found %d matching entries (Total: %d)\n", len(entries), total)
    for _, entry := range entries {
        log.Printf(" - Entry ID: %s, MimeType: %s\n", entry.Entry.Id, entry.Entry.MimeType)
    }
    return entries, nil
}
```

## 4. Fetching Issuer Metadata

When receiving a credential, the wallet must access the issuer's `.well-known/openid-credential-issuer` endpoint to obtain the issuer's configuration (credential endpoint, supported credential configurations, and so on).

`ReceiveCredential` fetches this metadata implicitly, but you can also fetch it explicitly with `FetchCredentialIssuerMetadata` and pass the result via the `CachedIssuerMetadata` field of `ReceiveCredentialRequest`. This avoids re-fetching the metadata on every `ReceiveCredential` call.

```go
import (
    "log"
    "net/url"

    receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func fetchIssuerMetadata(w *wallet.Wallet) (*receiverTypes.CredentialIssuerMetadata, error) {
    // Note: pass the issuer's base URL; the /.well-known/... path is resolved internally
    issuerURL, _ := url.Parse("http://localhost:8080")

    metadata, err := w.FetchCredentialIssuerMetadata(issuerURL, receiverTypes.Oid4vci)
    if err != nil {
        return nil, err
    }

    log.Printf("Fetched metadata for issuer: %s\n", metadata.CredentialIssuer)
    // metadata.CredentialEndpoint, metadata.CredentialConfigurationSupported, ...
    return metadata, nil
}
```

## 5. Explanation of Type Definitions

This section explains the main Go type definitions used when interacting with the `Wallet` in the vcknots/wallet library.

### IKeyEntry {#IKeyEntry}

Core interface for key management. Defines three methods: `ID()`, `PublicKey()`, and `Sign()`. Library users implement this to integrate with HSMs, secure enclaves, and similar systems.

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### Config {#Config}

Input for `NewWalletWithConfig`. Holds the six dispatcher components and the optional DPoP configuration ([DPoPConfig](#DPoPConfig)). `nil` fields fall back to default implementations.

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### ReceiveCredentialRequest {#ReceiveCredentialRequest}

Main input for `ReceiveCredential`. Encapsulates the [CredentialOffer](#CredentialOffer), the receiving protocol (`Type`), the key used for proof signing ([IKeyEntry](#IKeyEntry)), the requested credential format (`RequestedFormat`), the optional `CachedIssuerMetadata`, and the optional `TxCode`.

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### CredentialOffer {#CredentialOffer}

Details of the offer received from the issuer. Includes the issuer URL (`CredentialIssuer`), the credential configuration IDs (`CredentialConfigurationIDs`), and the authorization grants (`Grants`).

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### SavedCredential {#SavedCredential}

A credential stored in the credential store. Wraps `*credential.Credential` (the parsed credential) and `*types.CredentialEntry` (storage metadata: ID, raw bytes, MIME type, received time). Returned by `ReceiveCredential`, `GetCredentialEntries`, and `GetCredentialEntry`.

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### GetCredentialEntriesRequest {#GetCredentialEntriesRequest}

Search conditions for `GetCredentialEntries`. Supports pagination (`Offset`, `Limit`) and dynamic filtering via a Go function (`Filter`).

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### PresentCredentialOptions {#PresentCredentialOptions}

Input for `PresentCredentialWithOptions`. Holds the format-specific `SerializeOptions` and an optional `OnRedirect` callback.

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### SdJwtVcPresentationOptions {#SdJwtVcPresentationOptions}

Options for SD-JWT VC presentations: `SelectedClaims`, `RequireKeyBinding`, `Audience`, `Nonce`, and `TransactionData`. Audience and nonce are filled from the OID4VP request automatically.

For the definition, see [wallet/serializer/plugins/sdjwtvc/sdjwtvc.go](https://github.com/trustknots/vcknots/blob/main/wallet/serializer/plugins/sdjwtvc/sdjwtvc.go).

### DIDCreateOptions {#DIDCreateOptions}

Options for `GenerateDID`. Specifies the DID type (`TypeID`, e.g. `"did:key"`) and the associated public key (`PublicKey`).

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### DPoPConfig {#DPoPConfig}

Enables DPoP proofs for the token and credential endpoints (`Enabled`), with an optional dedicated key (`Key`). When enabled without a key, an in-memory P-256 key is generated.

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

## 6. Methods of Wallet

### ReceiveCredential

Receives a credential from an issuer via OID4VCI (pre-authorized code flow) and stores it in the credential store.

```go
func (w *Wallet) ReceiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error)
```

**Parameters**:
- `req`: Receive request ([ReceiveCredentialRequest](#ReceiveCredentialRequest))

**Return value**:
- The received and stored credential ([SavedCredential](#SavedCredential))

### PresentCredential

Responds to an OID4VP authorization request and submits a Verifiable Presentation to the verifier.

```go
func (w *Wallet) PresentCredential(uriString string, key IKeyEntry, options serializerTypes.SerializePresentationOptions) (string, error)
```

**Parameters**:
- `uriString`: The OID4VP request URI (`openid4vp://authorize?...`)
- `key`: The key used to sign the presentation ([IKeyEntry](#IKeyEntry))
- `options`: Format-specific presentation options (for SD-JWT VC, [SdJwtVcPresentationOptions](#SdJwtVcPresentationOptions)); pass `nil` to use the defaults for the credential's format

**Return value**:
- The redirect URI provided by the verifier, or an empty string when there is none

### PresentCredentialWithOptions

Same as `PresentCredential`, and additionally invokes a callback when the verifier returns a redirect URI.

```go
func (w *Wallet) PresentCredentialWithOptions(uriString string, key IKeyEntry, options *PresentCredentialOptions) (string, error)
```

**Parameters**:
- `uriString`: The OID4VP request URI (`openid4vp://authorize?...`)
- `key`: The key used to sign the presentation ([IKeyEntry](#IKeyEntry))
- `options`: Serialization options and redirect callback ([PresentCredentialOptions](#PresentCredentialOptions))

**Return value**:
- The redirect URI provided by the verifier, or an empty string when there is none

### GetCredentialEntries

Retrieves stored credentials with optional pagination and filtering.

```go
func (w *Wallet) GetCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error)
```

**Parameters**:
- `req`: Search conditions ([GetCredentialEntriesRequest](#GetCredentialEntriesRequest))

**Return value**:
- The matching credentials ([SavedCredential](#SavedCredential)) and the total number of matches

### GetCredentialEntry

Retrieves a single stored credential by ID.

```go
func (w *Wallet) GetCredentialEntry(id string) (*SavedCredential, error)
```

**Parameters**:
- `id`: The credential entry ID

**Return value**:
- The stored credential ([SavedCredential](#SavedCredential)); with the default local store, an error is returned when the ID does not exist

### FetchCredentialIssuerMetadata

Fetches the issuer metadata from the issuer's `.well-known/openid-credential-issuer` endpoint.

```go
func (w *Wallet) FetchCredentialIssuerMetadata(endpoint *url.URL, receivingType receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error)
```

**Parameters**:
- `endpoint`: The issuer's base URL (the `/.well-known/...` path is resolved internally)
- `receivingType`: The receiving protocol (`receiver.Oid4vci`)

**Return value**:
- The issuer metadata (`receiverTypes.CredentialIssuerMetadata`)

### GenerateDID

Generates a DID from a public key.

```go
func (w *Wallet) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error)
```

**Parameters**:
- `options`: The DID type and public key ([DIDCreateOptions](#DIDCreateOptions))

**Return value**:
- The generated identity profile (`idprofTypes.IdentityProfile`)

## OpenID4VCI 1.0 issuance (Final / HAIP)

The Final issuance path is the authorization-code flow. `ReceiveCredential` remains the pre-authorized code path and also serves the Draft 13 entry point.

### Pre-authorized code

`ReceiveCredential` resolves the credential offer, fetches the issuer and authorization server metadata, obtains an access token with the pre-authorized code, signs the JWT proof with `Key`, requests the credential and stores it. This is the flow shown in section 3-2 and the simplest way to integrate. A credential offer may be passed by value (`credential_offer`) or by reference (`credential_offer_uri`) through `ResolveCredentialOffer` / `ResolveCredentialOfferContext`.

### Authorization code with browser delegation

The authorization endpoint needs a system browser, so the flow is split in two:

```go
authorization, err := w.BeginOID4VCIFinalAuthorization(ctx, request)
// Open authorization.AuthorizationURL in the system browser.
// authorization is JSON-serialisable and survives a process restart.
result, err := w.ResumeOID4VCIFinalAuthorization(ctx, request, authorization, redirectURLFromBrowser)
```

`BeginOID4VCIFinalAuthorization` performs everything before the user agent is involved: metadata discovery, credential configuration validation, and the RFC 9126 Pushed Authorization Request when the authorization server advertises one. `ResumeOID4VCIFinalAuthorization` validates the RFC 6749 / RFC 9207 authorization response against the persisted state, exchanges the code at the token endpoint and performs the credential request.

A test or conformance issuer that answers the authorization endpoint with the code redirect and needs no user interaction can be driven in one call by setting `AllowSelfDrivenAuthorization` and calling `ReceiveOID4VCIFinalCredentialContext`. A wallet with a user must not set it; the default is `false` and `ReceiveOID4VCIFinalCredential` refuses without it.

Wallet-initiated issuance is supported: with `CredentialOffer` nil, set `CredentialIssuer` and `CredentialConfigurationID` (both required) to start the same flow without an offer.

`AuthorizationRequestType` selects how the credential configuration is requested: the empty value uses `scope` when the configuration advertises one and `authorization_details` otherwise; `"scope"` requires an advertised scope; `"authorization_details"` sends an `openid_credential` authorization detail. Under HAIP only `scope` is accepted.

### Deferred issuance

`DeferredPollAttempts` bounds the number of §9 deferred credential polls. A zero value does not poll and returns a pending result carrying the `transaction_id` and access token. `ResumeOID4VCIFinalDeferredCredential` resumes polling, optionally from `IssuerURL` when `IssuerMetadata` is nil. The issuer-named interval is capped at 60 seconds unless `MaxDeferredInterval` overrides it, and the `…Context` variants can cancel the wait. The deferred request repeats `credential_response_encryption`.

### Notifications

After storage succeeds, the wallet sends `credential_accepted`; on verification or storage failure it sends `credential_failure`. `NotifyOID4VCIFinalCredentialDeleted` sends `credential_deleted` for a credential removed from storage. The wallet only sends an event when the issuer advertised a notification endpoint and returned a `notification_id`.

### Credential response encryption

Set `OID4VCIFinalReceiveRequest.CredentialResponseEncryptionKey` to a public JWK to request an encrypted credential response (OpenID4VCI 1.0 §8.2: `jwk`, `enc`, optional `zip`, no `alg`). When the issuer requires encryption and no key is supplied, the flow fails closed, and a plaintext response after encryption was requested is rejected.

### Attestation providers

The library never holds the attester's private key. `Config.ClientAttestation` (`ClientAttestationProvider`) and `Config.KeyAttestation` (`KeyAttestationProvider`) let the caller obtain attestations from a remote attester:

* `ClientAttestationProvider` is called once per issuance with the selected authorization server identifier and must return a compact JWS with typ `oauth-client-attestation+jwt`, `sub` = `ClientID` and `cnf.jwk` = the wallet instance key.
* `KeyAttestationProvider` is called with the holder keys and `c_nonce` and must return a `key-attestation+jwt` whose `attested_keys` contain every holder key.

Before use the wallet validates the provider result without verifying the attester signature: `typ`, `sub`, RFC 7638 `cnf.jwk` thumbprint and future `exp`. Under HAIP the header must also carry a non-self-signed `x5c` leaf. `StaticClientAttester` and `StaticKeyAttester` self-issue for tests and single-operator deployments only; the deprecated `OID4VCIFinalReceiveRequest.AttesterKey` / `AttesterIssuer` fallback wraps a static attester for one request.

### Transport and signer

A receiver plugin implements `receiverTypes.Receiver` for the Draft 13 flow and `receiverTypes.OID4VCIFinalTransport` for Final / HAIP. The transport contract is HTTP only, so a plugin never holds the wallet's private keys. Those keys are used behind `receiverTypes.OID4VCIFinalSigner` (`CreateDpopProof`, `CreateCredentialRequestJWTProofWithOptions`, `CreateClientAttestationPop`). `Config.OID4VCISigner` selects the implementation, so a wallet can sign in a hardware module or a remote signing service and still use the bundled transport. `receiverTypes.OID4VCIFinalReceiver` is the deprecated union of the two and is kept for source compatibility.

### Signed issuer metadata

`Oid4vciReceiver.IssuerMetadataSigning` configures OpenID4VCI 1.0 §12.2.3 signed credential issuer metadata. `Request` sends the signed-metadata `Accept` header and has no effect without trust material; `Require` rejects an unsigned `application/json` response. The `Oid4vciReceiver` and the wallet's default HTTP client refuse HTTP redirects (`ErrHTTPRedirectNotAllowed`); `NoRedirectClient` wraps a caller-supplied client the same way.

## Credential acceptance

`Config.CredentialAcceptance` (`CredentialAcceptancePolicy`) decides whether a received credential may be stored. The Final and HAIP issuance paths require a policy: a nil policy is a fail-closed `ErrCredentialAcceptancePolicyRequired`. The Draft 13 `ReceiveCredential` path keeps the policy optional.

Before storage the library verifies:

* **Parse and algorithm.** The credential must parse, the issuer JWT must carry a supported `alg` and, for SD-JWT VC, a `dc+sd-jwt` / `vc+sd-jwt` `typ`, and a `cnf.jwk` that does not match the holder key used for the proof is rejected.
* **Issuer trust.** `IssuerX509` verifies the `x5c` chain with the shared signing-chain and CRL primitives. `ResolveIssuerKeys` supplies candidate public keys when the credential has no usable `x5c` (JWKS, DID or a static registry). When `IssuerX509` is not configured, `ResolveIssuerKeys` is used even for credentials that carry `x5c`. A credential with `x5c` and neither mechanism configured is rejected.
* **Holder binding.** `RequireHolderBinding` rejects a credential without a `cnf` claim.
* **Validity and disclosures.** With a policy, the signature, `exp` / `nbf` and SD-JWT disclosure integrity (every disclosure referenced exactly once by an `_sd` or `...` digest) are also checked.

`SavedCredential.Verification` (`CredentialVerification`) records the issuer key id, certificate fingerprints, revocation counters and holder-binding outcome.

### Fail-closed defaults and the `UnverifiedIssuer` opt-out

* No `CredentialAcceptance` policy on the Final / HAIP paths: nothing is stored (`ErrCredentialAcceptancePolicyRequired`).
* An `x5c` credential with no configured issuer trust mechanism other than `ResolveIssuerKeys` / `IssuerX509`: rejected.
* `UnverifiedIssuer: true` stores a credential without authenticating the issuer key. It only takes effect when neither `IssuerX509` nor `ResolveIssuerKeys` is configured, and the other checks (holder binding, `exp` / `nbf`, disclosure integrity) still apply. Set it deliberately so an unauthenticated-issuer deployment says so in one place.
* `AllowUnadvertisedRevocation` keeps certificates without published CRL / OCSP information on the trust path and reports them separately, never as positively checked. OCSP is not implemented; only CRLs are consulted.

`IssuerX509TrustOptions.RequireIssuerDNSBinding` is an ecosystem policy (not an SD-JWT VC §3.5 requirement): when `iss` is an `https` URL, the leaf certificate must carry a `dNSName` SAN equal to its host.

## OpenID4VP 1.0 presentation (Final / HAIP)

`PresentCredential` parses the request, authenticates any signed Request Object, selects credentials that satisfy the DCQL query, serializes and signs the Verifiable Presentation and posts it to the verifier. `PresentCredentialWithOptions` adds an `OnRedirect` callback.

### Request Object authentication

Signed Request Objects are authenticated against caller-configured X.509 trust through `RequestObjectValidation` (`RequestObjectValidationOptions`):

* `TrustAnchors` or `RootCAs` carry the anchors (configure exactly one).
* `x509_san_dns` binds the leaf certificate's DNS SAN and the `response_uri` (`direct_post` modes) or `redirect_uri`; `x509_hash` binds the leaf certificate hash and implies no DNS binding. Both require a signed Request Object and are resolved through `X509TrustChainRoots` / `RequestObjectValidation`.
* `redirect_uri:<uri>` binds the response endpoint to the client identifier, and a colon-less identifier is treated as a pre-registered client (OpenID4VP §5.9.2). Register pre-registered verifiers in `Oid4vpPresenter.PreRegisteredClients` or `ResolvePreRegisteredClient`; an unresolvable one is rejected with `ErrPreRegisteredClientUnknown`. The request's own `client_metadata` is not authoritative for a pre-registered client.
* `RequireExpiry` rejects a Request Object without `exp`; `MaxAge` bounds its lifetime (`exp - iat`, or `exp - now` when `iat` is absent). Final keeps the permissive default; the HAIP profile turns `RequireExpiry` on and applies a 10-minute `MaxAge` when the caller leaves it zero.
* The verification outcome is exposed only in `CredentialPresentationRequest.RequestObjectVerification` and is never read from request data. It records the client id, certificate SHA-256 fingerprints, revocation counters, the echoed `WalletNonce`, the observed `Delivery` (`"reference"`, `"value"` or `"query"`) and `DeliveryAttested`.

An application that fetched a signed Request Object through `request_uri` at admission time and later re-submits it by value can attest this with `RequestObjectValidationOptions.DeliveredByReference`, which satisfies the HAIP §5.1 delivery check for that request only. Set it only when the application's own admission path recorded the fetch.

### DCQL

`ParsePresentationRequest` and `ResolveSatisfiableDCQLCredentials` evaluate `credential_sets` with `options` and `required`, `claims` / `claim_sets` / `values`, nested and array claim paths (OpenID4VP §7), `trusted_authorities` (`aki` only) and `multiple`. All required queries must be satisfiable before any response is sent; a query no stored credential can satisfy returns `AuthorizationRequestError{Code: AccessDeniedError}`. Credentials that do not support holder binding are excluded from a query that requires it.

### `transaction_data`

`Config.SupportedTransactionDataTypes` lists the `transaction_data` `type` values the application understands. Each object must be base64url-encoded JSON with known `credential_ids`; the hash is bound into the KB-JWT. The hash algorithm is selected per object from its `transaction_data_hashes_alg` array (`sha-256`, `sha-384`, `sha-512`), defaulting to `sha-256`; conflicting algorithms across objects are rejected. With an empty list every `transaction_data` request is rejected with `invalid_transaction_data`.

### Response encryption

`direct_post.jwt` uses ECDH-ES with a P-256 key and A128GCM or A256GCM. When both are supported the wallet prefers A256GCM (HAIP §5.2). Encryption keys in `client_metadata.jwks` must carry `alg`; keys without it are skipped. Error responses are encrypted when the verifier metadata allows and otherwise sent in plaintext as the §8.3.1 fallback.

### Digital Credentials API

`PresentCredentialToDCAPI` answers a W3C Digital Credentials API invocation. `ParseDCAPIRequest` accepts `openid4vp-v1-unsigned`, `openid4vp-v1-signed` and `openid4vp-v1-multisigned`; the caller supplies the platform-authenticated `origin`, which is never read from the request data. The response is returned by `BuildDCAPIResponse`: `{"vp_token": {...}}` for `dc_api`, or a compact JWE for `dc_api.jwt`. The Key Binding JWT `aud` is `origin:<origin>` (OID4VP 1.0 Appendix A.4). The library makes no browser or OS integration and no HTTP call in this path.

## Environment variables

The wallet runtime behaviour is controlled by environment variables defined in `wallet/env/env.go`.

| Variable | Default | Description |
| :---- | :---- | :---- |
| `VCKNOTS_WALLET_HTTP_ALLOWED` | `false` (unset/empty) | When set to `true`, HTTP endpoints are allowed for wallet HTTP calls (local development/testing only). This is the only variable that relaxes the HTTPS requirement. A client assertion is the exception: it is sent over plain HTTP only to a loopback host, so `private_key_jwt` against a remote `http://` endpoint is refused even with this set. Rejected under HAIP. |
| `VCKNOTS_WALLET_DEBUG` | `false` (unset/empty) | Enables debug logging only. It does **not** relax the HTTPS requirement. |

`IsHTTPAllowed()` is `true` only when `VCKNOTS_WALLET_HTTP_ALLOWED=true`. Call `env.SetHTTPAllowed(true)` to set it from test code, or `env.SetDebugMode(true)` for logging.

## Migration notes for existing users

* **Redirects are refused.** The OID4VCI receiver and the wallet's default HTTP client reject every redirect (`ErrHTTPRedirectNotAllowed`); a 307/308 would replay the request body with the Authorization, DPoP and attestation headers against an origin the response chose. Callers that relied on following redirects must stop.
* **HTTP allowance is explicit.** Built-in dispatchers snapshot the environment's HTTP allowance when constructed. Set `VCKNOTS_WALLET_HTTP_ALLOWED` (or the plugin's `AllowHTTP` / `WithHTTPAllowed`) before constructing the wallet. Previously `VCKNOTS_WALLET_DEBUG` also relaxed HTTPS; that is no longer true, and `IsHTTPAllowed` is the single source of the policy.
* **Final Request Objects are authenticated.** `ParsePresentationRequest` and `NewRequestBuilder` now follow the Final path and authenticate signed Request Objects for `x509_san_dns` and `x509_hash`, with `aud` / `exp` / `nbf`, an optional EKU and CRL policy. Plain query-parameter requests that use an X.509 prefix are rejected. `InsecureSkipX509Verify` no longer applies to the Final path; configure explicit anchors instead. The Draft 24 entry points keep the old behaviour.
* **`response_uri` is bound to the client identifier.** For `direct_post` modes the `response_uri` must match what `x509_san_dns` or `redirect_uri` derives; `redirect_uri` and `response_uri` are mutually exclusive. `redirect_uri` must be absent in the DC API modes.
* **Pre-registered clients need a registry.** A colon-less `client_id` is no longer a format error; it is a pre-registered client that must be present in `PreRegisteredClients` / `ResolvePreRegisteredClient`, otherwise the request is rejected.
* **Response encryption prefers A256GCM.** When the verifier lists both, the wallet uses A256GCM; the per-object `transaction_data_hashes_alg` replaces the former top-level parameter (Appendix B.3.3.1).
* **HAIP tightens Request Object validity.** HAIP requires `exp` and applies a 10-minute `MaxAge` by default; the permissive Final defaults are unchanged.
* **The receiver contract is split.** `receiverTypes.OID4VCIFinalReceiver` is deprecated in favour of `OID4VCIFinalTransport` + `OID4VCIFinalSigner`. Existing implementations and callers keep compiling through the compound alias; five signing methods moved to `OID4VCIFinalSigner` (see `wallet/API-MIGRATION.md`).
* **Credential acceptance is mandatory on the Final path.** Configure `Config.CredentialAcceptance`; a nil policy is a fail-closed error. `UnverifiedIssuer` preserves the old permissive store for unauthenticated test issuers. `VerifyCredential` now returns true only on success.

## Draft 13 / Draft 24 legacy entry points (still supported)

The earlier profiles remain available and keep their historical behaviour, including `InsecureSkipX509Verify` and ignoring the Final / HAIP profile:

* Draft 13 receiving: `ReceiveCredential`.
* Draft 24 presenting: `Wallet.PresentDraft24Credential`, `Oid4vpPresenter.ParseDraft24PresentationRequest`, `NewDraft24RequestBuilder`, `PresentDraft24`.
* `ParseDraft24PresentationRequest` supports Presentation Exchange and DCQL request syntax; `PresentDraft24` submits a Presentation Exchange response. The Final path rejects Presentation Exchange parameters.

New integrations should use the Final entry points described above and select HAIP with `profile.HAIP` only when HAIP 1.0 is required.

## 7. Notes

1. **Mock key entries must not be used in production (CRITICAL):**
    - The in-memory key implementation shown in this tutorial (and `MockKeyEntry` in `wallet/examples/common/`) is intended only for testing and demonstration, because it keeps the private key in plaintext on the Go heap.
    - In a production environment, implement `IKeyEntry` so that the `Sign` operation is delegated to an OS keystore (iOS Secure Enclave, Android Keystore) or an HSM, and the private key itself is never loaded into the application's memory space (non-exportable).

2. **GOPRIVATE configuration:**
    - If `go mod download` or `go build` fails, the most likely cause is a missing GOPRIVATE environment variable.

3. **Signature format compatibility:**
    - `Sign` may return either DER-encoded ASN.1 or raw IEEE P1363 signatures for ES256; the library normalizes DER to P1363 before embedding signatures in JWS structures.

4. **Persistent storage (bbolt):**
    - `credstore.WithDefaultConfig()` persists credentials with `go.etcd.io/bbolt` to `<user config dir>/vcknots/wallet/.local_credstore.db`. Make sure the process can create and write to this directory.

5. **HTTPS enforcement and runtime environment variables (`wallet/env/env.go`):**
    - The wallet requires HTTPS for issuer and verifier endpoints by default.
    - `VCKNOTS_WALLET_HTTP_ALLOWED=true` allows HTTP endpoints and is the only variable that relaxes HTTPS (intended for local development/testing only).
    - `VCKNOTS_WALLET_DEBUG=true` enables debug logging only; it does not relax the HTTPS requirement.
    - **Production guidance:** keep both variables unset (or `false`) so HTTPS-only validation remains active.

6. **Strict validation of OpenID4VP `client_id`:**
    - The wallet validates `client_id` strictly, in line with the OpenID4VP conformance tests. Duplicate prefixes (for example, `x509_san_dns:x509_san_dns:...`) and malformed values are rejected.
    - For the `x509_san_dns:` scheme, the certificate is extracted from the `x5c` header of the request JWT, and the Subject Alternative Name (SAN) DNS field of the certificate is matched against the `client_id` value.
    - See `wallet/presenter/plugins/oid4vp/` for the validation logic.

7. **Test configuration for certificate validation (`InsecureSkipX509Verify`):**
    - The `Oid4vpPresenter` struct provides the `InsecureSkipX509Verify` option for test environments.
    - **Default behavior (production):** full certificate chain validation is performed against `X509TrustChainRoots`.
    - **Test configuration (`InsecureSkipX509Verify: true`):** skips certificate chain validation and extracts the certificate directly from the `x5c` header; only SAN-to-`client_id` matching is performed.
    - ⚠️ **Critical warning:** use `InsecureSkipX509Verify: true` only for conformance testing or local development. **Never** use this in production.

8. **DPoP support (optional):**
    - Setting `wallet.Config{DPoP: wallet.DPoPConfig{Enabled: true}}` makes the wallet attach DPoP proofs to token and credential requests, and handle DPoP nonce challenges from the server.

## 8. Troubleshooting

* **Q: `go mod download` fails with `package ... is private` or `404 Not Found`.**
  * **A:** The GOPRIVATE environment variable is not configured. Go back to "1. Prerequisites" and make sure `export GOPRIVATE="github.com/trustknots/vcknots/wallet"` has been executed (or use mise).

* **Q: `ReceiveCredential` or `PresentCredential` fails with `connection refused` or `timeout`.**
  * **A:** The Issuer/Verifier server is not running. Follow "1. Prerequisites", start the server with `pnpm -F @trustknots/server start`, and confirm that http://localhost:8080 responds.

* **Q: `ReceiveCredential` fails with `credential issuer must use https scheme`.**
  * **A:** The wallet enforces HTTPS by default. For local testing against the HTTP sample server, set `VCKNOTS_WALLET_HTTP_ALLOWED=true` (or call `env.SetHTTPAllowed(true)`).

* **Q: `ReceiveCredential` fails with `failed to fetch issuer metadata`.**
  * **A:** The server may be running, but the `/.well-known/openid-credential-issuer` endpoint might not be functioning. Run `curl http://localhost:8080/.well-known/openid-credential-issuer` and confirm that JSON metadata is returned.

* **Q: A `client_id` validation error occurs during OpenID4VP conformance testing.**
  * **A:** Conformance tests intentionally send malformed `client_id` values (such as duplicate prefixes) to test the wallet's validation logic. Errors like `invalid client_id: duplicate prefix detected` or `SAN of the certificate and client_id did not match` are **expected behavior** and indicate that the wallet is correctly enforcing its security checks.

* **Q: An `x509: certificate is not standards compliant` error occurs during OpenID4VP conformance testing.**
  * **A:** Conformance test servers may use self-signed or non-standard certificates. Set `InsecureSkipX509Verify: true` only in test environments:
    ```go
    p := &oid4vp.Oid4vpPresenter{
        X509TrustChainRoots:    systemRoots,
        InsecureSkipX509Verify: true, // Test environments only
    }
    ```
  * ⚠️ **Warning:** always leave this `false` (or unset) in production.

For runnable end-to-end samples (JWT-VC, SD-JWT VC, and SD-JWT VC with KB-JWT), see [wallet/examples/README.md](https://github.com/trustknots/vcknots/blob/main/wallet/examples/README.md).
