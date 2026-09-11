# Public Wallet API driver

This independent Go module calls the public Wallet APIs. It accepts one JSON
operation on stdin and returns one JSON result on stdout. A protocol error exits
with code 1; invalid command/configuration input exits with code 2.

The driver supports an initial SD-JWT VC pre-authorized issuance path, persistent
credential listing, and the public presentation method. Code flow, mdoc, platform
DC API, real attestation and protected key providers are subsequent work. This
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
| `followRedirect` | bool | `true` | When true (or absent), `present` opens a returned `redirect_uri` like a same-device browser: HTTP GET with the TLS-configured client, `Accept: text/html,*/*`, `User-Agent: official_driver`, a 15 s timeout, and at most 5 followed redirects. Set `false` to return the URI without opening it. |

`wallet.Config.CredentialAcceptance` is built only when at least one of
`issuerCAFiles`, `issuerJWKSFiles` or `requireHolderBinding` is set. When all are
omitted the policy is nil and only the library's minimum rules apply (credential
must parse, and a `cnf` that does not match the holder key is rejected).

The TLS-configured HTTP client is passed as `IssuerX509TrustOptions.HTTPClient`
and as `RequestObjectValidationOptions.CRL.HTTPClient`, so CRL fetches honour
`tlsCAFiles`. Unknown profile values and inconsistent options (for example an
`*AllowUnadvertisedRevocation` flag without its CA files, or `walletAudience`
without `verifierCAFiles`) are rejected at compose time before any operation runs.

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
  "clientId": "registered-wallet-client"
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
{"operation":"list"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"present","uri":"openid4vp://?client_id=...&request_uri=..."}
JSON
```

`receive-preauth` returns the saved `credentialId` plus the library's
`verification` record for that credential. `present` returns `redirectUri` plus
`redirectFollowed` (whether the driver opened it) and `redirectStatus` (the final
HTTP status, `0` when not opened). `list` returns `credentialIds` and `total`.
Existing fields keep their names.

Each invocation is a new process, so listing and presenting use the persisted
credential. Use the issuer/verifier's complete launch URI unchanged. The driver
does not repair queries, issue its own credentials, retry protocol failures, or
construct presentation responses. When `followRedirect` is enabled and the
verifier returns a `redirect_uri`, the driver opens it as the same-device browser
would (HAIP §5.1, OpenID4VP §8.2); the fragment is never transmitted. A non-2xx/3xx
final status is reported as an error naming the status.

## 日本語

この独立moduleは公開Wallet APIへ操作を委譲します。
設定に鍵・信頼する証明書・保存先を明示し、上記のJSONを標準入力から渡してください。
`profile`でFinal/HAIPの方針を選び、`verifierCAFiles`と`issuerCAFiles`で検証者・発行者の信頼基点、
`issuerJWKSFiles`でx5cの無いcredential向け公開鍵を指定します。
`verifierCAFiles`を省略するとX.509 Request Objectは検証されず拒否され（fail-closed）、
発行者鍵の指定をすべて省略するとlibrary最小限の受理規則だけが適用されます。
`public-keys`で登録用公開鍵を取得し、`receive-preauth`で受領後、別プロセスの`list`で保存を確認できます。
`present`は保存済みcredentialを使う公開APIの動作をそのまま返します。
`followRedirect`が有効（既定は有効）で`redirect_uri`が返ると、same-deviceブラウザと同様に
TLS設定済みclientでGETし最大5回のリダイレクトを追跡します（fragmentは送信しません）。
URIの補正、独自の再試行、認証の補完、提示専用seedは行いません。
software JWKの試験設定を実attestationやハードウェア保護の実証とは扱いません。
