# Public Wallet API driver

This independent Go module calls the public Wallet APIs. It accepts one JSON
operation on stdin and returns one JSON result on stdout. A protocol error exits
with code 1; invalid command/configuration input exits with code 2.

The driver supports an initial SD-JWT VC pre-authorized issuance path, persistent
credential listing, and the public presentation method. It does not claim full
Final/HAIP support. In particular, successful issuance does not prove issuer
authentication before storage, and current presentation defaults still need
conformance fixes. Code flow, mdoc, platform DC API, real attestation and protected
key providers are subsequent work. This software-JWK configuration makes no
hardware protection claim.

## Configure and run

Use Go 1.26.6 for the repository validation environment. From this directory:

```sh
go build -o official_driver .
```

Provide separate EC signing JWK files for the holder, DPoP and client keys.
The key files must contain private components, and the client public JWK must be
registered with the issuer. Do not use production keys for tests. Use explicit
absolute paths in the configuration:

```json
{
  "stateDirectory": "/path/to/isolated-wallet-state",
  "tlsCAFiles": ["/path/to/test-transport-ca.pem"],
  "verifierCAFiles": ["/path/to/verifier-trust-anchor.pem"],
  "holderKeyFile": "/path/to/holder.jwk",
  "dpopKeyFile": "/path/to/dpop.jwk",
  "clientKeyFile": "/path/to/client.jwk",
  "clientId": "registered-wallet-client"
}
```

Transport verification uses system roots plus `tlsCAFiles`. Verifier certificate
policy receives only `verifierCAFiles`. The example does not disable TLS or X.509
checks; the library remains responsible for enforcing each protocol's trust
requirements. Credentials use the library's bbolt local storage plugin.

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

Each invocation is a new process, so listing and presenting use the persisted
credential. Use the issuer/verifier's complete launch URI unchanged. The driver
does not repair queries, issue its own credentials, retry protocol failures, or
construct presentation responses. A returned redirect URI is handed to the
orchestrating browser; this command does not create a substitute browser session.

## 日本語

この独立moduleは公開Wallet APIへ操作を委譲します。
設定に鍵・信頼する証明書・保存先を明示し、上記のJSONを標準入力から渡してください。
`public-keys`で登録用公開鍵を取得し、`receive-preauth`で受領後、別プロセスの`list`で保存を確認できます。
`present`は保存済みcredentialを使う公開APIの動作をそのまま返します。
URIの補正、独自の再試行、認証の補完、提示専用seedは行いません。
現在は最初の試験経路を構築するためのdriverで、Final/HAIP全体の適合を示すものではありません。
software JWKの試験設定を実attestationやハードウェア保護の実証とは扱いません。
