# 公開 Wallet API driver

この独立した Go module は公開 Wallet API を呼び出します。stdin から 1 つの JSON
操作を受け取り、stdout へ 1 つの JSON 結果を返します。protocol error は exit code
1、不正な command / 設定入力は exit code 2 で終了します。

この driver は、SD-JWT VC の pre-authorized 発行経路、OpenID4VCI 1.0 Final の
authorization code フロー、永続化された credential の一覧、公開 presentation
メソッド、W3C Digital Credentials API 上の OpenID4VP 1.0 に対応します。mdoc と
remote attestation provider は後続の作業です。この software JWK の設定は
ハードウェア保護を主張しません。

## 設定と実行

リポジトリの検証環境には Go 1.26.6 を使用します。このディレクトリから実行します。

```sh
go build -o official_driver .
```

holder、DPoP、client 用に別々の EC 署名 JWK ファイルを用意します。鍵ファイルには
秘密成分を含める必要があり、client の公開 JWK は issuer に登録しておく必要が
あります。テストに本番鍵を使わないでください。設定には絶対パスを使用します。

### 設定フィールド

| フィールド | 型 | 既定値 | 効果 |
| --- | --- | --- | --- |
| `stateDirectory` | string | 必須 | bbolt credential store のディレクトリ。 |
| `clientId` | string | 必須 | issuer token endpoint で使う OAuth2 `client_id`。 |
| `holderKeyFile` | string | 必須 | credential holder 鍵として使う秘密 JWK。 |
| `dpopKeyFile` | string | 必須 | DPoP proof に使う秘密 JWK。 |
| `clientKeyFile` | string | 必須 | `private_key_jwt` クライアント認証に使う秘密 JWK。 |
| `tlsCAFiles` | []string | `[]` | TLS のシステムルートに追加する PEM ルート。CRL 取得（issuer と Request Object）にも使います。 |
| `profile` | string | `""` | protocol policy: `""`/`"final"`/`"haip"` → `profile.Profile`。`wallet.Config.Profile` と構築する両 plugin に適用し、一致している必要があります。未知の値は拒否します。 |
| `verifierCAFiles` | []string | `[]` | 署名付き Request Object の PEM trust anchor → `RequestObjectValidation.TrustAnchors`。すべての CERTIFICATE ブロックを parse し、無いファイルは拒否します。空の場合 `RequestObjectValidation` は nil のままで、X.509 Request Object を拒否します（fail-closed）。 |
| `verifierAllowUnadvertisedRevocation` | bool | `false` | → `RequestObjectValidation.AllowUnadvertisedRevocation`。`verifierCAFiles` が必要です。 |
| `walletAudience` | []string | `[]` | → `RequestObjectValidation.WalletAudience`。`verifierCAFiles` が必要です。 |
| `issuerCAFiles` | []string | `[]` | credential の `x5c` チェーン用 PEM issuer trust anchor → `IssuerX509TrustOptions.TrustAnchors`。parse と拒否の規則は `verifierCAFiles` と同じです。 |
| `issuerAllowUnadvertisedRevocation` | bool | `false` | → `IssuerX509TrustOptions.AllowUnadvertisedRevocation`。`issuerCAFiles` が必要です。 |
| `issuerJWKSFiles` | []string | `[]` | `x5c` ヘッダを持たない credential 用の公開 issuer 鍵の JWKS ファイル（`{"keys":[...]}`）。空でない場合 `CredentialAcceptancePolicy.ResolveIssuerKeys` を設定し、operator が選んだすべての鍵を返します。library は `kid` で照合します。秘密鍵は拒否します。 |
| `requireHolderBinding` | bool | `false` | → `CredentialAcceptancePolicy.RequireHolderBinding`。`cnf` の無い credential を拒否します。 |
| `redirectUri` | string | `""` | authorization code フローの Wallet 登録済み redirect URI。`receive-code` と `receive-code-wallet-initiated` で必須です。 |
| `authorizationRequestType` | string | `""` | → `OID4VCIFinalReceiveRequest.AuthorizationRequestType`。`receive-code`/`receive-code-wallet-initiated` が Credential Configuration を要求する方法を選びます（OpenID4VCI 1.0 §5.1.1/§5.1.2）。`""` は configuration が広告する scope があれば `scope`、無ければ `authorization_details` を使います。`"scope"` は広告された scope を必須とし（無ければ PAR 前にエラー）、`"authorization_details"` は `[{"type":"openid_credential","credential_configuration_id":...}]` を送り scope を付けません。HAIP では `scope` のみを受け付けます（HAIP §4.1/§4.2 が `scope` での Credential Type 伝達を要求するため、明示的な `"authorization_details"` は拒否します）。 |
| `attesterKeyFile` | string | `""` | テスト専用 `wallet.StaticClientAttester` の秘密 JWK → `wallet.Config.ClientAttestation`。`attesterIssuer` と同時に設定が必要です。JWK の `x5c` チェーンがあれば client attestation の header チェーンになります。 |
| `attesterIssuer` | string | `""` | static client attester の `iss`。`attesterKeyFile` と同時に設定が必要です。 |
| `keyAttesterKeyFile` | string | `""` | テスト専用 `wallet.StaticKeyAttester` の秘密 JWK → `wallet.Config.KeyAttestation`。`keyAttesterIssuer` と同時に設定が必要です。 |
| `keyAttesterIssuer` | string | `""` | static key attester の `iss`。`keyAttesterKeyFile` と同時に設定が必要です。 |
| `includeKeyAttestation` | bool | `false` | → `OID4VCIFinalReceiveRequest.IncludeKeyAttestation`。issuer が要求しなくても OpenID4VCI Appendix D の key attestation を要求します。 |
| `deferredPollAttempts` | int | `10` | → `OID4VCIFinalReceiveRequest.DeferredPollAttempts`。0 以下は既定の 10 を選びます。 |
| `credentialResponseEncryption` | bool | `false` | true のとき authorization code 操作は実行ごとに一時 P-256 鍵を生成し、`CredentialResponseEncryptionKey` として渡すので issuer が credential 応答を暗号化します。 |
| `followRedirect` | bool | `true` | true（または未指定）のとき、`present` が返した `redirect_uri` を same-device ブラウザのように開きます。TLS 設定済み client で HTTP GET、`Accept: text/html,*/*`、`User-Agent: official_driver`、15 秒 timeout、最大 5 回の redirect 追跡です。false にすると URI を開かずに返します。 |

`wallet.Config.CredentialAcceptance` は常に設定します。OpenID4VCI 1.0 Final / HAIP
の発行経路は policy 無しでは credential を保存しないためです。`issuerCAFiles` か
`issuerJWKSFiles` がある場合、policy は issuer 鍵を認証します。どちらも無い場合、
driver は `CredentialAcceptancePolicy.UnverifiedIssuer` を設定するので、任意の
テスト issuer に対する実行はそのまま動き、そのことを 1 か所で明示します。
`requireHolderBinding` はどちらの場合にも適用されます。

TLS 設定済み HTTP client は `IssuerX509TrustOptions.HTTPClient` と
`RequestObjectValidationOptions.CRL.HTTPClient` に渡すので、CRL 取得も
`tlsCAFiles` を尊重します。未知の profile 値や不整合なオプション（CA ファイルを
伴わない `*AllowUnadvertisedRevocation` フラグ、`verifierCAFiles` 無しの
`walletAudience` など）は、操作が走る前に compose 時に拒否します。attester 鍵と
その issuer、key-attester 鍵とその issuer はそれぞれ同時に設定が必要で、
`redirectUri` 無しの `receive-code` は拒否します。

`StaticClientAttester` と `StaticKeyAttester` は、ローカルに保持した attester 鍵で
attestation を自己発行します。これはテストと単独運用者専用です。静的 attester は
テスト専用の evidence であり、本番 attestation として扱ってはいけません。本番では
Wallet が attester の秘密鍵を持たず、remote attester から attestation を取得する
分割に従います。

設定例:

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

Transport の検証にはシステムルートと `tlsCAFiles` を使います。この例は TLS や
X.509 検証を無効化しません。各プロトコルの trust 要件を強制するのは library の
責務のままです。credential は library の bbolt ローカルストレージ plugin を使います。

### 操作と出力

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

`receive-preauth` は保存した `credentialId` と、その credential の library
`verification` レコードを返します。`receive-code` は offer URI から OpenID4VCI 1.0
Final authorization code フローを実行し（`credential_offer_uri` は解決されます）、
`clientId`、`redirectUri`、`holderKeyFile`、`clientKeyFile` を使い、`credentialIds`、
credential 順の `verification` 配列、`notificationId`、`transactionId` を返します。
issuer が deferred ポーリング後も pending のままなら `pending` が `true` です。driver は
`OID4VCIFinalReceiveRequest.AllowSelfDrivenAuthorization` を設定するので、library が
authorization endpoint 自体を駆動します。同じ TLS client が redirect を追わずに取得し、
302 `code` 応答を期待します。ここにブラウザエミュレーションは追加しません。ユーザーの
いる Wallet は逆に、`BeginOID4VCIFinalAuthorization` を呼び、返された
`authorization_url` をシステムブラウザで開き、redirect を
`ResumeOID4VCIFinalAuthorization` へ渡します。`present` は `redirectUri` と
`redirectFollowed`（driver が開いたか）、`redirectStatus`（最後の HTTP status、開かない
場合は `0`）を返します。`list` は `credentialIds` と `total` を返します。既存の
フィールド名は維持します。`receive-code` の protocol error はそのまま伝播し、driver は
再試行も修復もしません。

`receive-code-wallet-initiated` は Credential Offer 無しで同じ OpenID4VCI 1.0
authorization code フローを実行します（OpenID4VCI 1.0 §5: "The Wallet can also start
the issuance without a Credential Offer"）。`uri` の代わりに `credentialIssuer` と
`credentialConfigurationId` を取り、Credential Issuer metadata を自身で取得し、その
Credential Configuration を `scope` または `authorization_details` で要求し
（§5.1.1/§5.1.2）、`issuer_state` を送りません。出力は `pending` を含め `receive-code`
と同じです。

`present-dcapi` は launch URI の代わりに W3C Digital Credentials API の invocation に
応答します。`dcapiRequest` は platform request の entry（`protocol` とプロトコルの
`data` object）で、`origin` は platform が認証した呼出し元 origin です。origin は
`data` からは読みません。3 種すべてを受け付けます: `openid4vp-v1-unsigned`、
`openid4vp-v1-signed`、`openid4vp-v1-multisigned`。結果は runner が verifier へ提出する
`DCAPIResponse` object です: `dc_api` は `{"protocol":<同じ protocol>,"data":{"vp_token":{...}}}`、
`dc_api.jwt` は `{"protocol":...,"data":{"response":"<JWE compact>"}}`。driver は HTTP
呼出しをしません。Key Binding JWT の `aud` は `origin:<origin>`（OID4VP 1.0
Appendix A.4）で、request の `client_id` ではありません。

呼出しごとに新しいプロセスなので、一覧と提示は永続化された credential を使います。
issuer / verifier の完全な launch URI をそのまま使ってください。driver は query の補正、
独自 credential の発行、protocol 失敗の再試行、presentation response の構築を行いません。
`followRedirect` が有効で verifier が `redirect_uri` を返すと、driver は same-device
ブラウザと同様にそれを開きます（HAIP §5.1、OpenID4VP §8.2）。fragment は送信しません。
2xx/3xx 以外の最終 status は status を名指しするエラーとして報告します。

### additionalHolderKeys

`additionalHolderKeys`（integer、既定 0）は authorization code 操作に、その数だけ
一時 P-256 鍵で追加 proof を送らせ、`batch_credential_issuance` を広告する issuer が
複数の credential を返せるようにします（OpenID4VCI 1.0 §14.6）。一時鍵は実行後に
破棄され、得られた credential は保存されますが後から提示はできません。batch の
control にのみ使用してください。
