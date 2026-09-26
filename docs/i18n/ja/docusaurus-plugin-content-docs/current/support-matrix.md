---
sidebar_position: 21
---

# VC Knots のサポート範囲

下記の表は、[OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) および [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) を基準に、このリポジトリの現在の実装範囲を整理したものです。

`✅` は該当ロールで実装済み、`❌` は未実装またはエンドツーエンドでは利用できないことを示します。設定に依存する機能は、備考欄に条件を記載しています。`⏳` はテスト確認予定を示します。

## OpenID for Verifiable Credential Issuance 1.0

| 仕様セクション | 機能領域 | 仕様上の役割・機能 | Issuer | Wallet | 備考 |
| --- | --- | --- | --- | --- | --- |
| [3.5](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.5) | Issuance Flow | Pre-Authorized Code Flow | `v0.6.0` 以降<br />✅ | ✅ | `AuthorizePreAuthorizedIssuance`。 |
| [3.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.4) | Issuance Flow | Authorization Code Flow | ❌ | ✅ | `BeginIssuance` / `AuthorizeIssuance`。PKCE S256、PAR（HAIP のとき、またはサーバーが `require_pushed_authorization_requests` を示すときは必須）、RFC 9207 の `iss`、Issuer 起点と Wallet 起点。ライブラリは認可 URL（https のみ）を返し、自身では開きません。 |
| [4.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1) | Credential Offer | `credential_offer` / `credential_offer_uri` | `v0.6.0` 以降<br />✅ 生成（値渡し） | ✅ 解析・取得 | `ResolveCredentialOffer`。`grants` の無い Offer は、認可サーバーのメタデータから grant を決めます（4.1.1 節）。 |
| [3.5](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.5) | Transaction Code | `tx_code` | `v0.6.0` 以降<br />✅ 発行・検証 | ✅ 送信 | Offer が求めるときだけ送ります（6.1 節）。 |
| [A.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.1) | Credential Format | `jwt_vc_json` / `ldp_vc` | `v0.6.0` 以降<br />✅ 発行（`jwt_vc_json`） | ✅ 受領 |  |
| [A.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.3) | Credential Format | `dc+sd-jwt`（SD-JWT VC） | `v0.6.0` 以降<br />✅ 発行 | ✅ 受領 |  |
| [A.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.2) | Credential Format | `mso_mdoc` | ❌ | ❌ |  |
| [6](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6) | Token Endpoint | Access Token の発行 | `v0.6.0` 以降<br />✅ | ✅ | `token_type` は Bearer か DPoP。それ以外は拒否します。 |
| [13.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.2) | Client Authentication | `private_key_jwt` | `v0.6.0` 以降<br />✅ 検証 | ✅ 送信 | Wallet が `private_key_jwt` を設定し、Authorization Server Metadata がその方式と署名アルゴリズムを示すときに送ります。 |
| [E](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E) | Client Authentication | Wallet Attestation（`attest_jwt_client_auth`） | ❌ | ✅ 送信 | PAR と Token Endpoint で Client Attestation と PoP を送ります。Attestation は段階ごとに、その認可サーバー向けに取得します。HAIP では必須。 |
| [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1) | Client Authentication | 匿名の Pre-Authorized Token Request | `v0.6.0` 以降<br />✅ 条件付き | ✅ 送信 | `pre-authorized_grant_anonymous_access_supported` が `true` のときだけ。 |
| [13.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.2) | Sender Constraint | DPoP による送信者制約付き Access Token | `v0.6.0` 以降<br />✅ | ✅ | Issuer は `off`、`optional`、`required` を設定できます。Wallet は `Config.DPoP.Key` があれば常に DPoP proof を送り、`use_dpop_nonce` に 1 回応じます。HAIP では必須。外部仕様: [RFC 9449](https://www.rfc-editor.org/info/rfc9449) |
| [8](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8) | Credential Endpoint | Credential Request / Response | `v0.6.0` 以降<br />✅ | ✅ |  |
| [8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2) | Credential Proof | JWT Proof | `v0.6.0` 以降<br />✅ 検証 | ✅ 生成 | holder 鍵ごとに 1 つの proof。Issuer が求めるときは `key_attestation` ヘッダー（Appendix D）を付けます。 |
| [7](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7) | Nonce | Nonce Endpoint / `c_nonce` | `v0.6.0` 以降<br />✅ 発行 | ✅ 取得・使用 | `invalid_nonce` のあと、新しい `c_nonce` を 1 回取得します。 |
| [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2) | Nonce | DPoP-Nonce | `v0.6.0` 以降<br />✅ 条件付き | ✅ | Nonce Response の DPoP-Nonce を次の DPoP proof に使います。 |
| [12.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2) | Metadata | Credential Issuer Metadata | `v0.6.0` 以降<br />✅ 署名なし JSON | ✅ 取得 | 署名付きメタデータ（`application/jwt`、12.2.3 節）は、設定した x5c のトラストアンカーで検証します。 |
| [5.1.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.1) | Credential Selection | `authorization_details` | ❌ | ✅ | Authorization Request と Token Response。 |
| [3.3.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.3.4) | Credential Selection | `credential_identifier` | ❌ | ✅ | Token Response の `credential_identifiers` をすべて保持し、Credential Request はその 1 つを指定します。 |
| [3.3.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.3.2) | Credential Issuance | Batch Credential Issuance | ❌ | ✅ | `batch_size` までの複数の key proof。 |
| [9](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9) | Credential Issuance | Deferred Credential Endpoint | ❌ | ✅ | `RequestDeferredCredential`。ライブラリはポーリングせず、Issuer の `interval` をそのまま返します。 |
| [10](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10) | Encryption | Credential Request の暗号化 | ❌ | ✅ | 任意の暗号化は断れます。 |
| [10](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10) | Encryption | Credential Response の暗号化 | ❌ | ✅ | 発行ごとに一時的な P-256 鍵を使います。 |
| [11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11) | Notification | Notification Endpoint | ❌ | ✅ | `NotifyIssuer`。 |

Wallet 列は Go の Wallet ライブラリ（`wallet/`）を指します。このライブラリは OpenID4VCI Draft 13（`Draft13()`）も扱い、`profile.HAIP()` で HAIP 1.0 を強制します。詳しくは [Wallet](./wallet.md) を参照してください。

## OpenID for Verifiable Presentations 1.0

| 仕様セクション | 機能領域 | 仕様上の役割・機能 | Verifier | Wallet | 備考 |
| --- | --- | --- | --- | --- | --- |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5) | Authorization Request | Authorization Request | `v0.7.0` 以降<br />✅ `request_uri`、URL エンコードされたパラメータ | ⏳ `request`、`request_uri`、URL エンコードされたパラメータ |  |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5) | Authorization Request | 署名付き Authorization Request（JAR） | `v0.7.0` 以降<br />✅ | ⏳ | Request Objectを使用。外部仕様: [RFC 9101](https://www.rfc-editor.org/info/rfc9101) |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5) | Authorization Request | 暗号化された Authorization Request（JAR） | ❌ | ❌ | 外部仕様: [RFC 9101](https://www.rfc-editor.org/info/rfc9101) |
| [5.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.5) | Credential Query | スコープを使用した Authorization Request | ❌ | ❌ | |
| [5.9.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3) | Client Identification | Client Identifier Prefix | `v0.7.0` 以降<br />✅ `redirect_uri`、`x509_san_dns` | ⏳ `redirect_uri`、`x509_san_dns` |  |
| [5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10) | Request URI | Request URI Method | `v0.7.0` 以降<br />✅ GET | ⏳ GET、POST |  |
| [6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l) | Credential Query | DCQL | `v0.7.0` 以降<br />✅ | ⏳ | `dcql_query` パラメータを使用。 |
| [8.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1) | Authorization Response | Authorization Response | `v0.7.0` 以降<br />✅ | ⏳ |  |
| [8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2) | Response Mode | Response Mode | `v0.7.0` 以降<br />✅ `direct_post` | ⏳ `direct_post` |  |
| [8.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3) | Authorization Response | 暗号化された Authorization Response | ❌ | ⏳ |  |
| [8.4](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4) | Transaction Data | Transaction Data | `v0.7.0` 以降<br />✅ | ⏳ | `dc+sd-jwt` のみ対応。 |
| [8.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.5) | Authorization Response | Authorization Error Response | ❌ | ❌ | |
| [10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-10) | Metadata | Wallet Metadata | ❌ | ❌ | |
| [11](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-11) | Metadata | Verifier Metadata — `client_metadata` | `v0.7.0` 以降<br />✅ | ⏳ 解析 |  |
| [12](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12) | Client Authentication | Verifier Attestation JWT | ❌ | ❌ | |
| [Appendix A](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A) | Digital Credentials API | Digital Credential API／DC API | ❌ | ❌ | |
| [Appendix B.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1) | Credential Format | `jwt_vc_json`形式 | `v0.7.0` 以降<br />✅ | ⏳ |  |
| [Appendix B.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2) | Credential Format | `mso_mdoc`（Mobile Documents／mdocs） | ❌ | ❌ | |
| [Appendix B.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3) | Credential Format | SD-JWT-VC形式（`dc+sd-jwt`） | `v0.7.0` 以降<br />✅ | ⏳ |  |
| [Appendix B.3.6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.6) | Holder Binding | SD-JWT VC Key Binding／KB-JWT | `v0.7.0` 以降<br />✅ | ⏳ |  |
