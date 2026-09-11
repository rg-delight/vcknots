---
sidebar_position: 13
---

# Wallet機能のセットアップと使用方法

このチュートリアルは、VCKnots の wallet ライブラリ（Go ライブラリ）のセットアップ、Credential の受領と提示のサンプル実装、本番環境での利用に向けた考慮事項を説明します。

wallet は OpenID for Verifiable Credentials の各仕様を実装しています。

* **Credential の受領（OID4VCI）:** Credential Offer と pre-authorized code フローを使って、Issuer から Credential を受け取ります。
* **Credential の提示（OID4VP）:** `openid4vp://` 形式の Authorization Request に応答し、Verifiable Presentation を Verifier に送信します。

受領と提示のどちらも **JWT-VC**（`application/vc+jwt`）と **SD-JWT VC**（`application/dc+sd-jwt`）に対応しています。
SD-JWT VC では選択的開示と Key Binding JWT も利用できます。

## 対応プロトコルとプロファイル

この Wallet は **OpenID4VCI 1.0** と **OpenID4VP 1.0** を実装しています。**HAIP 1.0** は明示的に選択するプロファイルです。`profile.Profile` のゼロ値は `profile.Final` に正規化され、`profile.HAIP` を選ぶと HAIP の制約が Final に追加されます。Draft 13 / Draft 24 の入口も従来の挙動のまま残しています。`Partial` はインターフェースは存在するが、本番での接続は呼出し側の責務である機能を表します。

| プロトコル / 機能 | 状態 | 公開 API の入口 | 備考 |
| --- | --- | --- | --- |
| OpenID4VCI 1.0 pre-authorized code | Implemented | `Wallet.ReceiveCredential`（`ReceiveCredentialRequest`） | 旧 Draft 13 の入口も兼ねます。 |
| OpenID4VCI 1.0 authorization code（PAR / PKCE / DPoP / `private_key_jwt` / client attestation） | Implemented | `Wallet.BeginOID4VCIFinalAuthorization` と `Wallet.ResumeOID4VCIFinalAuthorization`、または `Wallet.ReceiveOID4VCIFinalCredential`（`OID4VCIFinalReceiveRequest`） | PAR は認可サーバーが広告する場合に使用し、必須なのは HAIP のみです（HAIP §4）。PKCE は常に `S256`、`private_key_jwt` は認可サーバーが広告する場合に使用、attestation によるクライアント認証は `Config.ClientAttestation` を使用します。 |
| Deferred | Implemented | `Wallet.ReceiveOID4VCIFinalCredential`（`DeferredPollAttempts`）、`Wallet.ResumeOID4VCIFinalDeferredCredential` | 広告された interval でポーリングします。interval は 60 秒で頭打ちにし（`MaxDeferredInterval` で上書き可）、`…Context` 版で中断できます。`OID4VCIFinalDeferredRequest` で別プロセスから再開できます。 |
| Notification endpoint | Implemented | `Wallet.NotifyOID4VCIFinalCredentialDeleted`（`OID4VCIFinalNotificationRequest`） | `credential_deleted` を送信します。`credential_accepted` と `credential_failure` は保存の成否後に内部で送信します。 |
| Batch | Implemented | `Wallet.ReceiveOID4VCIFinalCredential`（`AdditionalHolderKeys`） | holder 鍵ごとに 1 つの proof を送り、`batch_credential_issuance.batch_size` を上限とします。 |
| Credential response encryption | Implemented | `OID4VCIFinalReceiveRequest.CredentialResponseEncryptionKey` | OpenID4VCI 1.0 §8.2（`jwk`、`enc`、任意の `zip`、`alg` なし）。issuer が暗号化を要求しているのに鍵が無い場合は fail-closed です。 |
| Key attestation | Partial | `Config.KeyAttestation`（`KeyAttestationProvider`）、`StaticKeyAttester`、`OID4VCIFinalReceiveRequest.IncludeKeyAttestation` | library は provider の JWT（`typ`、`attested_keys`、`exp`）を検証しますが、attester の署名は検証しません。本番の attester / HSM は呼出し側が用意します。 |
| OpenID4VP 1.0 redirect flow（`x509_hash` / `x509_san_dns` / `redirect_uri` / pre-registered） | Implemented | `Wallet.PresentCredential`、`Wallet.PresentCredentialWithOptions`、`Oid4vpPresenter.ParsePresentationRequest` | 署名付き Request Object の認証は `x509_san_dns` と `x509_hash` に対応し、コロンを含まない identifier は pre-registered client として扱います（OpenID4VP §5.9.2）。HAIP は `x509_hash` を要求します。 |
| `request_uri` の GET / POST と `wallet_nonce` | Implemented | `Oid4vpPresenter.ParsePresentationRequest`、`requestBuilder.WithRequestObjectURI`、`Oid4vpPresenter.RequestURINonce` | Final の POST は毎回新しい `wallet_nonce` と任意の `wallet_metadata` を送り、echo は `RequestObjectVerification.WalletNonce` に現れます。 |
| DCQL（`credential_sets`、`claims`、`claim_sets`、`values`、nested / array claim path、`aki` の `trusted_authorities`、`multiple`） | Implemented | `Oid4vpPresenter.ParsePresentationRequest`、`ResolveSatisfiableDCQLCredentials`、`AuthorityKeyIdentifiersFromCredential` | 評価するのは `aki` 種別のみで（HAIP §5）、他の種別は無視します。`multiple: true` は一致するものをすべて返します。 |
| `direct_post` / `direct_post.jwt` | Implemented | `Wallet.PresentCredential`、`Oid4vpPresenter.PresentDCQL`、`Oid4vpPresenter.CreateEncryptedAuthorizationResponse` | `direct_post` は平文 form POST、`direct_post.jwt` は ECDH-ES の JWE です。エラー応答は verifier metadata が許す場合に暗号化し、それ以外は §8.3.1 の平文 fallback を送ります。 |
| `transaction_data` | Implemented | `Config.SupportedTransactionDataTypes`、`Oid4vpPresenter.SetSupportedTransactionDataTypes` | 各 object は既知の `credential_ids` を持つ base64url JSON で、hash は KB-JWT に束縛されます。リストが空の場合、`transaction_data` を含む要求はすべて `invalid_transaction_data` で拒否します。 |
| W3C Digital Credentials API（`dc_api` / `dc_api.jwt`、unsigned / signed / multi-signed） | Implemented（protocol のみ） | `Wallet.PresentCredentialToDCAPI`、`Oid4vpPresenter.ParseDCAPIRequest`、`Oid4vpPresenter.BuildDCAPIResponse` | `openid4vp-v1-unsigned`、`-signed`、`-multisigned` に対応します。platform が認証した `origin` は呼出し側が渡し、library に browser / OS 連携はありません。 |
| HAIP 1.0 profile switch | Implemented | `profile.HAIP`、`Config.Profile`、`Oid4vpPresenter.Profile`、`Oid4vciReceiver.Profile` | 既定は `profile.Final` です。profile は全 plugin へ伝播し、呼出し側が注入した dispatcher の plugin が異なる profile を報告した場合は拒否します。 |
| Draft 13 / Draft 24 の旧入口 | Implemented | `Wallet.ReceiveCredential`、`Wallet.PresentDraft24Credential`、`Oid4vpPresenter.ParseDraft24PresentationRequest`、`NewDraft24RequestBuilder`、`PresentDraft24` | Draft 経路は `InsecureSkipX509Verify` を含む従来の挙動を保ち、Final / HAIP の profile を無視します。 |
| 形式: SD-JWT VC（`dc+sd-jwt`、`vc+sd-jwt`）と `jwt_vc_json` | Implemented | `credential.SDJwtVC`、`credential.JwtVc`、SD-JWT VC / JWT VC serializer plugin | 両形式のシリアライズと提示に対応します。SD-JWT VC の issuer `typ` は `dc+sd-jwt` または `vc+sd-jwt` です。 |

**未実装。** ISO mdoc（`mso_mdoc`）: mdoc / COSE / CBOR の serializer はなく、提示を構築できません。`verifier_attestation`、`openid_federation`、`decentralized_identifier` の Client Identifier Prefix は解析しますが、Final 経路では認証しません。DCQL の trust authority は `aki` 種別のみを評価し、`etsi_tl` と `openid_federation` の entry は無視します（未知の種別だけの query は制約を課しません）。

### プロファイル（Final と HAIP）

* **Final** は追加制約なしの OpenID4VCI 1.0 / OpenID4VP 1.0 です。既定であり、`profile.Profile` のゼロ値（`""`）は `profile.Final` に正規化されます。
* **HAIP** は Final に HAIP 1.0 の制約を加えたもので、`wallet.Config.Profile`、`oid4vci.Oid4vciReceiver.Profile`、`oid4vp.Oid4vpPresenter.Profile` で `profile.HAIP` を選びます。
* ルート Wallet は profile を全 plugin へ伝播します。呼出し側が注入した dispatcher の plugin が `profile.Carrier` を実装し異なる profile を報告した場合、root policy を下位 API で回避できないよう拒否します。
* Draft 13 / Draft 24 の入口は profile を無視します。
* HAIP では Final 経路がさらに次を拒否します（一例）: `AllowHTTP` と `InsecureSkipX509Verify`、DPoP 束縛でない access token、`scope` の無い credential configuration、cryptographic binding を広告しながら `nonce_endpoint` が無い issuer、OAuth クライアント認証が未設定の発行、client identifier prefix が `x509_hash` でない / response mode が `direct_post.jwt` / `dc_api.jwt` でない / DCQL 形式が `dc+sd-jwt` / `mso_mdoc` でない提示要求、ECDH-ES で A128GCM / A256GCM 以外の応答暗号化、`cnf` を持つ SD-JWT VC の KB-JWT 欠落。各制約は Final 受理 / HAIP 拒否のテスト対でカバーされています。

## 1. 前提条件

* **対応している仕様:**
    - 受領: [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)（pre-authorized code と authorization code）。HAIP 1.0 は任意プロファイル
    - 提示: [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)。HAIP 1.0 は任意プロファイル。以前の Draft 13 / Draft 24 フローも引き続き対応
    - 各機能の実装範囲の詳細は [VC Knots Coverage](./support-matrix.md) を参照してください。

### 1-1. Go環境の要件

* **Goのバージョン:** vcknots/wallet ライブラリは、`wallet/mise.toml` に固定されたバージョンの Go（現在は Go 1.26.5）を要求します。
* **開発環境管理 (mise):**
    - 開発環境の管理には [mise](https://mise.jdx.dev/) の使用を推奨します。
    - `wallet` ディレクトリで `mise install` を実行すると、必要な Go バージョンがインストールされ、環境変数も設定されます。

```bash
# macOS
brew install mise

# curl経由でのインストール
curl https://mise.jdx.dev/install.sh | sh

# (vcknotsリポジトリのルートから)
cd wallet
mise install
```

* **GOPRIVATE 環境変数:**
    - mise を使用しない場合は、以下の環境変数を手動で設定してください。設定しないと `go mod download` が失敗します。

```bash
export GOPRIVATE="github.com/trustknots/vcknots/wallet"
```

### 1-2. サンプル実行環境の要件 (Issuer/Verifierサーバー)

このチュートリアルのサンプルコード（Credential の受領と提示）は、対話する相手（Issuer と Verifier）が存在することを前提としています。
このリポジトリの Node.js ベースのサンプルサーバー（`server/`）が両方の役割を提供します。

wallet のサンプルコードを実行する前に、サーバーを起動してください。

```bash
# vcknotsリポジトリのルートから
pnpm install

# issuer+verifierモジュール、server-coreモジュール、serverモジュールをbuild
pnpm -F @trustknots/vcknots build
pnpm -F @trustknots/server-core build
pnpm -F @trustknots/server build

# サーバーを起動（http://localhost:8080 で待ち受け）
pnpm -F @trustknots/server start
```

サーバーは、このチュートリアルで使用する以下のエンドポイントを提供します。

* `POST /configurations/:configurationId/offer`：Credential Offer の作成
* `POST /token`, `POST /nonce`, `POST /credentials`：OID4VCI の token エンドポイント、nonce エンドポイント、credential エンドポイント
* `POST /request`, `POST /request-object`：OID4VP の Authorization Request の作成
* `POST /callback`：Verifier の応答受け取りエンドポイント
* `GET /.well-known/openid-credential-issuer`, `GET /.well-known/oauth-authorization-server`：メタデータエンドポイント

* **ローカルテストでの HTTP 許可:** wallet はデフォルトで、Issuer と Verifier のエンドポイントに HTTPS を要求します。
ローカルのサンプルサーバーは HTTP で動作するため、ローカルテスト時は明示的に HTTP を許可してください。

```bash
export VCKNOTS_WALLET_HTTP_ALLOWED=true
```

テストコードから `env.SetHTTPAllowed(true)`（パッケージ `github.com/trustknots/vcknots/wallet/env`）を呼び出す方法もあります。

> ⚠️ **セキュリティ警告**: 本番環境では `VCKNOTS_WALLET_HTTP_ALLOWED` を有効化しないでください。HTTPS 必須の検証を維持してください。

## 2. 初期設定

このセクションでは、ライブラリの依存関係をインストールし、wallet のコア機能を集約する `Wallet` インスタンスを初期化する手順を説明します。

### 2-1. 依存関係のインストール

GOPRIVATE を設定した後、`wallet` ディレクトリで以下のコマンドを実行し、`go.mod` にリストされている依存ライブラリ（`github.com/go-jose/go-jose/v4`, `go.etcd.io/bbolt`, `golang.org/x/crypto` など）をダウンロードします。

```bash
go mod download
```

### 2-2. Walletの初期化

ライブラリのトップレベル API は `github.com/trustknots/vcknots/wallet` パッケージにあります。
最も簡単な初期化は `wallet.NewWallet()` で、すべてのディスパッチャコンポーネントをデフォルトのプラグイン実装で初期化します。

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

`Wallet` は内部で 6 つのディスパッチャコンポーネントを協調させます。
それぞれが wallet 機能の一つの側面を担当します。

* `credstore.CredStoreDispatcher`：Credential の永続化（デフォルトは bbolt を使うローカルストレージ）
* `receiver.ReceivingDispatcher`：Credential 発行プロトコル（OID4VCI）
* `presenter.PresentationDispatcher`：Credential 提示プロトコル（OID4VP）
* `serializer.SerializationDispatcher`：Credential のシリアライズ（JWT-VC, SD-JWT VC）
* `verifier.VerificationDispatcher`：署名の暗号学的検証
* `idprof.IdentityProfileDispatcher`：DID とアイデンティティプロファイル（`did:key`）

カスタム設定が必要な場合（たとえば OID4VP の Request Object 検証に使うトラストルートを設定する場合）は、ディスパッチャを自分で構築して `wallet.NewWalletWithConfig` に渡します。
各ディスパッチャのコンストラクタはエラーを返します。
`wallet.Config` で `nil` のままにしたフィールドには、デフォルト実装が自動的に補われます。
以下のコードは、`wallet/examples/` 配下のサンプルで使われている初期化です。

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

    // OID4VP Request Objectのx5c証明書チェーン検証に使うトラストルート
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

* **保存先:** デフォルトの Credential ストアは、`go.etcd.io/bbolt` を使って `<ユーザー設定ディレクトリ>/vcknots/wallet/.local_credstore.db` に永続化します（Linux では `~/.config/vcknots/wallet/.local_credstore.db`、macOS では `~/Library/Application Support/vcknots/wallet/.local_credstore.db` など）。

## 3. Wallet機能のサンプル実装

`Wallet` インスタンスを使用して、wallet の主要な機能（鍵の準備、Credential の受領、Credential の提示）を実行する具体的な Go コードサンプルを示します。
これらのサンプルは `wallet/examples/server_integration_sdjwt/server_integration_sdjwt.go` と `wallet/examples/common/common.go` に基づいています。

### 3-1. テスト用の鍵の準備 (IKeyEntryインターフェース)

主要なワークフローメソッド（`ReceiveCredential`, `PresentCredential`）は、署名操作のために `IKeyEntry` インターフェースを要求します。
これにより、ライブラリ利用者は鍵管理の実装（例: メモリ、HSM、セキュアエンクレーブ）を差し替えることができます。

`IKeyEntry` インターフェースは以下のように定義されています。

```go
// IKeyEntry は、署名操作のための鍵エントリを表すインターフェースです。
type IKeyEntry interface {
    ID() string
    PublicKey() jose.JSONWebKey
    Sign(data []byte) ([]byte, error)
}
```

* **署名フォーマット:** ECDSA 実装の `Sign` は、DER エンコードされた ASN.1 署名と、生の IEEE P1363（`R || S`）署名のどちらを返しても構いません。
ライブラリが内部で（`JWKSigner` により）DER 署名を IEEE P1363 に正規化するため、両方の形式が動作します。

チュートリアル用に、`wallet/examples/common/common.go` の `MockKeyEntry` と同等のインメモリ実装を使用します。

```go
// MockKeyEntry は IKeyEntry のテスト用実装です。
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
        Algorithm: "ES256", // P-256曲線
        Use:       "sig",
    }
}

// Sign は SHA-256 ハッシュ -> ECDSA署名 -> IEEE P1363 形式へのシリアライズ を行います。
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

### 3-2. Credentialの受領 (OID4VCI)

wallet は、Issuer から取得した `CredentialOffer` を `ReceiveCredential` に渡して Credential を受領します。
実際の運用では offer URI は QR コードやディープリンクから取得します。
ローカルのサンプルサーバーでは `POST /configurations/:configurationId/offer` で作成できます。

offer URI は `openid-credential-offer://?credential_offer=...` という形式です。
これを `wallet.CredentialOffer` にパースして `ReceiveCredential` に渡します。

```go
import (
    "encoding/json"
    "net/url"

    "github.com/trustknots/vcknots/wallet"
    "github.com/trustknots/vcknots/wallet/credential"
    "github.com/trustknots/vcknots/wallet/receiver"
)

func receiveSDJwtCredential(w *wallet.Wallet, key wallet.IKeyEntry, offerURI string) (*wallet.SavedCredential, error) {
    // 1. openid-credential-offer:// URIをパース
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
        Grants:                     offerJSON.Grants, // キー: "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }

    // 2. OID4VCI (pre-authorized codeフロー) でCredentialを受領
    return w.ReceiveCredential(wallet.ReceiveCredentialRequest{
        CredentialOffer: offer,
        Type:            receiver.Oid4vci,
        Key:             key,                 // JWT proof (key binding) の署名に使用
        RequestedFormat: credential.SDJwtVC,  // "application/dc+sd-jwt"
    })
}
```

`ReceiveCredentialRequest` の補足:

* **RequestedFormat:** SD-JWT VC を受領する場合は `credential.SDJwtVC`、JWT-VC を受領する場合は `credential.JwtVc` を指定します。
省略した場合は、先頭の credential configuration ID について Issuer メタデータからフォーマットを解決します（解決できない場合は JWT-VC にフォールバックします）。
* **TxCode:** offer が transaction code を要求する場合は `TxCode` を設定します。token エンドポイントに `tx_code` として送信されます。
* **CachedIssuerMetadata:** 設定すると、`ReceiveCredential` は Issuer メタデータの取得をスキップします（セクション 4 を参照）。

`ReceiveCredential` は、Issuer と Authorization Server のメタデータを取得し、pre-authorized code でアクセストークンを取得し、`Key` で署名した JWT proof を生成して Credential を要求し、結果を Credential ストアに保存します。
戻り値の `*wallet.SavedCredential` には、パース済みの Credential とストレージエントリの両方が含まれます。

### 3-3. Credentialの提示 (OpenID4VP)

Verifier から `openid4vp://authorize?...` 形式のリクエスト URI を受け取ったら（通常は QR コードのスキャンで取得します。ローカルのサンプルサーバーでは `POST /request` または `POST /request-object` で作成できます）、`PresentCredential` を呼び出します。

```go
import (
    "log"

    sdjwtvc "github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

func presentCredential(w *wallet.Wallet, key wallet.IKeyEntry, oid4vpURI string) error {
    // SD-JWT VC提示のオプション: 選択的開示とKey Binding JWT
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

`PresentCredential` は、OID4VP リクエストをパースし（`request_uri` で参照される JAR Request Object も含み、その署名は `X509TrustChainRoots` に対して検証されます）、保存済みの Credential のうち最も新しく受領した 1 件を選択し（presentation definition との照合は現時点では行いません）、`key` で Verifiable Presentation をシリアライズして署名し、Verifier の `response_uri`（`response_mode=direct_post`）に POST します。
Wallet が `redirect_uri` に送信することはありません。
Verifier の応答に `redirect_uri` が含まれる場合、その値が戻り値として呼び出し側に返されます（含まれない場合は空文字列です）。

* **提示オプション:** 第 3 引数にはフォーマット固有のオプションを渡します。
SD-JWT VC では `sdjwtvc.SdJwtVcPresentationOptions` により、開示するクレーム（`SelectedClaims`）と Key Binding JWT の付与（`RequireKeyBinding`）を制御します。
KB-JWT の audience と nonce は OID4VP リクエスト（`client_id` と `nonce`）から自動的に設定されます。リクエストに transaction data が含まれる場合の `transaction_data` ハッシュも同様です。
`nil` を渡すと、その Credential のフォーマットに応じたデフォルトのオプションが使われます（JWT-VC の提示では `nil` が典型的です）。
* **リダイレクト処理:** Verifier のリダイレクト URI をコールバックで受け取りたい場合は、`PresentCredentialWithOptions` に `&wallet.PresentCredentialOptions{OnRedirect: func(uri string) error {...}}` を渡します。

### 3-4. 保存されたCredentialの参照

`ReceiveCredential` で保存された Credential は、`GetCredentialEntries` で一覧取得できます。
ページネーション（`Offset`, `Limit`）と Go 関数によるフィルタリング（`Filter`）をサポートします。
ID を指定して 1 件だけ取得する場合は `GetCredentialEntry` を使います。

```go
func listSavedCredentials(w *wallet.Wallet) ([]*wallet.SavedCredential, error) {
    limit := 10
    entries, total, err := w.GetCredentialEntries(wallet.GetCredentialEntriesRequest{
        Offset: 0,
        Limit:  &limit,
        Filter: func(sc *wallet.SavedCredential) bool {
            return true // 例: return sc.Entry.MimeType == string(credential.SDJwtVC)
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

## 4. Issuerメタデータの取得

Credential を受領する際、wallet は Issuer の `.well-known/openid-credential-issuer` エンドポイントにアクセスし、Issuer の設定（credential エンドポイント、サポートする credential configuration など）を取得する必要があります。

`ReceiveCredential` はこのメタデータを内部で取得しますが、`FetchCredentialIssuerMetadata` で明示的に取得し、`ReceiveCredentialRequest` の `CachedIssuerMetadata` フィールドに渡すこともできます。
これにより、`ReceiveCredential` を呼び出すたびにメタデータを再取得するオーバーヘッドを回避できます。

```go
import (
    "log"
    "net/url"

    receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func fetchIssuerMetadata(w *wallet.Wallet) (*receiverTypes.CredentialIssuerMetadata, error) {
    // 注意: IssuerのベースURLを渡します。/.well-known/... パスは内部で解決されます
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

## 5. 型定義の説明

vcknots/wallet ライブラリの `Wallet` とのインタラクションに使用される主要な Go の型定義について説明します。

### IKeyEntry {#IKeyEntry}

鍵管理のコアインターフェース。`ID()`, `PublicKey()`, `Sign()` の 3 つのメソッドを定義します。ライブラリ利用者は、HSM やセキュアエンクレーブと連携するためにこれを実装します。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### Config {#Config}

`NewWalletWithConfig` の入力。6 つのディスパッチャコンポーネントと、オプションの DPoP 設定（[DPoPConfig](#DPoPConfig)）を保持します。`nil` のフィールドにはデフォルト実装が補われます。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### ReceiveCredentialRequest {#ReceiveCredentialRequest}

`ReceiveCredential` の主要な入力。[CredentialOffer](#CredentialOffer)、受領プロトコル（`Type`）、proof の署名に使用する鍵（[IKeyEntry](#IKeyEntry)）、要求する Credential フォーマット（`RequestedFormat`）、オプションの `CachedIssuerMetadata` と `TxCode` をカプセル化します。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### CredentialOffer {#CredentialOffer}

Issuer から受け取るオファーの詳細。Issuer の URL（`CredentialIssuer`）、credential configuration ID（`CredentialConfigurationIDs`）、認可グラント（`Grants`）を含みます。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### SavedCredential {#SavedCredential}

Credential ストアに保存された Credential。`*credential.Credential`（パース済みの Credential）と `*types.CredentialEntry`（ストレージメタデータ: ID、生データ、MIME タイプ、受領時刻）をラップします。`ReceiveCredential`, `GetCredentialEntries`, `GetCredentialEntry` の戻り値です。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### GetCredentialEntriesRequest {#GetCredentialEntriesRequest}

`GetCredentialEntries` の検索条件。ページネーション（`Offset`, `Limit`）と、Go 関数による動的なフィルタリング（`Filter`）をサポートします。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### PresentCredentialOptions {#PresentCredentialOptions}

`PresentCredentialWithOptions` の入力。フォーマット固有の `SerializeOptions` と、オプションの `OnRedirect` コールバックを保持します。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### SdJwtVcPresentationOptions {#SdJwtVcPresentationOptions}

SD-JWT VC 提示のオプション: `SelectedClaims`, `RequireKeyBinding`, `Audience`, `Nonce`, `TransactionData`。audience と nonce は OID4VP リクエストから自動的に設定されます。

定義は [wallet/serializer/plugins/sdjwtvc/sdjwtvc.go](https://github.com/trustknots/vcknots/blob/main/wallet/serializer/plugins/sdjwtvc/sdjwtvc.go) を参照してください。

### DIDCreateOptions {#DIDCreateOptions}

`GenerateDID` のオプション。DID のタイプ（`TypeID`、例: `"did:key"`）と、関連付ける公開鍵（`PublicKey`）を指定します。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### DPoPConfig {#DPoPConfig}

token エンドポイントと credential エンドポイントへの DPoP proof 付与を有効化します（`Enabled`）。専用の鍵（`Key`）も指定できます。有効化時に鍵を指定しない場合は、インメモリの P-256 鍵が生成されます。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

## 6. Walletのメソッド

### ReceiveCredential

OID4VCI（Pre-Authorized Code フロー）で Issuer から Credential を受領し、Credential ストアに保存します。

```go
func (w *Wallet) ReceiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error)
```

**パラメータ**:
- `req`: 受領リクエスト（[ReceiveCredentialRequest](#ReceiveCredentialRequest)）

**戻り値**:
- 受領し保存された Credential（[SavedCredential](#SavedCredential)）

### PresentCredential

OID4VP の Authorization Request に応答し、Verifiable Presentation を Verifier に送信します。

```go
func (w *Wallet) PresentCredential(uriString string, key IKeyEntry, options serializerTypes.SerializePresentationOptions) (string, error)
```

**パラメータ**:
- `uriString`: OID4VP リクエスト URI（`openid4vp://authorize?...`）
- `key`: Presentation の署名に使用する鍵（[IKeyEntry](#IKeyEntry)）
- `options`: フォーマット固有の提示オプション（SD-JWT VC では [SdJwtVcPresentationOptions](#SdJwtVcPresentationOptions)）。`nil` を渡すと、その Credential のフォーマットのデフォルトが使われます

**戻り値**:
- Verifier が提示したリダイレクト URI（リダイレクトがない場合は空文字列）

### PresentCredentialWithOptions

`PresentCredential` と同じ動作に加えて、Verifier がリダイレクト URI を返した場合にコールバックを呼び出します。

```go
func (w *Wallet) PresentCredentialWithOptions(uriString string, key IKeyEntry, options *PresentCredentialOptions) (string, error)
```

**パラメータ**:
- `uriString`: OID4VP リクエスト URI（`openid4vp://authorize?...`）
- `key`: Presentation の署名に使用する鍵（[IKeyEntry](#IKeyEntry)）
- `options`: シリアライズオプションとリダイレクトコールバック（[PresentCredentialOptions](#PresentCredentialOptions)）

**戻り値**:
- Verifier が提示したリダイレクト URI（リダイレクトがない場合は空文字列）

### GetCredentialEntries

保存された Credential を、ページネーションとフィルタリング付きで取得します。

```go
func (w *Wallet) GetCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error)
```

**パラメータ**:
- `req`: 検索条件（[GetCredentialEntriesRequest](#GetCredentialEntriesRequest)）

**戻り値**:
- 条件に一致した Credential（[SavedCredential](#SavedCredential)）と、一致件数の合計

### GetCredentialEntry

ID を指定して、保存された Credential を 1 件取得します。

```go
func (w *Wallet) GetCredentialEntry(id string) (*SavedCredential, error)
```

**パラメータ**:
- `id`: Credential エントリの ID

**戻り値**:
- 保存された Credential（[SavedCredential](#SavedCredential)）。デフォルトのローカルストアでは、ID が存在しない場合はエラーを返します

### FetchCredentialIssuerMetadata

Issuer の `.well-known/openid-credential-issuer` エンドポイントから Issuer メタデータを取得します。

```go
func (w *Wallet) FetchCredentialIssuerMetadata(endpoint *url.URL, receivingType receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error)
```

**パラメータ**:
- `endpoint`: Issuer のベース URL（`/.well-known/...` パスは内部で解決されます）
- `receivingType`: 受領プロトコル（`receiver.Oid4vci`）

**戻り値**:
- Issuer メタデータ（`receiverTypes.CredentialIssuerMetadata`）

### GenerateDID

公開鍵から DID を生成します。

```go
func (w *Wallet) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error)
```

**パラメータ**:
- `options`: DID のタイプと公開鍵（[DIDCreateOptions](#DIDCreateOptions)）

**戻り値**:
- 生成されたアイデンティティプロファイル（`idprofTypes.IdentityProfile`）

## OpenID4VCI 1.0 の発行（Final / HAIP）

Final の発行経路は authorization code フローです。`ReceiveCredential` は引き続き pre-authorized code 経路であり、Draft 13 の入口も兼ねます。

### Pre-authorized code

`ReceiveCredential` は credential offer を解決し、issuer と認可サーバーのメタデータを取得し、pre-authorized code で access token を取得し、`Key` で JWT proof を署名して credential を要求・保存します。3-2 で示した最も簡単な統合方法です。credential offer は値（`credential_offer`）でも参照（`credential_offer_uri`）でも渡せ、`ResolveCredentialOffer` / `ResolveCredentialOfferContext` で解決します。

### ブラウザ委譲つき authorization code

authorization endpoint にはシステムブラウザが必要なため、フローは 2 つに分かれます。

```go
authorization, err := w.BeginOID4VCIFinalAuthorization(ctx, request)
// authorization.AuthorizationURL をシステムブラウザで開きます。
// authorization は JSON 直列化可能で、プロセス再起動をまたいで保持できます。
result, err := w.ResumeOID4VCIFinalAuthorization(ctx, request, authorization, redirectURLFromBrowser)
```

`BeginOID4VCIFinalAuthorization` は user agent が関与する前の処理（メタデータ探索、credential configuration の検証、認可サーバーが広告する場合の RFC 9126 Pushed Authorization Request）を行います。`ResumeOID4VCIFinalAuthorization` は保持した state に対して RFC 6749 / RFC 9207 の認可応答を検証し、token endpoint で code を交換して credential request を実行します。

ユーザー操作を必要とせず authorization endpoint が code redirect を返すテスト / 適合性試験の issuer は、`AllowSelfDrivenAuthorization` を設定して `ReceiveOID4VCIFinalCredentialContext` を 1 回呼ぶだけで実行できます。ユーザーのいる Wallet は設定してはいけません。既定は `false` で、未設定のまま `ReceiveOID4VCIFinalCredential` を呼ぶと拒否されます。

Wallet 起点の発行にも対応します。`CredentialOffer` を nil にし、`CredentialIssuer` と `CredentialConfigurationID`（どちらも必須）を設定すると、offer 無しで同じフローを開始できます。

`AuthorizationRequestType` は credential configuration の要求方法を選びます。空値は configuration が `scope` を広告していれば `scope`、そうでなければ `authorization_details` を使います。`"scope"` は広告された scope を必須とし、`"authorization_details"` は `openid_credential` の authorization detail を送ります。HAIP では `scope` のみを受け付けます。

### Deferred

`DeferredPollAttempts` は §9 deferred credential endpoint のポーリング回数の上限です。0 の場合はポーリングせず、`transaction_id` と access token を持つ pending 結果を返します。`ResumeOID4VCIFinalDeferredCredential` はポーリングを再開し、`IssuerMetadata` が nil の場合は `IssuerURL` から取得できます。issuer が指定する interval は、`MaxDeferredInterval` で上書きしない限り 60 秒で頭打ちにし、`…Context` 版は待機をキャンセルできます。deferred request は `credential_response_encryption` を再送します。

### Notification

保存に成功すると `credential_accepted`、検証・保存に失敗すると `credential_failure` を送ります。`NotifyOID4VCIFinalCredentialDeleted` は保存から削除した credential について `credential_deleted` を送ります。issuer が notification endpoint を広告し `notification_id` を返した場合にだけ送信します。

### Credential response encryption

`OID4VCIFinalReceiveRequest.CredentialResponseEncryptionKey` に公開 JWK を設定すると、credential 応答の暗号化を要求します（OpenID4VCI 1.0 §8.2: `jwk`、`enc`、任意の `zip`、`alg` なし）。issuer が暗号化を要求しているのに鍵が無い場合は fail-closed となり、暗号化を要求した後に平文応答が返ると拒否します。

### Attestation provider

library は attester の秘密鍵を持ちません。`Config.ClientAttestation`（`ClientAttestationProvider`）と `Config.KeyAttestation`（`KeyAttestationProvider`）で、呼出し側が remote attester から attestation を取得します。

* `ClientAttestationProvider` は発行ごとに 1 回、選択した認可サーバー識別子とともに呼び出され、typ `oauth-client-attestation+jwt`、`sub` = `ClientID`、`cnf.jwk` = Wallet instance 鍵の compact JWS を返す必要があります。
* `KeyAttestationProvider` は holder 鍵と `c_nonce` とともに呼び出され、`attested_keys` にすべての holder 鍵を含む `key-attestation+jwt` を返す必要があります。

使用前に Wallet は attester 署名を検証せずに provider の結果を検証します（`typ`、`sub`、RFC 7638 `cnf.jwk` thumbprint、未来の `exp`）。HAIP では header に非 self-signed の `x5c` leaf も必要です。`StaticClientAttester` と `StaticKeyAttester` はテストと単独運用者専用の自己発行で、非推奨の `OID4VCIFinalReceiveRequest.AttesterKey` / `AttesterIssuer` はリクエスト単位で静的 attester をラップします。

### Transport と signer

receiver プラグインは Draft 13 では `receiverTypes.Receiver`、Final / HAIP では `receiverTypes.OID4VCIFinalTransport` を実装します。transport の契約は HTTP だけなので、プラグインが Wallet の秘密鍵を持つことはありません。秘密鍵を使う操作は `receiverTypes.OID4VCIFinalSigner`（`CreateDpopProof`、`CreateCredentialRequestJWTProofWithOptions`、`CreateClientAttestationPop`）の側にあります。実装は `Config.OID4VCISigner` で選べるので、署名を HSM やリモート署名サービスに置いたまま同梱の transport を使えます。`receiverTypes.OID4VCIFinalReceiver` は 2 つを合わせた非推奨のインターフェースで、ソース互換のため残しています。

### 署名付き issuer metadata

`Oid4vciReceiver.IssuerMetadataSigning` は OpenID4VCI 1.0 §12.2.3 の署名付き credential issuer metadata を設定します。`Request` は署名付き metadata の `Accept` ヘッダを送り、trust material が無い場合は効果がありません。`Require` は平文の `application/json` 応答を拒否します。`Oid4vciReceiver` と呼出し側の既定 HTTP client は HTTP redirect を拒否します（`ErrHTTPRedirectNotAllowed`）。`NoRedirectClient` は呼出し側の client を同様にラップします。

## Credential の受理

`Config.CredentialAcceptance`（`CredentialAcceptancePolicy`）は、受領した credential を保存してよいかを決めます。Final / HAIP の発行経路は policy を必須とし、nil の場合は fail-closed の `ErrCredentialAcceptancePolicyRequired` です。Draft 13 の `ReceiveCredential` は policy を任意のままにします。

保存前に library は次を検証します。

* **Parse と alg。** credential が parse でき、issuer JWT が対応する `alg` を持ち、SD-JWT VC では `dc+sd-jwt` / `vc+sd-jwt` の `typ` を持つ必要があります。proof に使った holder 鍵と一致しない `cnf.jwk` は拒否します。
* **Issuer trust。** `IssuerX509` は共通の署名チェーンと CRL primitive で `x5c` を検証します。`ResolveIssuerKeys` は使える `x5c` が無い credential（JWKS、DID、静的レジストリ）の候補公開鍵を供給します。`IssuerX509` が未設定の場合、`x5c` を持つ credential でも `ResolveIssuerKeys` を使います。`x5c` を持ちどちらの手段も未設定の credential は拒否します。
* **Holder binding。** `RequireHolderBinding` は `cnf` の無い credential を拒否します。
* **有効性と開示。** policy がある場合、署名、`exp` / `nbf`、SD-JWT の開示完全性（各 disclosure が `_sd` または `...` の digest からちょうど 1 回参照される）も検証します。

`SavedCredential.Verification`（`CredentialVerification`）は issuer 鍵 id、証明書 fingerprint、失効カウンタ、holder binding の結果を記録します。

### fail-closed の既定値と `UnverifiedIssuer` opt-out

* Final / HAIP 経路で `CredentialAcceptance` が無い場合、何も保存しません（`ErrCredentialAcceptancePolicyRequired`）。
* `IssuerX509` / `ResolveIssuerKeys` 以外に issuer trust の手段が無い `x5c` credential は拒否します。
* `UnverifiedIssuer: true` は issuer 鍵を認証せずに credential を保存します。`IssuerX509` も `ResolveIssuerKeys` も未設定の場合にのみ効果があり、holder binding、`exp` / `nbf`、開示完全性などの他の検証は引き続き適用されます。issuer を認証しない運用であることを 1 か所で明示するために設定します。
* `AllowUnadvertisedRevocation` は CRL / OCSP が公開されていない証明書を trust path に残し、検証済みではなく別枠として報告します。OCSP は実装しておらず、参照するのは CRL のみです。

`IssuerX509TrustOptions.RequireIssuerDNSBinding` は ecosystem policy であり（SD-JWT VC §3.5 の要件ではありません）、`iss` が `https` URL のとき leaf 証明書に host と一致する `dNSName` SAN を要求します。

## OpenID4VP 1.0 の提示（Final / HAIP）

`PresentCredential` は request を解析し、署名付き Request Object を認証し、DCQL query を満たす credential を選択し、Verifiable Presentation を署名して verifier へ送信します。`PresentCredentialWithOptions` は `OnRedirect` コールバックを追加します。

### Request Object の認証

署名付き Request Object は、呼出し側が設定した X.509 trust（`RequestObjectValidation` / `RequestObjectValidationOptions`）に対して認証します。

* `TrustAnchors` または `RootCAs` のどちらか一方に anchor を設定します。
* `x509_san_dns` は leaf 証明書の DNS SAN と `response_uri`（`direct_post` モード）または `redirect_uri` を束縛し、`x509_hash` は leaf 証明書の hash を束縛し DNS binding を要求しません。どちらも署名付き Request Object を必要とし、`X509TrustChainRoots` / `RequestObjectValidation` で解決します。
* `redirect_uri:<uri>` は client identifier に response endpoint を束縛し、コロンを含まない identifier は pre-registered client として扱います（OpenID4VP §5.9.2）。pre-registered の verifier は `Oid4vpPresenter.PreRegisteredClients` または `ResolvePreRegisteredClient` に登録し、解決できない場合は `ErrPreRegisteredClientUnknown` で拒否します。pre-registered client では request 自身の `client_metadata` は権威ではありません。
* `RequireExpiry` は `exp` の無い Request Object を拒否し、`MaxAge` は有効期間（`exp - iat`、`iat` が無い場合は `exp - now`）を制限します。`RequireExpiry` はどの profile でも既定で無効です（OpenID4VP 1.0 も HAIP も Request Object の `exp` を要求せず、公式 conformance verifier は `exp` 無しで署名します）。HAIP profile は `exp` を持つ Request Object に対し、呼出し側が `MaxAge` を 0 のままにした場合に 10 分を適用します。
* 検証結果は `CredentialPresentationRequest.RequestObjectVerification` にのみ現れ、request data からは読み取りません。client id、証明書 SHA-256 fingerprint、失効カウンタ、echo された `WalletNonce`、観測した `Delivery`（`"reference"`、`"value"`、`"query"`）、`DeliveryAttested` を記録します。

admission 時に `request_uri` で署名付き Request Object を取得し、後に値を直接再送するアプリは、`RequestObjectValidationOptions.DeliveredByReference` でそれを証明できます。HAIP §5.1 の配送要件をその request についてのみ満たします。アプリ自身の admission 経路が取得を記録した場合にだけ設定してください。

### DCQL

`ParsePresentationRequest` と `ResolveSatisfiableDCQLCredentials` は `credential_sets`（`options` と `required`）、`claims` / `claim_sets` / `values`、nested / array claim path（OpenID4VP §7）、`trusted_authorities`（`aki` のみ）、`multiple` を評価します。必須 query がすべて成立するまで応答は送信しません。保存済み credential で満たせない query は `AuthorizationRequestError{Code: AccessDeniedError}` を返します。holder binding を要求する query では、対応しない credential を除外します。

### `transaction_data`

`Config.SupportedTransactionDataTypes` はアプリが理解する `transaction_data` の `type` 値を並べます。各 object は既知の `credential_ids` を持つ base64url JSON で、hash は KB-JWT に束縛されます。hash アルゴリズムは object ごとに `transaction_data_hashes_alg` 配列（`sha-256`、`sha-384`、`sha-512`）から選び、既定は `sha-256` です。object 間でアルゴリズムが競合すると拒否します。リストが空の場合、`transaction_data` を含む要求はすべて `invalid_transaction_data` で拒否します。

### 応答の暗号化

`direct_post.jwt` は P-256 鍵の ECDH-ES と A128GCM または A256GCM を使います。両方に対応する場合、Wallet は A256GCM を優先します（HAIP §5.2）。`client_metadata.jwks` の暗号鍵は `alg` を持つ必要があり、無い鍵はスキップします。エラー応答は verifier metadata が許す場合に暗号化し、それ以外は §8.3.1 の平文 fallback を送ります。

### Digital Credentials API

`PresentCredentialToDCAPI` は W3C Digital Credentials API の invocation に応答します。`ParseDCAPIRequest` は `openid4vp-v1-unsigned`、`openid4vp-v1-signed`、`openid4vp-v1-multisigned` に対応し、platform が認証した `origin` は呼出し側が渡します（request data からは読みません）。応答は `BuildDCAPIResponse` が返し、`dc_api` は `{"vp_token": {...}}`、`dc_api.jwt` は compact JWE です。KB-JWT の `aud` は `origin:<origin>` です（OID4VP 1.0 Appendix A.4）。library に browser / OS 連携はなく、この経路で HTTP 呼出しもしません。

## 環境変数

Wallet の実行時挙動は `wallet/env/env.go` で定義された環境変数で制御されます。

| 環境変数 | 既定値 | 説明 |
| :---- | :---- | :---- |
| `VCKNOTS_WALLET_HTTP_ALLOWED` | `false`（未設定/空） | `true` を設定すると、Wallet の HTTP 通信で HTTP エンドポイントを許可します（ローカル開発/テスト用途）。HTTPS 要件を緩和するのはこの変数だけです。ただし client assertion は例外で、平文 HTTP で送るのはループバックホスト宛てに限られ、リモートの `http://` エンドポイントへの `private_key_jwt` は有効にしても拒否されます。HAIP では拒否されます。 |
| `VCKNOTS_WALLET_DEBUG` | `false`（未設定/空） | デバッグログのみを有効化します。HTTPS 必須要件は緩和**しません**。 |

`IsHTTPAllowed()` は `VCKNOTS_WALLET_HTTP_ALLOWED=true` の場合にのみ `true` になります。テストコードから `env.SetHTTPAllowed(true)`、ログには `env.SetDebugMode(true)` を呼びます。

## 既存利用者のための移行ノート

* **redirect は拒否します。** OID4VCI receiver と呼出し側の既定 HTTP client はすべての redirect を拒否します（`ErrHTTPRedirectNotAllowed`）。307/308 は Authorization、DPoP、attestation ヘッダとリクエスト body を、応答が選んだ origin に対して再送してしまうためです。redirect 追跡に依存していた呼出し側は変更が必要です。
* **HTTP 許可は明示的です。** 内蔵 dispatcher は構築時に環境の HTTP 許可をスナップショットします。Wallet を構築する前に `VCKNOTS_WALLET_HTTP_ALLOWED`（または plugin の `AllowHTTP` / `WithHTTPAllowed`）を設定してください。以前は `VCKNOTS_WALLET_DEBUG` も HTTPS を緩和していましたが、それは無くなり、`IsHTTPAllowed` が唯一の情報源です。
* **Final Request Object は認証します。** `ParsePresentationRequest` と `NewRequestBuilder` は Final 経路に従い、`x509_san_dns` / `x509_hash` の署名付き Request Object を `aud` / `exp` / `nbf`、任意の EKU / CRL policy とともに認証します。X.509 prefix を使う平文クエリパラメータ要求は拒否します。`InsecureSkipX509Verify` は Final 経路には適用されず、明示的な anchor が必要です。Draft 24 の入口は従来の挙動を保ちます。
* **`response_uri` は client identifier に束縛します。** `direct_post` モードでは `response_uri` が `x509_san_dns` / `redirect_uri` の導出値と一致する必要があり、`redirect_uri` と `response_uri` は同時に指定できません。DC API モードでは `redirect_uri` を指定してはいけません。
* **pre-registered client にはレジストリが必要です。** コロンを含まない `client_id` は format error ではなく pre-registered client であり、`PreRegisteredClients` / `ResolvePreRegisteredClient` に存在しなければ拒否します。
* **応答暗号化は A256GCM を優先します。** verifier が両方を列挙した場合、Wallet は A256GCM を使います。object 単位の `transaction_data_hashes_alg` が以前のトップレベルパラメータを置き換えます（Appendix B.3.3.1）。
* **HAIP は Request Object の有効期間を制限します。** `exp` を持つ HAIP の Request Object は既定で 10 分に制限されます（`MaxAge`）。`exp` 自体は `RequireExpiry` を設定しない限り任意です。Final の既定は変わりません。
* **receiver 契約は分割されました。** `receiverTypes.OID4VCIFinalReceiver` は非推奨で、`OID4VCIFinalTransport` + `OID4VCIFinalSigner` に置き換わりました。既存の実装と呼出し側は複合 alias でそのままコンパイルできます。5 つの署名メソッドは `OID4VCIFinalSigner` に移動しました（詳細は `wallet/API-MIGRATION.md`）。
* **Final 経路では credential 受理が必須です。** `Config.CredentialAcceptance` を設定してください。nil の場合は fail-closed です。`UnverifiedIssuer` は認証しないテスト issuer 向けに以前の緩い保存を維持します。`VerifyCredential` は成功時のみ true を返します。

## Draft 13 / Draft 24 の旧入口（引き続き対応）

以前のプロファイルは利用可能で、`InsecureSkipX509Verify` を含む従来の挙動を保ち、Final / HAIP profile を無視します。

* Draft 13 の受領: `ReceiveCredential`。
* Draft 24 の提示: `Wallet.PresentDraft24Credential`、`Oid4vpPresenter.ParseDraft24PresentationRequest`、`NewDraft24RequestBuilder`、`PresentDraft24`。
* `ParseDraft24PresentationRequest` は Presentation Exchange と DCQL の両方の request 構文に対応し、`PresentDraft24` は Presentation Exchange 応答を送信します。Final 経路は Presentation Exchange パラメータを拒否します。

新しい統合では上記の Final の入口を使い、HAIP 1.0 が必要な場合にのみ `profile.HAIP` を選んでください。

## 7. 注意事項

1. **モック鍵は本番環境で使用禁止 (CRITICAL):**
    - このチュートリアルで示したインメモリの鍵実装（および `wallet/examples/common/` の `MockKeyEntry`）は、秘密鍵を Go のヒープメモリ上に平文で保持するため、テストとデモンストレーションのみを目的としています。
    - 本番環境では、`Sign` オペレーションを OS のキーストア（iOS Secure Enclave, Android Keystore）や HSM に委譲し、秘密鍵自体がアプリケーションのメモリ空間にロードされない（non-exportable な）形で `IKeyEntry` を実装してください。

2. **GOPRIVATE の設定:**
    - `go mod download` または `go build` が失敗する場合、GOPRIVATE 環境変数の設定が欠落している可能性が最も高いです。

3. **署名フォーマットの互換性:**
    - `Sign` は ES256 について、DER エンコードされた ASN.1 署名と生の IEEE P1363 署名のどちらを返しても構いません。ライブラリが JWS 構造に埋め込む前に DER を P1363 に正規化します。

4. **永続化ストレージ (bbolt):**
    - `credstore.WithDefaultConfig()` は、`go.etcd.io/bbolt` を使って `<ユーザー設定ディレクトリ>/vcknots/wallet/.local_credstore.db` に Credential を永続化します。プロセスがこのディレクトリを作成し書き込めることを確認してください。

5. **HTTPS の強制と実行時の環境変数（`wallet/env/env.go`）:**
    - wallet はデフォルトで、Issuer と Verifier のエンドポイントに HTTPS を要求します。
    - `VCKNOTS_WALLET_HTTP_ALLOWED=true` を設定すると、HTTP エンドポイントを許可します。HTTPS を緩和するのはこの変数だけです（ローカル開発とテスト用途のみ）。
    - `VCKNOTS_WALLET_DEBUG=true` はデバッグログのみを有効化します。HTTPS 必須要件は緩和しません。
    - **本番運用の指針:** 本番環境では両方とも未設定（または `false`）のままにし、HTTPS 必須の検証を維持してください。

6. **OpenID4VP `client_id` の厳格な検証:**
    - この wallet は、OpenID4VP コンフォーマンステストに準拠するため、`client_id` を厳格に検証します。重複プレフィックス（例: `x509_san_dns:x509_san_dns:...`）や不正な形式は拒否されます。
    - `x509_san_dns:` スキームの場合、リクエスト JWT の `x5c` ヘッダーから証明書を抽出し、証明書の Subject Alternative Name (SAN) DNS フィールドと `client_id` の値を照合します。
    - 検証ロジックは `wallet/presenter/plugins/oid4vp/` を参照してください。

7. **証明書検証のテスト設定（`InsecureSkipX509Verify`）:**
    - `Oid4vpPresenter` 構造体は、テスト環境用に `InsecureSkipX509Verify` オプションを提供しています。
    - **デフォルト動作（本番環境）:** `X509TrustChainRoots` に対する完全な証明書チェーン検証を実行します。
    - **テスト設定（`InsecureSkipX509Verify: true`）:** 証明書チェーンの検証をスキップし、`x5c` ヘッダーから証明書を直接抽出します。SAN と `client_id` の照合のみを実行します。
    - ⚠️ **重大な警告**: `InsecureSkipX509Verify: true` は、コンフォーマンステストやローカル開発環境でのみ使用してください。本番環境では**絶対に**使用しないでください。

8. **DPoP サポート（オプション）:**
    - `wallet.Config{DPoP: wallet.DPoPConfig{Enabled: true}}` を設定すると、wallet は token リクエストと credential リクエストに DPoP proof を付与し、サーバーからの DPoP nonce チャレンジも処理します。

## 8. トラブルシューティング

* **Q: `go mod download` が `package ... is private` または `404 Not Found` で失敗する。**
  * **A:** GOPRIVATE 環境変数が設定されていません。「1. 前提条件」に戻り、`export GOPRIVATE="github.com/trustknots/vcknots/wallet"` が実行されていること（または mise を使用していること）を確認してください。

* **Q: `ReceiveCredential` または `PresentCredential` が `connection refused` または `timeout` で失敗する。**
  * **A:** Issuer/Verifier サーバーが起動していません。「1. 前提条件」に従い、`pnpm -F @trustknots/server start` でサーバーを起動し、http://localhost:8080 が応答することを確認してください。

* **Q: `ReceiveCredential` が `credential issuer must use https scheme` で失敗する。**
  * **A:** wallet はデフォルトで HTTPS を強制します。HTTP のサンプルサーバーに対してローカルテストする場合は、`VCKNOTS_WALLET_HTTP_ALLOWED=true` を設定してください（または `env.SetHTTPAllowed(true)` を呼び出してください）。

* **Q: `ReceiveCredential` が `failed to fetch issuer metadata` で失敗する。**
  * **A:** サーバーは起動していても、`/.well-known/openid-credential-issuer` エンドポイントが正しく機能していない可能性があります。`curl http://localhost:8080/.well-known/openid-credential-issuer` を実行して、JSON メタデータが返されることを確認してください。

* **Q: OpenID4VP コンフォーマンステストで `client_id` 検証エラーが発生する。**
  * **A:** コンフォーマンステストは、意図的に不正な `client_id`（重複プレフィックスなど）を送信して wallet の検証ロジックをテストします。`invalid client_id: duplicate prefix detected` や `SAN of the certificate and client_id did not match` のようなエラーは**期待される動作**であり、wallet が正しくセキュリティチェックを実施していることを示します。

* **Q: OpenID4VP コンフォーマンステストで `x509: certificate is not standards compliant` エラーが発生する。**
  * **A:** コンフォーマンステストサーバーは、自己署名証明書や非標準的な証明書を使用することがあります。テスト環境でのみ `InsecureSkipX509Verify: true` を設定してください。
    ```go
    p := &oid4vp.Oid4vpPresenter{
        X509TrustChainRoots:    systemRoots,
        InsecureSkipX509Verify: true, // テスト環境のみ
    }
    ```
  * ⚠️ **警告**: 本番環境では必ず `false`（または未設定）にしてください。

実行可能なエンドツーエンドのサンプル（JWT-VC、SD-JWT VC、KB-JWT 付き SD-JWT VC）は [wallet/examples/README.ja.md](https://github.com/trustknots/vcknots/blob/main/wallet/examples/README.ja.md) を参照してください。
