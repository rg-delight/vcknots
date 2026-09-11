package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

type acceptanceFixture struct {
	wallet *Wallet
	store  *credstore.CredStoreDispatcher
	server *httptest.Server
	wireCh chan string
	holder *mockKeyEntry
}

func newAcceptanceFixture(t *testing.T, policy *CredentialAcceptancePolicy) *acceptanceFixture {
	t.Helper()
	storage, err := local.NewLocalCredentialStorage(filepath.Join(t.TempDir(), "credentials.db"))
	require.NoError(t, err)
	store, err := credstore.NewCredStoreDispatcher(credstore.WithPlugin(local.Local, storage))
	require.NoError(t, err)

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	writeJSON := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Error(err)
		}
	}
	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"credential_issuer":     server.URL,
			"credential_endpoint":   server.URL + "/credential",
			"nonce_endpoint":        server.URL + "/nonce",
			"authorization_servers": []string{server.URL},
			"credential_configurations_supported": map[string]any{
				"acceptance-config": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:acceptance"},
			},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":         server.URL,
			"token_endpoint": server.URL + "/token",
			"pre-authorized_grant_anonymous_access_supported": true,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"access_token": "acceptance-token", "token_type": "Bearer", "c_nonce": "acceptance-nonce"})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"c_nonce": "acceptance-nonce"})
	})
	wireCh := make(chan string, 1)
	mux.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
		select {
		case wire := <-wireCh:
			writeJSON(w, map[string]any{"credential": wire})
		case <-r.Context().Done():
		}
	})

	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{HTTPClient: server.Client()}))
	require.NoError(t, err)
	w, err := NewWalletWithConfig(Config{CredStore: store, Receiver: receiving, CredentialAcceptance: policy})
	require.NoError(t, err)
	return &acceptanceFixture{wallet: w, store: store, server: server, wireCh: wireCh, holder: newMockKeyEntry()}
}

func (f *acceptanceFixture) send(wire string) {
	f.wireCh <- wire
}

func (f *acceptanceFixture) receive(t *testing.T) (*SavedCredential, error) {
	t.Helper()
	issuer, err := url.Parse(f.server.URL)
	require.NoError(t, err)
	return f.wallet.ReceiveCredential(ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuer,
			CredentialConfigurationIDs: []string{"acceptance-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {PreAuthorizedCode: "code"},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  f.holder,
	})
}

func (f *acceptanceFixture) storeCredential(t *testing.T, wire string, holder *jose.JSONWebKey) (*SavedCredential, error) {
	t.Helper()
	return f.wallet.storeAndParseCredential(&wire, credential.SDJwtVC, holder)
}

func (f *acceptanceFixture) entryCount(t *testing.T) int {
	t.Helper()
	result, err := f.store.GetCredentialEntries(0, nil, credstoreTypes.SupportedCredStoreTypes(0))
	require.NoError(t, err)
	if result.Entries == nil {
		return 0
	}
	return len(*result.Entries)
}

type acceptanceWire struct {
	issuer          string
	vct             string
	typ             string
	cnf             *jose.JSONWebKey
	exp             time.Time
	nbf             *time.Time
	disclosures     map[string]string
	extraDisclosure bool
	x5c             []string
	signingKey      *ecdsa.PrivateKey
	kid             string
	tamperSignature bool
}

func buildAcceptanceWire(t *testing.T, spec acceptanceWire) string {
	t.Helper()
	if spec.typ == "" {
		spec.typ = "dc+sd-jwt"
	}
	if spec.issuer == "" {
		spec.issuer = "https://issuer.example.test"
	}
	if spec.vct == "" {
		spec.vct = "urn:test:acceptance"
	}
	if spec.exp.IsZero() {
		spec.exp = time.Now().Add(time.Hour)
	}
	require.NotNil(t, spec.signingKey)

	claims := map[string]any{
		"iss": spec.issuer,
		"vct": spec.vct,
		"iat": time.Now().Unix(),
		"exp": spec.exp.Unix(),
	}
	if spec.nbf != nil {
		claims["nbf"] = spec.nbf.Unix()
	}
	if spec.cnf != nil {
		claims["cnf"] = map[string]any{"jwk": spec.cnf.Public()}
	}

	var disclosures, hashes []string
	names := make([]string, 0, len(spec.disclosures))
	for name := range spec.disclosures {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw, err := json.Marshal([]any{"salt-" + name, name, spec.disclosures[name]})
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		disclosures = append(disclosures, encoded)
		digest := sha256.Sum256([]byte(encoded))
		hashes = append(hashes, base64.RawURLEncoding.EncodeToString(digest[:]))
	}
	if len(hashes) > 0 {
		claims["_sd"] = hashes
		claims["_sd_alg"] = "sha-256"
	}
	if spec.extraDisclosure {
		raw, err := json.Marshal([]any{"orphan-salt", "orphan_claim", "orphan-value"})
		require.NoError(t, err)
		disclosures = append(disclosures, base64.RawURLEncoding.EncodeToString(raw))
	}

	signerOptions := (&jose.SignerOptions{}).WithType(jose.ContentType(spec.typ))
	if len(spec.x5c) > 0 {
		signerOptions = signerOptions.WithHeader("x5c", spec.x5c)
	}
	if spec.kid != "" {
		signerOptions = signerOptions.WithHeader("kid", spec.kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: spec.signingKey}, signerOptions)
	require.NoError(t, err)
	signed, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	wire := strings.Join(append([]string{signed}, disclosures...), "~") + "~"
	if spec.tamperSignature {
		wire = tamperIssuerSignature(t, wire)
	}
	return wire
}

func tamperIssuerSignature(t *testing.T, wire string) string {
	t.Helper()
	parts := strings.SplitN(wire, "~", 2)
	jwtParts := strings.Split(parts[0], ".")
	require.Len(t, jwtParts, 3)
	signature, err := base64.RawURLEncoding.DecodeString(jwtParts[2])
	require.NoError(t, err)
	require.NotEmpty(t, signature)
	signature[0] ^= 0xFF
	jwtParts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return strings.Join(jwtParts, ".") + "~" + parts[1]
}

func newTestECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

type testIssuerChain struct {
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	leafCert *x509.Certificate
	leafKey  *ecdsa.PrivateKey
}

func (c testIssuerChain) x5c() []string {
	return []string{
		base64.StdEncoding.EncodeToString(c.leafCert.Raw),
		base64.StdEncoding.EncodeToString(c.caCert.Raw),
	}
}

func (c testIssuerChain) anchors() []*x509.Certificate {
	return []*x509.Certificate{c.caCert}
}

func newTestIssuerChain(t *testing.T, dnsNames []string) testIssuerChain {
	t.Helper()
	caKey := newTestECKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Acceptance Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey := newTestECKey(t)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Acceptance Test Issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return testIssuerChain{caCert: caCert, caKey: caKey, leafCert: leafCert, leafKey: leafKey}
}

func TestCredentialAcceptance_NilPolicy(t *testing.T) {
	t.Run("malformed credential in the response is rejected and not stored", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, nil)
		fixture.send("this-is-not-a-credential")
		_, err := fixture.receive(t)
		require.Error(t, err)
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("cnf bound to another holder key is rejected", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, nil)
		holder := fixture.holder.PublicKey()
		otherHolder := newMockKeyEntry().PublicKey()
		wire := buildAcceptanceWire(t, acceptanceWire{cnf: &otherHolder, signingKey: newTestECKey(t)})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "credential is bound to a different holder key")
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("matching cnf is stored with HolderBound", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, nil)
		holder := fixture.holder.PublicKey()
		wire := buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: newTestECKey(t)})
		saved, err := fixture.storeCredential(t, wire, &holder)
		require.NoError(t, err)
		require.NotNil(t, saved.Verification)
		require.True(t, saved.Verification.HolderBound)
		require.Equal(t, 1, fixture.entryCount(t))
	})
}

func TestCredentialAcceptance_X509Policy(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	otherChain := newTestIssuerChain(t, []string{"issuer.example.test"})

	policy := func(anchors []*x509.Certificate, dnsBinding bool) *CredentialAcceptancePolicy {
		return &CredentialAcceptancePolicy{
			IssuerX509: &IssuerX509TrustOptions{
				TrustAnchors:                anchors,
				AllowUnadvertisedRevocation: true,
				RequireIssuerDNSBinding:     dnsBinding,
			},
		}
	}

	t.Run("valid x5c credential is stored and records verification", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, policy(chain.anchors(), false))
		wire := buildAcceptanceWire(t, acceptanceWire{
			signingKey:  chain.leafKey,
			x5c:         chain.x5c(),
			cnf:         &holder,
			disclosures: map[string]string{"given_name": "Taro"},
		})
		saved, err := fixture.storeCredential(t, wire, &holder)
		require.NoError(t, err)
		require.NotNil(t, saved.Verification)
		require.Len(t, saved.Verification.CertificateSHA256, 2)
		require.GreaterOrEqual(t, saved.Verification.RevocationUnadvertised, 1)
		require.Equal(t, saved.Verification.CertificateSHA256[0], saved.Verification.IssuerKeyID)
		require.Equal(t, 1, fixture.entryCount(t))
	})

	t.Run("anchors that do not contain the CA are rejected", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, policy(otherChain.anchors(), false))
		wire := buildAcceptanceWire(t, acceptanceWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "issuer certificate chain is not trusted")
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("expired credential is rejected", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, policy(chain.anchors(), false))
		wire := buildAcceptanceWire(t, acceptanceWire{
			signingKey: chain.leafKey,
			x5c:        chain.x5c(),
			cnf:        &holder,
			exp:        time.Now().Add(-time.Hour),
		})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "expired")
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("tampered signature is rejected", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, policy(chain.anchors(), false))
		wire := buildAcceptanceWire(t, acceptanceWire{
			signingKey:      chain.leafKey,
			x5c:             chain.x5c(),
			cnf:             &holder,
			tamperSignature: true,
		})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "issuer signature could not be verified")
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("disclosure without a referencing digest is rejected", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, policy(chain.anchors(), false))
		wire := buildAcceptanceWire(t, acceptanceWire{
			signingKey:      chain.leafKey,
			x5c:             chain.x5c(),
			cnf:             &holder,
			disclosures:     map[string]string{"given_name": "Taro"},
			extraDisclosure: true,
		})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "disclosure is not referenced")
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("issuer DNS binding mismatch is rejected", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, policy(chain.anchors(), true))
		wire := buildAcceptanceWire(t, acceptanceWire{
			signingKey: chain.leafKey,
			x5c:        chain.x5c(),
			cnf:        &holder,
			issuer:     "https://other.example.test",
		})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "not bound to issuer host")
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("issuer DNS binding match is accepted", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, policy(chain.anchors(), true))
		wire := buildAcceptanceWire(t, acceptanceWire{
			signingKey: chain.leafKey,
			x5c:        chain.x5c(),
			cnf:        &holder,
			issuer:     "https://issuer.example.test",
		})
		saved, err := fixture.storeCredential(t, wire, &holder)
		require.NoError(t, err)
		require.NotNil(t, saved)
		require.Equal(t, 1, fixture.entryCount(t))
	})

	t.Run("non SD-JWT typ is rejected", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, policy(chain.anchors(), false))
		wire := buildAcceptanceWire(t, acceptanceWire{
			signingKey: chain.leafKey,
			x5c:        chain.x5c(),
			cnf:        &holder,
			typ:        "JWT",
		})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "typ header")
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("x5c without configured issuer trust is rejected", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, &CredentialAcceptancePolicy{})
		wire := buildAcceptanceWire(t, acceptanceWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "x5c issuer authentication is not configured")
		require.Equal(t, 0, fixture.entryCount(t))
	})
}

func TestCredentialAcceptance_ResolveIssuerKeys(t *testing.T) {
	issuerKey := newTestECKey(t)
	issuerJWK := jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"}
	holder := newMockKeyEntry().PublicKey()

	t.Run("resolved key verifies and records the kid", func(t *testing.T) {
		policy := &CredentialAcceptancePolicy{ResolveIssuerKeys: func(issuer string, header map[string]any) ([]jose.JSONWebKey, error) {
			return []jose.JSONWebKey{issuerJWK}, nil
		}}
		fixture := newAcceptanceFixture(t, policy)
		wire := buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, kid: "issuer-key-1", cnf: &holder})
		saved, err := fixture.storeCredential(t, wire, &holder)
		require.NoError(t, err)
		require.NotNil(t, saved.Verification)
		require.Equal(t, "issuer-key-1", saved.Verification.IssuerKeyID)
		require.Equal(t, 1, fixture.entryCount(t))
	})

	t.Run("only wrong resolved keys are rejected", func(t *testing.T) {
		wrongKey := newTestECKey(t)
		wrongJWK := jose.JSONWebKey{Key: &wrongKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"}
		policy := &CredentialAcceptancePolicy{ResolveIssuerKeys: func(issuer string, header map[string]any) ([]jose.JSONWebKey, error) {
			return []jose.JSONWebKey{wrongJWK}, nil
		}}
		fixture := newAcceptanceFixture(t, policy)
		wire := buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, kid: "issuer-key-1", cnf: &holder})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "issuer signature could not be verified")
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("nil hook without x5c is rejected", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, &CredentialAcceptancePolicy{})
		wire := buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, cnf: &holder})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "issuer key resolution is not configured")
		require.Equal(t, 0, fixture.entryCount(t))
	})
}

func TestCredentialAcceptance_FinalResponseAllOrNothing(t *testing.T) {
	fixture := newAcceptanceFixture(t, nil)
	holder := fixture.holder.PublicKey()
	valid := buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: newTestECKey(t)})
	response := &receiverTypes.CredentialResponse{Credentials: []any{valid, "this-is-not-a-credential"}}
	metadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialConfigurationSupported: map[string]receiverTypes.CredentialConfiguration{
			"acceptance-config": {Format: "dc+sd-jwt"},
		},
	}
	_, err := fixture.wallet.storeOID4VCIFinalCredentialResponse(response, metadata, "acceptance-config", &holder)
	require.Error(t, err)
	require.Equal(t, 0, fixture.entryCount(t))
}

func TestVerifyCredential_ValidAndWrongKey(t *testing.T) {
	fixture := newAcceptanceFixture(t, nil)
	issuerKey := newTestECKey(t)
	holder := jose.JSONWebKey{Key: &issuerKey.PublicKey, Algorithm: "ES256"}
	wire := buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: issuerKey})
	saved, err := fixture.storeCredential(t, wire, &holder)
	require.NoError(t, err)
	require.True(t, fixture.wallet.VerifyCredential(saved.Credential, holder))

	wrongKey := newTestECKey(t)
	require.False(t, fixture.wallet.VerifyCredential(saved.Credential, jose.JSONWebKey{Key: &wrongKey.PublicKey, Algorithm: "ES256"}))
}
