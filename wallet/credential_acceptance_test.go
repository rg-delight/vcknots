package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/trustknots/vcknots/wallet/profile"
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

func newAcceptanceStore(t *testing.T) *credstore.CredStoreDispatcher {
	t.Helper()
	storage, err := local.NewLocalCredentialStorage(filepath.Join(t.TempDir(), "credentials.db"))
	require.NoError(t, err)
	store, err := credstore.NewCredStoreDispatcher(credstore.WithPlugin(local.Local, storage))
	require.NoError(t, err)
	return store
}

func acceptanceEntryCount(t *testing.T, store *credstore.CredStoreDispatcher) int {
	t.Helper()
	result, err := store.GetCredentialEntries(0, nil, credstoreTypes.SupportedCredStoreTypes(0))
	require.NoError(t, err)
	if result.Entries == nil {
		return 0
	}
	return len(*result.Entries)
}

// newAcceptanceWallet builds a wallet with an explicit protocol profile and no
// receiver plugin: the acceptance path runs on a credential the test already
// holds, so no issuance transport is needed to reach it.
func newAcceptanceWallet(t *testing.T, p profile.Profile, policy *CredentialAcceptancePolicy) (*Wallet, *credstore.CredStoreDispatcher) {
	t.Helper()
	store := newAcceptanceStore(t)
	w, err := NewWalletWithConfig(Config{Profile: p, CredStore: store, CredentialAcceptance: policy})
	require.NoError(t, err)
	return w, store
}

func newAcceptanceFixture(t *testing.T, policy *CredentialAcceptancePolicy) *acceptanceFixture {
	t.Helper()
	store := newAcceptanceStore(t)

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
	return f.wallet.storeAndParseCredential(t.Context(), &wire, credential.SDJwtVC, holder, false)
}

func (f *acceptanceFixture) entryCount(t *testing.T) int {
	t.Helper()
	return acceptanceEntryCount(t, f.store)
}

type acceptanceWire struct {
	issuer string
	vct    string
	typ    string
	cnf    *jose.JSONWebKey
	// cnfRaw sets the confirmation object verbatim and takes precedence over
	// cnf, so a test can build the confirmation methods the wallet refuses.
	cnfRaw          map[string]any
	exp             time.Time
	nbf             *time.Time
	disclosures     map[string]string
	extraDisclosure bool
	// sdAlg overrides the _sd_alg claim written next to the disclosure
	// digests, so a hash the wallet does not accept can be offered.
	sdAlg string
	x5c   []string
	// signingKey is the ECDSA issuer key of an ES256 credential, which is what
	// most cases need. alg and signer together replace it when the credential
	// must be signed with another algorithm or key type.
	signingKey      *ecdsa.PrivateKey
	alg             jose.SignatureAlgorithm
	signer          any
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
	if spec.alg == "" {
		spec.alg = jose.ES256
	}
	if spec.signer == nil {
		require.NotNil(t, spec.signingKey)
		spec.signer = spec.signingKey
	}

	claims := map[string]any{
		"iss": spec.issuer,
		"vct": spec.vct,
		"iat": time.Now().Unix(),
		"exp": spec.exp.Unix(),
	}
	if spec.nbf != nil {
		claims["nbf"] = spec.nbf.Unix()
	}
	switch {
	case spec.cnfRaw != nil:
		claims["cnf"] = spec.cnfRaw
	case spec.cnf != nil:
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
		if spec.sdAlg != "" {
			claims["_sd_alg"] = spec.sdAlg
		}
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
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: spec.alg, Key: spec.signer}, signerOptions)
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

	t.Run("x5c is ignored when the caller resolves issuer keys without X.509 trust", func(t *testing.T) {
		leafPublic := jose.JSONWebKey{Key: chain.leafKey.Public(), KeyID: "leaf"}
		fixture := newAcceptanceFixture(t, &CredentialAcceptancePolicy{
			ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
				return []jose.JSONWebKey{leafPublic}, nil
			},
		})
		wire := buildAcceptanceWire(t, acceptanceWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder})
		saved, err := fixture.storeCredential(t, wire, &holder)
		require.NoError(t, err)
		require.Nil(t, saved.Verification.CertificateSHA256)
		require.Equal(t, "leaf", saved.Verification.IssuerKeyID)
		require.Equal(t, 1, fixture.entryCount(t))
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
	// The Final issuance path requires an acceptance policy, so the property
	// under test here — one unusable credential discards the whole batch — is
	// exercised with issuer authentication explicitly opted out of rather than
	// with the policy missing.
	fixture := newAcceptanceFixture(t, &CredentialAcceptancePolicy{UnverifiedIssuer: true})
	holder := fixture.holder.PublicKey()
	valid := buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: newTestECKey(t)})
	response := &receiverTypes.CredentialResponse{Credentials: []any{valid, "this-is-not-a-credential"}}
	metadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialConfigurationSupported: map[string]receiverTypes.CredentialConfiguration{
			"acceptance-config": {Format: "dc+sd-jwt"},
		},
	}
	_, err := fixture.wallet.storeOID4VCIFinalCredentialResponse(t.Context(), response, metadata, "acceptance-config", &holder)
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

func TestVerifyCredentialForAcceptanceRequiresPolicy(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	wire := buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: newTestECKey(t)})

	t.Run("a nil policy fails closed when the caller requires one", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, nil)
		_, _, err := fixture.wallet.verifyCredentialForAcceptanceContext(context.Background(), []byte(wire), credential.SDJwtVC, &holder, true)
		require.ErrorIs(t, err, ErrCredentialAcceptancePolicyRequired)
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("the same credential parses when the caller does not require one", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, nil)
		parsed, verification, err := fixture.wallet.verifyCredentialForAcceptanceContext(context.Background(), []byte(wire), credential.SDJwtVC, &holder, false)
		require.NoError(t, err)
		require.NotNil(t, parsed)
		require.True(t, verification.HolderBound)
	})

	t.Run("a configured policy satisfies the requirement", func(t *testing.T) {
		issuerKey := newTestECKey(t)
		signed := buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: issuerKey, kid: "issuer-key-1"})
		fixture := newAcceptanceFixture(t, &CredentialAcceptancePolicy{
			ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
				return []jose.JSONWebKey{{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"}}, nil
			},
		})
		_, verification, err := fixture.wallet.verifyCredentialForAcceptanceContext(context.Background(), []byte(signed), credential.SDJwtVC, &holder, true)
		require.NoError(t, err)
		require.Equal(t, "issuer-key-1", verification.IssuerKeyID)
	})
}

func TestUnverifiedIssuerOptOutAcceptsUnauthenticatedX5C(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	wire := buildAcceptanceWire(t, acceptanceWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder})

	t.Run("a policy without issuer trust keeps rejecting the x5c credential", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, &CredentialAcceptancePolicy{})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "x5c issuer authentication is not configured")
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("the opt-out stores it and records no issuer authentication", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, &CredentialAcceptancePolicy{UnverifiedIssuer: true})
		saved, err := fixture.storeCredential(t, wire, &holder)
		require.NoError(t, err)
		require.NotNil(t, saved.Verification)
		require.True(t, saved.Verification.HolderBound)
		require.Nil(t, saved.Verification.CertificateSHA256)
		require.Empty(t, saved.Verification.IssuerKeyID)
		require.Equal(t, 1, fixture.entryCount(t))
	})

	t.Run("the opt-out leaves the rest of the policy in force", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, &CredentialAcceptancePolicy{UnverifiedIssuer: true})
		expired := buildAcceptanceWire(t, acceptanceWire{
			signingKey: chain.leafKey,
			x5c:        chain.x5c(),
			cnf:        &holder,
			exp:        time.Now().Add(-time.Hour),
		})
		_, err := fixture.storeCredential(t, expired, &holder)
		require.ErrorContains(t, err, "expired")
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("the opt-out yields to configured issuer trust", func(t *testing.T) {
		otherChain := newTestIssuerChain(t, nil)
		fixture := newAcceptanceFixture(t, &CredentialAcceptancePolicy{
			UnverifiedIssuer: true,
			IssuerX509: &IssuerX509TrustOptions{
				TrustAnchors:                otherChain.anchors(),
				AllowUnadvertisedRevocation: true,
			},
		})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "issuer certificate chain is not trusted")
		require.Equal(t, 0, fixture.entryCount(t))
	})
}

func TestHAIPCredentialRejectsAnchorInX5CWithRootCAs(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	wire := buildAcceptanceWire(t, acceptanceWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder})

	poolPolicy := func() *CredentialAcceptancePolicy {
		roots := x509.NewCertPool()
		roots.AddCert(chain.caCert)
		return &CredentialAcceptancePolicy{IssuerX509: &IssuerX509TrustOptions{
			RootCAs:                     roots,
			AllowUnadvertisedRevocation: true,
		}}
	}

	t.Run("Final accepts the pool-trusted chain", func(t *testing.T) {
		w, store := newAcceptanceWallet(t, profile.Final, poolPolicy())
		saved, err := w.storeAndParseCredential(t.Context(), &wire, credential.SDJwtVC, &holder, false)
		require.NoError(t, err)
		require.Len(t, saved.Verification.CertificateSHA256, 2)
		require.Equal(t, 1, acceptanceEntryCount(t, store))
	})

	t.Run("HAIP rejects the trust anchor carried in x5c", func(t *testing.T) {
		w, store := newAcceptanceWallet(t, profile.HAIP, poolPolicy())
		_, err := w.storeAndParseCredential(t.Context(), &wire, credential.SDJwtVC, &holder, false)
		require.ErrorContains(t, err, "HAIP forbids including the trust anchor certificate in the x5c header")
		require.Equal(t, 0, acceptanceEntryCount(t, store))
	})
}

func TestAcceptanceRejectsUnsupportedConfirmationMethod(t *testing.T) {
	issuerKey := newTestECKey(t)
	holder := newMockKeyEntry().PublicKey()
	policy := func() *CredentialAcceptancePolicy {
		return &CredentialAcceptancePolicy{ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
			return []jose.JSONWebKey{{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"}}, nil
		}}
	}

	confirmations := map[string]map[string]any{
		"kid":      {"kid": "urn:issuer:holder-key-1"},
		"x5t#S256": {"x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"},
		"jwe":      {"jwe": "eyJhbGciOiJSU0EtT0FFUCJ9.encrypted.key"},
	}
	for member, confirmation := range confirmations {
		t.Run("cnf."+member+" is rejected", func(t *testing.T) {
			fixture := newAcceptanceFixture(t, policy())
			wire := buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, kid: "issuer-key-1", cnfRaw: confirmation})
			_, err := fixture.storeCredential(t, wire, &holder)
			require.ErrorIs(t, err, ErrHolderBindingConfirmationUnsupported)
			require.ErrorContains(t, err, "cnf members: "+member)
			require.Equal(t, 0, fixture.entryCount(t))
		})
	}

	t.Run("cnf.jwk alongside another member is still accepted", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, policy())
		wire := buildAcceptanceWire(t, acceptanceWire{
			signingKey: issuerKey,
			kid:        "issuer-key-1",
			cnfRaw:     map[string]any{"jwk": holder.Public(), "kid": "urn:issuer:holder-key-1"},
		})
		saved, err := fixture.storeCredential(t, wire, &holder)
		require.NoError(t, err)
		require.True(t, saved.Verification.HolderBound)
		require.Equal(t, 1, fixture.entryCount(t))
	})

	t.Run("a credential without cnf is unaffected", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, policy())
		wire := buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, kid: "issuer-key-1"})
		saved, err := fixture.storeCredential(t, wire, &holder)
		require.NoError(t, err)
		require.False(t, saved.Verification.HolderBound)
		require.Equal(t, 1, fixture.entryCount(t))
	})
}

// acceptanceIssuer is an issuer key of one algorithm together with the JWK a
// resolution hook hands back for it, so the algorithm coverage cases differ
// only in the key they are built from.
type acceptanceIssuer struct {
	algorithm jose.SignatureAlgorithm
	private   any
	public    jose.JSONWebKey
}

// acceptanceIssuers builds one issuer per signature algorithm the bundled
// verification plugins implement. The RSA keys are generated once and shared:
// the algorithms differ in digest and padding, not in the key.
func acceptanceIssuers(t *testing.T) []acceptanceIssuer {
	t.Helper()
	issuers := make([]acceptanceIssuer, 0, 10)
	for _, ec := range []struct {
		algorithm jose.SignatureAlgorithm
		curve     elliptic.Curve
	}{
		{jose.ES256, elliptic.P256()},
		{jose.ES384, elliptic.P384()},
		{jose.ES512, elliptic.P521()},
	} {
		key, err := ecdsa.GenerateKey(ec.curve, rand.Reader)
		require.NoError(t, err)
		issuers = append(issuers, acceptanceIssuer{
			algorithm: ec.algorithm,
			private:   key,
			public:    jose.JSONWebKey{Key: &key.PublicKey, KeyID: "issuer-key-1", Algorithm: string(ec.algorithm)},
		})
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, algorithm := range []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512} {
		issuers = append(issuers, acceptanceIssuer{
			algorithm: algorithm,
			private:   rsaKey,
			public:    jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "issuer-key-1", Algorithm: string(algorithm)},
		})
	}

	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	issuers = append(issuers, acceptanceIssuer{
		algorithm: jose.EdDSA,
		private:   edPrivate,
		public:    jose.JSONWebKey{Key: edPublic, KeyID: "issuer-key-1", Algorithm: string(jose.EdDSA)},
	})
	return issuers
}

// TestVerifyCredentialForAcceptance_SigningAlgorithms proves that every
// algorithm the default verification dispatcher registers authenticates a real
// credential end to end, and that reaching it takes a policy that lists the
// algorithm: registering a plugin alone never widens what is accepted.
func TestVerifyCredentialForAcceptance_SigningAlgorithms(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()

	for _, issuer := range acceptanceIssuers(t) {
		t.Run(string(issuer.algorithm), func(t *testing.T) {
			wire := buildAcceptanceWire(t, acceptanceWire{
				alg:    issuer.algorithm,
				signer: issuer.private,
				kid:    "issuer-key-1",
				cnf:    &holder,
			})
			// The issuer key is handed back the way a JWKS or a DID document
			// delivers one: serialized JWK JSON, so the kty and crv of every
			// algorithm go through the JWK to public key conversion.
			encoded, err := issuer.public.MarshalJSON()
			require.NoError(t, err)
			resolve := func(string, map[string]any) ([]jose.JSONWebKey, error) {
				var key jose.JSONWebKey
				if err := key.UnmarshalJSON(encoded); err != nil {
					return nil, err
				}
				return []jose.JSONWebKey{key}, nil
			}

			listed, _ := newAcceptanceWallet(t, profile.Final, &CredentialAcceptancePolicy{
				ResolveIssuerKeys: resolve,
				SigningAlgorithms: []jose.SignatureAlgorithm{issuer.algorithm},
			})
			parsed, verification, err := listed.VerifyCredentialForAcceptance(t.Context(), []byte(wire), credential.SDJwtVC, &holder)
			require.NoError(t, err)
			require.NotNil(t, parsed)
			require.Equal(t, "issuer-key-1", verification.IssuerKeyID)
			require.True(t, verification.HolderBound)

			// A tampered signature must fail for every algorithm, so a
			// positive result cannot come from a check that was skipped.
			tampered := buildAcceptanceWire(t, acceptanceWire{
				alg:             issuer.algorithm,
				signer:          issuer.private,
				kid:             "issuer-key-1",
				cnf:             &holder,
				tamperSignature: true,
			})
			_, _, err = listed.VerifyCredentialForAcceptance(t.Context(), []byte(tampered), credential.SDJwtVC, &holder)
			require.ErrorIs(t, err, ErrIssuerSignatureInvalid)

			// The same credential under a policy that lists no algorithm falls
			// back to DefaultCredentialSigningAlgorithms, which is ES256 alone.
			unlisted, _ := newAcceptanceWallet(t, profile.Final, &CredentialAcceptancePolicy{ResolveIssuerKeys: resolve})
			_, _, err = unlisted.VerifyCredentialForAcceptance(t.Context(), []byte(wire), credential.SDJwtVC, &holder)
			if issuer.algorithm == jose.ES256 {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrCredentialAlgUnsupported)
			require.ErrorContains(t, err, "is not listed by the credential acceptance policy")
		})
	}
}

// TestVerifyCredentialForAcceptance_AlgorithmWithoutPlugin covers the second
// half of the algorithm decision: an algorithm the caller's policy lists but no
// verification plugin implements is still refused, rather than accepted with
// its signature unchecked.
func TestVerifyCredentialForAcceptance_AlgorithmWithoutPlugin(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	issuerKey := newTestECKey(t)
	policy := &CredentialAcceptancePolicy{
		ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
			return []jose.JSONWebKey{{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"}}, nil
		},
		SigningAlgorithms: []jose.SignatureAlgorithm{jose.ES256, jose.HS256, jose.SignatureAlgorithm("none")},
	}
	w, _ := newAcceptanceWallet(t, profile.Final, policy)

	accepted := buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, kid: "issuer-key-1", cnf: &holder})
	_, _, err := w.VerifyCredentialForAcceptance(t.Context(), []byte(accepted), credential.SDJwtVC, &holder)
	require.NoError(t, err)

	// HS256 is a MAC: the wallet holds no shared secret and registers no
	// plugin for it, so listing it in the policy cannot make it acceptable.
	_, _, err = w.VerifyCredentialForAcceptance(t.Context(), []byte(unsignedAcceptanceWire(t, "HS256")), credential.SDJwtVC, &holder)
	require.ErrorIs(t, err, ErrCredentialAlgUnsupported)
	require.ErrorContains(t, err, "is not supported by the verifier")

	// "none" is refused before the policy is consulted at all.
	_, _, err = w.VerifyCredentialForAcceptance(t.Context(), []byte(unsignedAcceptanceWire(t, "none")), credential.SDJwtVC, &holder)
	require.ErrorIs(t, err, ErrCredentialAlgUnsupported)
	require.ErrorContains(t, err, "alg header is missing or none")
}

// unsignedAcceptanceWire assembles an SD-JWT VC whose protected header names
// algorithm and whose signature segment is meaningless. It exists because a
// signing library will not produce "none" or a MAC over a public key, and the
// wallet must still refuse such a credential.
func unsignedAcceptanceWire(t *testing.T, algorithm string) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": algorithm, "typ": "dc+sd-jwt"})
	require.NoError(t, err)
	claims, err := json.Marshal(map[string]any{
		"iss": "https://issuer.example.test",
		"vct": "urn:test:acceptance",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	return strings.Join([]string{
		base64.RawURLEncoding.EncodeToString(header),
		base64.RawURLEncoding.EncodeToString(claims),
		base64.RawURLEncoding.EncodeToString([]byte("not-a-signature")),
	}, ".") + "~"
}

// leafOnlyX5C is the chain HAIP §6.1.1 asks for: the issuer's signing
// certificate without the trust anchor the wallet already holds.
func (c testIssuerChain) leafOnlyX5C() []string {
	return []string{base64.StdEncoding.EncodeToString(c.leafCert.Raw)}
}

// TestVerifyCredentialForAcceptance_TypedFailures walks every acceptance
// failure the library names with a sentinel. Each case runs the same wallet
// twice: once on a credential it must accept, so the rejection cannot come from
// a misconfigured fixture, and once on the input that triggers the condition.
func TestVerifyCredentialForAcceptance_TypedFailures(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	otherHolder := newMockKeyEntry().PublicKey()
	issuerKey := newTestECKey(t)
	issuerJWK := jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"}
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})

	// resolvingPolicy authenticates the issuer through a resolution hook that
	// knows one kid, which is all most cases need.
	resolvingPolicy := func() *CredentialAcceptancePolicy {
		return &CredentialAcceptancePolicy{ResolveIssuerKeys: func(_ string, header map[string]any) ([]jose.JSONWebKey, error) {
			if kid, _ := header["kid"].(string); kid != "issuer-key-1" {
				return nil, nil
			}
			return []jose.JSONWebKey{issuerJWK}, nil
		}}
	}
	x509Policy := func(mutate func(*IssuerX509TrustOptions)) *CredentialAcceptancePolicy {
		options := &IssuerX509TrustOptions{TrustAnchors: chain.anchors(), AllowUnadvertisedRevocation: true}
		if mutate != nil {
			mutate(options)
		}
		return &CredentialAcceptancePolicy{IssuerX509: options}
	}
	signed := func(spec acceptanceWire) string {
		if spec.signingKey == nil && spec.signer == nil {
			spec.signingKey = issuerKey
			spec.kid = "issuer-key-1"
		}
		if spec.cnfRaw == nil && spec.cnf == nil {
			spec.cnf = &holder
		}
		return buildAcceptanceWire(t, spec)
	}
	x5cSigned := func(spec acceptanceWire) string {
		spec.signingKey = chain.leafKey
		if spec.x5c == nil {
			spec.x5c = chain.leafOnlyX5C()
		}
		spec.cnf = &holder
		return buildAcceptanceWire(t, spec)
	}
	disclosed := map[string]string{"given_name": "Erika"}

	cases := []struct {
		name     string
		profile  profile.Profile
		policy   *CredentialAcceptancePolicy
		accepted string
		rejected string
		sentinel error
	}{
		{
			name:     "parse",
			policy:   resolvingPolicy(),
			accepted: signed(acceptanceWire{}),
			rejected: "this-is-not-a-credential",
			sentinel: ErrCredentialParse,
		},
		{
			name:     "typ",
			policy:   resolvingPolicy(),
			accepted: signed(acceptanceWire{typ: "vc+sd-jwt"}),
			rejected: signed(acceptanceWire{typ: "JWT"}),
			sentinel: ErrCredentialTypInvalid,
		},
		{
			name:     "alg",
			policy:   resolvingPolicy(),
			accepted: signed(acceptanceWire{}),
			rejected: unsignedAcceptanceWire(t, "none"),
			sentinel: ErrCredentialAlgUnsupported,
		},
		{
			name: "holder binding missing",
			policy: func() *CredentialAcceptancePolicy {
				policy := resolvingPolicy()
				policy.RequireHolderBinding = true
				return policy
			}(),
			accepted: signed(acceptanceWire{}),
			// No cnf claim at all, which is what RequireHolderBinding refuses.
			rejected: buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, kid: "issuer-key-1"}),
			sentinel: ErrHolderBindingMissing,
		},
		{
			name:     "holder binding mismatch",
			policy:   resolvingPolicy(),
			accepted: signed(acceptanceWire{}),
			rejected: signed(acceptanceWire{cnf: &otherHolder}),
			sentinel: ErrHolderBindingMismatch,
		},
		{
			name:     "issuer key unresolved",
			policy:   resolvingPolicy(),
			accepted: signed(acceptanceWire{}),
			rejected: signed(acceptanceWire{signingKey: issuerKey, kid: "another-key"}),
			sentinel: ErrIssuerKeyUnresolved,
		},
		{
			name:     "issuer signature invalid",
			policy:   resolvingPolicy(),
			accepted: signed(acceptanceWire{}),
			rejected: signed(acceptanceWire{tamperSignature: true}),
			sentinel: ErrIssuerSignatureInvalid,
		},
		{
			name:     "expired",
			policy:   resolvingPolicy(),
			accepted: signed(acceptanceWire{}),
			rejected: signed(acceptanceWire{exp: time.Now().Add(-time.Hour)}),
			sentinel: ErrCredentialExpired,
		},
		{
			name:     "not yet valid",
			policy:   resolvingPolicy(),
			accepted: signed(acceptanceWire{}),
			rejected: signed(acceptanceWire{nbf: ptr(time.Now().Add(time.Hour))}),
			sentinel: ErrCredentialNotYetValid,
		},
		{
			name:     "disclosure integrity",
			policy:   resolvingPolicy(),
			accepted: signed(acceptanceWire{disclosures: disclosed}),
			rejected: signed(acceptanceWire{disclosures: disclosed, extraDisclosure: true}),
			sentinel: ErrDisclosureIntegrity,
		},
		{
			name:     "sd_alg",
			policy:   resolvingPolicy(),
			accepted: signed(acceptanceWire{disclosures: disclosed}),
			rejected: signed(acceptanceWire{disclosures: disclosed, sdAlg: "sha-1"}),
			sentinel: ErrSDAlgUnsupported,
		},
		{
			name:     "issuer DNS binding",
			policy:   x509Policy(func(options *IssuerX509TrustOptions) { options.RequireIssuerDNSBinding = true }),
			accepted: x5cSigned(acceptanceWire{}),
			rejected: x5cSigned(acceptanceWire{issuer: "https://other.example.test"}),
			sentinel: ErrIssuerDNSBindingFailed,
		},
		{
			name:     "HAIP x5c required",
			profile:  profile.HAIP,
			policy:   x509Policy(nil),
			accepted: x5cSigned(acceptanceWire{}),
			rejected: signed(acceptanceWire{}),
			sentinel: ErrHAIPX5CRequired,
		},
		{
			name:     "HAIP trust anchor in x5c",
			profile:  profile.HAIP,
			policy:   x509Policy(nil),
			accepted: x5cSigned(acceptanceWire{}),
			rejected: x5cSigned(acceptanceWire{x5c: chain.x5c()}),
			sentinel: ErrHAIPTrustAnchorInX5C,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			walletProfile := testCase.profile
			if walletProfile == "" {
				walletProfile = profile.Final
			}
			w, store := newAcceptanceWallet(t, walletProfile, testCase.policy)

			parsed, verification, err := w.VerifyCredentialForAcceptance(t.Context(), []byte(testCase.accepted), credential.SDJwtVC, &holder)
			require.NoError(t, err, "the control credential must be accepted")
			require.NotNil(t, parsed)
			require.NotNil(t, verification)

			_, _, err = w.VerifyCredentialForAcceptance(t.Context(), []byte(testCase.rejected), credential.SDJwtVC, &holder)
			require.ErrorIs(t, err, testCase.sentinel)
			// Acceptance never stores: both runs leave the store untouched.
			require.Equal(t, 0, acceptanceEntryCount(t, store))
		})
	}

	t.Run("policy required", func(t *testing.T) {
		w, _ := newAcceptanceWallet(t, profile.Final, nil)
		_, _, err := w.VerifyCredentialForAcceptance(t.Context(), []byte(signed(acceptanceWire{})), credential.SDJwtVC, &holder)
		require.ErrorIs(t, err, ErrCredentialAcceptancePolicyRequired)
	})
}

// TestVerifyCredentialWithPolicy covers the per-call form: the same wallet
// judges one credential under two policies, and a nil policy runs the minimum
// rules without authenticating an issuer.
func TestVerifyCredentialWithPolicy(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	otherHolder := newMockKeyEntry().PublicKey()
	issuerKey := newTestECKey(t)
	issuerJWK := jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"}
	wire := buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, kid: "issuer-key-1", cnf: &holder})

	// The wallet itself is configured with a policy that resolves nothing, so
	// the outcome below can only come from the policy passed per call.
	w, _ := newAcceptanceWallet(t, profile.Final, &CredentialAcceptancePolicy{})

	trusting := &CredentialAcceptancePolicy{ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
		return []jose.JSONWebKey{issuerJWK}, nil
	}}
	_, verification, err := w.VerifyCredentialWithPolicy(t.Context(), []byte(wire), credential.SDJwtVC, &holder, trusting)
	require.NoError(t, err)
	require.Equal(t, "issuer-key-1", verification.IssuerKeyID)
	require.True(t, verification.HolderBound)

	_, _, err = w.VerifyCredentialForAcceptance(t.Context(), []byte(wire), credential.SDJwtVC, &holder)
	require.ErrorIs(t, err, ErrIssuerKeyUnresolved)

	expiring := &CredentialAcceptancePolicy{
		ResolveIssuerKeys: trusting.ResolveIssuerKeys,
		Now:               func() time.Time { return time.Now().Add(2 * time.Hour) },
	}
	_, _, err = w.VerifyCredentialWithPolicy(t.Context(), []byte(wire), credential.SDJwtVC, &holder, expiring)
	require.ErrorIs(t, err, ErrCredentialExpired)

	t.Run("a nil policy authenticates no issuer and still binds the holder", func(t *testing.T) {
		_, verification, err := w.VerifyCredentialWithPolicy(t.Context(), []byte(wire), credential.SDJwtVC, &holder, nil)
		require.NoError(t, err)
		require.Empty(t, verification.IssuerKeyID)
		require.True(t, verification.HolderBound)

		_, _, err = w.VerifyCredentialWithPolicy(t.Context(), []byte(wire), credential.SDJwtVC, &otherHolder, nil)
		require.ErrorIs(t, err, ErrHolderBindingMismatch)
	})
}

func ptr[T any](value T) *T {
	return &value
}

// TestVerifyCredentialWithPolicyRequiresAProvableHolderBinding pins the
// fail-closed reading of RequireHolderBinding: a credential that carries a cnf
// confirmation key is only holder-bound once the wallet has compared it with a
// holder key, so an acceptance call that supplies none must be refused instead
// of stored with HolderBound left false.
func TestVerifyCredentialWithPolicyRequiresAProvableHolderBinding(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	issuerKey := newTestECKey(t)
	issuerJWK := jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"}
	wire := []byte(buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, kid: "issuer-key-1", cnf: &holder}))
	resolve := func(string, map[string]any) ([]jose.JSONWebKey, error) { return []jose.JSONWebKey{issuerJWK}, nil }

	w, _ := newAcceptanceWallet(t, profile.Final, &CredentialAcceptancePolicy{})
	requiring := &CredentialAcceptancePolicy{ResolveIssuerKeys: resolve, RequireHolderBinding: true}

	t.Run("a cnf compared with the holder key is accepted", func(t *testing.T) {
		_, verification, err := w.VerifyCredentialWithPolicy(t.Context(), wire, credential.SDJwtVC, &holder, requiring)
		require.NoError(t, err)
		require.True(t, verification.HolderBound)
	})

	t.Run("a cnf with no holder key to compare is refused", func(t *testing.T) {
		_, _, err := w.VerifyCredentialWithPolicy(t.Context(), wire, credential.SDJwtVC, nil, requiring)
		require.ErrorIs(t, err, ErrHolderBindingMissing)
	})

	t.Run("without the requirement the same credential is accepted unbound", func(t *testing.T) {
		optional := &CredentialAcceptancePolicy{ResolveIssuerKeys: resolve}
		_, verification, err := w.VerifyCredentialWithPolicy(t.Context(), wire, credential.SDJwtVC, nil, optional)
		require.NoError(t, err)
		require.False(t, verification.HolderBound)
	})
}

// TestIssuerSignedJOSEHeader pins the credential-acceptance header extraction:
// the protected header is read without verifying the signature, and for an
// SD-JWT VC only the issuer-signed JWT before the first disclosure separator is
// considered.
func TestIssuerSignedJOSEHeader(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"dc+sd-jwt"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"vct":"https://example/pid"}`))

	t.Run("sd-jwt-vc-stops-at-the-disclosure", func(t *testing.T) {
		got, err := IssuerSignedJOSEHeader(credential.SDJwtVC, []byte(header+"."+payload+".signature~disclosure"))
		require.NoError(t, err)
		require.Equal(t, "dc+sd-jwt", got["typ"])
	})
	t.Run("jwt-vc-header", func(t *testing.T) {
		got, err := IssuerSignedJOSEHeader(credential.JwtVc, []byte(header+"."+payload+".signature"))
		require.NoError(t, err)
		require.Equal(t, "ES256", got["alg"])
	})
	t.Run("not-a-compact-jws", func(t *testing.T) {
		_, err := IssuerSignedJOSEHeader(credential.JwtVc, []byte("not-a-jwt"))
		require.ErrorIs(t, err, ErrCredentialParse)
	})
	t.Run("header-not-base64url", func(t *testing.T) {
		_, err := IssuerSignedJOSEHeader(credential.JwtVc, []byte("!!!."+payload+".signature"))
		require.ErrorIs(t, err, ErrCredentialParse)
	})
	t.Run("header-not-json", func(t *testing.T) {
		notJSON := base64.RawURLEncoding.EncodeToString([]byte("not json"))
		_, err := IssuerSignedJOSEHeader(credential.JwtVc, []byte(notJSON+"."+payload+".signature"))
		require.ErrorIs(t, err, ErrCredentialParse)
	})
}
