package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type requestObjectFixture struct {
	root, leaf   *x509.Certificate
	rootKey, key *ecdsa.PrivateKey
	now          time.Time
	server       *httptest.Server
	mu           sync.RWMutex
	crl          []byte
	crlRequests  int
}

func newRequestObjectFixture(t *testing.T, dnsNames ...string) *requestObjectFixture {
	t.Helper()
	f := &requestObjectFixture{now: time.Now().UTC().Truncate(time.Second)}
	var err error
	f.rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Verifier test root"},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &f.rootKey.PublicKey, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	f.root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f.setCRL(t, false)
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/root.crl" {
			http.NotFound(w, r)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.crlRequests++
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(f.crl)
	}))
	t.Cleanup(f.server.Close)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Verifier signing key"},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		DNSNames: dnsNames, CRLDistributionPoints: []string{f.server.URL + "/root.crl"},
	}
	der, err = x509.CreateCertificate(rand.Reader, leaf, f.root, &f.key.PublicKey, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	f.leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *requestObjectFixture) setCRL(t *testing.T, revoked bool) {
	t.Helper()
	list := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: f.now.Add(-time.Minute), NextUpdate: f.now.Add(time.Hour)}
	if revoked {
		list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(2), RevocationTime: f.now.Add(-time.Minute)}}
	}
	der, err := x509.CreateRevocationList(rand.Reader, list, f.root, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.crl = der
	f.mu.Unlock()
}

func (f *requestObjectFixture) clientID() string {
	hash := sha256.Sum256(f.leaf.Raw)
	return "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])
}

func (f *requestObjectFixture) options() RequestObjectValidationOptions {
	return RequestObjectValidationOptions{TrustAnchors: []*x509.Certificate{f.root}, Now: func() time.Time { return f.now }}
}

func (f *requestObjectFixture) presenter() *Oid4vpPresenter {
	options := f.options()
	return &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &options}
}

func (f *requestObjectFixture) claims() map[string]any {
	return map[string]any{
		"aud": "https://self-issued.me/v2", "client_id": f.clientID(),
		"nonce": "nonce", "response_type": "vp_token", "response_mode": "direct_post.jwt",
		"response_uri": "https://verifier.example/response",
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"urn:eudi:pid:1"}},
		}}},
	}
}

func (f *requestObjectFixture) sign(t *testing.T, claims map[string]any, options *jose.SignerOptions) string {
	t.Helper()
	if options == nil {
		options = (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt").WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: f.key}, options)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (f *requestObjectFixture) parse(t *testing.T, claims map[string]any) (*CredentialPresentationRequest, error) {
	t.Helper()
	uri := "openid4vp://authorize?" + url.Values{"client_id": []string{f.clientID()}, "request": []string{f.sign(t, claims, nil)}}.Encode()
	return f.presenter().ParsePresentationRequest(uri)
}
