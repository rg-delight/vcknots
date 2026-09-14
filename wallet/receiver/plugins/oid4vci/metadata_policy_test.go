package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestIssuerMetadataDoesNotRetryInvalidOrForbiddenResponses(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusInternalServerError, http.StatusNotFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if requests == 1 {
					w.WriteHeader(status)
					fmt.Fprint(w, `{"credential_request_encryption":{"encryption_required":"invalid"}}`)
					return
				}
				fmt.Fprint(w, `{"credential_request_encryption":{"encryption_required":false}}`)
			}))
			defer server.Close()
			endpoint, err := common.ParseURIField(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
			metadata, err := receiver.FetchIssuerMetadata(*endpoint, types.Oid4vci)
			if err == nil || metadata != nil {
				t.Fatalf("metadata = %v, error = %v; want failure", metadata, err)
			}
			if requests != 1 {
				t.Fatalf("requests = %d, want 1", requests)
			}
		})
	}
}

func TestIssuerMetadataRetriesOnlyMissingDistinctLocalDiscoveryPath(t *testing.T) {
	var paths []string
	var acceptedIdentifier string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/.well-known/openid-credential-issuer/tenant" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"credential_issuer":"https://discarded.example","credential_request_encryption":{"encryption_required":true}}`)
			return
		}
		// §12.2.4 binds credential_issuer to the requested identifier, which
		// for this tenant is the base URL plus the /tenant path.
		acceptedIdentifier = "http://" + r.Host + "/tenant"
		fmt.Fprint(w, `{"credential_issuer":"`+acceptedIdentifier+`"}`)
	}))
	defer server.Close()
	endpoint, err := common.ParseURIField(server.URL + "/tenant")
	if err != nil {
		t.Fatal(err)
	}
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	metadata, err := receiver.FetchIssuerMetadata(*endpoint, types.Oid4vci)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[1] != "/tenant/.well-known/openid-credential-issuer" {
		t.Fatalf("paths = %v", paths)
	}
	if metadata.CredentialIssuer != acceptedIdentifier || metadata.CredentialRequestEncryption != nil {
		t.Fatalf("metadata from discarded response leaked: %+v", metadata)
	}
}

// signedMetadataFixture issues the certificates and JWTs the §12.2.3 signed
// Credential Issuer Metadata tests need.
type signedMetadataFixture struct {
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey
}

func newSignedMetadataFixture(t *testing.T) signedMetadataFixture {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Signed Metadata Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Signed Metadata Test Issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return signedMetadataFixture{caCert: caCert, caKey: caKey, leaf: leaf, leafKey: leafKey}
}

// sign serializes claims as signed metadata carrying chain in its x5c header.
func (f signedMetadataFixture) sign(t *testing.T, claims map[string]any, chain []*x509.Certificate) string {
	t.Helper()
	encoded := make([]string, 0, len(chain))
	for _, certificate := range chain {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(certificate.Raw))
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: f.leafKey},
		(&jose.SignerOptions{}).WithType("openidvci-issuer-metadata+jwt").WithHeader("x5c", encoded),
	)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return serialized
}

// serveIssuerMetadata starts a Credential Issuer that answers the §12.2.2
// well-known path with a document the test supplies, and records the Accept
// header the wallet negotiated with.
func serveIssuerMetadata(t *testing.T, tls bool, document func(identifier string) (contentType string, body string)) (serverURL string, client *http.Client, acceptHeader func() string) {
	t.Helper()
	var accept atomic.Value
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		accept.Store(r.Header.Get("Accept"))
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		contentType, body := document(scheme + "://" + r.Host)
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	server := httptest.NewUnstartedServer(handler)
	if tls {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server.URL, server.Client(), func() string {
		stored, _ := accept.Load().(string)
		return stored
	}
}

func TestFetchIssuerMetadataVerifiesSignedMetadata(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	var compact string
	serverURL, client, acceptHeader := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		compact = fixture.sign(t, map[string]any{
			"sub":                 identifier,
			"iss":                 identifier,
			"iat":                 time.Now().Add(-time.Minute).Unix(),
			"exp":                 time.Now().Add(time.Hour).Unix(),
			"credential_issuer":   identifier,
			"credential_endpoint": identifier + "/credential",
			"nonce_endpoint":      identifier + "/nonce",
		}, []*x509.Certificate{fixture.leaf})
		return "application/jwt", compact
	})

	receiver := &Oid4vciReceiver{
		HTTPClient: client,
		AllowHTTP:  true,
		IssuerMetadataSigning: &IssuerMetadataSigningOptions{
			Request:                     true,
			TrustAnchors:                []*x509.Certificate{fixture.caCert},
			AllowUnadvertisedRevocation: true,
		},
	}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err != nil {
		t.Fatalf("FetchIssuerMetadata() error = %v", err)
	}
	if !strings.Contains(acceptHeader(), "application/jwt") {
		t.Fatalf("Accept = %q, want signed metadata to be requested", acceptHeader())
	}
	// §12.2.3 requires every metadata parameter to be a top-level claim of the
	// payload, so the payload is the whole document: nothing is merged in from
	// an unsigned response.
	if metadata.CredentialIssuer != serverURL {
		t.Fatalf("credential_issuer = %q, want %q", metadata.CredentialIssuer, serverURL)
	}
	if metadata.NonceEndpoint == nil || !strings.HasSuffix(url.URL(*metadata.NonceEndpoint).Path, "/nonce") {
		t.Fatalf("nonce_endpoint = %#v", metadata.NonceEndpoint)
	}
	if metadata.SignedMetadata != compact {
		t.Fatalf("SignedMetadata = %q, want the compact JWS", metadata.SignedMetadata)
	}
	if metadata.MetadataSignature == nil {
		t.Fatal("MetadataSignature is nil, want the signer identity")
	}
	digest := sha256.Sum256(fixture.leaf.Raw)
	if metadata.MetadataSignature.LeafCertificateSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("LeafCertificateSHA256 = %q", metadata.MetadataSignature.LeafCertificateSHA256)
	}
	if metadata.MetadataSignature.Subject != fixture.leaf.Subject.String() {
		t.Fatalf("Subject = %q", metadata.MetadataSignature.Subject)
	}
	if metadata.MetadataSignature.IssuedAt.IsZero() || metadata.MetadataSignature.ExpiresAt == nil {
		t.Fatalf("MetadataSignature = %#v", metadata.MetadataSignature)
	}
}

func TestFetchIssuerMetadataRejectsUntrustedSignedMetadata(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	foreign := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		return "application/jwt", foreign.sign(t, map[string]any{
			"sub":                 identifier,
			"iat":                 time.Now().Unix(),
			"credential_issuer":   identifier,
			"credential_endpoint": identifier + "/credential",
		}, []*x509.Certificate{foreign.leaf})
	})

	receiver := &Oid4vciReceiver{
		HTTPClient: client,
		AllowHTTP:  true,
		IssuerMetadataSigning: &IssuerMetadataSigningOptions{
			Request:                     true,
			TrustAnchors:                []*x509.Certificate{fixture.caCert},
			AllowUnadvertisedRevocation: true,
		},
	}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err == nil {
		t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
	}
	if !strings.Contains(err.Error(), "signed issuer metadata is not trusted") {
		t.Fatalf("error = %v", err)
	}
}

func TestFetchIssuerMetadataRejectsIssuerMismatchInSignedMetadata(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		return "application/jwt", fixture.sign(t, map[string]any{
			// §12.2.3: sub is "REQUIRED. String matching the Credential Issuer
			// Identifier".
			"sub":                 "https://other-issuer.example",
			"iat":                 time.Now().Unix(),
			"credential_issuer":   identifier,
			"credential_endpoint": identifier + "/credential",
		}, []*x509.Certificate{fixture.leaf})
	})

	receiver := &Oid4vciReceiver{
		HTTPClient: client,
		AllowHTTP:  true,
		IssuerMetadataSigning: &IssuerMetadataSigningOptions{
			Request:                     true,
			TrustAnchors:                []*x509.Certificate{fixture.caCert},
			AllowUnadvertisedRevocation: true,
		},
	}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err == nil {
		t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
	}
	if !strings.Contains(err.Error(), `signed issuer metadata sub "https://other-issuer.example" does not match the credential issuer`) {
		t.Fatalf("error = %v", err)
	}
}

// TestFetchIssuerMetadataRejectsTrailingSlashInSignedMetadataSub pins that the
// sub comparison is exact. §12.2.4 states the rule for a Credential Issuer's
// identity: "The value MUST be identical to the Credential Issuer's identifier
// value into which the well-known URI string was inserted to create the URL used
// to retrieve the metadata. If these values are not identical (when compared
// using a simple string comparison with no normalization), the data contained in
// the response MUST NOT be used." A sub that differs only by a trailing slash is
// therefore a different identifier, not the same one written differently.
func TestFetchIssuerMetadataRejectsTrailingSlashInSignedMetadataSub(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		return "application/jwt", fixture.sign(t, map[string]any{
			"sub":                 identifier + "/",
			"iat":                 time.Now().Unix(),
			"credential_issuer":   identifier,
			"credential_endpoint": identifier + "/credential",
		}, []*x509.Certificate{fixture.leaf})
	})

	receiver := &Oid4vciReceiver{
		HTTPClient: client,
		AllowHTTP:  true,
		IssuerMetadataSigning: &IssuerMetadataSigningOptions{
			Request:                     true,
			TrustAnchors:                []*x509.Certificate{fixture.caCert},
			AllowUnadvertisedRevocation: true,
		},
	}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err == nil {
		t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
	}
	if !strings.Contains(err.Error(), `does not match the credential issuer "`+serverURL+`"`) {
		t.Fatalf("error = %v", err)
	}
}

// TestFetchIssuerMetadataRejectsCredentialIssuerMismatchInSignedMetadata pins
// that §12.2.4 also binds the credential_issuer member of a signed payload: the
// sub claim and the credential_issuer parameter must both name the requested
// Credential Issuer Identifier.
func TestFetchIssuerMetadataRejectsCredentialIssuerMismatchInSignedMetadata(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		return "application/jwt", fixture.sign(t, map[string]any{
			"sub":                 identifier,
			"iat":                 time.Now().Unix(),
			"credential_issuer":   "https://other-issuer.example",
			"credential_endpoint": identifier + "/credential",
		}, []*x509.Certificate{fixture.leaf})
	})

	receiver := &Oid4vciReceiver{
		HTTPClient: client,
		AllowHTTP:  true,
		IssuerMetadataSigning: &IssuerMetadataSigningOptions{
			Request:                     true,
			TrustAnchors:                []*x509.Certificate{fixture.caCert},
			AllowUnadvertisedRevocation: true,
		},
	}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err == nil {
		t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
	}
	if !errors.Is(err, ErrIssuerIdentifierMismatch) {
		t.Fatalf("errors.Is(ErrIssuerIdentifierMismatch) = false, err = %v", err)
	}
}

// HAIP §4.1: "the X.509 certificate of the trust anchor MUST NOT be included in
// the `x5c` JOSE header of the signed request."
func TestFetchIssuerMetadataRejectsAnchorInSignedMetadataX5C(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, true, func(identifier string) (string, string) {
		return "application/jwt", fixture.sign(t, map[string]any{
			"sub":                 identifier,
			"iat":                 time.Now().Unix(),
			"credential_issuer":   identifier,
			"credential_endpoint": identifier + "/credential",
		}, []*x509.Certificate{fixture.leaf, fixture.caCert})
	})
	signing := &IssuerMetadataSigningOptions{
		Request:                     true,
		TrustAnchors:                []*x509.Certificate{fixture.caCert},
		AllowUnadvertisedRevocation: true,
	}

	haip := &Oid4vciReceiver{HTTPClient: client, Profile: profile.HAIP, IssuerMetadataSigning: signing}
	metadata, err := haip.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err == nil {
		t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
	}
	if !strings.Contains(err.Error(), "HAIP forbids including the trust anchor certificate in the x5c header") {
		t.Fatalf("error = %v", err)
	}

	// The same chain is accepted outside HAIP, where the rule does not apply.
	final := &Oid4vciReceiver{HTTPClient: client, Profile: profile.Final, IssuerMetadataSigning: signing}
	if _, err := final.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci); err != nil {
		t.Fatalf("Final FetchIssuerMetadata() error = %v", err)
	}
}

func TestFetchIssuerMetadataRequireRejectsUnsignedResponse(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		return "application/json", `{"credential_issuer":"` + identifier + `","credential_endpoint":"` + identifier + `/credential"}`
	})

	receiver := &Oid4vciReceiver{
		HTTPClient: client,
		AllowHTTP:  true,
		IssuerMetadataSigning: &IssuerMetadataSigningOptions{
			Request:                     true,
			Require:                     true,
			TrustAnchors:                []*x509.Certificate{fixture.caCert},
			AllowUnadvertisedRevocation: true,
		},
	}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err == nil {
		t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
	}
	if !strings.Contains(err.Error(), "issuer metadata is not signed but signed metadata is required") {
		t.Fatalf("error = %v", err)
	}

	t.Run("requiring signed metadata without trust material is a configuration error", func(t *testing.T) {
		unconfigured := &Oid4vciReceiver{
			HTTPClient:            client,
			AllowHTTP:             true,
			IssuerMetadataSigning: &IssuerMetadataSigningOptions{Require: true},
		}
		_, err := unconfigured.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
		if err == nil || !strings.Contains(err.Error(), "signed issuer metadata is required but no trust anchors are configured") {
			t.Fatalf("error = %v", err)
		}
	})
}

// HAIP §4.1 makes signed metadata conditional -- "When Ecosystem policies
// require Issuer Authentication to a higher level than possible with TLS alone"
// -- so a HAIP wallet must still accept the unsigned document every Credential
// Issuer publishes.
func TestFetchIssuerMetadataHAIPAcceptsUnsignedByDefault(t *testing.T) {
	serverURL, client, acceptHeader := serveIssuerMetadata(t, true, func(identifier string) (string, string) {
		return "application/json", `{"credential_issuer":"` + identifier + `","credential_endpoint":"` + identifier + `/credential"}`
	})

	receiver := &Oid4vciReceiver{HTTPClient: client, Profile: profile.HAIP}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err != nil {
		t.Fatalf("FetchIssuerMetadata() error = %v", err)
	}
	if metadata.CredentialIssuer != serverURL {
		t.Fatalf("credential_issuer = %q, want %q", metadata.CredentialIssuer, serverURL)
	}
	if metadata.SignedMetadata != "" || metadata.MetadataSignature != nil {
		t.Fatalf("unsigned metadata must not claim a signature: %#v", metadata.MetadataSignature)
	}
	// Without trust material the wallet cannot authenticate a signed document,
	// so it does not ask for one it would have to reject.
	if strings.Contains(acceptHeader(), "application/jwt") {
		t.Fatalf("Accept = %q, want application/json only", acceptHeader())
	}
}
