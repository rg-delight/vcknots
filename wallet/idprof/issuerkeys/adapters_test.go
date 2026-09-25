package issuerkeys

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
)

// The adapter is handed to a hook whose signature the rest of the library
// fixes; this assignment fails to compile if it drifts.
var _ func(ctx context.Context, issuer string, header map[string]any) ([]jose.JSONWebKey, error) = (&Resolver{}).StatusListKeyFunc(Request{}, nil)

// stubTransport answers GET requests from canned JSON documents keyed by URL
// and refuses every other request, so a fixture can publish documents under
// any https origin without a network.
type stubTransport struct {
	mu        sync.Mutex
	documents map[string]any
	requests  []string
}

func newStubTransport() *stubTransport {
	return &stubTransport{documents: map[string]any{}}
}

func (s *stubTransport) publish(url string, document any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.documents[url] = document
}

func (s *stubTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.requests = append(s.requests, request.URL.String())
	document, ok := s.documents[request.URL.String()]
	s.mu.Unlock()
	if !ok {
		return nil, errors.New("unexpected request")
	}
	body, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}, nil
}

func (s *stubTransport) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func TestResolutionCandidateFor(t *testing.T) {
	t.Parallel()
	signer := newES256Key(t, "issuer-key-1")
	network := newStubTransport()
	network.publish("https://issuer.example.test/.well-known/jwt-vc-issuer", map[string]any{
		"issuer": "https://issuer.example.test", "jwks": jwksObject(t, signer.public),
	})
	resolver := &Resolver{HTTPClient: &http.Client{Transport: network}, Mechanisms: Mechanisms{JWTVCIssuerMetadata: true}, Now: fixedNow}
	resolution, err := resolver.Resolve(context.Background(), Request{
		Issuer: "https://issuer.example.test", Algorithm: "ES256",
		CredentialFormat: FormatSDJWTVC, CredentialIssuer: "https://issuer.example.test",
	})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	// The verified key comes back from the acceptor without its kid; the
	// thumbprint still finds its candidate.
	candidate, ok := resolution.CandidateFor(jose.JSONWebKey{Key: signer.public.Key})
	if !ok || candidate.Mechanism != MechanismJWTVCIssuerMetadata || candidate.Issuer != "https://issuer.example.test" {
		t.Errorf("CandidateFor = %+v, %v", candidate, ok)
	}
	if _, ok := resolution.CandidateFor(newES256Key(t, "").public); ok {
		t.Errorf("CandidateFor found a key the resolver never produced")
	}
}

// statusListFixture is an issuer that signs Status List Tokens under an https
// identifier, with a CA that certifies its signing key and JWT VC Issuer
// Metadata publishing another key.
type statusListFixture struct {
	issuer   string
	ca       testCertificate
	leaf     testCertificate
	metadata testKey
	resolver *Resolver
	network  *stubTransport
}

func newStatusListFixture(t *testing.T) *statusListFixture {
	t.Helper()
	ca := newTestCA(t, "status list root")
	network := newStubTransport()
	metadata := newES256Key(t, "metadata-key")
	issuer := "https://issuer.example.test"
	network.publish(issuer+"/.well-known/jwt-vc-issuer", map[string]any{"issuer": issuer, "jwks": jwksObject(t, metadata.public)})
	return &statusListFixture{
		issuer:   issuer,
		ca:       ca,
		leaf:     newTestLeaf(t, ca, "issuer.example.test"),
		metadata: metadata,
		network:  network,
		resolver: &Resolver{
			HTTPClient: &http.Client{Transport: network},
			Mechanisms: Mechanisms{X5C: true, JWTVCIssuerMetadata: true, DIDJWK: true, DIDConfiguration: true},
			Now:        fixedNow,
		},
	}
}

func (f *statusListFixture) template() Request {
	return Request{CredentialFormat: FormatSDJWTVC, CredentialIssuer: f.issuer}
}

func (f *statusListFixture) trust(anchors ...*x509.Certificate) *X5CTrust {
	return &X5CTrust{TrustAnchors: anchors, AllowUnadvertisedRevocation: true}
}

func (f *statusListFixture) header(leaf testCertificate) map[string]any {
	chain := x5cOf(leaf)
	values := make([]any, 0, len(chain))
	for _, value := range chain {
		values = append(values, value)
	}
	return map[string]any{"alg": "ES256", "typ": "statuslist+jwt", "x5c": values}
}

func TestStatusListKeys(t *testing.T) {
	t.Parallel()

	t.Run("a trusted chain puts the leaf key first, then the metadata key", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		keys, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), f.trust(f.ca.certificate), f.issuer, f.header(f.leaf))
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismX5CTrustedChain, MechanismJWTVCIssuerMetadata}) {
			t.Fatalf("mechanisms = %v", got)
		}
		if len(keys) != 2 || !keys[0].IsPublic() {
			t.Fatalf("keys = %+v", keys)
		}
		trusted, ok := resolution.CandidateFor(jose.JSONWebKey{Key: f.leaf.certificate.PublicKey})
		if !ok || trusted.Mechanism != MechanismX5CTrustedChain || trusted.Issuer != f.issuer || len(trusted.CertificateSHA256) != 2 {
			t.Errorf("trusted candidate = %+v, %v", trusted, ok)
		}
	})

	t.Run("a chain reaching no configured anchor is recorded and the metadata key is offered", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		other := newTestCA(t, "other root")
		keys, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), f.trust(other.certificate), f.issuer, f.header(f.leaf))
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismJWTVCIssuerMetadata}) || len(keys) != 1 {
			t.Fatalf("mechanisms = %v", got)
		}
		diagnostic := diagnosticFor(t, resolution.Diagnostics, RungX5C)
		if diagnostic.Failure != failureChainUntrusted || diagnostic.Attempted || diagnostic.CandidateCount != 0 {
			t.Errorf("x5c diagnostic = %+v", diagnostic)
		}
	})

	t.Run("an untrusted chain and nothing else is an unresolved error naming the chain", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		f.resolver.Mechanisms.JWTVCIssuerMetadata = false
		_, _, err := f.resolver.StatusListKeys(context.Background(), f.template(), f.trust(), f.issuer, f.header(f.leaf))
		var unresolved *UnresolvedError
		if !errors.As(err, &unresolved) {
			t.Fatalf("StatusListKeys error = %v, want *UnresolvedError", err)
		}
		if got := diagnosticFor(t, unresolved.Diagnostics, RungX5C).Failure; got != failureChainUntrusted {
			t.Errorf("x5c failure = %q", got)
		}
	})

	t.Run("a leaf that does not name the issuer host is not trusted", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		stranger := newTestLeaf(t, f.ca, "other.example.test")
		_, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), f.trust(f.ca.certificate), f.issuer, f.header(stranger))
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismJWTVCIssuerMetadata}) {
			t.Errorf("mechanisms = %v", got)
		}
		if got := diagnosticFor(t, resolution.Diagnostics, RungX5C).Failure; got != failureChainUntrusted {
			t.Errorf("x5c failure = %q", got)
		}
	})

	t.Run("a revocation status that cannot be established ends the verification", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		trust := f.trust(f.ca.certificate)
		trust.AllowUnadvertisedRevocation = false
		keys, _, err := f.resolver.StatusListKeys(context.Background(), f.template(), trust, f.issuer, f.header(f.leaf))
		if err == nil || keys != nil {
			t.Fatalf("StatusListKeys = %v, %v; want the chain refusal", keys, err)
		}
		if errors.Is(err, ErrNoIssuerKeyResolved) {
			t.Fatalf("a revocation refusal fell through to the ladder: %v", err)
		}
		if code, _ := common.CodeOf(err); code != "x509_chain_revocation_unknown" {
			t.Errorf("code = %q, want x509_chain_revocation_unknown", code)
		}
	})

	t.Run("a kid naming a DID does not make an https iss a DID", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		didValue := didJWK(t, f.metadata.public)
		header := map[string]any{"alg": "ES256", "kid": didValue + "#0"}
		keys, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), nil, f.issuer, header)
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismJWTVCIssuerMetadata}) || len(keys) != 1 {
			t.Fatalf("mechanisms = %v", got)
		}
	})

	t.Run("a token signed under a DID iss is offered the DID Configuration candidate", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		signer := newES256Key(t, "")
		didValue := didJWK(t, signer.public)
		linkageHeader, linkageClaims := domainLinkage(didValue, didValue+"#0", f.issuer)
		f.network.publish(f.issuer+"/.well-known/did-configuration.json", map[string]any{
			"linked_dids": []any{signJWT(t, signer, linkageHeader, linkageClaims)},
		})
		keys, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), nil, didValue, map[string]any{"alg": "ES256", "kid": didValue + "#0"})
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismDIDConfigurationBinding}) || len(keys) != 1 {
			t.Fatalf("mechanisms = %v", got)
		}
	})

	t.Run("without x5c trust the chain is never walked", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		_, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), nil, f.issuer, f.header(f.leaf))
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismJWTVCIssuerMetadata}) {
			t.Errorf("mechanisms = %v", got)
		}
		if diagnostic := diagnosticFor(t, resolution.Diagnostics, RungX5C); diagnostic.Failure != "" || !diagnostic.Attempted {
			t.Errorf("x5c diagnostic = %+v, want the untouched rung result", diagnostic)
		}
	})

	t.Run("the x5c rung switched off leaves the chain unwalked", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		f.resolver.Mechanisms.X5C = false
		_, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(), f.trust(f.ca.certificate), f.issuer, f.header(f.leaf))
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismJWTVCIssuerMetadata}) {
			t.Errorf("mechanisms = %v", got)
		}
	})
}
