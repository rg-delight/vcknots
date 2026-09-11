package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// dpopNonceTestServer is a Credential Issuer with a Nonce Endpoint and a
// Credential Endpoint on the same origin, which is the granularity RFC 9449
// Section 8.2 assigns a DPoP nonce to. It records the DPoP proof of every
// credential request so a test can read the proof the wallet sent first.
type dpopNonceTestServer struct {
	server *httptest.Server

	mu              sync.Mutex
	nonceCalls      int
	credentialProof []string
}

// newDPoPNonceTestServer starts the fixture. serverDPoPNonce is sent as the
// RFC 9449 Section 8.2 DPoP-Nonce response header of the Nonce Response when it
// is non-empty, and omitted entirely when it is empty.
func newDPoPNonceTestServer(t *testing.T, serverDPoPNonce string) *dpopNonceTestServer {
	t.Helper()
	fixture := &dpopNonceTestServer{}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nonce":
			fixture.mu.Lock()
			fixture.nonceCalls++
			fixture.mu.Unlock()
			if serverDPoPNonce != "" {
				w.Header().Set("DPoP-Nonce", serverDPoPNonce)
			}
			_ = mockserver.JSONResponse(w, http.StatusOK, map[string]any{"c_nonce": "c-nonce-1"})
		case "/credential":
			fixture.mu.Lock()
			fixture.credentialProof = append(fixture.credentialProof, r.Header.Get("DPoP"))
			fixture.mu.Unlock()
			_ = mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential": "credential-1"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *dpopNonceTestServer) proofs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.credentialProof...)
}

// dpopProofClaims parses a DPoP proof JWT for its claims. The signature is not
// verified: the test only needs to read what the wallet put in the proof.
func dpopProofClaims(t *testing.T, proof string) map[string]any {
	t.Helper()
	parsed, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("failed to parse DPoP proof %q: %v", proof, err)
	}
	claims := map[string]any{}
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("failed to read DPoP proof claims: %v", err)
	}
	return claims
}

// newDPoPNonceTestKey is the holder key the fixture signs DPoP proofs with.
func newDPoPNonceTestKey(t *testing.T) jose.JSONWebKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return jose.JSONWebKey{Key: privateKey, KeyID: "holder-key-1", Algorithm: string(jose.ES256), Use: "sig"}
}

// postOneCredentialRequest drives the Credential Endpoint through the public
// transport API with a real DPoP proof factory, and returns the c_nonce the
// accepted request was built with.
func postOneCredentialRequest(t *testing.T, receiver *Oid4vciReceiver, key jose.JSONWebKey, credentialEndpoint string) {
	t.Helper()
	endpoint := mustURIField(t, credentialEndpoint)
	_, _, err := receiver.PostCredentialEndpointWithNonceRetryForToken(
		t.Context(),
		endpoint,
		types.CredentialIssuanceAccessToken{Token: "access-token-1", TokenType: "DPoP"},
		nil,
		"c-nonce-1",
		func(string) ([]byte, string, error) {
			return []byte(`{"credential_configuration_id":"pid"}`), "application/json", nil
		},
		func(nonce string) (string, error) {
			return receiver.CreateDpopProof(key, http.MethodPost, credentialEndpoint, nonce, "access-token-1")
		},
	)
	if err != nil {
		t.Fatalf("PostCredentialEndpointWithNonceRetryForToken() error = %v", err)
	}
}

// TestNonceEndpointDPoPNonceSeedsTheFirstCredentialProof covers OpenID4VCI 1.0
// Section 7.2 Nonce Response: "The Credential Issuer MAY provide a DPoP nonce in
// an HTTP header as defined in Section 8.2 of [@!RFC9449]. In this case, the
// Wallet uses the new nonce value in the DPoP proof when presenting an access
// token at the Credential Endpoint."
//
// The header is observed at one endpoint and has to reach the proof built for
// another endpoint of the same server, without the wasted 401 round trip the
// challenge retry would otherwise cost: the FIRST credential request already
// carries it.
func TestNonceEndpointDPoPNonceSeedsTheFirstCredentialProof(t *testing.T) {
	fixture := newDPoPNonceTestServer(t, "server-dpop-nonce-1")
	receiver := &Oid4vciReceiver{HTTPClient: fixture.server.Client(), AllowHTTP: true}
	key := newDPoPNonceTestKey(t)

	nonceResponse, err := receiver.FetchNonceResponse(t.Context(), mustURIField(t, fixture.server.URL+"/nonce"))
	if err != nil {
		t.Fatalf("FetchNonceResponse() error = %v", err)
	}
	if nonceResponse.CNonce != "c-nonce-1" {
		t.Fatalf("c_nonce = %q, want c-nonce-1", nonceResponse.CNonce)
	}
	if nonceResponse.DPoPNonce != "server-dpop-nonce-1" {
		t.Fatalf("DPoPNonce = %q, want the DPoP-Nonce response header", nonceResponse.DPoPNonce)
	}

	postOneCredentialRequest(t, receiver, key, fixture.server.URL+"/credential")

	proofs := fixture.proofs()
	if len(proofs) != 1 {
		t.Fatalf("credential requests = %d, want exactly one: the stored nonce must spare the challenge round trip", len(proofs))
	}
	claims := dpopProofClaims(t, proofs[0])
	if claims["nonce"] != "server-dpop-nonce-1" {
		t.Fatalf("first credential request DPoP nonce = %#v, want server-dpop-nonce-1", claims["nonce"])
	}
}

// TestNonceEndpointWithoutDPoPNonceLeavesTheProofNonceless is the negative half:
// Section 7.2 makes the DPoP nonce header OPTIONAL ("MAY provide"), so an issuer
// that sends none leaves the wallet with nothing to put in the proof. Inventing
// a nonce, or reusing one from another server, would only be rejected.
func TestNonceEndpointWithoutDPoPNonceLeavesTheProofNonceless(t *testing.T) {
	fixture := newDPoPNonceTestServer(t, "")
	receiver := &Oid4vciReceiver{HTTPClient: fixture.server.Client(), AllowHTTP: true}
	key := newDPoPNonceTestKey(t)

	nonceResponse, err := receiver.FetchNonceResponse(t.Context(), mustURIField(t, fixture.server.URL+"/nonce"))
	if err != nil {
		t.Fatalf("FetchNonceResponse() error = %v", err)
	}
	if nonceResponse.DPoPNonce != "" {
		t.Fatalf("DPoPNonce = %q, want empty when the Nonce Response carries no DPoP-Nonce header", nonceResponse.DPoPNonce)
	}

	postOneCredentialRequest(t, receiver, key, fixture.server.URL+"/credential")

	proofs := fixture.proofs()
	if len(proofs) != 1 {
		t.Fatalf("credential requests = %d, want exactly one", len(proofs))
	}
	claims := dpopProofClaims(t, proofs[0])
	if _, present := claims["nonce"]; present {
		t.Fatalf("first credential request DPoP proof carries nonce = %#v, want none", claims["nonce"])
	}
}

// TestDPoPNonceStoreIsKeyedByServer pins the RFC 9449 Section 8.2 scope of a
// nonce: "Clients should expect that a server will use the same nonce for all
// requests to that server." A nonce learned from one server is never presented
// to another, which would leak it and be rejected anyway.
func TestDPoPNonceStoreIsKeyedByServer(t *testing.T) {
	issuer := newDPoPNonceTestServer(t, "server-dpop-nonce-1")
	other := newDPoPNonceTestServer(t, "")
	receiver := &Oid4vciReceiver{HTTPClient: issuer.server.Client(), AllowHTTP: true}
	key := newDPoPNonceTestKey(t)

	if _, err := receiver.FetchNonceResponse(t.Context(), mustURIField(t, issuer.server.URL+"/nonce")); err != nil {
		t.Fatalf("FetchNonceResponse() error = %v", err)
	}

	postOneCredentialRequest(t, receiver, key, other.server.URL+"/credential")

	proofs := other.proofs()
	if len(proofs) != 1 {
		t.Fatalf("credential requests = %d, want exactly one", len(proofs))
	}
	claims := dpopProofClaims(t, proofs[0])
	if _, present := claims["nonce"]; present {
		t.Fatalf("proof to a second server carries nonce = %#v, want none", claims["nonce"])
	}
}

// TestDPoPNonceStoreIsRaceSafe drives the lazily created store from several
// goroutines at once, because callers build Oid4vciReceiver as a literal and the
// map cannot be allocated in a constructor. Run with -race.
func TestDPoPNonceStoreIsRaceSafe(t *testing.T) {
	fixture := newDPoPNonceTestServer(t, "server-dpop-nonce-1")
	receiver := &Oid4vciReceiver{HTTPClient: fixture.server.Client(), AllowHTTP: true}
	endpoint := mustURIField(t, fixture.server.URL+"/nonce")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := receiver.FetchNonceResponse(t.Context(), endpoint); err != nil {
				t.Errorf("FetchNonceResponse() error = %v", err)
			}
		}()
	}
	wg.Wait()
}
