package issuerkeys

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// The adapters are handed to hooks whose signatures the rest of the library
// fixes; these assignments fail to compile if either drifts.
var (
	_ func(issuer string, header map[string]any) ([]jose.JSONWebKey, error) = (&KeyLookup{}).Keys
)

func TestKeyLookup(t *testing.T) {
	t.Parallel()

	t.Run("fills the request from the header and returns the candidates of the iss", func(t *testing.T) {
		t.Parallel()
		signer := newES256Key(t, "")
		didValue := didJWK(t, signer.public)
		transport := &failingTransport{}
		resolver := &Resolver{HTTPClient: &http.Client{Transport: transport}, Mechanisms: allMechanisms(), Now: fixedNow}
		lookup := resolver.NewKeyLookup(context.Background(), Request{
			CredentialFormat:   FormatJWTVCJSON,
			CredentialIssuer:   "https://issuer.example.test/issuer",
			IssuerMetadataJWKS: keySet(signer.withKeyID("metadata-key", "ES256")),
			// Overwritten by Keys.
			Issuer: "https://ignored.example.test", KeyID: "ignored",
		})

		keys, err := lookup.Keys(didValue, map[string]any{"alg": "ES256", "kid": didValue + "#0", "typ": "JWT"})
		if err != nil {
			t.Fatalf("Keys failed: %v", err)
		}
		// The metadata candidate names the Credential Issuer, not the JWT's
		// DID `iss`, so it is not returned.
		if got := keyIDs(keys); !slices.Equal(got, []string{didValue + "#0"}) {
			t.Fatalf("key IDs = %v", got)
		}
		for _, key := range keys {
			if !key.IsPublic() {
				t.Errorf("key %q is not public", key.KeyID)
			}
		}
		if transport.count() != 0 {
			t.Errorf("requests were made: %d", transport.count())
		}

		resolution := lookup.Resolution()
		if resolution == nil || lookup.Err() != nil {
			t.Fatalf("Resolution() = %v, Err() = %v", resolution, lookup.Err())
		}
		// The verified key comes back from the acceptor without its kid; the
		// thumbprint still finds its candidate.
		bare := jose.JSONWebKey{Key: signer.public.Key}
		candidate, ok := resolution.CandidateFor(bare)
		if !ok || candidate.Mechanism != MechanismDIDMetadataBinding || candidate.DID != didValue {
			t.Errorf("CandidateFor = %+v, %v", candidate, ok)
		}
		if _, ok := resolution.CandidateFor(newES256Key(t, "").public); ok {
			t.Errorf("CandidateFor found a key the ladder never produced")
		}
	})

	t.Run("reads an x5c header decoded as a generic JSON array", func(t *testing.T) {
		t.Parallel()
		ca := newTestCA(t, "root")
		leaf := newTestLeaf(t, ca, "issuer.example.test")
		resolver := &Resolver{HTTPClient: &http.Client{Transport: &failingTransport{}}, Mechanisms: Mechanisms{X5C: true, IssuerMetadataJWKS: true}}
		lookup := resolver.NewKeyLookup(context.Background(), Request{
			CredentialFormat:   FormatSDJWTVC,
			CredentialIssuer:   "https://issuer.example.test",
			IssuerMetadataJWKS: keySet(leafJWK(leaf, "leaf")),
		})
		header := map[string]any{"alg": "ES256", "x5c": []any{x5cOf(leaf)[0]}}
		keys, err := lookup.Keys("https://issuer.example.test", header)
		if err != nil {
			t.Fatalf("Keys failed: %v", err)
		}
		if got := mechanismsOf(lookup.Resolution().Candidates); !slices.Equal(got, []Mechanism{MechanismX5CMetadataJWKSBinding, MechanismCredentialIssuerMetadataJWKS}) {
			t.Errorf("mechanisms = %v", got)
		}
		if len(keys) != 2 || lookup.Resolution().IssuerDNSName != "issuer.example.test" {
			t.Errorf("keys = %d, DNS name = %q", len(keys), lookup.Resolution().IssuerDNSName)
		}
	})

	t.Run("keeps the diagnostics of a resolution that found nothing", func(t *testing.T) {
		t.Parallel()
		resolver := &Resolver{HTTPClient: &http.Client{Transport: &failingTransport{}}, Mechanisms: Mechanisms{}}
		lookup := resolver.NewKeyLookup(context.Background(), Request{CredentialFormat: FormatSDJWTVC, CredentialIssuer: "https://issuer.example.test"})
		keys, err := lookup.Keys("https://issuer.example.test", map[string]any{"alg": "ES256"})
		if keys != nil || !errors.Is(err, ErrNoIssuerKeyResolved) || !errors.Is(lookup.Err(), ErrNoIssuerKeyResolved) {
			t.Fatalf("Keys = %v, %v; Err() = %v", keys, err, lookup.Err())
		}
		if got := len(lookup.Resolution().Diagnostics); got != 4 {
			t.Errorf("diagnostics = %d, want 4", got)
		}
	})

	t.Run("reports DID-only trust as its own error", func(t *testing.T) {
		t.Parallel()
		signer := newES256Key(t, "")
		didValue := didJWK(t, signer.public)
		resolver := &Resolver{HTTPClient: &http.Client{Transport: &failingTransport{}}, Mechanisms: Mechanisms{DIDJWK: true}}
		lookup := resolver.NewKeyLookup(context.Background(), Request{CredentialFormat: FormatJWTVCJSON, CredentialIssuer: "https://issuer.example.test"})
		_, err := lookup.Keys(didValue, map[string]any{"alg": "ES256", "kid": didValue + "#0"})
		if !errors.Is(err, ErrDIDOnlyTrustUnsupported) {
			t.Fatalf("Keys error = %v, want ErrDIDOnlyTrustUnsupported", err)
		}
		diagnostic := diagnosticFor(t, lookup.Resolution().Diagnostics, RungDID)
		if want := []string{SwitchIssuerMetadataJWKS, SwitchCredentialIssuerBinding, SwitchDIDConfiguration}; !slices.Equal(diagnostic.DisabledBy, want) {
			t.Errorf("DisabledBy = %v, want %v", diagnostic.DisabledBy, want)
		}
	})
}

func keyIDs(keys []jose.JSONWebKey) []string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.KeyID)
	}
	return ids
}
