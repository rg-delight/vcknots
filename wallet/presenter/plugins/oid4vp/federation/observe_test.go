package federation

import (
	"context"
	"net/http"
	"testing"

	"github.com/trustknots/vcknots/wallet/common/observe"
)

// TestObserveLabelsTrustChainFetches: a Trust Chain resolution labels each
// Entity Configuration and each Subordinate Statement fetch with its role.
func TestObserveLabelsTrustChainFetches(t *testing.T) {
	f := newDirectFederation(t, directOptions{})
	resolver := f.resolver()
	recorder := observe.NewRecorder(8)
	client := *resolver.HTTPClient
	client.Transport = observe.Transport(client.Transport, recorder)
	resolver.HTTPClient = &client

	if _, err := resolver.ResolveTrustChains(context.Background(), f.verifier); err != nil {
		t.Fatal(err)
	}

	want := []struct {
		path     string
		endpoint observe.Endpoint
	}{
		{"/verifier/.well-known/openid-federation", observe.EndpointFederationEntityConfiguration},
		{"/anchor/.well-known/openid-federation", observe.EndpointFederationEntityConfiguration},
		{"/anchor/fetch", observe.EndpointFederationSubordinateStatement},
	}
	exchanges := recorder.Exchanges()
	if len(exchanges) != len(want) {
		t.Fatalf("recorded %d exchanges, want %d: %+v", len(exchanges), len(want), exchanges)
	}
	for i, exchange := range exchanges {
		if exchange.URL.Path != want[i].path || exchange.Endpoint != want[i].endpoint || exchange.Method != http.MethodGet {
			t.Errorf("exchange %d = %s %s labelled %q, want GET %s labelled %q",
				i, exchange.Method, exchange.URL.Path, exchange.Endpoint, want[i].path, want[i].endpoint)
		}
	}
}
