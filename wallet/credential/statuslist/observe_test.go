package statuslist

import (
	"context"
	"net/http"
	"testing"

	"github.com/trustknots/vcknots/wallet/common/observe"
)

// TestObserveLabelsStatusListTokenFetch: the Status List Token fetch carries
// its protocol role.
func TestObserveLabelsStatusListTokenFetch(t *testing.T) {
	h := newHarness(t)
	h.serveToken(signES256(t, h.key, defaultHeader(), defaultClaims(h.uri)))
	checker := h.checker()
	recorder := observe.NewRecorder(4)
	client := *checker.HTTPClient
	client.Transport = observe.Transport(client.Transport, recorder)
	checker.HTTPClient = &client

	if _, err := checker.CheckReference(context.Background(), h.reference(1)); err != nil {
		t.Fatal(err)
	}

	exchanges := recorder.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("recorded %d exchanges, want 1: %+v", len(exchanges), exchanges)
	}
	exchange := exchanges[0]
	if exchange.Endpoint != observe.EndpointStatusList || exchange.Method != http.MethodGet || exchange.URL.Path != statusPath {
		t.Fatalf("exchange = %s %s labelled %q, want GET %s labelled %q",
			exchange.Method, exchange.URL.Path, exchange.Endpoint, statusPath, observe.EndpointStatusList)
	}
	if exchange.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", exchange.StatusCode)
	}
}
