package did

import (
	"net/http"
	"testing"

	"github.com/trustknots/vcknots/wallet/common/observe"
)

// TestObserveLabelsDIDWebDocumentFetch: the did:web document fetch is labelled
// as issuer key material.
func TestObserveLabelsDIDWebDocumentFetch(t *testing.T) {
	t.Parallel()

	const identifier = "did:web:issuer.example.test:bank"
	plugin, _ := newDIDWebTestPlugin(t, func(writer http.ResponseWriter, _ *http.Request) {
		writeDIDDocument(t, writer, map[string]any{
			"id":              identifier,
			"assertionMethod": []any{verificationMethod(t, identifier+"#key-1", testPublicJWK(t))},
		})
	})
	recorder := observe.NewRecorder(4)
	plugin.HTTPClient.Transport = observe.Transport(plugin.HTTPClient.Transport, recorder)

	if _, err := plugin.Resolve(identifier); err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	exchanges := recorder.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("recorded %d exchanges, want 1: %+v", len(exchanges), exchanges)
	}
	exchange := exchanges[0]
	if exchange.Endpoint != observe.EndpointIssuerKeyMaterial || exchange.Method != http.MethodGet || exchange.URL.Path != "/bank/did.json" {
		t.Fatalf("exchange = %s %s labelled %q, want GET /bank/did.json labelled %q",
			exchange.Method, exchange.URL.Path, exchange.Endpoint, observe.EndpointIssuerKeyMaterial)
	}
}
