package wallet

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// fixtureEndpointByPath is the role each path of the Final issuance fixture
// plays (wallet_final_issuance_test.go serveHTTP).
var fixtureEndpointByPath = map[string]observe.Endpoint{
	"/.well-known/openid-credential-issuer":   observe.EndpointIssuerMetadata,
	"/.well-known/oauth-authorization-server": observe.EndpointAuthorizationServerMetadata,
	"/par":          observe.EndpointPushedAuthorization,
	"/authorize":    observe.EndpointAuthorization,
	"/token":        observe.EndpointToken,
	"/nonce":        observe.EndpointNonce,
	"/credential":   observe.EndpointCredential,
	"/deferred":     observe.EndpointDeferredCredential,
	"/notification": observe.EndpointNotification,
}

// observedClient routes client through an observe.Transport, the way an
// integrator wires the client it injects into the library.
func observedClient(client *http.Client, recorder *observe.Recorder) *http.Client {
	observed := *client
	observed.Transport = observe.Transport(client.Transport, recorder)
	return &observed
}

// observeFixtureTransport observes the fixture receiver's client.
func observeFixtureTransport(recorder *observe.Recorder) func(*finalIssuanceFixture) {
	return func(f *finalIssuanceFixture) {
		f.wrapReceiverPlugin = func(plugin receiverTypes.Receiver) receiverTypes.Receiver {
			receiver := plugin.(*oid4vci.Oid4vciReceiver)
			receiver.HTTPClient = observedClient(receiver.HTTPClient, recorder)
			return receiver
		}
	}
}

func requireFixtureEndpointLabels(t *testing.T, exchanges []observe.Exchange) []observe.Endpoint {
	t.Helper()
	labels := make([]observe.Endpoint, 0, len(exchanges))
	for _, exchange := range exchanges {
		want, known := fixtureEndpointByPath[exchange.URL.Path]
		require.True(t, known, "unexpected request to %s", exchange.URL.Path)
		require.Equal(t, want, exchange.Endpoint, "role of %s %s", exchange.Method, exchange.URL.Path)
		require.NotZero(t, exchange.StatusCode)
		labels = append(labels, exchange.Endpoint)
	}
	return labels
}

// TestObserveLabelsEveryFinalIssuanceRequest drives an authorization code
// issuance through an observed client: every request the library sends is
// labelled with the role it was sent for, so an integrator never classifies a
// URL itself.
func TestObserveLabelsEveryFinalIssuanceRequest(t *testing.T) {
	recorder := observe.NewRecorder(64)
	fixture := newFinalIssuanceFixture(t, observeFixtureTransport(recorder), func(f *finalIssuanceFixture) {
		f.includeNotification = true
		f.responseEncryption = true
		f.requestEncryption = true
	})

	req := fixture.request()
	req.CredentialResponseEncryptionKey = &fixture.encryptionKey
	// The self-driven authorization GET uses the request's client.
	req.HTTPClient = observedClient(fixture.server.Client(), recorder)

	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)

	exchanges := recorder.Exchanges()
	labels := requireFixtureEndpointLabels(t, exchanges)
	for _, want := range []observe.Endpoint{
		observe.EndpointIssuerMetadata,
		observe.EndpointAuthorizationServerMetadata,
		observe.EndpointPushedAuthorization,
		observe.EndpointAuthorization,
		observe.EndpointToken,
		observe.EndpointNonce,
		observe.EndpointCredential,
		observe.EndpointNotification,
	} {
		require.Contains(t, labels, want)
	}
	for _, exchange := range exchanges {
		switch exchange.Endpoint {
		case observe.EndpointToken, observe.EndpointCredential, observe.EndpointNotification:
			require.True(t, exchange.DPoP, "%s carries a DPoP proof", exchange.Endpoint)
		case observe.EndpointIssuerMetadata:
			require.False(t, exchange.DPoP)
		}
		if exchange.Endpoint == observe.EndpointCredential {
			require.True(t, exchange.RequestJWT, "the encrypted Credential Request is application/jwt")
			require.True(t, exchange.ResponseJWT, "the encrypted Credential Response is application/jwt")
		}
		require.Nil(t, exchange.ResponseEncrypted, "only an OpenID4VP response is annotated")
	}
	require.False(t, recorder.Truncated())
}

// TestObserveLabelsDeferredCredentialPoll checks that the Credential Endpoint
// call the deferred poll shares with the first request is labelled by the
// endpoint it actually addresses.
func TestObserveLabelsDeferredCredentialPoll(t *testing.T) {
	recorder := observe.NewRecorder(64)
	fixture := newFinalIssuanceFixture(t, observeFixtureTransport(recorder), func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"transaction_id": "tx-1"})
		}
		f.deferredHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential": f.issuedCredential})
		}
	})
	req := fixture.request()
	req.DeferredPollAttempts = 1

	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)

	labels := requireFixtureEndpointLabels(t, recorder.Exchanges())
	require.Contains(t, labels, observe.EndpointCredential)
	require.Contains(t, labels, observe.EndpointDeferredCredential)
}
