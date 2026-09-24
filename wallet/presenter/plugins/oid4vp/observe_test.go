package oid4vp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

func observePresenterClient(p *Oid4vpPresenter, recorder *observe.Recorder) {
	client := *p.HTTPClient
	client.Transport = observe.Transport(client.Transport, recorder)
	p.HTTPClient = &client
}

func requireSingleExchange(t *testing.T, recorder *observe.Recorder) observe.Exchange {
	t.Helper()
	exchanges := recorder.Exchanges()
	require.Len(t, exchanges, 1)
	return exchanges[0]
}

// TestObserveLabelsRequestObjectFetch: the request_uri fetch is labelled even
// though its URL appears nowhere but inside the Authorization Request.
func TestObserveLabelsRequestObjectFetch(t *testing.T) {
	f := newRequestObjectFixture(t)
	recorder := observe.NewRecorder(8)
	f.mu.Lock()
	f.requestObject = []byte(f.signWithRoot(t, f.claims(), false))
	f.mu.Unlock()
	p := f.presenterWith(requestFixtureOptions{})
	observePresenterClient(p, recorder)

	uri := "openid4vp://authorize?" + url.Values{
		"client_id":   {f.clientID()},
		"request_uri": {f.server.URL + "/request-object"},
	}.Encode()
	_, err := p.ParsePresentationRequest(uri)
	require.NoError(t, err)

	exchanges := recorder.Exchanges()
	require.NotEmpty(t, exchanges)
	exchange := exchanges[0]
	require.Equal(t, observe.EndpointRequestObject, exchange.Endpoint)
	require.Equal(t, http.MethodGet, exchange.Method)
	require.Equal(t, "/request-object", exchange.URL.Path)
	require.Equal(t, http.StatusOK, exchange.StatusCode)
	require.Nil(t, exchange.ResponseEncrypted)
	// The X.509 chain walk that authenticates the Request Object downloads its
	// CRL through the same client; a CRL has no protocol role of its own.
	for _, later := range exchanges[1:] {
		require.Equal(t, observe.EndpointOther, later.Endpoint, later.URL.Path)
	}
}

// TestObserveAnnotatesAuthorizationResponseEncryption: the Response Endpoint
// POST states whether the form carried a JWE, which its wire shape cannot show.
func TestObserveAnnotatesAuthorizationResponseEncryption(t *testing.T) {
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encryptedRequest := &types.PresentationRequest{
		State: "state-1",
		ClientMetadata: &VerifierMetadata{
			AuthorizationEncryptedResponseAlg:   string(jose.ECDH_ES),
			EncryptedResponseEncValuesSupported: []string{"A256GCM"},
			Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &recipient.PublicKey, KeyID: "verifier-encryption", Use: "enc", Algorithm: string(jose.ECDH_ES),
			}}},
		},
	}
	for name, testCase := range map[string]struct {
		request *types.PresentationRequest
		want    bool
	}{
		"plaintext direct_post": {request: &types.PresentationRequest{State: "state-1"}, want: false},
		"encrypted response":    {request: encryptedRequest, want: true},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := observe.NewRecorder(8)
			p, endpoint, _, _ := dcqlTransportEndpoint(t)
			observePresenterClient(p, recorder)

			_, err := p.PresentDCQL(types.Oid4vp, endpoint, map[string][]string{"pid": {"presentation"}}, testCase.request)
			require.NoError(t, err)

			exchange := requireSingleExchange(t, recorder)
			require.Equal(t, observe.EndpointResponse, exchange.Endpoint)
			require.Equal(t, http.MethodPost, exchange.Method)
			require.NotNil(t, exchange.ResponseEncrypted)
			require.Equal(t, testCase.want, *exchange.ResponseEncrypted)
		})
	}

	t.Run("error response", func(t *testing.T) {
		recorder := observe.NewRecorder(8)
		p, endpoint, _, _ := dcqlTransportEndpoint(t)
		observePresenterClient(p, recorder)

		request := admitDirectPost(t, p, endpoint.String(), "state-1")
		_, err := p.SubmitErrorResponse(context.Background(), request, "access_denied", "")
		require.NoError(t, err)

		exchange := requireSingleExchange(t, recorder)
		require.Equal(t, observe.EndpointResponse, exchange.Endpoint)
		require.NotNil(t, exchange.ResponseEncrypted)
		require.False(t, *exchange.ResponseEncrypted)
	})
}
