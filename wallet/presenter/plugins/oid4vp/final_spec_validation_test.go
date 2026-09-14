package oid4vp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

const finalDcqlParam = `{"credentials":[{"id":"cred","format":"dc+sd-jwt","meta":{"vct_values":["urn:test"]}}]}`

func finalQueryURI(values url.Values) string {
	return "openid4vp://present?" + values.Encode()
}

// Fix 1: OID4VP 1.0 §5.6 defines the vp_token Response Type.
func TestFinalResponseTypeMustBeVPToken(t *testing.T) {
	base := func(responseType string) string {
		return finalQueryURI(url.Values{
			"client_id":     {"redirect_uri:https://verifier.example/cb"},
			"redirect_uri":  {"https://verifier.example/cb"},
			"response_type": {responseType},
			"response_mode": {"fragment"},
			"nonce":         {"n"},
			"dcql_query":    {finalDcqlParam},
		})
	}
	p := &Oid4vpPresenter{}
	if _, err := p.ParsePresentationRequest(base("vp_token")); err != nil {
		t.Fatalf("vp_token must be accepted: %v", err)
	}
	_, err := p.ParsePresentationRequest(base("code"))
	assertAuthzErrorCode(t, err, InvalidRequestError)
}

// Fix 2: OID4VP 1.0 §5.9.2 pre-registered fallback for a colon-less client_id.
func TestFinalPreRegisteredClientID(t *testing.T) {
	// §5.9.2 also requires the Client Identifier to be "known to the Wallet in
	// advance of the Authorization Request", so these cases register it.
	registry := map[string]PreRegisteredClient{"example-client": {}}

	t.Run("accepted on the Final path", func(t *testing.T) {
		uri := finalQueryURI(url.Values{
			"client_id":     {"example-client"},
			"redirect_uri":  {"https://verifier.example/cb"},
			"response_type": {"vp_token"},
			"response_mode": {"fragment"},
			"nonce":         {"n"},
			"dcql_query":    {finalDcqlParam},
		})
		req, err := (&Oid4vpPresenter{PreRegisteredClients: registry}).ParsePresentationRequest(uri)
		require.NoError(t, err)
		require.Equal(t, "example-client", req.ClientID)
	})

	t.Run("signed pre-registered request object stays unsupported", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["client_id"] = "example-client"
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {"example-client"},
			"request":   {f.sign(t, claims, nil)},
		}.Encode()
		p := f.presenter()
		p.PreRegisteredClients = registry
		_, err := p.ParsePresentationRequest(uri)
		require.ErrorContains(t, err, "no configured authentication method")
	})
}

func TestHAIPRejectsPreRegisteredClientID(t *testing.T) {
	builder := NewRequestBuilder()
	builder.profile = profile.HAIP
	builder.requestSource = "reference"
	builder.req.ClientID = "example-client"
	builder.req.ResponseMode = OAuthAuthzReqResponseModeDirectPostJWT
	err := builder.enforceHAIPProfile()
	assertAuthzErrorCode(t, err, InvalidRequestError)
	require.Contains(t, err.Error(), "x509_hash")
}

// Fix 3: RFC 9101 §5 forbids request and request_uri in the same request.
func TestFinalRequestAndRequestURIMutuallyExclusive(t *testing.T) {
	f := newRequestObjectFixture(t)
	if _, err := f.parse(t, f.claims()); err != nil {
		t.Fatalf("request alone must be accepted: %v", err)
	}
	uri := "openid4vp://authorize?" + url.Values{
		"client_id":   {f.clientID()},
		"request":     {"a.b.c"},
		"request_uri": {"https://verifier.example/request"},
	}.Encode()
	_, err := (&Oid4vpPresenter{}).ParsePresentationRequest(uri)
	assertAuthzErrorCode(t, err, InvalidRequestError)
}

// Fix 4: OID4VP 1.0 §5.1/§5.10 request_uri_method is case-sensitive and
// requires request_uri.
func TestFinalRequestURIMethodValidation(t *testing.T) {
	newReference := func(t *testing.T, method string) (*requestObjectFixture, string) {
		t.Helper()
		f := newRequestObjectFixture(t)
		f.mu.Lock()
		f.requestObject = []byte(f.sign(t, f.claims(), nil))
		f.mu.Unlock()
		values := url.Values{
			"client_id":   {f.clientID()},
			"request_uri": {f.server.URL + "/request-object"},
		}
		if method != "" {
			values.Set("request_uri_method", method)
		}
		return f, "openid4vp://authorize?" + values.Encode()
	}

	t.Run("lowercase get accepted", func(t *testing.T) {
		f, uri := newReference(t, "get")
		if _, err := f.presenter().ParsePresentationRequest(uri); err != nil {
			t.Fatalf("get must be accepted: %v", err)
		}
	})
	t.Run("uppercase rejected", func(t *testing.T) {
		f, uri := newReference(t, "GET")
		_, err := f.presenter().ParsePresentationRequest(uri)
		assertAuthzErrorCode(t, err, InvalidRequestURIMethodError)
	})
	t.Run("without request_uri rejected", func(t *testing.T) {
		uri := finalQueryURI(url.Values{
			"client_id":          {"redirect_uri:https://verifier.example/cb"},
			"redirect_uri":       {"https://verifier.example/cb"},
			"response_type":      {"vp_token"},
			"response_mode":      {"fragment"},
			"nonce":              {"n"},
			"dcql_query":         {finalDcqlParam},
			"request_uri_method": {"get"},
		})
		_, err := (&Oid4vpPresenter{}).ParsePresentationRequest(uri)
		assertAuthzErrorCode(t, err, InvalidRequestError)
	})
}

// Fix 5: OID4VP 1.0 §5.1/§8.4 transaction_data validation.
func TestFinalTransactionDataValidation(t *testing.T) {
	encode := func(raw string) string { return base64.RawURLEncoding.EncodeToString([]byte(raw)) }
	parseWith := func(t *testing.T, entry string, supported []string) (*CredentialPresentationRequest, error) {
		t.Helper()
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["transaction_data"] = []any{entry}
		p := f.presenter()
		p.SupportedTransactionDataTypes = supported
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {f.clientID()},
			"request":   {f.sign(t, claims, nil)},
		}.Encode()
		return p.ParsePresentationRequest(uri)
	}

	req, err := parseWith(t, encode(`{"type":"example","credential_ids":["pid"]}`), []string{"example"})
	require.NoError(t, err)
	require.Len(t, req.TransactionData, 1)

	_, err = parseWith(t, encode(`{"type":"example","credential_ids":["pid"],"transaction_data_hashes_alg":["sha-256"]}`), []string{"example"})
	require.NoError(t, err)

	for _, tc := range []struct {
		name, entry string
		supported   []string
	}{
		{"nil supported types", encode(`{"type":"example","credential_ids":["pid"]}`), nil},
		{"unknown type", encode(`{"type":"example","credential_ids":["pid"]}`), []string{"other"}},
		{"unknown credential", encode(`{"type":"example","credential_ids":["nope"]}`), []string{"example"}},
		{"empty credential_ids", encode(`{"type":"example","credential_ids":[]}`), []string{"example"}},
		{"missing type", encode(`{"credential_ids":["pid"]}`), []string{"example"}},
		{"malformed base64", "not base64!!", []string{"example"}},
		{"empty hashes alg", encode(`{"type":"example","credential_ids":["pid"],"transaction_data_hashes_alg":[]}`), []string{"example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseWith(t, tc.entry, tc.supported)
			assertAuthzErrorCode(t, err, InvalidTransactionDataError)
		})
	}

	t.Run("query-encoded transaction_data is validated", func(t *testing.T) {
		entry := encode(`{"type":"example","credential_ids":["cred"]}`)
		raw, err := json.Marshal([]string{entry})
		require.NoError(t, err)
		uri := finalQueryURI(url.Values{
			"client_id":        {"redirect_uri:https://verifier.example/cb"},
			"redirect_uri":     {"https://verifier.example/cb"},
			"response_type":    {"vp_token"},
			"response_mode":    {"fragment"},
			"nonce":            {"n"},
			"dcql_query":       {finalDcqlParam},
			"transaction_data": {string(raw)},
		})
		if _, err := (&Oid4vpPresenter{SupportedTransactionDataTypes: []string{"example"}}).ParsePresentationRequest(uri); err != nil {
			t.Fatalf("supported query transaction_data rejected: %v", err)
		}
		_, err = (&Oid4vpPresenter{}).ParsePresentationRequest(uri)
		assertAuthzErrorCode(t, err, InvalidTransactionDataError)
	})
}

// Fix 6: OID4VP 1.0 §6.1, Appendix B.2.3/B.3.5 format-specific meta checks.
func TestFinalDcqlMetaValidation(t *testing.T) {
	if _, err := parseDcqlQuery(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test"]}}]}`); err != nil {
		t.Fatalf("valid vct_values rejected: %v", err)
	}
	for _, raw := range []string{
		`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":"urn:test"}}]}`,
		`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":[]}}]}`,
		`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":[1]}}]}`,
	} {
		_, err := parseDcqlQuery(raw)
		assertAuthzErrorCode(t, err, InvalidRequestError)
	}
	// mso_mdoc is not a supported wallet format, so the parse path rejects it
	// earlier; exercise the meta check directly.
	if err := validateCredentialQueryMeta(0, "mso_mdoc", map[string]any{"doctype_value": 5}); err == nil {
		t.Fatal("non-string doctype_value must be rejected")
	} else {
		assertAuthzErrorCode(t, err, InvalidRequestError)
	}
	if err := validateCredentialQueryMeta(0, "mso_mdoc", map[string]any{"doctype_value": "org.iso.18013.5.1.mDL"}); err != nil {
		t.Fatalf("valid doctype_value rejected: %v", err)
	}
}

// Fix 7: OID4VP 1.0 §8.3.1 encrypted error response for direct_post.jwt.
func TestFinalEncryptedErrorResponse(t *testing.T) {
	recipient := newP256Recipient(t)
	newServer := func(t *testing.T) (*httptest.Server, *url.Values) {
		t.Helper()
		captured := &url.Values{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse form: %v", err)
			}
			*captured = r.PostForm
			w.WriteHeader(http.StatusOK)
		}))
		return server, captured
	}
	metadata := func() *VerifierMetadata {
		return &VerifierMetadata{
			Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &recipient.PublicKey, KeyID: "enc-key", Use: "enc", Algorithm: "ECDH-ES",
			}}},
			EncryptedResponseEncValuesSupported: []string{"A256GCM"},
		}
	}
	newURI := func(t *testing.T, serverURL string, md *VerifierMetadata) string {
		t.Helper()
		raw, err := json.Marshal(md)
		require.NoError(t, err)
		return finalQueryURI(url.Values{
			// §5.9.3: the redirect_uri Client Identifier is the Response URI of
			// a direct_post.jwt request, so both name the same endpoint.
			"client_id":       {"redirect_uri:" + serverURL + "/response"},
			"response_type":   {"vp_token"},
			"response_mode":   {"direct_post.jwt"},
			"response_uri":    {serverURL + "/response"},
			"state":           {"err-state"},
			"nonce":           {"n"},
			"client_metadata": {string(raw)},
			"dcql_query":      {`{"credentials":[]}`},
		})
	}

	t.Run("encrypted", func(t *testing.T) {
		server, captured := newServer(t)
		defer server.Close()
		p := &Oid4vpPresenter{AllowHTTP: true, HTTPClient: server.Client()}
		_, err := p.ParsePresentationRequest(newURI(t, server.URL, metadata()))
		require.Error(t, err)
		token := captured.Get("response")
		require.NotEmpty(t, token, "direct_post.jwt error must be encrypted")
		payload := decryptAuthorizationResponse(t, token, recipient, jose.ECDH_ES, jose.A256GCM)
		require.Equal(t, "invalid_request", payload["error"])
		require.Equal(t, "err-state", payload["state"])
	})

	t.Run("plaintext fallback when unable to encrypt", func(t *testing.T) {
		server, captured := newServer(t)
		defer server.Close()
		md := metadata()
		md.Jwks = jose.JSONWebKeySet{}
		p := &Oid4vpPresenter{AllowHTTP: true, HTTPClient: server.Client()}
		_, err := p.ParsePresentationRequest(newURI(t, server.URL, md))
		require.Error(t, err)
		require.Empty(t, captured.Get("response"))
		require.Equal(t, "invalid_request", captured.Get("error"))
	})
}

// Fix 8: the Final-defined error codes exist and are usable.
func TestFinalErrorCodesRegistered(t *testing.T) {
	for _, code := range []OAuthAuthzError{
		InvalidRequestURIMethodError, InvalidTransactionDataError, WalletUnavailableError, InvalidClientError,
	} {
		require.NotEmpty(t, string(code))
	}
}

// Fix 9: SubmitEncryptedAuthorizationResponse bounds the verifier body.
func TestSubmitEncryptedAuthorizationResponseBoundedBody(t *testing.T) {
	recipient := newP256Recipient(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxVerifierResponseBodySize+512))
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	require.NoError(t, err)
	p := &Oid4vpPresenter{}
	body, err := p.SubmitEncryptedAuthorizationResponse(*endpoint, map[string]any{
		"vp_token": map[string]any{"pid": []string{"presented"}},
	}, &VerifierMetadata{
		Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &recipient.PublicKey, KeyID: "enc", Use: "enc", Algorithm: "ECDH-ES",
		}}},
	})
	require.NoError(t, err)
	require.Len(t, body, maxVerifierResponseBodySize)
}

// Fix 10: OID4VP 1.0 §8.3 requires alg on JWKs used for encryption.
func TestPresentDCQLRejectsEncryptionKeyWithoutAlg(t *testing.T) {
	recipient := newP256Recipient(t)
	s := newEncryptionServer(t)
	p := &Oid4vpPresenter{HTTPClient: s.server.Client()}
	request := &types.PresentationRequest{ClientMetadata: &VerifierMetadata{
		Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &recipient.PublicKey, KeyID: "no-alg", Use: "enc",
		}}},
	}}
	_, err := p.PresentDCQL(types.Oid4vp, s.endpoint(t), map[string][]string{"pid": {"credential"}}, request)
	require.ErrorContains(t, err, "no usable verifier encryption key")
	require.Equal(t, int32(0), s.calls.Load())
}

// Fix 11: OID4VP 1.0 §5.9.3 — "the original Client Identifier part (without the
// prefix redirect_uri:) is the Verifier's Redirect URI (or Response URI when
// Response Mode direct_post is used)". The Response URI of a direct_post
// request is therefore bound to the Client Identifier.
func TestRedirectURIClientIDBindsResponseURI(t *testing.T) {
	for _, mode := range []string{"direct_post", "direct_post.jwt"} {
		t.Run(mode, func(t *testing.T) {
			uri := finalQueryURI(url.Values{
				"client_id":     {"redirect_uri:https://verifier.example/response"},
				"response_type": {"vp_token"},
				"response_mode": {mode},
				"response_uri":  {"https://verifier.example/response"},
				"nonce":         {"n"},
				"dcql_query":    {finalDcqlParam},
			})
			req, err := (&Oid4vpPresenter{}).ParsePresentationRequest(uri)
			require.NoError(t, err)
			require.Equal(t, "https://verifier.example/response", req.ResponseURI)
			// §8.2: the response goes to the Response URI, so no Redirect URI
			// is carried by the parsed request.
			require.Empty(t, req.RedirectURI)
		})
	}
}

// Fix 11 (continued): §5.9.3 lets the Client Identifier itself be the Response
// URI, so response_uri may be omitted.
func TestRedirectURIClientIDDefaultsResponseURI(t *testing.T) {
	uri := finalQueryURI(url.Values{
		"client_id":     {"redirect_uri:https://verifier.example/response"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"n"},
		"dcql_query":    {finalDcqlParam},
	})
	req, err := (&Oid4vpPresenter{}).ParsePresentationRequest(uri)
	require.NoError(t, err)
	require.Equal(t, "https://verifier.example/response", req.ResponseURI)
	require.Empty(t, req.RedirectURI)
}

// Fix 11 (continued): a response_uri the Client Identifier does not
// authenticate must not receive the VP Token, nor the error response.
func TestRedirectURIClientIDRejectsForeignResponseURI(t *testing.T) {
	attacker := newCountingResponseServer(t)
	verifier := newCountingResponseServer(t)
	uri := finalQueryURI(url.Values{
		"client_id":     {"redirect_uri:" + verifier.server.URL + "/response"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {attacker.server.URL + "/post"},
		"nonce":         {"n"},
		"dcql_query":    {finalDcqlParam},
	})
	p := &Oid4vpPresenter{AllowHTTP: true, HTTPClient: verifier.server.Client()}
	_, err := p.ParsePresentationRequest(uri)
	assertAuthzErrorCode(t, err, InvalidRequestError)
	require.ErrorContains(t, err, "response_uri does not match the redirect_uri Client Identifier")
	require.Equal(t, int32(0), attacker.calls.Load(), "the foreign response_uri must receive nothing")
	require.Equal(t, int32(1), verifier.calls.Load(), "the authenticated Client Identifier receives the error response")
}

// Fix 11 (regression): the Draft24 entrypoint keeps its previous behavior, where
// response_uri is independent of the redirect_uri Client Identifier.
func TestDraft24RedirectURIClientIDUnchanged(t *testing.T) {
	values := url.Values{
		"client_id":               {"redirect_uri:https://verifier.example/cb"},
		"response_type":           {"vp_token"},
		"response_mode":           {"direct_post"},
		"response_uri":            {"https://verifier.example/elsewhere"},
		"nonce":                   {"n"},
		"presentation_definition": {`{"id":"definition"}`},
	}
	req, err := (&Oid4vpPresenter{}).ParseDraft24PresentationRequest(finalQueryURI(values))
	require.NoError(t, err)
	require.Equal(t, "https://verifier.example/elsewhere", req.ResponseURI)
	require.Equal(t, "https://verifier.example/cb", req.RedirectURI)

	// Draft24 also keeps requiring the response_uri parameter for direct_post.
	values.Del("response_uri")
	_, err = (&Oid4vpPresenter{}).ParseDraft24PresentationRequest(finalQueryURI(values))
	require.ErrorContains(t, err, "response_uri")
}

// countingResponseServer records how many authorization (error) responses an
// endpoint received.
type countingResponseServer struct {
	server *httptest.Server
	calls  *atomic.Int32
}

func newCountingResponseServer(t *testing.T) *countingResponseServer {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return &countingResponseServer{server: server, calls: calls}
}

// Fix 12: OID4VP 1.0 §5.9.2 — "the Client Identifier needs to be known to the
// Wallet in advance of the Authorization Request".
func TestPreRegisteredClientIDRejectedWithoutRegistry(t *testing.T) {
	uri := finalQueryURI(url.Values{
		"client_id":     {"example-client"},
		"redirect_uri":  {"https://verifier.example/cb"},
		"response_type": {"vp_token"},
		"response_mode": {"fragment"},
		"nonce":         {"n"},
		"dcql_query":    {finalDcqlParam},
	})
	_, err := (&Oid4vpPresenter{}).ParsePresentationRequest(uri)
	require.ErrorIs(t, err, ErrPreRegisteredClientUnknown)
	require.ErrorContains(t, err, `"example-client"`)
}

func TestPreRegisteredClientIDAcceptedFromRegistry(t *testing.T) {
	uri := finalQueryURI(url.Values{
		"client_id":     {"example-client"},
		"redirect_uri":  {"https://verifier.example/cb"},
		"response_type": {"vp_token"},
		"response_mode": {"fragment"},
		"nonce":         {"n"},
		"dcql_query":    {finalDcqlParam},
	})
	p := &Oid4vpPresenter{PreRegisteredClients: map[string]PreRegisteredClient{
		"example-client": {Metadata: &VerifierMetadata{ClientName: "Registered Verifier"}},
	}}
	req, err := p.ParsePresentationRequest(uri)
	require.NoError(t, err)
	require.Equal(t, "example-client", req.ClientID)
	require.NotNil(t, req.ClientMetadata)
	require.Equal(t, "Registered Verifier", req.ClientMetadata.ClientName)
}

func TestPreRegisteredClientIDResolverConsultedWhenMapMisses(t *testing.T) {
	newURI := func(clientID string) string {
		return finalQueryURI(url.Values{
			"client_id":     {clientID},
			"redirect_uri":  {"https://verifier.example/cb"},
			"response_type": {"vp_token"},
			"response_mode": {"fragment"},
			"nonce":         {"n"},
			"dcql_query":    {finalDcqlParam},
		})
	}
	var asked []string
	p := &Oid4vpPresenter{
		PreRegisteredClients: map[string]PreRegisteredClient{
			"mapped-client": {Metadata: &VerifierMetadata{ClientName: "From map"}},
		},
		ResolvePreRegisteredClient: func(clientID string) (*PreRegisteredClient, error) {
			asked = append(asked, clientID)
			if clientID == "resolved-client" {
				return &PreRegisteredClient{Metadata: &VerifierMetadata{ClientName: "From resolver"}}, nil
			}
			return nil, nil
		},
	}

	req, err := p.ParsePresentationRequest(newURI("mapped-client"))
	require.NoError(t, err)
	require.Equal(t, "From map", req.ClientMetadata.ClientName)
	require.Empty(t, asked, "the map is consulted before the resolver")

	req, err = p.ParsePresentationRequest(newURI("resolved-client"))
	require.NoError(t, err)
	require.Equal(t, "From resolver", req.ClientMetadata.ClientName)
	require.Equal(t, []string{"resolved-client"}, asked)

	_, err = p.ParsePresentationRequest(newURI("unknown-client"))
	require.ErrorIs(t, err, ErrPreRegisteredClientUnknown)
}

// Fix 12 (regression): Draft24 refuses a pre-registered Client Identifier even
// when the wallet has a registry, because it never authenticated one.
func TestDraft24PreRegisteredClientStillRejected(t *testing.T) {
	uri := finalQueryURI(url.Values{
		"client_id":               {"example-client"},
		"redirect_uri":            {"https://verifier.example/cb"},
		"response_type":           {"vp_token"},
		"response_mode":           {"fragment"},
		"nonce":                   {"n"},
		"presentation_definition": {`{"id":"definition"}`},
	})
	p := &Oid4vpPresenter{PreRegisteredClients: map[string]PreRegisteredClient{
		"example-client": {Metadata: &VerifierMetadata{ClientName: "Registered Verifier"}},
	}}
	_, err := p.ParseDraft24PresentationRequest(uri)
	require.ErrorContains(t, err, "invalid client_id format")
	require.NotErrorIs(t, err, ErrPreRegisteredClientUnknown)
}
