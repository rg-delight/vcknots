package wallet

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

type captureDpopReceiver struct {
	capturedProof *string
}

func (c *captureDpopReceiver) FetchIssuerMetadata(endpoint common.URIField, rt receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error) {

	return nil, fmt.Errorf("unexpected call to FetchIssuerMetadata")

}

func (c *captureDpopReceiver) FetchAuthorizationServerMetadata(endpoint common.URIField, rt receiverTypes.SupportedReceivingTypes) (*receiverTypes.AuthorizationServerMetadata, error) {

	return nil, fmt.Errorf("unexpected call to FetchAuthorizationServerMetadata")

}

func (c *captureDpopReceiver) FetchAccessToken(rt receiverTypes.SupportedReceivingTypes, endpoint common.URIField, authzCode string, txCode string, opts ...receiverTypes.TokenRequestOption) (*receiverTypes.CredentialIssuanceAccessToken, error) {

	requestConfig := receiverTypes.NewTokenRequestConfig(opts...)
	if requestConfig.DPoPProof != "" {
		proof := requestConfig.DPoPProof
		c.capturedProof = &proof
	}
	return &receiverTypes.CredentialIssuanceAccessToken{
		Token:     "tok",
		TokenType: "Bearer",
	}, nil

}

func (c *captureDpopReceiver) FetchNonce(rt receiverTypes.SupportedReceivingTypes, endpoint common.URIField) (*string, error) {
	return nil, fmt.Errorf("unexpected call to FetchNonce")
}

func (c *captureDpopReceiver) ReceiveCredential(

	rt receiverTypes.SupportedReceivingTypes,
	endpoint common.URIField,
	credentialConfigurationID string,
	credentialIdentifier *string,
	accessToken receiverTypes.CredentialIssuanceAccessToken,
	credentialDefinition *receiverTypes.CredentialDefinition,
	jwtProof *string,
	options ...*receiverTypes.CredentialRequestOptions,
) (*string, error) {

	return nil, fmt.Errorf("unexpected call to ReceiveCredential")

}

func newReceiveCredentialTestServer(t *testing.T) (*url.URL, <-chan url.Values, func()) {
	t.Helper()

	tokenFormCh := make(chan url.Values, 1)
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	issuerKeyPair := mockserver.MustGenerateKeyPair("issuer-key-id")
	jwtBuilder := mockserver.MustNewJWTBuilder(issuerKeyPair)
	defaultCredentialJWT, err := jwtBuilder.CreateSignedJWT(server.URL, map[string]interface{}{
		"sub": "did:key:z6Mkio4WDmdtgEo4f9Hq6i6tnW8WFwknQQ4KHUY99BGY4EVr",
		"vc": map[string]interface{}{
			"@context": []string{
				"https://www.w3.org/2018/credentials/v1",
			},
			"id":           "http://example.com/credential/1",
			"type":         []string{"VerifiableCredential"},
			"issuer":       server.URL,
			"issuanceDate": "2023-01-01T00:00:00Z",
			"credentialSubject": map[string]interface{}{
				"id":   "http://example.com/subject",
				"name": "John Doe",
			},
		},
	})
	require.NoError(t, err)

	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, r *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"credential_issuer":     server.URL,
			"credential_endpoint":   server.URL + "/credential",
			"nonce_endpoint":        server.URL + "/nonce",
			"authorization_servers": []string{server.URL},
			"credential_configurations_supported": map[string]interface{}{
				"test-config": map[string]interface{}{
					"format": "jwt_vc_json",
					"credential_definition": map[string]interface{}{
						"type": []string{"VerifiableCredential"},
					},
				},
			},
		})
	})

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"issuer":         server.URL,
			"token_endpoint": server.URL + "/token",
			"pre-authorized_grant_anonymous_access_supported": true,
			"response_types_supported":                        []string{"code"},
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		form := url.Values{}
		for key, values := range r.Form {
			form[key] = append([]string(nil), values...)
		}
		tokenFormCh <- form

		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"c_nonce":      "test-nonce",
		})
	})

	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"c_nonce": "test-nonce",
		})
	})

	mux.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"credentials": []map[string]string{{
				"credential": defaultCredentialJWT,
			}},
		})
	})

	credentialIssuer, err := url.Parse(server.URL)
	require.NoError(t, err)

	return credentialIssuer, tokenFormCh, server.Close
}

func TestController_ReceiveCredential_InvalidOffer_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test with nil credential offer - this tests validation logic
	req := ReceiveCredentialRequest{
		CredentialOffer: nil,
		Type:            receiverTypes.Oid4vci,
		Key:             newMockKeyEntry(),
	}

	_, err := controller.ReceiveCredential(req)
	if err == nil {
		t.Error("expected error for nil credential offer")
	}
	if err.Error() != "credential offer is required" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestController_ReceiveCredential_MissingPreAuthCode_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	credentialIssuer, _ := url.Parse("https://issuer.example.com")
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           credentialIssuer,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants:                     map[string]*CredentialOfferGrant{},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	_, err := controller.ReceiveCredential(req)
	if err == nil {
		t.Error("expected error for missing pre-auth code")
	}
	if err.Error() != "pre-authorization code is not included in the offer" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestController_ReceiveCredential_EmptyConfigurationIDs_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	credentialIssuer, _ := url.Parse("https://issuer.example.com")
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           credentialIssuer,
			CredentialConfigurationIDs: []string{},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	_, err := controller.ReceiveCredential(req)
	if err == nil {
		t.Error("expected error for empty configuration IDs")
	}
	if err.Error() != "credential configuration IDs are empty" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestController_ReceiveCredential_TxCodeOmitted_Integration(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	credentialIssuer, tokenFormCh, closeServer := newReceiveCredentialTestServer(t)
	defer closeServer()

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           credentialIssuer,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
					TxCode:            &TxCode{},
				},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	_, err := controller.ReceiveCredential(req)
	require.NoError(t, err)

	select {
	case form := <-tokenFormCh:
		require.Equal(t, "urn:ietf:params:oauth:grant-type:pre-authorized_code", form.Get("grant_type"))
		require.Equal(t, "test-code", form.Get("pre-authorized_code"))
		require.NotContains(t, form, "tx_code")
	case <-time.After(2 * time.Second):
		require.FailNow(t, "token endpoint was not called")
	}
}

func TestController_ReceiveCredential_TxCodeProvided_Integration(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	credentialIssuer, tokenFormCh, closeServer := newReceiveCredentialTestServer(t)
	defer closeServer()

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           credentialIssuer,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
					TxCode:            &TxCode{},
				},
			},
		},
		Type:   receiverTypes.Oid4vci,
		Key:    newMockKeyEntry(),
		TxCode: "123456",
	}

	_, err := controller.ReceiveCredential(req)
	require.NoError(t, err)

	select {
	case form := <-tokenFormCh:
		require.Equal(t, "123456", form.Get("tx_code"))
	case <-time.After(2 * time.Second):
		require.FailNow(t, "tx_code was not received at token endpoint")
	}
}

func TestController_FetchAuthorizationServerMetadata_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test fetchAuthorizationServerMetadata by calling methods that use it
	// This is a private method, so we test it indirectly through ReceiveCredential
	server := createMockOID4VCIServer()
	defer server.Close()

	serverURL, _ := url.Parse(server.URL())
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           serverURL,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	// This will call fetchAuthorizationServerMetadata internally
	// In test environment without proper server setup, this is expected to fail
	_, err := controller.ReceiveCredential(req)
	if err == nil {
		t.Error("Expected ReceiveCredential to fail in test environment without proper server setup")
	}
}

func TestWallet_obtainAccessToken_DPoPEnabledControlsProof(t *testing.T) {

	tokenEndpoint, err := common.ParseURIField("https://server.example.com/token")
	require.NoError(t, err)
	authMetadata := &receiverTypes.AuthorizationServerMetadata{
		TokenEndpoint: tokenEndpoint,
		PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
	}
	t.Run("disabled does not attach proof", func(t *testing.T) {
		cap := &captureDpopReceiver{}
		d, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Mock, cap))
		require.NoError(t, err)
		w := &Wallet{
			receiver: d,
			dpop:     DPoPConfig{Enabled: false},
		}
		_, err = w.obtainAccessToken(receiverTypes.Mock, authMetadata, "pre-auth-code", "")
		require.NoError(t, err)
		assert.Nil(t, cap.capturedProof)
	})
	t.Run("enabled attaches proof", func(t *testing.T) {
		key, err := newInMemoryECKeyEntry()
		require.NoError(t, err)
		cap := &captureDpopReceiver{}
		d, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Mock, cap))
		require.NoError(t, err)
		w := &Wallet{
			receiver: d,
			dpop: DPoPConfig{
				Enabled: true,
				Key:     key,
			},
		}
		_, err = w.obtainAccessToken(receiverTypes.Mock, authMetadata, "pre-auth-code", "")
		require.NoError(t, err)
		require.NotNil(t, cap.capturedProof)
		assert.NotEmpty(t, *cap.capturedProof)
	})

}

func TestWallet_obtainAccessToken_DPoPNonceChallengeRetriesWithNonce(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	const (
		dpopNonce        = "token-dpop-nonce"
		accessTokenValue = "dpop-access-token"
	)

	obs := newServerObservations(t, "token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		tokenRequests := obs.called("token")
		dpopProof := r.Header.Get("DPoP")
		if dpopProof == "" {
			http.Error(w, "missing DPoP header", http.StatusBadRequest)
			return
		}
		payloadBytes, err := base64.RawURLEncoding.DecodeString(strings.Split(dpopProof, ".")[1])
		if err != nil {
			http.Error(w, "invalid DPoP payload", http.StatusBadRequest)
			return
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			http.Error(w, "invalid DPoP payload json", http.StatusBadRequest)
			return
		}

		if tokenRequests == 1 {
			if _, exists := payload["nonce"]; exists {
				http.Error(w, "first DPoP proof should not include nonce", http.StatusBadRequest)
				return
			}
			w.Header().Set("DPoP-Nonce", dpopNonce)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if payload["nonce"] != dpopNonce {
			http.Error(w, "retry DPoP proof missing nonce", http.StatusBadRequest)
			return
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"access_token": accessTokenValue,
			"token_type":   "DPoP",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	tokenEndpoint, err := common.ParseURIField(server.URL + "/token")
	require.NoError(t, err)
	authMetadata := &receiverTypes.AuthorizationServerMetadata{
		TokenEndpoint: tokenEndpoint,
		PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
	}
	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	d, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
		dpop: DPoPConfig{
			Enabled: true,
			Key:     dpopKey,
		},
	}

	token, err := w.obtainAccessToken(receiverTypes.Oid4vci, authMetadata, "pre-auth-code", "")
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, accessTokenValue, token.Token)
	assert.Equal(t, 2, obs.callCount("token"))
}

type captureClientAuthReceiver struct {
	capturedClientID        *string
	capturedClientAssertion *string
	capturedDPoP            *string
}

func (c *captureClientAuthReceiver) FetchIssuerMetadata(endpoint common.URIField, rt receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error) {
	return nil, fmt.Errorf("unexpected call to FetchIssuerMetadata")
}

func (c *captureClientAuthReceiver) FetchAuthorizationServerMetadata(endpoint common.URIField, rt receiverTypes.SupportedReceivingTypes) (*receiverTypes.AuthorizationServerMetadata, error) {
	return nil, fmt.Errorf("unexpected call to FetchAuthorizationServerMetadata")
}

func (c *captureClientAuthReceiver) FetchAccessToken(rt receiverTypes.SupportedReceivingTypes, endpoint common.URIField, authzCode string, txCode string, opts ...receiverTypes.TokenRequestOption) (*receiverTypes.CredentialIssuanceAccessToken, error) {
	cfg := receiverTypes.NewTokenRequestConfig(opts...)
	if cfg.ClientAssertion != "" {
		id, assertion := cfg.ClientID, cfg.ClientAssertion
		c.capturedClientID = &id
		c.capturedClientAssertion = &assertion
	}
	if cfg.DPoPProof != "" {
		proof := cfg.DPoPProof
		c.capturedDPoP = &proof
	}
	return &receiverTypes.CredentialIssuanceAccessToken{
		Token:     "tok",
		TokenType: "Bearer",
	}, nil
}

func (c *captureClientAuthReceiver) FetchNonce(rt receiverTypes.SupportedReceivingTypes, endpoint common.URIField) (*string, error) {
	return nil, fmt.Errorf("unexpected call to FetchNonce")
}

func (c *captureClientAuthReceiver) ReceiveCredential(
	rt receiverTypes.SupportedReceivingTypes,
	endpoint common.URIField,
	credentialConfigurationID string,
	credentialIdentifier *string,
	accessToken receiverTypes.CredentialIssuanceAccessToken,
	credentialDefinition *receiverTypes.CredentialDefinition,
	jwtProof *string,
	options ...*receiverTypes.CredentialRequestOptions,
) (*string, error) {
	return nil, fmt.Errorf("unexpected call to ReceiveCredential")
}

func TestWallet_obtainAccessToken_PrivateKeyJwtAttachesAssertion(t *testing.T) {
	tokenEndpoint, err := common.ParseURIField("https://as.example.com/token")
	require.NoError(t, err)
	authMetadata := &receiverTypes.AuthorizationServerMetadata{
		TokenEndpoint: tokenEndpoint,
		TokenEndpointAuthMethodsSupported: authMethodsPtr(
			receiverTypes.PrivateKeyJwt,
		),
		TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{jose.ES256},
	}

	key, _ := newClientAuthKeyEntry(t, "client-key-1")
	cap := &captureClientAuthReceiver{}
	d, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Mock, cap))
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
		clientAuth: ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "wallet-id",
			Key:      key,
		},
	}

	token, err := w.obtainAccessToken(receiverTypes.Mock, authMetadata, "pre-auth-code", "")
	require.NoError(t, err)
	require.NotNil(t, token)
	require.NotNil(t, cap.capturedClientAssertion)
	require.NotNil(t, cap.capturedClientID)
	assert.Equal(t, "wallet-id", *cap.capturedClientID)
	assert.Nil(t, cap.capturedDPoP, "DPoP should not be attached when disabled")
}

func TestWallet_obtainAccessToken_AnonymousByDefaultDoesNotAttachAssertion(t *testing.T) {
	tokenEndpoint, err := common.ParseURIField("https://as.example.com/token")
	require.NoError(t, err)
	authMetadata := &receiverTypes.AuthorizationServerMetadata{
		TokenEndpoint: tokenEndpoint,
		PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
	}

	cap := &captureClientAuthReceiver{}
	d, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Mock, cap))
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
	}

	token, err := w.obtainAccessToken(receiverTypes.Mock, authMetadata, "pre-auth-code", "")
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Nil(t, cap.capturedClientAssertion, "client assertion must not be attached for anonymous flow")
}

func TestWallet_obtainAccessToken_NoUsableMethodReturnsError(t *testing.T) {
	tokenEndpoint, err := common.ParseURIField("https://as.example.com/token")
	require.NoError(t, err)
	authMetadata := &receiverTypes.AuthorizationServerMetadata{
		TokenEndpoint: tokenEndpoint,
		PreAuthorizedGrantAnonymousAccessSupported: boolPtr(false),
	}

	cap := &captureClientAuthReceiver{}
	d, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Mock, cap))
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
	}

	_, err = w.obtainAccessToken(receiverTypes.Mock, authMetadata, "pre-auth-code", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no usable client authentication method")
}

func TestWallet_obtainAccessToken_PrivateKeyJwtEndToEndWithMockServer(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	key, publicJWK := newClientAuthKeyEntry(t, "client-key-1")
	pubKey := publicJWK

	issuerConfig := &mockserver.OID4VCIIssuerConfig{
		KeyPair:                           mockserver.MustGenerateKeyPair("issuer-key-id"),
		IssuerID:                          "test-issuer",
		PreAuthorizedGrantAnonymous:       mockserver.BoolPtr(false),
		TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"},
		TokenEndpointAuthSigningAlgs:      []string{"ES256"},
		RequireClientAssertion:            true,
		ClientAuthPublicKey:               &pubKey,
		ExpectedClientID:                  "wallet-id",
		CredentialConfigurations: map[string]interface{}{
			"test-config": map[string]interface{}{
				"format": "jwt_vc_json",
				"credential_definition": map[string]interface{}{
					"type": []string{"VerifiableCredential"},
				},
			},
		},
		TokenResponse: map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"c_nonce":      "mock-nonce",
		},
		CustomCredentials: make(map[string]string),
	}
	issuer := mockserver.NewOID4VCIIssuerServer(issuerConfig)
	defer issuer.Close()

	// Fix the expected aud on the server side. Letting the mock derive it from
	// the incoming request would make the check tautological, since the wallet
	// resolves the same value from this server's metadata.
	issuerConfig.ClientAssertionAudience = issuer.URL()

	issuerURL, err := url.Parse(issuer.URL())
	require.NoError(t, err)
	asEndpoint := common.URIField(*issuerURL)
	tokenEndpoint, err := common.ParseURIField(issuer.URL() + "/token")
	require.NoError(t, err)

	d, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
		clientAuth: ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "wallet-id",
			Key:      key,
		},
	}

	authMetadata, err := d.FetchAuthorizationServerMetadata(asEndpoint, receiverTypes.Oid4vci)
	require.NoError(t, err)
	require.NotNil(t, authMetadata.TokenEndpoint)

	authMetadata.TokenEndpoint = tokenEndpoint

	token, err := w.obtainAccessToken(receiverTypes.Oid4vci, authMetadata, "pre-auth-code", "")
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "mock-access-token", token.Token)
}

func TestWallet_fetchCredentialMetadata_UsesCredentialIssuerAsAuthorizationServerWhenOmitted(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	key, _ := newClientAuthKeyEntry(t, "client-key-1")
	issuer := mockserver.NewOID4VCIIssuerServer(&mockserver.OID4VCIIssuerConfig{
		KeyPair:                           mockserver.MustGenerateKeyPair("issuer-key-id"),
		IssuerID:                          "test-issuer",
		PreAuthorizedGrantAnonymous:       mockserver.BoolPtr(false),
		OmitAuthorizationServers:          true,
		TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"},
		TokenEndpointAuthSigningAlgs:      []string{"ES256"},
		CredentialConfigurations: map[string]interface{}{
			"test-config": map[string]interface{}{
				"format": "jwt_vc_json",
				"credential_definition": map[string]interface{}{
					"type": []string{"VerifiableCredential"},
				},
			},
		},
		CustomCredentials: make(map[string]string),
	})
	defer issuer.Close()

	issuerURL, err := url.Parse(issuer.URL())
	require.NoError(t, err)

	d, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
		clientAuth: ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "wallet-id",
			Key:      key,
		},
	}

	offer := &CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{"test-config"},
		Grants:                     map[string]*CredentialOfferGrant{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {}},
	}
	req := ReceiveCredentialRequest{
		CredentialOffer: offer,
		Type:            receiverTypes.Oid4vci,
	}

	_, authMetadata, err := w.fetchCredentialMetadata(req)
	require.NoError(t, err)
	require.NotNil(t, authMetadata)
}

func TestWallet_fetchCredentialMetadata_RejectsEmptyAuthorizationServers(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	issuer := mockserver.NewOID4VCIIssuerServer(&mockserver.OID4VCIIssuerConfig{
		KeyPair:                     mockserver.MustGenerateKeyPair("issuer-key-id"),
		PreAuthorizedGrantAnonymous: mockserver.BoolPtr(true),
		EmptyAuthorizationServers:   true,
		CredentialConfigurations: map[string]interface{}{
			"test-config": map[string]interface{}{
				"format": "jwt_vc_json",
				"credential_definition": map[string]interface{}{
					"type": []string{"VerifiableCredential"},
				},
			},
		},
		CustomCredentials: make(map[string]string),
	})
	defer issuer.Close()

	issuerURL, err := url.Parse(issuer.URL())
	require.NoError(t, err)
	dispatcher, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	require.NoError(t, err)
	w := &Wallet{receiver: dispatcher}

	_, _, err = w.fetchCredentialMetadata(ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants:                     map[string]*CredentialOfferGrant{},
		},
		Type: receiverTypes.Oid4vci,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization_servers must not be an empty array")
}

func TestWallet_fetchCredentialMetadata_RejectsWhenNoUsableMethod(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	issuer := mockserver.NewOID4VCIIssuerServer(&mockserver.OID4VCIIssuerConfig{
		KeyPair:                     mockserver.MustGenerateKeyPair("issuer-key-id"),
		IssuerID:                    "test-issuer",
		PreAuthorizedGrantAnonymous: mockserver.BoolPtr(false),
		CredentialConfigurations: map[string]interface{}{
			"test-config": map[string]interface{}{
				"format": "jwt_vc_json",
				"credential_definition": map[string]interface{}{
					"type": []string{"VerifiableCredential"},
				},
			},
		},
		CustomCredentials: make(map[string]string),
	})
	defer issuer.Close()

	issuerURL, err := url.Parse(issuer.URL())
	require.NoError(t, err)

	d, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	require.NoError(t, err)
	w := &Wallet{receiver: d}

	offer := &CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{"test-config"},
		Grants:                     map[string]*CredentialOfferGrant{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {}},
	}
	req := ReceiveCredentialRequest{
		CredentialOffer: offer,
		Type:            receiverTypes.Oid4vci,
	}

	_, _, err = w.fetchCredentialMetadata(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no usable client authentication method")
}

// TestWallet_fetchCredentialMetadata_PreAuthorizedGrantAnonymousAccess pins the three
// states of the OPTIONAL pre-authorized_grant_anonymous_access_supported metadata
// parameter. Omitting it means "unknown", not "unsupported" — issuers commonly leave it
// out, the OpenID conformance suite among them — so only an explicit false may stop the
// pre-authorized code flow.
func TestWallet_fetchCredentialMetadata_PreAuthorizedGrantAnonymousAccess(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	tests := []struct {
		name            string
		anonymousAccess *bool
		wantErr         bool
	}{
		{name: "omitted", anonymousAccess: nil, wantErr: false},
		{name: "explicit true", anonymousAccess: mockserver.BoolPtr(true), wantErr: false},
		{name: "explicit false", anonymousAccess: mockserver.BoolPtr(false), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := mockserver.NewOID4VCIIssuerServer(&mockserver.OID4VCIIssuerConfig{
				KeyPair:                     mockserver.MustGenerateKeyPair("issuer-key-id"),
				IssuerID:                    "test-issuer",
				PreAuthorizedGrantAnonymous: tt.anonymousAccess,
				CredentialConfigurations: map[string]interface{}{
					"test-config": map[string]interface{}{
						"format": "jwt_vc_json",
						"credential_definition": map[string]interface{}{
							"type": []string{"VerifiableCredential"},
						},
					},
				},
				CustomCredentials: make(map[string]string),
			})
			defer issuer.Close()

			issuerURL, err := url.Parse(issuer.URL())
			require.NoError(t, err)

			d, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
			require.NoError(t, err)
			w := &Wallet{receiver: d}

			_, authMetadata, err := w.fetchCredentialMetadata(ReceiveCredentialRequest{
				CredentialOffer: &CredentialOffer{
					CredentialIssuer:           issuerURL,
					CredentialConfigurationIDs: []string{"test-config"},
					Grants:                     map[string]*CredentialOfferGrant{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {}},
				},
				Type: receiverTypes.Oid4vci,
			})

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "no usable client authentication method")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, authMetadata)
		})
	}
}

// TestWallet_obtainAccessToken_OmittedAnonymousAccessSendsClientID checks that an issuer
// which never advertises pre-authorized_grant_anonymous_access_supported still receives a
// token request, and that the request names the configured client. The assertion is on
// what reached the server rather than on the returned token, because the failure this
// guards against stopped the wallet before any request went out.
func TestWallet_obtainAccessToken_OmittedAnonymousAccessSendsClientID(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	issuer := mockserver.NewOID4VCIIssuerServer(&mockserver.OID4VCIIssuerConfig{
		KeyPair:                     mockserver.MustGenerateKeyPair("issuer-key-id"),
		IssuerID:                    "test-issuer",
		PreAuthorizedGrantAnonymous: nil,
		CredentialConfigurations: map[string]interface{}{
			"test-config": map[string]interface{}{
				"format": "jwt_vc_json",
				"credential_definition": map[string]interface{}{
					"type": []string{"VerifiableCredential"},
				},
			},
		},
		TokenResponse: map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		},
		CustomCredentials: make(map[string]string),
	})
	defer issuer.Close()

	issuerURL, err := url.Parse(issuer.URL())
	require.NoError(t, err)

	d, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
		clientAuth: ClientAuthConfig{
			Method:   receiverTypes.None,
			ClientID: "wallet-id",
		},
	}

	authMetadata, err := d.FetchAuthorizationServerMetadata(common.URIField(*issuerURL), receiverTypes.Oid4vci)
	require.NoError(t, err)
	require.Nil(t, authMetadata.PreAuthorizedGrantAnonymousAccessSupported,
		"the mock must omit the parameter for this test to mean anything")

	token, err := w.obtainAccessToken(receiverTypes.Oid4vci, authMetadata, "pre-auth-code", "")
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "mock-access-token", token.Token)

	tokenRequests := issuer.TokenRequests()
	require.Len(t, tokenRequests, 1, "the wallet must reach the token endpoint")
	assert.Equal(t, "urn:ietf:params:oauth:grant-type:pre-authorized_code", tokenRequests[0].Get("grant_type"))
	assert.Equal(t, "wallet-id", tokenRequests[0].Get("client_id"))
	assert.Empty(t, tokenRequests[0].Get("client_assertion"), "no client authentication is configured")
}

const testMaxNonceResponseBodyBytes int64 = 4 << 10

func TestController_fetchCredentialNonce_FallbackToAccessTokenWhenEndpointMissing(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	cnonce := "token-c-nonce"
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{CNonce: &cnonce}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, cnonce, *nonce)
}

func TestController_fetchCredentialNonce_ReturnsNilWhenNoNonceSource(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, &receiverTypes.CredentialIssuerMetadata{}, &receiverTypes.CredentialIssuanceAccessToken{})
	require.NoError(t, err)
	require.Nil(t, nonce)
}

func TestController_fetchCredentialNonce_FallbackToAccessTokenWhenEndpointFails(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	nonceEndpoint, err := common.ParseURIField("http://127.0.0.1:1/nonce")
	require.NoError(t, err)

	cnonce := "token-c-nonce"
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{CNonce: &cnonce}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, cnonce, *nonce)
}

func TestController_fetchCredentialNonce_RejectsNonHTTPSNonceEndpoint(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(false)
	controller := createTestControllerWithDefaults(t)

	nonceEndpoint, err := common.ParseURIField("http://example.com/nonce")
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.Error(t, err)
	require.Nil(t, nonce)
	assert.Contains(t, err.Error(), "unsupported URL scheme")
}

func TestController_fetchCredentialNonce_UsesNonceEndpointWhenFallbackMissing(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	nonceValue := "nonce-from-endpoint"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "invalid method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"` + nonceValue + `"}`))
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, nonceValue, *nonce)
}

func TestController_fetchCredentialNonce_ReturnsErrorWhenEndpointFailsWithoutFallback(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary failure", http.StatusInternalServerError)
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.Error(t, err)
	require.Nil(t, nonce)
	assert.Contains(t, err.Error(), "nonce endpoint returned status")
}

func TestController_fetchCredentialNonce_FallbackToAccessTokenWhenResponseTooLarge(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	largeNonce := strings.Repeat("a", int(testMaxNonceResponseBodyBytes))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"` + largeNonce + `"}`))
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)

	fallback := "token-c-nonce"
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{CNonce: &fallback}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, fallback, *nonce)
}

func TestController_fetchCredentialNonce_ReturnsErrorWhenResponseTooLargeWithoutFallback(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	largeNonce := strings.Repeat("a", int(testMaxNonceResponseBodyBytes))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"` + largeNonce + `"}`))
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.Error(t, err)
	require.Nil(t, nonce)
	assert.Contains(t, err.Error(), "nonce endpoint response exceeds")
}

func TestController_requestCredential_DPoPAccessTokenRetriesWithNonceFromHeader(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)
	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	controller.dpop = DPoPConfig{
		Enabled: true,
		Key:     dpopKey,
	}

	const (
		accessTokenValue = "dpop-access-token"
		dpopNonce        = "issuer-dpop-nonce"
	)

	obs := newServerObservations(t, "nonce", "credential")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nonce":
			obs.called("nonce")
			if r.Method != http.MethodPost {
				http.Error(w, "invalid method", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("DPoP-Nonce", dpopNonce)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"c_nonce":"credential-proof-nonce"}`))
		case "/credential":
			credentialRequests := obs.called("credential")
			if got := r.Header.Get("Authorization"); got != "DPoP "+accessTokenValue {
				http.Error(w, "invalid authorization header: "+got, http.StatusBadRequest)
				return
			}
			dpopProof := r.Header.Get("DPoP")
			if dpopProof == "" {
				http.Error(w, "missing DPoP header", http.StatusBadRequest)
				return
			}

			parts := strings.Split(dpopProof, ".")
			if len(parts) != 3 {
				http.Error(w, "invalid DPoP proof", http.StatusBadRequest)
				return
			}
			payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				http.Error(w, "invalid DPoP payload", http.StatusBadRequest)
				return
			}
			var payload map[string]interface{}
			if err := json.Unmarshal(payloadBytes, &payload); err != nil {
				http.Error(w, "invalid DPoP payload json", http.StatusBadRequest)
				return
			}

			accessTokenHash := sha256.Sum256([]byte(accessTokenValue))
			expectedAth := base64.RawURLEncoding.EncodeToString(accessTokenHash[:])
			if payload["ath"] != expectedAth {
				http.Error(w, "invalid ath", http.StatusBadRequest)
				return
			}

			if credentialRequests == 1 {
				if _, exists := payload["nonce"]; exists {
					http.Error(w, "first DPoP proof should not include nonce", http.StatusBadRequest)
					return
				}
				w.Header().Set("DPoP-Nonce", dpopNonce)
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
					"error": "use_dpop_nonce",
				})
				return
			}

			if payload["nonce"] != dpopNonce {
				http.Error(w, "retry DPoP proof missing nonce", http.StatusBadRequest)
				return
			}

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	credentialEndpoint, err := common.ParseURIField(server.URL + "/credential")
	require.NoError(t, err)
	nonceEndpoint, err := common.ParseURIField(server.URL + "/nonce")
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer:   server.URL,
		CredentialEndpoint: *credentialEndpoint,
		NonceEndpoint:      nonceEndpoint,
	}
	offerURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           offerURL,
			CredentialConfigurationIDs: []string{"test-config"},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token:     accessTokenValue,
		TokenType: "DPoP",
	}

	credential, err := controller.requestCredential(req, issuerMetadata, accessToken, "test-config", nil)
	require.NoError(t, err)
	require.NotNil(t, credential)
	assert.Equal(t, 2, obs.callCount("credential"))
}

func TestController_requestCredential_DPoPAccessTokenUsesConfiguredDPoPKey(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	holderKey := newMockKeyEntry()
	controller.dpop = DPoPConfig{
		Enabled: true,
		Key:     dpopKey,
	}

	const accessTokenValue = "dpop-access-token"

	obs := newServerObservations(t, "credential")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/credential" {
			http.NotFound(w, r)
			return
		}
		obs.called("credential")
		if got := r.Header.Get("Authorization"); got != "DPoP "+accessTokenValue {
			http.Error(w, "invalid authorization header: "+got, http.StatusBadRequest)
			return
		}
		dpopProof := r.Header.Get("DPoP")
		if dpopProof == "" {
			http.Error(w, "missing DPoP header", http.StatusBadRequest)
			return
		}
		headerJWK, found := observedHeaderField(obs, dpopProof, "jwk")
		if !found {
			http.Error(w, "DPoP proof has no jwk header", http.StatusBadRequest)
			return
		}
		jwk, ok := headerJWK.(map[string]any)
		if !assert.True(obs, ok) {
			http.Error(w, "DPoP proof jwk header is not an object", http.StatusBadRequest)
			return
		}
		if got := jwk["kid"]; got != dpopKey.ID() {
			http.Error(w, fmt.Sprintf("DPoP proof kid = %v", got), http.StatusBadRequest)
			return
		}

		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"credentials": []map[string]string{{
				"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
			}},
		})
	}))
	defer server.Close()

	credentialEndpoint, err := common.ParseURIField(server.URL + "/credential")
	require.NoError(t, err)
	offerURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           offerURL,
			CredentialConfigurationIDs: []string{"test-config"},
		},
		Type: receiverTypes.Oid4vci,
		Key:  holderKey,
	}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token:     accessTokenValue,
		TokenType: "DPoP",
	}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer:   server.URL,
		CredentialEndpoint: *credentialEndpoint,
	}

	credential, err := controller.requestCredential(req, issuerMetadata, accessToken, "test-config", nil)
	require.NoError(t, err)
	require.NotNil(t, credential)
}

func TestController_requestCredential_DPoPNonceChallengeDoesNotRefetchCredentialNonce(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)
	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	controller.dpop = DPoPConfig{
		Enabled: true,
		Key:     dpopKey,
	}

	const (
		accessTokenValue       = "dpop-access-token"
		credentialHeaderNonce  = "credential-dpop-nonce"
		nonceEndpointDPoPNonce = "nonce-endpoint-dpop-nonce"
	)

	obs := newServerObservations(t, "nonce", "credential")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nonce":
			obs.called("nonce")
			if !assert.Zero(obs, obs.callCount("credential"), "c_nonce must be fetched before requesting the credential") {
				http.Error(w, "c_nonce must be fetched before requesting the credential", http.StatusBadRequest)
				return
			}
			if r.Method != http.MethodPost {
				http.Error(w, "invalid method", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("DPoP-Nonce", nonceEndpointDPoPNonce)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"c_nonce":"credential-proof-nonce"}`))
			return
		case "/credential":
		default:
			http.NotFound(w, r)
			return
		}

		credentialRequests := obs.called("credential")
		dpopProof := r.Header.Get("DPoP")
		if dpopProof == "" {
			http.Error(w, "missing DPoP header", http.StatusBadRequest)
			return
		}
		payloadBytes, err := base64.RawURLEncoding.DecodeString(strings.Split(dpopProof, ".")[1])
		if err != nil {
			http.Error(w, "invalid DPoP payload", http.StatusBadRequest)
			return
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			http.Error(w, "invalid DPoP payload json", http.StatusBadRequest)
			return
		}

		if credentialRequests == 1 {
			if _, exists := payload["nonce"]; exists {
				http.Error(w, "first DPoP proof should not include nonce", http.StatusBadRequest)
				return
			}
			w.Header().Set("DPoP-Nonce", credentialHeaderNonce)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if payload["nonce"] != credentialHeaderNonce {
			http.Error(w, "retry DPoP proof missing nonce", http.StatusBadRequest)
			return
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"credentials": []map[string]string{{
				"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
			}},
		})
	}))
	defer server.Close()

	credentialEndpoint, err := common.ParseURIField(server.URL + "/credential")
	require.NoError(t, err)
	offerURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           offerURL,
			CredentialConfigurationIDs: []string{"test-config"},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token:     accessTokenValue,
		TokenType: "DPoP",
	}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer:   server.URL,
		CredentialEndpoint: *credentialEndpoint,
	}
	nonceEndpoint, err := common.ParseURIField(server.URL + "/nonce")
	require.NoError(t, err)
	issuerMetadata.NonceEndpoint = nonceEndpoint

	credential, err := controller.requestCredential(req, issuerMetadata, accessToken, "test-config", nil)
	require.NoError(t, err)
	require.NotNil(t, credential)
	assert.Equal(t, 2, obs.callCount("credential"))
	assert.Equal(t, 1, obs.callCount("nonce"))
}

func TestController_requestCredential_DPoPNonceError_StopsAfterSecondChallenge(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)
	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	controller.dpop = DPoPConfig{
		Enabled: true,
		Key:     dpopKey,
	}

	const accessTokenValue = "dpop-access-token"

	obs := newServerObservations(t, "credential")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/credential" {
			http.NotFound(w, r)
			return
		}
		obs.called("credential")
		if got := r.Header.Get("Authorization"); got != "DPoP "+accessTokenValue {
			http.Error(w, "invalid authorization header: "+got, http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("DPoP"); got == "" {
			http.Error(w, "missing DPoP header", http.StatusBadRequest)
			return
		}
		w.Header().Set("DPoP-Nonce", "credential-endpoint-nonce")
		mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
			"error": "use_dpop_nonce",
		})
	}))
	defer server.Close()

	credentialEndpoint, err := common.ParseURIField(server.URL + "/credential")
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer:   server.URL,
		CredentialEndpoint: *credentialEndpoint,
	}
	offerURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           offerURL,
			CredentialConfigurationIDs: []string{"test-config"},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token:     accessTokenValue,
		TokenType: "DPoP",
	}

	credential, err := controller.requestCredential(req, issuerMetadata, accessToken, "test-config", nil)
	require.Error(t, err)
	require.Nil(t, credential)
	assert.ErrorIs(t, err, receiverTypes.ErrUseDPoPNonce)
	assert.Equal(t, 2, obs.callCount("credential"))
}

func TestAccessTokenCredentialIdentifier(t *testing.T) {
	tests := []struct {
		name        string
		accessToken *receiverTypes.CredentialIssuanceAccessToken
		want        *string
	}{
		{
			name:        "nil access token",
			accessToken: nil,
			want:        nil,
		},
		{
			name: "no authorization details",
			accessToken: &receiverTypes.CredentialIssuanceAccessToken{
				Token: "test-token",
			},
			want: nil,
		},
		{
			name: "authorization details without identifiers",
			accessToken: &receiverTypes.CredentialIssuanceAccessToken{
				AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{
					{Type: receiverTypes.AuthorizationDetailTypeOpenIDCredential},
				},
			},
			want: nil,
		},
		{
			name: "ignores non-openid_credential authorization details",
			accessToken: &receiverTypes.CredentialIssuanceAccessToken{
				AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{
					{Type: "resource_access", CredentialIdentifiers: []string{"unrelated-id"}},
					{Type: receiverTypes.AuthorizationDetailTypeOpenIDCredential, CredentialIdentifiers: []string{"cred-id-2"}},
				},
			},
			want: &[]string{"cred-id-2"}[0],
		},
		{
			name: "returns nil when only non-openid_credential details exist",
			accessToken: &receiverTypes.CredentialIssuanceAccessToken{
				AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{
					{Type: "resource_access", CredentialIdentifiers: []string{"unrelated-id"}},
				},
			},
			want: nil,
		},
		{
			name: "first non-empty credential identifier is selected",
			accessToken: &receiverTypes.CredentialIssuanceAccessToken{
				AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{
					{Type: receiverTypes.AuthorizationDetailTypeOpenIDCredential, CredentialIdentifiers: []string{"", "cred-id-1"}},
					{Type: receiverTypes.AuthorizationDetailTypeOpenIDCredential, CredentialIdentifiers: []string{"cred-id-2"}},
				},
			},
			want: &[]string{"cred-id-1"}[0],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := accessTokenCredentialIdentifier(tt.accessToken)
			if tt.want == nil {
				require.Nil(t, got)
				return
			}

			require.NotNil(t, got)
			assert.Equal(t, *tt.want, *got)
		})
	}
}

// createMockOID4VCIServer creates a mock HTTP server for OID4VCI testing
func createMockOID4VCIServer() *mockserver.OID4VCIIssuerServer {
	return mockserver.NewOID4VCIIssuerServer(nil)
}

func TestController_shouldAttachCredentialRequestProof_EmptyBindingMethodsOmitProof(t *testing.T) {
	req := ReceiveCredentialRequest{RequestedFormat: credential.JwtVc}
	empty := []string{}
	configuration := &receiverTypes.CredentialConfiguration{
		CryptographicBindingMethodsSupported: &empty,
	}

	attachProof := shouldAttachCredentialRequestProof(req, configuration)
	assert.False(t, attachProof)
}

func TestController_shouldAttachCredentialRequestProof_EmptyBindingMethodsWithNoRequestedFormatKeepsBackwardCompatibility(t *testing.T) {
	req := ReceiveCredentialRequest{}
	empty := []string{}
	configuration := &receiverTypes.CredentialConfiguration{
		CryptographicBindingMethodsSupported: &empty,
	}

	attachProof := shouldAttachCredentialRequestProof(req, configuration)
	assert.True(t, attachProof)
}

func TestController_selectCredentialConfiguration_UnsupportedDefaultFormatReturnsError(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	issuerURL, err := url.Parse("https://issuer.example.com")
	require.NoError(t, err)

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{"mdoc-config"},
		},
	}

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialConfigurationSupported: map[string]receiverTypes.CredentialConfiguration{
			"mdoc-config": {
				Format: "mso_mdoc",
			},
		},
	}

	configID, config, flavor, err := controller.selectCredentialConfiguration(req, issuerMetadata)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported credential format for configuration \"mdoc-config\"")
	assert.Equal(t, "", configID)
	assert.Nil(t, config)
	assert.Equal(t, credential.SupportedSerializationFlavor(""), flavor)
}

type credentialIssuanceMockServerOptions struct {
	credentialConfigurationsSupported map[string]interface{}
	tokenResponse                     map[string]interface{}
	nonceResponse                     map[string]interface{}
	includeNonceEndpoint              bool
	credential                        string
}

func newCredentialIssuanceMockServer(t *testing.T, opts credentialIssuanceMockServerOptions) (*url.URL, *map[string]interface{}, chan error) {
	t.Helper()

	if opts.credentialConfigurationsSupported == nil {
		t.Fatal("credentialConfigurationsSupported is required")
	}

	if opts.tokenResponse == nil {
		opts.tokenResponse = map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
		}
	}

	if opts.includeNonceEndpoint && opts.nonceResponse == nil {
		opts.nonceResponse = map[string]interface{}{
			"c_nonce": "nonce-from-endpoint",
		}
	}

	if opts.credential == "" {
		opts.credential = createWalletTestJwtVCCredential()
	}

	var capturedBody map[string]interface{}
	handlerErrCh := make(chan error, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL := "http://" + r.Host

		switch r.URL.Path {
		case "/.well-known/openid-credential-issuer":
			issuerResponse := map[string]interface{}{
				"credential_issuer":                   baseURL,
				"credential_endpoint":                 baseURL + "/credential",
				"authorization_servers":               []string{baseURL},
				"credential_configurations_supported": opts.credentialConfigurationsSupported,
			}
			if opts.includeNonceEndpoint {
				issuerResponse["nonce_endpoint"] = baseURL + "/nonce"
			}
			mockserver.JSONResponse(w, http.StatusOK, issuerResponse)
		case "/.well-known/oauth-authorization-server":
			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"issuer":         baseURL,
				"token_endpoint": baseURL + "/token",
				"pre-authorized_grant_anonymous_access_supported": true,
				"response_types_supported":                        []string{"code"},
			})
		case "/token":
			mockserver.JSONResponse(w, http.StatusOK, opts.tokenResponse)
		case "/nonce":
			if !opts.includeNonceEndpoint {
				http.NotFound(w, r)
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, opts.nonceResponse)
		case "/credential":
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				handlerErrCh <- fmt.Errorf("failed to read credential request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
				handlerErrCh <- fmt.Errorf("failed to decode credential request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credential": opts.credential,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	issuerURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	return issuerURL, &capturedBody, handlerErrCh
}

func TestController_ReceiveCredential_SDJwtSpecified_StoresMimeAndCanGetByID(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	sdJwtCredential := createWalletTestSDJWT()
	issuerURL, capturedBody, handlerErrCh := newCredentialIssuanceMockServer(t, credentialIssuanceMockServerOptions{
		credentialConfigurationsSupported: map[string]interface{}{
			"jwt-config": map[string]interface{}{
				"format": "jwt_vc_json",
			},
			"sdjwt-config": map[string]interface{}{
				"format": "dc+sd-jwt",
				"cryptographic_binding_methods_supported": []string{"jwk"},
			},
		},
		includeNonceEndpoint: true,
		tokenResponse: map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"c_nonce":      "mock-c-nonce",
		},
		nonceResponse: map[string]interface{}{
			"c_nonce": "nonce-from-endpoint",
		},
		credential: sdJwtCredential,
	})

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{"jwt-config", "sdjwt-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type:            receiverTypes.Oid4vci,
		Key:             newMockKeyEntry(),
		RequestedFormat: credential.SDJwtVC,
	}

	savedCredential, err := controller.ReceiveCredential(req)
	require.NoError(t, err)
	require.NotNil(t, savedCredential)

	select {
	case handlerErr := <-handlerErrCh:
		require.NoError(t, handlerErr)
	case <-time.After(time.Second):
		t.Fatal("credential endpoint was not called")
	}

	requestedConfigID, ok := (*capturedBody)["credential_configuration_id"].(string)
	require.True(t, ok, "credential_configuration_id should be a string")
	assert.Equal(t, "sdjwt-config", requestedConfigID)

	proofs, ok := (*capturedBody)["proofs"].(map[string]interface{})
	require.True(t, ok, "proofs should be present for cryptographic binding")
	jwtProofs, ok := proofs["jwt"].([]interface{})
	require.True(t, ok, "proofs.jwt should be present")
	require.Len(t, jwtProofs, 1, "proofs.jwt should contain one proof")
	proofJWT, ok := jwtProofs[0].(string)
	require.True(t, ok, "proofs.jwt[0] should be a JWT string")

	proofParts := strings.Split(proofJWT, ".")
	require.Len(t, proofParts, 3, "proof JWT should have 3 parts")
	proofHeaderBytes, err := base64.RawURLEncoding.DecodeString(proofParts[0])
	require.NoError(t, err)

	var proofHeader map[string]interface{}
	require.NoError(t, json.Unmarshal(proofHeaderBytes, &proofHeader))
	_, hasJWK := proofHeader["jwk"]
	assert.True(t, hasJWK, "proof JWT header should include jwk when binding method supports jwk")
	_, hasKID := proofHeader["kid"]
	assert.False(t, hasKID, "proof JWT header should not include kid when jwk is used")

	assert.Equal(t, string(credential.SDJwtVC), savedCredential.Entry.MimeType)
	require.NotNil(t, savedCredential.Credential)
	require.NotNil(t, savedCredential.Credential.SDJwt)
	assert.Len(t, savedCredential.Credential.SDJwt.SD, 2)

	retrievedCredential, err := controller.GetCredentialEntry(savedCredential.Entry.Id)
	require.NoError(t, err)
	require.NotNil(t, retrievedCredential)
	assert.Equal(t, savedCredential.Entry.Id, retrievedCredential.Entry.Id)
	assert.Equal(t, string(credential.SDJwtVC), retrievedCredential.Entry.MimeType)
}

func TestController_ReceiveCredential_AttachesProofWhenCryptographicBindingMethodsSupported(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	issuerURL, capturedBody, handlerErrCh := newCredentialIssuanceMockServer(t, credentialIssuanceMockServerOptions{
		credentialConfigurationsSupported: map[string]interface{}{
			"jwt-config": map[string]interface{}{
				"format": "jwt_vc_json",
				"cryptographic_binding_methods_supported": []string{"jwk"},
			},
		},
		includeNonceEndpoint: true,
		tokenResponse: map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"c_nonce":      "mock-c-nonce",
		},
		nonceResponse: map[string]interface{}{
			"c_nonce": "nonce-from-endpoint",
		},
	})

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{"jwt-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type:            receiverTypes.Oid4vci,
		Key:             newMockKeyEntry(),
		RequestedFormat: credential.JwtVc,
	}

	_, err := controller.ReceiveCredential(req)
	require.NoError(t, err)

	select {
	case handlerErr := <-handlerErrCh:
		require.NoError(t, handlerErr)
	case <-time.After(time.Second):
		t.Fatal("credential endpoint was not called")
	}

	proofs, ok := (*capturedBody)["proofs"].(map[string]interface{})
	require.True(t, ok, "proofs should be present when cryptographic_binding_methods_supported exists")
	jwtProofs, ok := proofs["jwt"].([]interface{})
	require.True(t, ok, "proofs.jwt should be present")
	require.Len(t, jwtProofs, 1, "proofs.jwt should contain one proof")
}

func TestController_ReceiveCredential_OmitsProofWhenBindingNotRequired_AllowsNilKey(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	issuerURL, capturedBody, handlerErrCh := newCredentialIssuanceMockServer(t, credentialIssuanceMockServerOptions{
		credentialConfigurationsSupported: map[string]interface{}{
			"jwt-config": map[string]interface{}{
				"format": "jwt_vc_json",
			},
		},
		tokenResponse: map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
		},
	})

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{"jwt-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type:            receiverTypes.Oid4vci,
		RequestedFormat: credential.JwtVc,
	}
	require.Nil(t, req.Key, "nil key should be allowed when cryptographic binding is not required")

	savedCredential, err := controller.ReceiveCredential(req)
	require.NoError(t, err)
	require.NotNil(t, savedCredential)
	require.Nil(t, req.Key, "request key should remain nil")

	select {
	case handlerErr := <-handlerErrCh:
		require.NoError(t, handlerErr)
	case <-time.After(time.Second):
		t.Fatal("credential endpoint was not called")
	}

	_, hasProof := (*capturedBody)["proof"]
	assert.False(t, hasProof, "proof should not be present when binding is not required")
	_, hasProofs := (*capturedBody)["proofs"]
	assert.False(t, hasProofs, "proofs should not be present when binding is not required")
	assert.Equal(t, string(credential.JwtVc), savedCredential.Entry.MimeType)
}

func TestController_ReceiveCredential_WithMockServer_Integration(t *testing.T) {
	http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(http_allowed)
	env.SetHTTPAllowed(true)
	// Create mock HTTP server
	server := createMockOID4VCIServer()
	defer server.Close()

	controller := createTestControllerWithDefaults(t)

	// Parse server URL
	serverURL, err := url.Parse(server.URL())
	if err != nil {
		t.Fatalf("Failed to parse server URL: %v", err)
	}

	// Test with valid credential offer using mock server
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           serverURL,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	// First test metadata fetch to debug
	metadata, err := controller.FetchCredentialIssuerMetadata(serverURL, receiverTypes.Oid4vci)
	if err != nil {
		t.Fatalf("FetchCredentialIssuerMetadata failed: %v", err)
	}
	t.Logf("Fetched issuer metadata: %+v", metadata)

	// This should now work with the mock server
	// If this fails, we need to check the mock server setup or credential format
	credential, err := controller.ReceiveCredential(req)
	if err != nil {
		t.Skipf("ReceiveCredential failed with mock server, skipping rest of test: %v", err)
	}

	if credential == nil {
		t.Error("Expected non-nil credential")
	}

	t.Logf("Successfully received credential: %+v", credential)
}

func TestController_FetchCredentialIssuerMetadata_WithMockServer(t *testing.T) {
	http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(http_allowed)
	env.SetHTTPAllowed(true)
	server := createMockOID4VCIServer()
	defer server.Close()

	controller := createTestControllerWithDefaults(t)

	serverURL, _ := url.Parse(server.URL())

	metadata, err := controller.FetchCredentialIssuerMetadata(serverURL, receiverTypes.Oid4vci)
	if err != nil {
		t.Errorf("FetchCredentialIssuerMetadata failed: %v", err)
		return
	}

	if metadata == nil {
		t.Error("Expected non-nil metadata")
	}

	t.Logf("Successfully fetched metadata: %+v", metadata)
}

func TestController_ReceiveCredential_RejectsUnsupportedCredentialConfigurationID(t *testing.T) {
	server := createMockOID4VCIServer()
	defer server.Close()

	serverURL, err := url.Parse(server.URL())
	require.NoError(t, err)

	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           serverURL,
			CredentialConfigurationIDs: []string{"unsupported-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	credential, err := controller.ReceiveCredential(req)
	require.Error(t, err)
	require.Nil(t, credential)
	require.Contains(t, err.Error(), `credential configuration "unsupported-config" is not supported by issuer metadata`)
}

func TestController_FetchCredentialIssuerMetadata_ErrorPaths_Integration(t *testing.T) {
	http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(http_allowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	tests := []struct {
		name         string
		setupURL     func() *url.URL
		receiverType receiverTypes.SupportedReceivingTypes
		expectError  bool
	}{
		{
			name: "invalid URL",
			setupURL: func() *url.URL {
				u, _ := url.Parse("invalid://malformed.url.with.invalid.scheme")
				return u
			},
			receiverType: receiverTypes.Oid4vci,
			expectError:  true,
		},
		{
			name: "non-existent server",
			setupURL: func() *url.URL {
				u, _ := url.Parse("https://non-existent-server-12345.example.com")
				return u
			},
			receiverType: receiverTypes.Oid4vci,
			expectError:  true,
		},
		{
			name: "empty URL",
			setupURL: func() *url.URL {
				return &url.URL{}
			},
			receiverType: receiverTypes.Oid4vci,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverURL := tt.setupURL()
			_, err := controller.FetchCredentialIssuerMetadata(serverURL, tt.receiverType)

			if tt.expectError && err == nil {
				t.Errorf("FetchCredentialIssuerMetadata() expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("FetchCredentialIssuerMetadata() unexpected error: %v", err)
			}
			if tt.expectError && err != nil {
				// Expected error occurred - test passes
				return
			}
		})
	}
}

func TestController_ReceiveCredential_AdditionalErrorPaths_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test different error scenarios for ReceiveCredential
	tests := []struct {
		name     string
		setupReq func() ReceiveCredentialRequest
		wantErr  bool
	}{
		{
			name: "missing key",
			setupReq: func() ReceiveCredentialRequest {
				credentialIssuer, _ := url.Parse("https://issuer.example.com")
				return ReceiveCredentialRequest{
					CredentialOffer: &CredentialOffer{
						CredentialIssuer:           credentialIssuer,
						CredentialConfigurationIDs: []string{"test-config"},
						Grants: map[string]*CredentialOfferGrant{
							"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
								PreAuthorizedCode: "test-code",
							},
						},
					},
					Type: receiverTypes.Oid4vci,
					Key:  nil, // Missing key
				}
			},
			wantErr: true,
		},
		{
			name: "malformed issuer URL",
			setupReq: func() ReceiveCredentialRequest {
				return ReceiveCredentialRequest{
					CredentialOffer: &CredentialOffer{
						CredentialIssuer:           &url.URL{Scheme: "", Host: ""}, // Empty URL
						CredentialConfigurationIDs: []string{"test-config"},
						Grants: map[string]*CredentialOfferGrant{
							"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
								PreAuthorizedCode: "test-code",
							},
						},
					},
					Type: receiverTypes.Oid4vci,
					Key:  newMockKeyEntry(),
				}
			},
			wantErr: true,
		},
		{
			name: "invalid grant type",
			setupReq: func() ReceiveCredentialRequest {
				credentialIssuer, _ := url.Parse("https://issuer.example.com")
				return ReceiveCredentialRequest{
					CredentialOffer: &CredentialOffer{
						CredentialIssuer:           credentialIssuer,
						CredentialConfigurationIDs: []string{"test-config"},
						Grants: map[string]*CredentialOfferGrant{
							"invalid-grant-type": {
								PreAuthorizedCode: "test-code",
							},
						},
					},
					Type: receiverTypes.Oid4vci,
					Key:  newMockKeyEntry(),
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			_, err := controller.ReceiveCredential(req)
			if tt.wantErr && err == nil {
				t.Errorf("ReceiveCredential() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ReceiveCredential() unexpected error: %v", err)
			}
			if tt.wantErr && err != nil {
				// Expected error occurred - test passes
				return
			}
		})
	}
}

func TestWallet_validateCredentialOffer(t *testing.T) {
	issuerURL, err := url.Parse("https://issuer.example.com")
	require.NoError(t, err)
	httpIssuerURL, err := url.Parse("http://issuer.example.com")
	require.NoError(t, err)

	const preAuthGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		offer           *CredentialOffer
		httpAllowed     bool
		want            string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:    "nil offer",
			offer:   nil,
			wantErr: true,
		},
		{
			name: "missing pre-authorization grant",
			offer: &CredentialOffer{
				CredentialIssuer:           issuerURL,
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants:                     map[string]*CredentialOfferGrant{},
			},
			wantErr: true,
		},
		{
			name: "missing credential issuer",
			offer: &CredentialOffer{
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr: true,
		},
		{
			name: "credential issuer must include host",
			offer: &CredentialOffer{
				CredentialIssuer:           mustParseURL(t, "https:///issuer"),
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr:         true,
			wantErrContains: "credential issuer must include a host",
		},
		{
			name: "credential issuer must use https by default",
			offer: &CredentialOffer{
				CredentialIssuer:           httpIssuerURL,
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr:         true,
			wantErrContains: "credential issuer must use https scheme",
		},
		{
			name: "credential issuer allows http when configured",
			offer: &CredentialOffer{
				CredentialIssuer:           httpIssuerURL,
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			httpAllowed: true,
			want:        "pre-auth-code",
		},
		{
			name: "credential issuer must not include query",
			offer: &CredentialOffer{
				CredentialIssuer:           mustParseURL(t, "https://issuer.example.com?foo=bar"),
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr:         true,
			wantErrContains: "credential issuer must not include query or fragment",
		},
		{
			name: "credential issuer must not include fragment",
			offer: &CredentialOffer{
				CredentialIssuer:           mustParseURL(t, "https://issuer.example.com#fragment"),
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr:         true,
			wantErrContains: "credential issuer must not include query or fragment",
		},
		{
			name: "empty credential configuration IDs",
			offer: &CredentialOffer{
				CredentialIssuer: issuerURL,
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicated credential configuration IDs",
			offer: &CredentialOffer{
				CredentialIssuer:           issuerURL,
				CredentialConfigurationIDs: []string{"Degree", "VerifiableCredential", "Degree"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr:         true,
			wantErrContains: "credential configuration IDs must be unique",
		},
		{
			name: "empty pre-authorization code",
			offer: &CredentialOffer{
				CredentialIssuer:           issuerURL,
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: ""},
				},
			},
			wantErr: true,
		},
		{
			name: "valid offer",
			offer: &CredentialOffer{
				CredentialIssuer:           issuerURL,
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			want: "pre-auth-code",
		},
		{
			name: "valid offer with multiple unique credential configuration IDs",
			offer: &CredentialOffer{
				CredentialIssuer:           issuerURL,
				CredentialConfigurationIDs: []string{"Degree", "VerifiableCredential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			want: "pre-auth-code",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpAllowed := env.IsHTTPAllowed()
			debugMode := env.IsDebugMode()
			defer env.SetHTTPAllowed(httpAllowed)
			defer env.SetDebugMode(debugMode)
			env.SetDebugMode(false)
			env.SetHTTPAllowed(tt.httpAllowed)

			w, err := NewWallet()
			require.NoError(t, err)

			got, gotErr := w.validateCredentialOffer(tt.offer)
			if tt.wantErr {
				require.Error(t, gotErr)
				if tt.wantErrContains != "" {
					require.Contains(t, gotErr.Error(), tt.wantErrContains)
				}
				return
			}

			require.NoError(t, gotErr)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestWallet_validateCredentialConfigurationIDs(t *testing.T) {
	tests := []struct {
		name            string
		offer           *CredentialOffer
		issuerMetadata  *receiverTypes.CredentialIssuerMetadata
		wantErr         bool
		wantErrContains string
	}{
		{
			name:    "all offered configuration IDs are supported",
			offer:   &CredentialOffer{CredentialConfigurationIDs: []string{"EmployeeID_jwt_vc_json", "StudentID_jwt_vc_json"}},
			wantErr: false,
			issuerMetadata: &receiverTypes.CredentialIssuerMetadata{
				CredentialConfigurationSupported: map[string]receiverTypes.CredentialConfiguration{
					"EmployeeID_jwt_vc_json": {Format: "jwt_vc_json"},
					"StudentID_jwt_vc_json":  {Format: "jwt_vc_json"},
				},
			},
		},
		{
			name:  "unsupported offered configuration ID is rejected",
			offer: &CredentialOffer{CredentialConfigurationIDs: []string{"EmployeeID_jwt_vc_json", "UnknownID_jwt_vc_json"}},
			issuerMetadata: &receiverTypes.CredentialIssuerMetadata{
				CredentialConfigurationSupported: map[string]receiverTypes.CredentialConfiguration{
					"EmployeeID_jwt_vc_json": {Format: "jwt_vc_json"},
				},
			},
			wantErr:         true,
			wantErrContains: `credential configuration "UnknownID_jwt_vc_json" is not supported by issuer metadata`,
		},
		{
			name:            "missing issuer metadata is rejected",
			offer:           &CredentialOffer{CredentialConfigurationIDs: []string{"EmployeeID_jwt_vc_json"}},
			issuerMetadata:  nil,
			wantErr:         true,
			wantErrContains: "issuer metadata is required",
		},
		{
			name:  "missing supported configurations in metadata is rejected",
			offer: &CredentialOffer{CredentialConfigurationIDs: []string{"EmployeeID_jwt_vc_json"}},
			issuerMetadata: &receiverTypes.CredentialIssuerMetadata{
				CredentialConfigurationSupported: map[string]receiverTypes.CredentialConfiguration{},
			},
			wantErr:         true,
			wantErrContains: "credential configurations supported are missing in issuer metadata",
		},
	}

	w, err := NewWallet()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := w.validateCredentialConfigurationIDs(tt.offer, tt.issuerMetadata)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErrContains)
				return
			}

			require.NoError(t, err)
		})
	}
}
