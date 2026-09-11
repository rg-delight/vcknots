package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/oid4vcisign"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// Existing tests

func TestOid4vciReceiver_FetchIssuerMetadata(t *testing.T) {

	// Create mock OID4VCI issuer server
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL())
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = false

		_, err := receiver.FetchIssuerMetadata(endpoint, types.Oid4vci)
		if err == nil {
			t.Fatal("FetchIssuerMetadata should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		metadata, err := receiver.FetchIssuerMetadata(endpoint, types.Oid4vci)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if metadata == nil {
			t.Fatal("Expected metadata, got nil")
		}

		// Verify metadata contains expected fields from mock server
		if metadata.CredentialIssuer != endpoint.String() {
			t.Errorf("Expected CredentialIssuer %s, got %s", endpoint.String(), metadata.CredentialIssuer)
		}
	})

	t.Run("Unsupported receiving type", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}
		_, err := receiver.FetchIssuerMetadata(common.URIField{}, types.SupportedReceivingTypes(999))
		if err == nil {
			t.Fatal("Expected error for unsupported receiving type")
		}
	})

	t.Run("Server error", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/.well-known/openid-credential-issuer", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL())
		_, err := receiver.FetchIssuerMetadata(common.URIField(*errorURL), types.Oid4vci)
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("Empty response body", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		emptyServer := mockserver.NewMockServer()
		defer emptyServer.Close()

		emptyServer.SetTextResponse("/.well-known/openid-credential-issuer", http.StatusOK, "")

		emptyURL, _ := url.Parse(emptyServer.URL())
		_, err := receiver.FetchIssuerMetadata(common.URIField(*emptyURL), types.Oid4vci)
		if err == nil {
			t.Fatal("Expected error for empty response body")
		}
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/.well-known/openid-credential-issuer", http.StatusOK, "{not-a-valid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL())
		_, err := receiver.FetchIssuerMetadata(common.URIField(*invalidJSONURL), types.Oid4vci)
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})

	t.Run("Trailing slash in endpoint", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		metadata := types.CredentialIssuerMetadata{
			CredentialIssuer: "http://example.com",
		}
		// Use a raw handler to bypass ServeMux's automatic path cleaning and redirects
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check RequestURI for double slashes before any normalization
			if strings.Contains(r.RequestURI, "//") {
				http.Error(w, "Double slash detected: "+r.RequestURI, http.StatusBadRequest)
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, metadata)
		}))
		defer server.Close()

		// Create endpoint WITH trailing slash
		endpointURL, _ := url.Parse(server.URL + "/")
		endpoint := common.URIField(*endpointURL)

		res, err := receiver.FetchIssuerMetadata(endpoint, types.Oid4vci)
		if err != nil {
			t.Fatalf("Expected no error with trailing slash, got %v. If this is a 400 error, it means a double slash was detected.", err)
		}
		if res.CredentialIssuer != metadata.CredentialIssuer {
			t.Errorf("Expected metadata, got %v", res)
		}
	})

	t.Run("Trailing slash in endpoint with path component", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		metadata := types.CredentialIssuerMetadata{
			CredentialIssuer: "http://example.com/issuer",
		}
		// Use a raw handler to bypass ServeMux's automatic path cleaning and redirects
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.RequestURI, "//") {
				http.Error(w, "Double slash detected: "+r.RequestURI, http.StatusBadRequest)
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, metadata)
		}))
		defer server.Close()

		// Create endpoint WITH path and trailing slash
		endpointURL, _ := url.Parse(server.URL + "/issuer/")
		endpoint := common.URIField(*endpointURL)

		res, err := receiver.FetchIssuerMetadata(endpoint, types.Oid4vci)
		if err != nil {
			t.Fatalf("Expected no error with trailing slash and path, got %v. If this is a 400 error, it means a double slash was detected.", err)
		}
		if res.CredentialIssuer != metadata.CredentialIssuer {
			t.Errorf("Expected metadata, got %v", res)
		}
	})
}

func TestOid4vciReceiver_FetchAuthorizationServerMetadata(t *testing.T) {

	// Create mock OID4VCI issuer server (which also serves auth server metadata)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL())
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = false

		_, err := receiver.FetchAuthorizationServerMetadata(endpoint, types.Oid4vci)
		if err == nil {
			t.Fatal("FetchAuthorizationServerMetadata should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		metadata, err := receiver.FetchAuthorizationServerMetadata(endpoint, types.Oid4vci)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if metadata == nil {
			t.Fatal("Expected metadata, got nil")
		}

		// Verify metadata contains expected fields from mock server
		if metadata.Issuer.String() != endpoint.String() {
			t.Errorf("Expected Issuer %s, got %s", endpoint.String(), metadata.Issuer.String())
		}
		if metadata.TokenEndpoint == nil {
			t.Error("Expected TokenEndpoint to be set")
		}
	})

	t.Run("Server error", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/.well-known/oauth-authorization-server", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL())
		_, err := receiver.FetchAuthorizationServerMetadata(common.URIField(*errorURL), types.Oid4vci)
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/.well-known/oauth-authorization-server", http.StatusOK, "{invalid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL())
		_, err := receiver.FetchAuthorizationServerMetadata(common.URIField(*invalidJSONURL), types.Oid4vci)
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})
}

func TestOid4vciReceiver_FetchAccessToken(t *testing.T) {

	// Create mock OID4VCI issuer server (which serves token endpoint)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL() + "/token")
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = false

		_, err := receiver.FetchAccessToken(types.Oid4vci, endpoint, "test-code", "")
		if err == nil {
			t.Fatal("FetchAccessToken should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		token, err := receiver.FetchAccessToken(types.Oid4vci, endpoint, "test-code", "")
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if token == nil {
			t.Fatal("Expected token, got nil")
		}

		// Verify token contains expected fields from mock server
		if token.Token != "mock-access-token" {
			t.Errorf("Expected Token 'mock-access-token', got %s", token.Token)
		}
		if token.TokenType != "Bearer" {
			t.Errorf("Expected TokenType 'Bearer', got %s", token.TokenType)
		}
	})
	t.Run("Request includes tx_code when provided", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse request form: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
				handlerErrCh <- fmt.Errorf("expected grant_type to be urn:ietf:params:oauth:grant-type:pre-authorized_code, got %s", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("pre-authorized_code"); got != "test-code" {

				handlerErrCh <- fmt.Errorf("expected pre-authorized_code to be test-code, got %s", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("tx_code"); got != "123456" {
				handlerErrCh <- fmt.Errorf("expected tx_code to be 123456, got %s", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]string{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
			})
		})
		captureURL, _ := url.Parse(captureServer.URL() + "/token")
		token, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*captureURL), "test-code", "123456", nil)
		require.NoError(t, err)
		require.NotNil(t, token)
		require.NoError(t, <-handlerErrCh)
	})

	t.Run("DPoP header is set when proof is provided", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()
		var capturedDPoPValues []string
		captureServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			capturedDPoPValues = r.Header.Values("DPoP")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
		})
		captureURL, err := url.Parse(captureServer.URL() + "/token")
		require.NoError(t, err)
		proof := "header.payload.signature"
		token, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*captureURL), "code", "", types.WithDPoPProof(proof))
		require.NoError(t, err)
		require.NotNil(t, token)
		require.Len(t, capturedDPoPValues, 1)
		assert.Equal(t, proof, capturedDPoPValues[0])
	})

	t.Run("DPoP header is absent when proof is nil", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()
		var capturedDPoPValues []string
		captureServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			capturedDPoPValues = r.Header.Values("DPoP")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
		})
		captureURL, err := url.Parse(captureServer.URL() + "/token")
		require.NoError(t, err)
		token, err := receiver.FetchAccessToken(
			types.Oid4vci,
			common.URIField(*captureURL),
			"code",
			"",
		)
		require.NoError(t, err)
		require.NotNil(t, token)
		assert.Len(t, capturedDPoPValues, 0)
	})

	t.Run("DPoP header is absent when proof is empty string", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()
		var capturedDPoPValues []string
		captureServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			capturedDPoPValues = r.Header.Values("DPoP")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
		})
		captureURL, err := url.Parse(captureServer.URL() + "/token")
		require.NoError(t, err)
		empty := ""
		token, err := receiver.FetchAccessToken(
			types.Oid4vci,
			common.URIField(*captureURL),
			"code",
			"",
			types.WithDPoPProof(empty),
		)
		require.NoError(t, err)
		require.NotNil(t, token)
		assert.Len(t, capturedDPoPValues, 0)
	})

	t.Run("Server error", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/token", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL() + "/token")
		_, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*errorURL), "test-code", "")
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("use_dpop_nonce error includes nonce hint", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		nonceServer := mockserver.NewMockServer()
		defer nonceServer.Close()

		nonceServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("DPoP-Nonce", "token-dpop-nonce")
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
				"error": "use_dpop_nonce",
			})
		})

		nonceURL, _ := url.Parse(nonceServer.URL() + "/token")
		_, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*nonceURL), "test-code", "")
		require.Error(t, err)
		assert.ErrorIs(t, err, types.ErrTokenRequestFailed)
		assert.Contains(t, err.Error(), "use_dpop_nonce")
		assert.Contains(t, err.Error(), "token-dpop-nonce")
	})

	t.Run("bad request error field is surfaced", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
				"error": "invalid_dpop_proof",
			})
		})

		errorURL, _ := url.Parse(errorServer.URL() + "/token")
		_, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*errorURL), "test-code", "")
		require.Error(t, err)
		assert.ErrorIs(t, err, types.ErrTokenRequestFailed)
		assert.Contains(t, err.Error(), "invalid_dpop_proof")
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/token", http.StatusOK, "{invalid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL() + "/token")
		_, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*invalidJSONURL), "test-code", "")
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})
}

func TestOid4vciReceiver_FetchAccessToken_WithTransactionCode(t *testing.T) {
	form := fetchAccessTokenRequestForm(t, types.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "pre-authorized-code",
		TxCode:            "123456",
	})

	require.Equal(t, "urn:ietf:params:oauth:grant-type:pre-authorized_code", form.Get("grant_type"))
	require.Equal(t, "pre-authorized-code", form.Get("pre-authorized_code"))
	require.Equal(t, "123456", form.Get("tx_code"))
}

func TestOid4vciReceiver_FetchAccessToken_WithoutTransactionCode(t *testing.T) {
	form := fetchAccessTokenRequestForm(t, types.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "pre-authorized-code",
	})

	require.Equal(t, "urn:ietf:params:oauth:grant-type:pre-authorized_code", form.Get("grant_type"))
	require.Equal(t, "pre-authorized-code", form.Get("pre-authorized_code"))
	_, present := form["tx_code"]
	require.False(t, present)
}

func fetchAccessTokenRequestForm(t *testing.T, request types.PreAuthorizedCodeTokenRequest) url.Values {
	t.Helper()

	forms := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		forms <- r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-token","token_type":"Bearer"}`))
	}))
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	_, err = receiver.FetchAccessToken(types.Oid4vci, common.URIField(*serverURL), request.PreAuthorizedCode, request.TxCode)
	require.NoError(t, err)

	return <-forms
}

func TestOid4vciReceiver_FinalPrimitives(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/challenge":
			if r.Method != http.MethodPost {
				t.Errorf("challenge method = %s", r.Method)
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{"attestation_challenge": "challenge-1"})
		case "/par":
			if r.Method != http.MethodPost {
				t.Errorf("PAR method = %s", r.Method)
			}
			if got := r.Header.Get("OAuth-Client-Attestation"); got != "attestation-jwt" {
				t.Errorf("OAuth-Client-Attestation = %q", got)
			}
			if got := r.Header.Get("OAuth-Client-Attestation-PoP"); got != "pop-jwt" {
				t.Errorf("OAuth-Client-Attestation-PoP = %q", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse PAR form: %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "" {
				t.Errorf("PAR should not include grant_type, got %q", got)
			}
			if got := r.Form.Get("issuer_state"); got != "issuer-state-1" {
				t.Errorf("issuer_state = %q", got)
			}
			mockserver.JSONResponse(w, http.StatusCreated, map[string]any{"request_uri": "urn:request:1", "expires_in": 60})
		case "/token":
			if got := r.Header.Get("DPoP"); got != "dpop-token" {
				t.Errorf("DPoP header = %q", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse token form: %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "authorization_code" {
				t.Errorf("grant_type = %q", got)
			}
			if got := r.Form.Get("code_verifier"); got != "verifier-1" {
				t.Errorf("code_verifier = %q", got)
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"access_token": "access-1", "token_type": "DPoP"})
		case "/nonce":
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "nonce-1"})
		case "/credential":
			assertBearerJSONRequest(t, r, "access-1", "dpop-credential")
			var body types.CredentialRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode credential request: %v", err)
			}
			if body.CredentialConfigurationID != "pid" {
				t.Errorf("credential_configuration_id = %q", body.CredentialConfigurationID)
			}
			if body.Proofs == nil || len(body.Proofs.JWT) != 1 || body.Proofs.JWT[0] != "proof-jwt" {
				t.Errorf("proofs.jwt = %#v", body.Proofs)
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"transaction_id": "tx-1"})
		case "/deferred":
			assertBearerJSONRequest(t, r, "access-1", "dpop-deferred")
			var body types.DeferredCredentialRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode deferred request: %v", err)
			}
			if body.TransactionID != "tx-1" {
				t.Errorf("transaction_id = %q", body.TransactionID)
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential": "credential-jwt", "notification_id": "notification-1"})
		case "/notification":
			assertBearerJSONRequest(t, r, "access-1", "dpop-notification")
			var body types.NotificationRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode notification request: %v", err)
			}
			if body.NotificationID != "notification-1" || body.Event != "credential_accepted" {
				t.Errorf("notification body = %#v", body)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	endpoint := func(path string) common.URIField {
		t.Helper()
		parsed, err := url.Parse(server.URL + path)
		if err != nil {
			t.Fatalf("failed to parse endpoint: %v", err)
		}
		return common.URIField(*parsed)
	}

	challenge, err := receiver.FetchClientAttestationChallenge(endpoint("/challenge"))
	if err != nil {
		t.Fatalf("FetchClientAttestationChallenge() error = %v", err)
	}
	if challenge.AttestationChallenge != "challenge-1" {
		t.Fatalf("challenge = %#v", challenge)
	}

	par, err := receiver.PushAuthorizationRequest(endpoint("/par"), types.PushedAuthorizationRequest{
		ResponseType:        "code",
		ClientID:            "client-1",
		RedirectURI:         "https://wallet.example/callback",
		Scope:               "pid_scope",
		State:               "state-1",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		IssuerState:         "issuer-state-1",
	}, types.OAuthClientAttestationHeaders{
		ClientAttestation:    "attestation-jwt",
		ClientAttestationPop: "pop-jwt",
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest() error = %v", err)
	}
	if par.RequestURI != "urn:request:1" || par.ExpiresIn != 60 {
		t.Fatalf("PAR response = %#v", par)
	}

	token, err := receiver.ExchangeAuthorizationCode(endpoint("/token"), types.AuthorizationCodeTokenRequest{
		Code:         "code-1",
		RedirectURI:  "https://wallet.example/callback",
		CodeVerifier: "verifier-1",
		ClientID:     "client-1",
	}, types.OAuthClientAttestationHeaders{}, "dpop-token")
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}
	if token.Token != "access-1" || token.TokenType != "DPoP" {
		t.Fatalf("token response = %#v", token)
	}

	nonce, err := receiver.FetchNonceResponse(endpoint("/nonce"))
	if err != nil {
		t.Fatalf("FetchNonce() error = %v", err)
	}
	if nonce.CNonce != "nonce-1" {
		t.Fatalf("nonce response = %#v", nonce)
	}

	credential, err := receiver.RequestCredential(endpoint("/credential"), "access-1", types.CredentialRequest{
		CredentialConfigurationID: "pid",
		Proofs:                    &types.CredentialProofs{JWT: []string{"proof-jwt"}},
	}, "dpop-credential")
	if err != nil {
		t.Fatalf("RequestCredential() error = %v", err)
	}
	if credential.TransactionID != "tx-1" {
		t.Fatalf("credential response = %#v", credential)
	}

	deferred, err := receiver.RequestDeferredCredential(endpoint("/deferred"), "access-1", types.DeferredCredentialRequest{TransactionID: credential.TransactionID}, "dpop-deferred")
	if err != nil {
		t.Fatalf("RequestDeferredCredential() error = %v", err)
	}
	if deferred.Credential != "credential-jwt" || deferred.NotificationID != "notification-1" {
		t.Fatalf("deferred response = %#v", deferred)
	}

	if err := receiver.SendCredentialNotification(endpoint("/notification"), "access-1", types.NotificationRequest{
		NotificationID: deferred.NotificationID,
		Event:          "credential_accepted",
	}, "dpop-notification"); err != nil {
		t.Fatalf("SendCredentialNotification() error = %v", err)
	}
}

func TestOid4vciReceiver_RequestCredentialWithDpopRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if r.Header.Get("Authorization") != "DPoP access-1" {
			t.Errorf("Authorization header = %q", r.Header.Get("Authorization"))
		}
		if attempts == 1 {
			if r.Header.Get("DPoP") != "proof:" {
				t.Errorf("first DPoP proof = %q", r.Header.Get("DPoP"))
			}
			w.Header().Set("DPoP-Nonce", "nonce-1")
			http.Error(w, "use nonce", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("DPoP") != "proof:nonce-1" {
			t.Errorf("second DPoP proof = %q", r.Header.Get("DPoP"))
		}
		var body types.CredentialRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}
		if body.CredentialConfigurationID != "pid" {
			t.Errorf("credential_configuration_id = %q", body.CredentialConfigurationID)
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"credential": "credential-jwt"})
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	var proofNonces []string
	response, err := receiver.RequestCredentialWithDpopRetry(
		common.URIField(*parsed),
		"access-1",
		types.CredentialRequest{CredentialConfigurationID: "pid"},
		func(nonce string) (string, error) {
			proofNonces = append(proofNonces, nonce)
			return "proof:" + nonce, nil
		},
	)
	if err != nil {
		t.Fatalf("RequestCredentialWithDpopRetry() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
	if len(proofNonces) != 2 || proofNonces[0] != "" || proofNonces[1] != "nonce-1" {
		t.Fatalf("proof nonces = %#v", proofNonces)
	}
	if response.Credential != "credential-jwt" {
		t.Fatalf("response = %#v", response)
	}
}

func TestOid4vciReceiver_PostCredentialEndpointWithDpopRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if got := r.Header.Get("Authorization"); got != "DPoP access-1" {
			t.Errorf("Authorization header = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/jwt" {
			t.Errorf("Content-Type header = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		if string(body) != "encrypted-request" {
			t.Errorf("body = %q", string(body))
		}
		if attempts == 1 {
			if r.Header.Get("DPoP") != "proof:" {
				t.Errorf("first DPoP proof = %q", r.Header.Get("DPoP"))
			}
			w.Header().Set("DPoP-Nonce", "nonce-1")
			http.Error(w, "use nonce", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("DPoP") != "proof:nonce-1" {
			t.Errorf("second DPoP proof = %q", r.Header.Get("DPoP"))
		}
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte("encrypted-response"))
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	var proofNonces []string
	response, err := receiver.PostCredentialEndpointWithDpopRetry(
		common.URIField(*parsed),
		"access-1",
		[]byte("encrypted-request"),
		"application/jwt",
		func(nonce string) (string, error) {
			proofNonces = append(proofNonces, nonce)
			return "proof:" + nonce, nil
		},
	)
	if err != nil {
		t.Fatalf("PostCredentialEndpointWithDpopRetry() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
	if len(proofNonces) != 2 || proofNonces[0] != "" || proofNonces[1] != "nonce-1" {
		t.Fatalf("proof nonces = %#v", proofNonces)
	}
	if string(response.Body) != "encrypted-response" || response.ContentType != "application/jwt" {
		t.Fatalf("response = %#v", response)
	}
}

func TestOid4vciReceiver_ExchangeAuthorizationCodeWithDpopRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type header = %q", got)
		}
		if got := r.Header.Get("OAuth-Client-Attestation"); got != "attestation-jwt" {
			t.Errorf("OAuth-Client-Attestation header = %q", got)
		}
		if got := r.Header.Get("OAuth-Client-Attestation-PoP"); got != "attestation-pop-jwt" {
			t.Errorf("OAuth-Client-Attestation-PoP header = %q", got)
		}
		if attempts == 1 {
			if r.Header.Get("DPoP") != "proof:" {
				t.Errorf("first DPoP proof = %q", r.Header.Get("DPoP"))
			}
			w.Header().Set("DPoP-Nonce", "nonce-1")
			http.Error(w, "use nonce", http.StatusBadRequest)
			return
		}
		if r.Header.Get("DPoP") != "proof:nonce-1" {
			t.Errorf("second DPoP proof = %q", r.Header.Get("DPoP"))
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "authorization_code" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.Form.Get("code"); got != "code-1" {
			t.Errorf("code = %q", got)
		}
		if got := r.Form.Get("redirect_uri"); got != "openid-credential-offer://callback" {
			t.Errorf("redirect_uri = %q", got)
		}
		if got := r.Form.Get("code_verifier"); got != "verifier-1" {
			t.Errorf("code_verifier = %q", got)
		}
		if got := r.Form.Get("client_id"); got != "client-1" {
			t.Errorf("client_id = %q", got)
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{
			"access_token": "access-1",
			"token_type":   "DPoP",
		})
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	var proofNonces []string
	response, err := receiver.ExchangeAuthorizationCodeWithDpopRetry(
		common.URIField(*parsed),
		types.AuthorizationCodeTokenRequest{
			Code:         "code-1",
			RedirectURI:  "openid-credential-offer://callback",
			CodeVerifier: "verifier-1",
			ClientID:     "client-1",
		},
		types.OAuthClientAttestationHeaders{
			ClientAttestation:    "attestation-jwt",
			ClientAttestationPop: "attestation-pop-jwt",
		},
		func(nonce string) (string, error) {
			proofNonces = append(proofNonces, nonce)
			return "proof:" + nonce, nil
		},
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCodeWithDpopRetry() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
	if len(proofNonces) != 2 || proofNonces[0] != "" || proofNonces[1] != "nonce-1" {
		t.Fatalf("proof nonces = %#v", proofNonces)
	}
	if response.Token != "access-1" || response.TokenType != "DPoP" {
		t.Fatalf("response = %#v", response)
	}
}

func TestOid4vciReceiver_ExchangeAuthorizationCodeWithDpopAndAttestationRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	attempts := 0
	var attestationPops []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		attestationPops = append(attestationPops, r.Header.Get("OAuth-Client-Attestation-PoP"))
		if got := r.Header.Get("OAuth-Client-Attestation"); got != "attestation-jwt" {
			t.Errorf("OAuth-Client-Attestation header = %q", got)
		}
		if attempts == 1 {
			if r.Header.Get("DPoP") != "proof:" {
				t.Errorf("first DPoP proof = %q", r.Header.Get("DPoP"))
			}
			w.Header().Set("DPoP-Nonce", "nonce-1")
			http.Error(w, "use nonce", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("DPoP") != "proof:nonce-1" {
			t.Errorf("second DPoP proof = %q", r.Header.Get("DPoP"))
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{
			"access_token": "access-1",
			"token_type":   "DPoP",
		})
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	headerFactoryCalls := 0
	var proofNonces []string
	response, err := receiver.ExchangeAuthorizationCodeWithDpopAndAttestationRetry(
		common.URIField(*parsed),
		types.AuthorizationCodeTokenRequest{
			Code:         "code-1",
			RedirectURI:  "openid-credential-offer://callback",
			CodeVerifier: "verifier-1",
			ClientID:     "client-1",
		},
		func() (types.OAuthClientAttestationHeaders, error) {
			headerFactoryCalls++
			return types.OAuthClientAttestationHeaders{
				ClientAttestation:    "attestation-jwt",
				ClientAttestationPop: fmt.Sprintf("attestation-pop-jwt-%d", headerFactoryCalls),
			}, nil
		},
		func(nonce string) (string, error) {
			proofNonces = append(proofNonces, nonce)
			return "proof:" + nonce, nil
		},
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCodeWithDpopAndAttestationRetry() error = %v", err)
	}
	if response.Token != "access-1" || response.TokenType != "DPoP" {
		t.Fatalf("response = %#v", response)
	}
	if attempts != 2 || headerFactoryCalls != 2 {
		t.Fatalf("attempts = %d, headerFactoryCalls = %d", attempts, headerFactoryCalls)
	}
	if len(attestationPops) != 2 || attestationPops[0] == attestationPops[1] {
		t.Fatalf("attestation PoP headers = %#v", attestationPops)
	}
	if len(proofNonces) != 2 || proofNonces[0] != "" || proofNonces[1] != "nonce-1" {
		t.Fatalf("proof nonces = %#v", proofNonces)
	}
}

func TestOid4vciReceiver_RequestDeferredCredentialWithDpopRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			assertBearerJSONRequest(t, r, "access-1", "proof:")
			w.Header().Set("DPoP-Nonce", "nonce-1")
			http.Error(w, "use nonce", http.StatusUnauthorized)
			return
		}
		assertBearerJSONRequest(t, r, "access-1", "proof:nonce-1")
		var body types.DeferredCredentialRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}
		if body.TransactionID != "tx-1" {
			t.Errorf("transaction_id = %q", body.TransactionID)
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"credential": "credential-jwt"})
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	var proofNonces []string
	response, err := receiver.RequestDeferredCredentialWithDpopRetry(
		common.URIField(*parsed),
		"access-1",
		types.DeferredCredentialRequest{TransactionID: "tx-1"},
		func(nonce string) (string, error) {
			proofNonces = append(proofNonces, nonce)
			return "proof:" + nonce, nil
		},
	)
	if err != nil {
		t.Fatalf("RequestDeferredCredentialWithDpopRetry() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
	if len(proofNonces) != 2 || proofNonces[0] != "" || proofNonces[1] != "nonce-1" {
		t.Fatalf("proof nonces = %#v", proofNonces)
	}
	if response.Credential != "credential-jwt" {
		t.Fatalf("response = %#v", response)
	}
}

func TestOid4vciReceiver_SendCredentialNotificationWithDpopRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			assertBearerJSONRequest(t, r, "access-1", "proof:")
			w.Header().Set("DPoP-Nonce", "nonce-1")
			http.Error(w, "use nonce", http.StatusUnauthorized)
			return
		}
		assertBearerJSONRequest(t, r, "access-1", "proof:nonce-1")
		var body types.NotificationRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}
		if body.NotificationID != "notification-1" || body.Event != "credential_accepted" {
			t.Errorf("notification request = %#v", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	var proofNonces []string
	err = receiver.SendCredentialNotificationWithDpopRetry(
		common.URIField(*parsed),
		"access-1",
		types.NotificationRequest{NotificationID: "notification-1", Event: "credential_accepted"},
		func(nonce string) (string, error) {
			proofNonces = append(proofNonces, nonce)
			return "proof:" + nonce, nil
		},
	)
	if err != nil {
		t.Fatalf("SendCredentialNotificationWithDpopRetry() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
	if len(proofNonces) != 2 || proofNonces[0] != "" || proofNonces[1] != "nonce-1" {
		t.Fatalf("proof nonces = %#v", proofNonces)
	}
}

func TestOid4vciReceiver_CredentialRequestAndResponseEncryption(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate recipient key: %v", err)
	}
	metadata := &types.CredentialIssuerMetadata{
		CredentialRequestEncryption: &types.CredentialRequestEncryption{
			Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{
					Key:       &recipient.PublicKey,
					KeyID:     "issuer-enc-key",
					Use:       "enc",
					Algorithm: string(jose.ECDH_ES),
				},
			}},
			EncValuesSupported: []string{"A256GCM"},
		},
	}

	body, contentType, err := receiver.EncodeCredentialRequest(types.CredentialRequest{
		CredentialConfigurationID: "pid",
		Proofs:                    &types.CredentialProofs{JWT: []string{"proof-jwt"}},
	}, metadata)
	if err != nil {
		t.Fatalf("EncodeCredentialRequest() error = %v", err)
	}
	if contentType != "application/jwt" {
		t.Fatalf("contentType = %q", contentType)
	}
	jwe, err := jose.ParseEncrypted(string(body), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatalf("failed to parse request JWE: %v", err)
	}
	if jwe.Header.KeyID != "issuer-enc-key" {
		t.Fatalf("kid = %q", jwe.Header.KeyID)
	}
	if got := jwe.Header.ExtraHeaders[jose.HeaderContentType]; got != "json" {
		t.Fatalf("cty = %#v", got)
	}
	plaintext, err := jwe.Decrypt(recipient)
	if err != nil {
		t.Fatalf("failed to decrypt request JWE: %v", err)
	}
	var decodedRequest types.CredentialRequest
	if err := json.Unmarshal(plaintext, &decodedRequest); err != nil {
		t.Fatalf("failed to decode request: %v", err)
	}
	if decodedRequest.CredentialConfigurationID != "pid" || decodedRequest.Proofs.JWT[0] != "proof-jwt" {
		t.Fatalf("decoded request = %#v", decodedRequest)
	}

	responsePayload, err := json.Marshal(types.CredentialResponse{Credential: "credential-jwt", NotificationID: "notification-1"})
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.ECDH_ES, Key: &recipient.PublicKey, KeyID: "wallet-enc-key"},
		(&jose.EncrypterOptions{}).WithContentType("json"),
	)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}
	encryptedResponse, err := encrypter.Encrypt(responsePayload)
	if err != nil {
		t.Fatalf("failed to encrypt response: %v", err)
	}
	serializedResponse, err := encryptedResponse.CompactSerialize()
	if err != nil {
		t.Fatalf("failed to serialize response: %v", err)
	}

	decodedResponse, err := receiver.DecodeCredentialResponse([]byte(serializedResponse), "application/jwt", recipient)
	if err != nil {
		t.Fatalf("DecodeCredentialResponse() error = %v", err)
	}
	if decodedResponse.Credential != "credential-jwt" || decodedResponse.NotificationID != "notification-1" {
		t.Fatalf("decoded response = %#v", decodedResponse)
	}

	plainResponse, err := receiver.DecodeCredentialResponse([]byte(`{"transaction_id":"tx-1"}`), "application/json", nil)
	if err != nil {
		t.Fatalf("DecodeCredentialResponse() plain error = %v", err)
	}
	if plainResponse.TransactionID != "tx-1" {
		t.Fatalf("plain response = %#v", plainResponse)
	}
}

func TestOid4vciReceiver_CreateDpopAndCredentialProofJWTs(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	key := jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "wallet-key-1",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	dpop, err := receiver.CreateDpopProof(key, http.MethodPost, "https://issuer.example/credential?ignored=true#fragment", "nonce-1", "access-token")
	if err != nil {
		t.Fatalf("CreateDpopProof() error = %v", err)
	}
	parsedDpop, err := jwt.ParseSigned(dpop, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("failed to parse DPoP JWT: %v", err)
	}
	if typ := parsedDpop.Headers[0].ExtraHeaders[jose.HeaderType]; typ != "dpop+jwt" {
		t.Fatalf("DPoP typ = %#v", typ)
	}
	if parsedDpop.Headers[0].KeyID != "" {
		t.Fatalf("DPoP protected header should not contain top-level kid, got %q", parsedDpop.Headers[0].KeyID)
	}
	if parsedDpop.Headers[0].JSONWebKey == nil || parsedDpop.Headers[0].JSONWebKey.KeyID != "wallet-key-1" {
		t.Fatalf("DPoP jwk header = %#v", parsedDpop.Headers[0].JSONWebKey)
	}
	var dpopClaims map[string]any
	if err := parsedDpop.Claims(&privateKey.PublicKey, &dpopClaims); err != nil {
		t.Fatalf("failed to verify DPoP JWT: %v", err)
	}
	if dpopClaims["htm"] != http.MethodPost {
		t.Fatalf("htm = %#v", dpopClaims["htm"])
	}
	if dpopClaims["htu"] != "https://issuer.example/credential" {
		t.Fatalf("htu = %#v", dpopClaims["htu"])
	}
	if dpopClaims["nonce"] != "nonce-1" {
		t.Fatalf("nonce = %#v", dpopClaims["nonce"])
	}
	ath := sha256.Sum256([]byte("access-token"))
	if dpopClaims["ath"] != base64.RawURLEncoding.EncodeToString(ath[:]) {
		t.Fatalf("ath = %#v", dpopClaims["ath"])
	}

	proof, err := receiver.CreateCredentialRequestJWTProof(key, "https://issuer.example", "credential-nonce")
	if err != nil {
		t.Fatalf("CreateCredentialRequestJWTProof() error = %v", err)
	}
	parsedProof, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("failed to parse proof JWT: %v", err)
	}
	if typ := parsedProof.Headers[0].ExtraHeaders[jose.HeaderType]; typ != "openid4vci-proof+jwt" {
		t.Fatalf("proof typ = %#v", typ)
	}
	if parsedProof.Headers[0].KeyID != "" {
		t.Fatalf("proof protected header should not contain top-level kid, got %q", parsedProof.Headers[0].KeyID)
	}
	if parsedProof.Headers[0].JSONWebKey == nil || parsedProof.Headers[0].JSONWebKey.KeyID != "wallet-key-1" {
		t.Fatalf("proof jwk header = %#v", parsedProof.Headers[0].JSONWebKey)
	}
	var proofClaims map[string]any
	if err := parsedProof.Claims(&privateKey.PublicKey, &proofClaims); err != nil {
		t.Fatalf("failed to verify proof JWT: %v", err)
	}
	if proofClaims["aud"] != "https://issuer.example" || proofClaims["nonce"] != "credential-nonce" {
		t.Fatalf("proof claims = %#v", proofClaims)
	}
}

func TestOid4vciReceiver_CreateClientAttestationJWTs(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	clientPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	attesterPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate attester key: %v", err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &attesterPrivateKey.PublicKey, attesterPrivateKey)
	if err != nil {
		t.Fatalf("failed to create attester certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse attester certificate: %v", err)
	}
	clientKey := jose.JSONWebKey{Key: clientPrivateKey, KeyID: "client-key-1", Algorithm: string(jose.ES256), Use: "sig"}
	attesterKey := jose.JSONWebKey{Key: attesterPrivateKey, KeyID: "attester-key-1", Algorithm: string(jose.ES256), Use: "sig", Certificates: []*x509.Certificate{cert}}

	attestation, err := receiver.CreateClientAttestation(clientKey, attesterKey, "https://client-attester.example.org/", "client-1", time.Minute)
	if err != nil {
		t.Fatalf("CreateClientAttestation() error = %v", err)
	}
	parsedAttestation, err := jwt.ParseSigned(attestation, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("failed to parse attestation JWT: %v", err)
	}
	if typ := parsedAttestation.Headers[0].ExtraHeaders[jose.HeaderType]; typ != "oauth-client-attestation+jwt" {
		t.Fatalf("attestation typ = %#v", typ)
	}
	if parsedAttestation.Headers[0].KeyID != "attester-key-1" {
		t.Fatalf("attestation kid = %q", parsedAttestation.Headers[0].KeyID)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if chains, err := parsedAttestation.Headers[0].Certificates(x509.VerifyOptions{Roots: pool}); err != nil || len(chains) == 0 {
		t.Fatalf("expected x5c certificate chain, chains=%#v err=%v", chains, err)
	}
	var attestationClaims map[string]any
	if err := parsedAttestation.Claims(&attesterPrivateKey.PublicKey, &attestationClaims); err != nil {
		t.Fatalf("failed to verify attestation JWT: %v", err)
	}
	if attestationClaims["iss"] != "https://client-attester.example.org/" || attestationClaims["sub"] != "client-1" {
		t.Fatalf("attestation claims = %#v", attestationClaims)
	}
	cnf, ok := attestationClaims["cnf"].(map[string]any)
	if !ok || cnf["jwk"] == nil {
		t.Fatalf("attestation cnf = %#v", attestationClaims["cnf"])
	}

	pop, err := receiver.CreateClientAttestationPop(clientKey, "client-1", "https://issuer.example", "challenge-1", time.Minute)
	if err != nil {
		t.Fatalf("CreateClientAttestationPop() error = %v", err)
	}
	parsedPop, err := jwt.ParseSigned(pop, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("failed to parse PoP JWT: %v", err)
	}
	if typ := parsedPop.Headers[0].ExtraHeaders[jose.HeaderType]; typ != "oauth-client-attestation-pop+jwt" {
		t.Fatalf("PoP typ = %#v", typ)
	}
	var popClaims map[string]any
	if err := parsedPop.Claims(&clientPrivateKey.PublicKey, &popClaims); err != nil {
		t.Fatalf("failed to verify PoP JWT: %v", err)
	}
	if popClaims["iss"] != "client-1" || popClaims["aud"] != "https://issuer.example" || popClaims["challenge"] != "challenge-1" {
		t.Fatalf("PoP claims = %#v", popClaims)
	}
	if popClaims["jti"] == "" {
		t.Fatalf("PoP jti missing: %#v", popClaims)
	}
}

func assertBearerJSONRequest(t *testing.T, r *http.Request, accessToken string, dpopProof string) {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Errorf("method = %s", r.Method)
	}
	if got := r.Header.Get("Authorization"); got != "DPoP "+accessToken {
		t.Errorf("Authorization header = %q", got)
	}
	if got := r.Header.Get("DPoP"); got != dpopProof {
		t.Errorf("DPoP header = %q", got)
	}
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type header = %q", got)
	}
}

func TestOid4vciReceiver_FetchAccessToken_ClientAssertion(t *testing.T) {
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	t.Run("client_assertion form fields are sent when provided", func(t *testing.T) {

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse form: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("client_id"); got != "wallet-id" {
				handlerErrCh <- fmt.Errorf("expected client_id wallet-id, got %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("client_assertion_type"); got != types.ClientAssertionTypeJWTBearer {
				handlerErrCh <- fmt.Errorf("expected client_assertion_type jwt-bearer, got %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("client_assertion"); got != "assertion.jwt.value" {
				handlerErrCh <- fmt.Errorf("expected client_assertion assertion.jwt.value, got %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{
				"access_token": "tok",
				"token_type":   "Bearer",
			})
		})

		captureURL, err := url.Parse(captureServer.URL() + "/token")
		require.NoError(t, err)
		token, err := receiver.FetchAccessToken(
			types.Oid4vci,
			common.URIField(*captureURL),
			"code",
			"",
			types.WithClientAssertion("wallet-id", "assertion.jwt.value"),
		)
		require.NoError(t, err)
		require.NotNil(t, token)
		require.NoError(t, <-handlerErrCh)
	})

	t.Run("client_assertion form fields are absent when not provided", func(t *testing.T) {

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse form: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("client_assertion"); got != "" {
				handlerErrCh <- fmt.Errorf("client_assertion must be absent, got %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("client_id"); got != "" {
				handlerErrCh <- fmt.Errorf("client_id must be absent, got %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{
				"access_token": "tok",
				"token_type":   "Bearer",
			})
		})

		captureURL, err := url.Parse(captureServer.URL() + "/token")
		require.NoError(t, err)
		token, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*captureURL), "code", "")
		require.NoError(t, err)
		require.NotNil(t, token)
		require.NoError(t, <-handlerErrCh)
	})
}

// countingTransport records how many requests actually left the HTTP client.
type countingTransport struct {
	attempts int
}

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.attempts++
	return nil, fmt.Errorf("no request should have been attempted")
}

// withCountedTokenTransport injects a per-receiver transport so that a test
// can prove nothing was sent, and restores it afterwards.
func withCountedTokenTransport(t *testing.T, receiver *Oid4vciReceiver) *countingTransport {
	t.Helper()
	counter := &countingTransport{}
	original := receiver.HTTPClient
	receiver.HTTPClient = &http.Client{Transport: counter}
	t.Cleanup(func() { receiver.HTTPClient = original })
	return counter
}

func TestOid4vciReceiver_FetchAccessToken_RefusesClientAssertionOverPlainHTTP(t *testing.T) {
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	// HTTP is allowed, which is what makes this worth testing: the assertion
	// must still be refused on a host that is not this machine.

	tests := []struct {
		name    string
		rawURL  string
		allowed bool
	}{
		{name: "remote host over http", rawURL: "http://as.example.com/token", allowed: false},
		{name: "private network address over http", rawURL: "http://10.0.0.1:8080/token", allowed: false},
		{name: "host merely named like localhost", rawURL: "http://localhost.evil.com/token", allowed: false},
		{name: "loopback name over http", rawURL: "http://localhost:8080/token", allowed: true},
		{name: "loopback address over http", rawURL: "http://127.0.0.1:8080/token", allowed: true},
		{name: "IPv6 loopback over http", rawURL: "http://[::1]:8080/token", allowed: true},
		{name: "remote host over https", rawURL: "https://as.example.com/token", allowed: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counter := withCountedTokenTransport(t, receiver)

			tokenURL, err := url.Parse(tt.rawURL)
			require.NoError(t, err)

			_, err = receiver.FetchAccessToken(
				types.Oid4vci,
				common.URIField(*tokenURL),
				"code",
				"",
				types.WithClientAssertion("wallet-id", "assertion.jwt.value"),
			)
			require.Error(t, err)

			if tt.allowed {
				// The transport is reached, which is as far as this test goes;
				// it deliberately fails there rather than contacting anything.
				assert.Equal(t, 1, counter.attempts)
				assert.NotContains(t, err.Error(), "https is required")
				return
			}

			assert.Contains(t, err.Error(), "https is required for any host other than loopback")
			assert.Zero(t, counter.attempts, "the client assertion must not be sent at all")
		})
	}
}

func TestOid4vciReceiver_FetchAccessToken_PlainHTTPStaysAllowedWithoutAssertion(t *testing.T) {
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	// Without a client assertion the existing VCKNOTS_WALLET_HTTP_ALLOWED
	// behaviour is unchanged, so the restriction stays scoped to the assertion.
	counter := withCountedTokenTransport(t, receiver)

	tokenURL, err := url.Parse("http://as.example.com/token")
	require.NoError(t, err)

	_, err = receiver.FetchAccessToken(types.Oid4vci, common.URIField(*tokenURL), "code", "")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "https is required")
	assert.Equal(t, 1, counter.attempts, "the request must still be attempted")
}

func TestOid4vciReceiver_FetchAccessToken_RequiresClientIDWithAssertion(t *testing.T) {
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{
			"access_token": "tok",
			"token_type":   "Bearer",
		})
	}))
	defer server.Close()

	tokenURL, err := url.Parse(server.URL + "/token")
	require.NoError(t, err)

	token, err := receiver.FetchAccessToken(
		types.Oid4vci,
		common.URIField(*tokenURL),
		"code",
		"",
		types.WithClientAssertion("  ", "assertion.jwt.value"),
	)
	require.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "client_id is required when a client assertion is sent")
	assert.Zero(t, requests, "the request must not be sent at all")
}

func TestOid4vciReceiver_FetchAccessToken_DoesNotFollowRedirects(t *testing.T) {
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	// A 307 keeps the method and body, so following the redirect would replay
	// the client_assertion against this second origin.
	var relayedRequests int
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		relayedRequests++
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{
			"access_token": "leaked",
			"token_type":   "Bearer",
		})
	}))
	defer relay.Close()

	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, relay.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()

	tokenURL, err := url.Parse(redirecting.URL + "/token")
	require.NoError(t, err)

	token, err := receiver.FetchAccessToken(
		types.Oid4vci,
		common.URIField(*tokenURL),
		"code",
		"",
		types.WithClientAssertion("wallet-id", "assertion.jwt.value"),
	)
	require.Error(t, err)
	assert.Nil(t, token)
	assert.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	assert.Zero(t, relayedRequests, "the client_assertion must not reach the redirect target")
}

func TestOid4vciReceiver_ReceiveCredential(t *testing.T) {
	accessToken := types.CredentialIssuanceAccessToken{Token: "test_token", TokenType: "bearer"}

	// Create mock OID4VCI issuer server (which serves credential endpoint)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL() + "/credential")
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = false

		_, err := receiver.ReceiveCredential(types.Oid4vci, endpoint, "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("ReceiveCredential should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		credential, err := receiver.ReceiveCredential(types.Oid4vci, endpoint, "test-config", nil, accessToken, nil, nil)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if credential == nil || *credential == "" {
			t.Fatal("Expected credential, got empty string")
		}

		// The mock server returns a default JWT credential
		if !strings.HasPrefix(*credential, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9") {
			t.Errorf("Expected JWT credential to start with header, got %s", (*credential)[:50])
		}
	})

	t.Run("Request uses credential_configuration_id and proofs", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		var capturedBody map[string]interface{}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				handlerErrCh <- fmt.Errorf("failed to read request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)
		proof := "eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6InRlc3QifQ.signature"

		credential, err := receiver.ReceiveCredential(types.Oid4vci, captureEndpoint, "test-config", nil, accessToken, nil, &proof)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NotEmpty(t, *credential)
		require.NoError(t, <-handlerErrCh)

		_, exists := capturedBody["format"]
		assert.False(t, exists, "format should not be present in credential request body")
		_, exists = capturedBody["proof"]
		assert.False(t, exists, "proof should not be present in credential request body")

		credentialConfigurationID, ok := capturedBody["credential_configuration_id"].(string)
		require.True(t, ok, "credential_configuration_id must be present as string")
		assert.Equal(t, "test-config", credentialConfigurationID)

		proofs, ok := capturedBody["proofs"].(map[string]interface{})
		require.True(t, ok, "proofs must be present as object")
		jwtProofs, ok := proofs["jwt"].([]interface{})
		require.True(t, ok, "proofs.jwt must be present as array")
		require.Len(t, jwtProofs, 1, "proofs.jwt must contain one JWT value")
		assert.Equal(t, proof, jwtProofs[0])
	})

	t.Run("Request omits proof fields when jwt proof is not provided", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		var capturedBody map[string]interface{}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				handlerErrCh <- fmt.Errorf("failed to read request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)

		credential, err := receiver.ReceiveCredential(types.Oid4vci, captureEndpoint, "test-config", nil, accessToken, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NotEmpty(t, *credential)
		require.NoError(t, <-handlerErrCh)

		credentialConfigurationID, ok := capturedBody["credential_configuration_id"].(string)
		require.True(t, ok, "credential_configuration_id must be present as string")
		assert.Equal(t, "test-config", credentialConfigurationID)

		_, exists := capturedBody["proof"]
		assert.False(t, exists, "proof should not be present in credential request body")
		_, exists = capturedBody["proofs"]
		assert.False(t, exists, "proofs should not be present when proof is not provided")
		_, exists = capturedBody["format"]
		assert.False(t, exists, "format should not be present in credential request body")
	})

	t.Run("DPoP access token sends DPoP authorization and proof headers", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		dpopProof := "dpop.proof.jwt"
		dpopAccessToken := types.CredentialIssuanceAccessToken{
			Token:     "dpop-access-token",
			TokenType: "DPoP",
		}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "DPoP dpop-access-token" {
				handlerErrCh <- fmt.Errorf("Authorization header = %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Header.Get("DPoP"); got != dpopProof {
				handlerErrCh <- fmt.Errorf("DPoP header = %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)

		credential, err := receiver.ReceiveCredential(
			types.Oid4vci,
			captureEndpoint,
			"test-config",
			nil,
			dpopAccessToken,
			nil,
			nil,
			&types.CredentialRequestOptions{DPoPProofJWT: &dpopProof},
		)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NoError(t, <-handlerErrCh)
	})

	t.Run("use_dpop_nonce error is returned as sentinel error", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		dpopProof := "dpop.proof.jwt"
		dpopAccessToken := types.CredentialIssuanceAccessToken{
			Token:     "dpop-access-token",
			TokenType: "DPoP",
		}
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
				"error": "use_dpop_nonce",
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)

		_, err := receiver.ReceiveCredential(
			types.Oid4vci,
			captureEndpoint,
			"test-config",
			nil,
			dpopAccessToken,
			nil,
			nil,
			&types.CredentialRequestOptions{DPoPProofJWT: &dpopProof},
		)
		require.Error(t, err)
		assert.ErrorIs(t, err, types.ErrUseDPoPNonce)
	})

	t.Run("DPoP access token skips nil request options", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		dpopProof := "dpop.proof.jwt"
		dpopAccessToken := types.CredentialIssuanceAccessToken{
			Token:     "dpop-access-token",
			TokenType: "DPoP",
		}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("DPoP"); got != dpopProof {
				handlerErrCh <- fmt.Errorf("DPoP header = %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)

		credential, err := receiver.ReceiveCredential(
			types.Oid4vci,
			captureEndpoint,
			"test-config",
			nil,
			dpopAccessToken,
			nil,
			nil,
			nil,
			&types.CredentialRequestOptions{DPoPProofJWT: &dpopProof},
		)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NoError(t, <-handlerErrCh)
	})

	t.Run("Request uses credential_identifier when provided", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		var capturedBody map[string]interface{}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				handlerErrCh <- fmt.Errorf("failed to read request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)
		credentialIdentifier := "cred-id-1"

		credential, err := receiver.ReceiveCredential(types.Oid4vci, captureEndpoint, "test-config", &credentialIdentifier, accessToken, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NotEmpty(t, *credential)
		require.NoError(t, <-handlerErrCh)

		identifier, ok := capturedBody["credential_identifier"].(string)
		require.True(t, ok, "credential_identifier must be present as string")
		assert.Equal(t, credentialIdentifier, identifier)

		_, exists := capturedBody["credential_configuration_id"]
		assert.False(t, exists, "credential_configuration_id should not be present when credential_identifier is used")
	})

	t.Run("Server error", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/credential", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*errorURL), "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/credential", http.StatusOK, "{invalid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*invalidJSONURL), "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})

	t.Run("No credential in response", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		noCredServer := mockserver.NewMockServer()
		defer noCredServer.Close()

		// Return valid JSON but without credential field
		noCredServer.SetJSONResponse("/credential", http.StatusOK, map[string]string{"status": "success"})

		noCredURL, _ := url.Parse(noCredServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*noCredURL), "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error when no credential is present in the response")
		}
	})

	t.Run("Multiple credentials in response", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		multiCredServer := mockserver.NewMockServer()
		defer multiCredServer.Close()

		multiCredServer.SetJSONResponse("/credential", http.StatusOK, map[string]interface{}{
			"credentials": []map[string]string{
				{"credential": "cred-1"},
				{"credential": "cred-2"},
			},
		})

		multiCredURL, _ := url.Parse(multiCredServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*multiCredURL), "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error when multiple credentials are present in the response")
		}
	})
}

func TestOid4vciReceiver_MetadataDiscovery_UrlPatterns(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	tests := []struct {
		name         string
		identifier   string
		expectedPath string
		discovery    func(common.URIField) error
	}{
		{
			name:         "Auth Server (Base URL)",
			identifier:   "",
			expectedPath: "/.well-known/oauth-authorization-server",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchAuthorizationServerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Auth Server (Root Path)",
			identifier:   "/",
			expectedPath: "/.well-known/oauth-authorization-server",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchAuthorizationServerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Auth Server (With Path)",
			identifier:   "/tenant1",
			expectedPath: "/.well-known/oauth-authorization-server/tenant1",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchAuthorizationServerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Auth Server (With Trailing Slash)",
			identifier:   "/tenant1/",
			expectedPath: "/.well-known/oauth-authorization-server/tenant1",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchAuthorizationServerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Credential Issuer (Base URL)",
			identifier:   "",
			expectedPath: "/.well-known/openid-credential-issuer",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchIssuerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Credential Issuer (Root Path)",
			identifier:   "/",
			expectedPath: "/.well-known/openid-credential-issuer",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchIssuerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Credential Issuer (With Path)",
			identifier:   "/tenant2",
			expectedPath: "/.well-known/openid-credential-issuer/tenant2",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchIssuerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Credential Issuer (With Trailing Slash)",
			identifier:   "/tenant2/",
			expectedPath: "/.well-known/openid-credential-issuer/tenant2/",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchIssuerMetadata(u, types.Oid4vci)
				return err
			},
		},
	}

	receiver.AllowHTTP = true

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tt.expectedPath {
					w.WriteHeader(http.StatusOK)
					// Return minimal valid JSON for both types
					fmt.Fprint(w, `{"issuer": "https://example.com", "credential_issuer": "https://example.com"}`)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)
			identifierURL := *serverURL
			// Empty identifier keeps the parsed base URL's empty path (e.g. "https://host"),
			// while "/" sets the root path so the originalPath == "/" branch is exercised.
			if tt.identifier != "" {
				identifierURL.Path = tt.identifier
			}
			endpoint := common.URIField(identifierURL)

			assert.NoError(t, tt.discovery(endpoint), "Pattern %s failed: expected success at %s", tt.name, tt.expectedPath)
		})
	}
}

func TestOid4vciReceiver_PushAuthorizationRequestClientAssertion(t *testing.T) {
	t.Run("sends the assertion parameters when set", func(t *testing.T) {
		var captured url.Values
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			captured = r.Form
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"request_uri": "urn:request:1", "expires_in": 60})
		}))
		defer server.Close()

		parsed, err := url.Parse(server.URL)
		require.NoError(t, err)
		receiver := &Oid4vciReceiver{AllowHTTP: true}
		_, err = receiver.PushAuthorizationRequest(common.URIField(*parsed), types.PushedAuthorizationRequest{
			ResponseType:        "code",
			ClientID:            "client-1",
			RedirectURI:         "https://wallet.example/callback",
			ClientAssertion:     "assertion-jwt",
			ClientAssertionType: types.ClientAssertionTypeJWTBearer,
		}, types.OAuthClientAttestationHeaders{})
		require.NoError(t, err)
		assert.Equal(t, "assertion-jwt", captured.Get("client_assertion"))
		assert.Equal(t, types.ClientAssertionTypeJWTBearer, captured.Get("client_assertion_type"))
	})

	t.Run("omits the assertion parameters when unset", func(t *testing.T) {
		var captured url.Values
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			captured = r.Form
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"request_uri": "urn:request:1"})
		}))
		defer server.Close()

		parsed, err := url.Parse(server.URL)
		require.NoError(t, err)
		receiver := &Oid4vciReceiver{AllowHTTP: true}
		_, err = receiver.PushAuthorizationRequest(common.URIField(*parsed), types.PushedAuthorizationRequest{
			ResponseType: "code",
			ClientID:     "client-1",
			RedirectURI:  "https://wallet.example/callback",
		}, types.OAuthClientAttestationHeaders{})
		require.NoError(t, err)
		assert.Empty(t, captured.Get("client_assertion"))
		assert.Empty(t, captured.Get("client_assertion_type"))
	})
}

func TestOid4vciReceiver_PushAuthorizationRequestAuthorizationDetails(t *testing.T) {
	var captured url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		captured = r.Form
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{"request_uri": "urn:request:1", "expires_in": 60})
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	receiver := &Oid4vciReceiver{AllowHTTP: true}
	_, err = receiver.PushAuthorizationRequest(common.URIField(*parsed), types.PushedAuthorizationRequest{
		ResponseType: "code",
		ClientID:     "client-1",
		RedirectURI:  "https://wallet.example/callback",
		AuthorizationDetails: []map[string]any{
			{
				"type":                        types.AuthorizationDetailTypeOpenIDCredential,
				"credential_configuration_id": "pid",
			},
		},
	}, types.OAuthClientAttestationHeaders{})
	require.NoError(t, err)

	assert.Empty(t, captured.Get("scope"), "scope must be omitted when authorization_details is used")
	var details []map[string]any
	require.NoError(t, json.Unmarshal([]byte(captured.Get("authorization_details")), &details))
	require.Len(t, details, 1)
	assert.Equal(t, types.AuthorizationDetailTypeOpenIDCredential, details[0]["type"])
	assert.Equal(t, "pid", details[0]["credential_configuration_id"])
}

func TestOid4vciReceiver_ExchangeAuthorizationCodeClientAssertion(t *testing.T) {
	var captured url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		captured = r.Form
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"access_token": "access-1", "token_type": "DPoP"})
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	receiver := &Oid4vciReceiver{AllowHTTP: true}
	token, err := receiver.ExchangeAuthorizationCode(common.URIField(*parsed), types.AuthorizationCodeTokenRequest{
		Code:                "code-1",
		RedirectURI:         "https://wallet.example/callback",
		CodeVerifier:        "verifier-1",
		ClientID:            "client-1",
		ClientAssertion:     "assertion-jwt",
		ClientAssertionType: types.ClientAssertionTypeJWTBearer,
	}, types.OAuthClientAttestationHeaders{}, "dpop-proof")
	require.NoError(t, err)
	assert.Equal(t, "access-1", token.Token)
	assert.Equal(t, "assertion-jwt", captured.Get("client_assertion"))
	assert.Equal(t, types.ClientAssertionTypeJWTBearer, captured.Get("client_assertion_type"))
}

func TestOid4vciReceiver_ExchangeAuthorizationCodeRetryRefreshesClientAssertion(t *testing.T) {
	attempts := 0
	var captured []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		_ = r.ParseForm()
		captured = append(captured, r.Form)
		if attempts == 1 {
			w.Header().Set("DPoP-Nonce", "nonce-1")
			http.Error(w, "use nonce", http.StatusBadRequest)
			return
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"access_token": "access-1", "token_type": "DPoP"})
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	factoryCalls := 0
	_, err = receiver.ExchangeAuthorizationCodeWithDpopAndAttestationRetry(
		common.URIField(*parsed),
		types.AuthorizationCodeTokenRequest{
			Code:                "code-1",
			RedirectURI:         "https://wallet.example/callback",
			CodeVerifier:        "verifier-1",
			ClientID:            "client-1",
			ClientAssertionType: types.ClientAssertionTypeJWTBearer,
			ClientAssertionFactory: func() (string, error) {
				factoryCalls++
				return fmt.Sprintf("assertion-%d", factoryCalls), nil
			},
		},
		func() (types.OAuthClientAttestationHeaders, error) { return types.OAuthClientAttestationHeaders{}, nil },
		func(string) (string, error) { return "dpop-proof", nil },
	)
	require.NoError(t, err)
	require.Equal(t, 2, attempts)
	require.Equal(t, 2, factoryCalls)
	require.Len(t, captured, 2)
	for _, form := range captured {
		assert.Equal(t, types.ClientAssertionTypeJWTBearer, form.Get("client_assertion_type"))
	}
	assert.NotEqual(t, captured[0].Get("client_assertion"), captured[1].Get("client_assertion"))
}

// newRedirectingOID4VCIEndpoint starts an endpoint that answers every request
// with a 307 to a second server, and reports how many requests that second
// server received. A 307 preserves the method and the body, so following it
// would replay a DPoP-bound body and its Authorization header at an origin the
// response chose, which is the reason A2 refuses every OID4VCI redirect.
func newRedirectingOID4VCIEndpoint(t *testing.T) (redirectingURL string, relayedRequests func() int) {
	t.Helper()
	var relayed atomic.Int64
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		relayed.Add(1)
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"credential_issuer": "https://relay.example"})
	}))
	t.Cleanup(relay.Close)

	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, relay.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)

	return redirecting.URL, func() int { return int(relayed.Load()) }
}

func TestPushAuthorizationRequestRefusesRedirect(t *testing.T) {
	redirectingURL, relayedRequests := newRedirectingOID4VCIEndpoint(t)
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	response, err := receiver.PushAuthorizationRequest(
		mustURIField(t, redirectingURL+"/par"),
		types.PushedAuthorizationRequest{ResponseType: "code", ClientID: "wallet", RedirectURI: "https://wallet.example/cb"},
		types.OAuthClientAttestationHeaders{ClientAttestation: "attestation", ClientAttestationPop: "pop"},
	)

	require.Error(t, err)
	assert.Nil(t, response)
	assert.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	assert.Zero(t, relayedRequests(), "the pushed request must not reach the redirect target")
}

func TestPostCredentialEndpointRefusesRedirect(t *testing.T) {
	redirectingURL, relayedRequests := newRedirectingOID4VCIEndpoint(t)
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	response, err := receiver.PostCredentialEndpointWithDpopRetry(
		mustURIField(t, redirectingURL+"/credential"),
		"access-1",
		[]byte(`{"credential_configuration_id":"cfg"}`),
		"application/json",
		noopProofFactory,
	)

	require.Error(t, err)
	assert.Nil(t, response)
	assert.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	assert.Zero(t, relayedRequests(), "the credential request must not reach the redirect target")
}

func TestFetchIssuerMetadataRefusesRedirect(t *testing.T) {
	redirectingURL, relayedRequests := newRedirectingOID4VCIEndpoint(t)
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	// Metadata gets no same-origin exemption: Section 12.2.2 fixes the metadata
	// path inside the Credential Issuer Identifier, so a redirect can only serve
	// the document from an origin the identifier does not name.
	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, redirectingURL), types.Oid4vci)

	require.Error(t, err)
	assert.Nil(t, metadata)
	assert.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	assert.Zero(t, relayedRequests(), "the metadata request must not reach the redirect target")
}

func TestFetchNonceResponseRefusesRedirect(t *testing.T) {
	redirectingURL, relayedRequests := newRedirectingOID4VCIEndpoint(t)
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	response, err := receiver.FetchNonceResponse(mustURIField(t, redirectingURL+"/nonce"))

	require.Error(t, err)
	assert.Nil(t, response)
	assert.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	assert.Zero(t, relayedRequests(), "the nonce request must not reach the redirect target")
}

func TestNoRedirectClientDoesNotMutateCallerClient(t *testing.T) {
	transport := &http.Transport{}
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	caller := &http.Client{Transport: transport, Timeout: 7 * time.Second, Jar: jar}

	wrapped := NoRedirectClient(caller)

	require.NotSame(t, caller, wrapped)
	assert.Nil(t, caller.CheckRedirect, "the caller's client keeps following redirects")
	assert.Same(t, transport, wrapped.Transport, "the caller's transport, and so its connection pool, is reused")
	assert.Equal(t, 7*time.Second, wrapped.Timeout)
	assert.Same(t, jar, wrapped.Jar)

	require.NotNil(t, wrapped.CheckRedirect)
	redirected, err := http.NewRequest(http.MethodGet, "https://issuer.example/elsewhere", nil)
	require.NoError(t, err)
	assert.ErrorIs(t, wrapped.CheckRedirect(redirected, nil), ErrHTTPRedirectNotAllowed)

	// A caller with no client of its own gets the package default, which refuses
	// redirects as well.
	fallback := NoRedirectClient(nil)
	require.NotNil(t, fallback.CheckRedirect)
	assert.ErrorIs(t, fallback.CheckRedirect(redirected, nil), ErrHTTPRedirectNotAllowed)
}

func TestCredentialRequestUsesBearerSchemeForBearerToken(t *testing.T) {
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	response, cNonce, err := receiver.PostCredentialEndpointWithNonceRetryForToken(
		mustURIField(t, issuer.URL()+"/credential"),
		types.CredentialIssuanceAccessToken{Token: "bearer-access-token", TokenType: "Bearer"},
		nil,
		"c-nonce-1",
		func(nonce string) ([]byte, string, error) {
			return []byte(`{"credential_configuration_id":"test-config"}`), "application/json", nil
		},
		noopProofFactory,
	)

	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, "c-nonce-1", cNonce)

	requests := issuer.CredentialRequests()
	require.Len(t, requests, 1)
	assert.Equal(t, "Bearer bearer-access-token", requests[0].Authorization)
	assert.Empty(t, requests[0].DPoP, "a bearer token is not key-bound, so no DPoP proof is sent with it")
}

func TestCredentialRequestUsesDPoPSchemeForDPoPToken(t *testing.T) {
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	response, _, err := receiver.PostCredentialEndpointWithNonceRetryForToken(
		mustURIField(t, issuer.URL()+"/credential"),
		types.CredentialIssuanceAccessToken{Token: "dpop-access-token", TokenType: "dpop"},
		nil,
		"c-nonce-1",
		func(nonce string) ([]byte, string, error) {
			return []byte(`{"credential_configuration_id":"test-config"}`), "application/json", nil
		},
		noopProofFactory,
	)

	require.NoError(t, err)
	require.NotNil(t, response)

	requests := issuer.CredentialRequests()
	require.Len(t, requests, 1)
	// token_type is case insensitive (RFC 6749 Section 7.1) but the scheme is
	// spelled as RFC 9449 Section 7.1 defines it.
	assert.Equal(t, "DPoP dpop-access-token", requests[0].Authorization)
	assert.Equal(t, "dpop-proof", requests[0].DPoP)
}

// transportOnlyReceiver exposes only the transport half of the bundled plugin.
// Embedding the interface, rather than the concrete receiver, means the signing
// primitives are not promoted, which is what a third-party HTTP-only plugin
// looks like.
type transportOnlyReceiver struct {
	types.OID4VCIFinalTransport
}

// TestOid4vciReceiverSatisfiesTransportAndSigner pins the split of the Final
// receiver capability into a transport contract a plugin owns and a signer
// contract the wallet may replace. The bundled plugin implements both, so it
// also satisfies the deprecated compound interface; a transport-only plugin
// satisfies the transport contract alone.
func TestOid4vciReceiverSatisfiesTransportAndSigner(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	var transport types.OID4VCIFinalTransport = receiver
	var signer types.OID4VCIFinalSigner = receiver
	var compound types.OID4VCIFinalReceiver = receiver
	if compound == nil {
		t.Fatal("compound interface is nil")
	}

	if _, ok := any(&transportOnlyReceiver{OID4VCIFinalTransport: receiver}).(types.OID4VCIFinalSigner); ok {
		t.Fatal("a transport-only plugin must not satisfy OID4VCIFinalSigner")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key := jose.JSONWebKey{Key: privateKey, KeyID: "holder-key-1", Algorithm: string(jose.ES256), Use: "sig"}

	// Signer view: the key proof of Section 8.2.1.1 verifies under the holder key.
	proof, err := signer.CreateCredentialRequestJWTProofWithOptions(key, types.ProofOptions{
		Audience:         "https://issuer.example",
		Nonce:            "credential-nonce",
		SigningAlgValues: []jose.SignatureAlgorithm{jose.ES256},
	})
	require.NoError(t, err)
	parsedProof, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	var proofClaims map[string]any
	require.NoError(t, parsedProof.Claims(&privateKey.PublicKey, &proofClaims))
	require.Equal(t, "https://issuer.example", proofClaims["aud"])
	require.Equal(t, "credential-nonce", proofClaims["nonce"])

	// The same proof comes out of the default signer on its own, which is what a
	// wallet gets when its plugin implements the transport contract only.
	standalone, err := oid4vcisign.Default{}.CreateCredentialRequestJWTProofWithOptions(key, types.ProofOptions{
		Audience:         "https://issuer.example",
		SigningAlgValues: []jose.SignatureAlgorithm{jose.ES256},
	})
	require.NoError(t, err)
	standaloneParsed, err := jwt.ParseSigned(standalone, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	require.Equal(t, "openid4vci-proof+jwt", standaloneParsed.Headers[0].ExtraHeaders[jose.HeaderType])

	// Transport view: the Credential Request codec round-trips without any key.
	body, contentType, err := transport.EncodeCredentialRequest(
		map[string]any{"credential_configuration_id": "pid", "proofs": map[string]any{"jwt": []string{proof}}},
		&types.CredentialIssuerMetadata{},
	)
	require.NoError(t, err)
	require.Equal(t, "application/json", contentType)
	var encoded map[string]any
	require.NoError(t, json.Unmarshal(body, &encoded))
	require.Equal(t, "pid", encoded["credential_configuration_id"])

	response, err := transport.DecodeCredentialResponse([]byte(`{"credential":"credential-1"}`), "application/json", nil)
	require.NoError(t, err)
	require.Equal(t, "credential-1", response.Credential)
}
