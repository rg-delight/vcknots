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
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// Existing tests

func TestOid4vciReceiver_FetchIssuerMetadata(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	// Create mock OID4VCI issuer server
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL())
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		dbg_mode := env.IsDebugMode()
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetDebugMode(dbg_mode)
		defer env.SetHTTPAllowed(http_allowed)
		env.SetDebugMode(false)
		env.SetHTTPAllowed(false)

		_, err := receiver.FetchIssuerMetadata(endpoint, types.Oid4vci)
		if err == nil {
			t.Fatal("FetchIssuerMetadata should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

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
		_, err := receiver.FetchIssuerMetadata(common.URIField{}, types.SupportedReceivingTypes(999))
		if err == nil {
			t.Fatal("Expected error for unsupported receiving type")
		}
	})

	t.Run("Server error", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

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
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

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
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

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
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

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
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

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
	receiver := &Oid4vciReceiver{}

	// Create mock OID4VCI issuer server (which also serves auth server metadata)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL())
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		dbg_mode := env.IsDebugMode()
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetDebugMode(dbg_mode)
		defer env.SetHTTPAllowed(http_allowed)
		env.SetDebugMode(false)
		env.SetHTTPAllowed(false)

		_, err := receiver.FetchAuthorizationServerMetadata(endpoint, types.Oid4vci)
		if err == nil {
			t.Fatal("FetchAuthorizationServerMetadata should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

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
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

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
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

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
	receiver := &Oid4vciReceiver{}

	// Create mock OID4VCI issuer server (which serves token endpoint)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL())
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		dbg_mode := env.IsDebugMode()
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetDebugMode(dbg_mode)
		defer env.SetHTTPAllowed(http_allowed)
		env.SetDebugMode(false)
		env.SetHTTPAllowed(false)

		_, err := receiver.FetchAccessToken(types.Oid4vci, endpoint, "test-code")
		if err == nil {
			t.Fatal("FetchAccessToken should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		token, err := receiver.FetchAccessToken(types.Oid4vci, endpoint, "test-code")
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

	t.Run("Server error", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/token", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL())
		_, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*errorURL), "test-code")
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/token", http.StatusOK, "{invalid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL())
		_, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*invalidJSONURL), "test-code")
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})
}

func TestOid4vciReceiver_FinalPrimitives(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	httpAllowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

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

	nonce, err := receiver.FetchNonce(endpoint("/nonce"))
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
	httpAllowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

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

func TestOid4vciReceiver_ExchangeAuthorizationCodeWithDpopRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	httpAllowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

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

func TestOid4vciReceiver_RequestDeferredCredentialWithDpopRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	httpAllowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

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
	httpAllowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

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

func TestOid4vciReceiver_ReceiveCredential(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	accessToken := types.CredentialIssuanceAccessToken{Token: "test_token", TokenType: "bearer"}

	// Create mock OID4VCI issuer server (which serves credential endpoint)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL() + "/credential")
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		dbg_mode := env.IsDebugMode()
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetDebugMode(dbg_mode)
		defer env.SetHTTPAllowed(http_allowed)
		env.SetDebugMode(false)
		env.SetHTTPAllowed(false)

		_, err := receiver.ReceiveCredential(types.Oid4vci, endpoint, "jwt_vc_json", accessToken, nil, nil)
		if err == nil {
			t.Fatal("ReceiveCredential should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		credential, err := receiver.ReceiveCredential(types.Oid4vci, endpoint, "jwt_vc_json", accessToken, nil, nil)
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

	t.Run("Server error", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/credential", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*errorURL), "jwt_vc_json", accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/credential", http.StatusOK, "{invalid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*invalidJSONURL), "jwt_vc_json", accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})

	t.Run("No credential in response", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		noCredServer := mockserver.NewMockServer()
		defer noCredServer.Close()

		// Return valid JSON but without credential field
		noCredServer.SetJSONResponse("/credential", http.StatusOK, map[string]string{"status": "success"})

		noCredURL, _ := url.Parse(noCredServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*noCredURL), "jwt_vc_json", accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error when no credential is in the response")
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
			expectedPath: "/tenant2/.well-known/openid-credential-issuer",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchIssuerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Credential Issuer (With Trailing Slash)",
			identifier:   "/tenant2/",
			expectedPath: "/tenant2/.well-known/openid-credential-issuer",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchIssuerMetadata(u, types.Oid4vci)
				return err
			},
		},
	}

	http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(http_allowed)
	env.SetHTTPAllowed(true)

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
			if tt.identifier != "/" {
				identifierURL.Path = tt.identifier
			}
			endpoint := common.URIField(identifierURL)

			if err := tt.discovery(endpoint); err != nil {
				t.Errorf("Pattern %s failed: expected success at %s, got %v", tt.name, tt.expectedPath, err)
			}
		})
	}
}
