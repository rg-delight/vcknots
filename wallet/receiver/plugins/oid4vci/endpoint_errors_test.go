package oid4vci

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// requireEndpointError recovers the stage classification of a failed endpoint
// and asserts the fields a caller reports from.
func requireEndpointError(t *testing.T, err error, stage Stage, status int, oauthError string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	var endpointError *EndpointError
	if !errors.As(err, &endpointError) {
		t.Fatalf("errors.As(*EndpointError) = false, err = %v", err)
	}
	if endpointError.Stage != stage {
		t.Errorf("Stage = %q, want %q", endpointError.Stage, stage)
	}
	if endpointError.StatusCode != status {
		t.Errorf("StatusCode = %d, want %d", endpointError.StatusCode, status)
	}
	if endpointError.OAuthError != oauthError {
		t.Errorf("OAuthError = %q, want %q", endpointError.OAuthError, oauthError)
	}
}

// Every endpoint of a Final issuance names itself when it refuses the request,
// so a caller reports which step failed without inspecting message text.
func TestEndpointErrorNamesTheFailedStage(t *testing.T) {
	status := http.StatusServiceUnavailable
	body := map[string]string{"error": "temporarily_unavailable"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = mockserver.JSONResponse(w, status, body)
	}))
	defer server.Close()
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	endpoint := mustURIField(t, server.URL+"/issuer")

	_, err := receiver.FetchIssuerMetadata(endpoint, types.Oid4vci)
	requireEndpointError(t, err, StageIssuerMetadata, status, "temporarily_unavailable")

	_, err = receiver.FetchAuthorizationServerMetadata(endpoint, types.Oid4vci)
	requireEndpointError(t, err, StageAuthorizationServerMetadata, status, "temporarily_unavailable")

	_, err = receiver.PushAuthorizationRequest(context.Background(), endpoint, types.PushedAuthorizationRequest{ResponseType: "code"}, types.OAuthClientAttestationHeaders{})
	requireEndpointError(t, err, StagePAR, status, "temporarily_unavailable")

	_, err = receiver.FetchNonceResponse(context.Background(), endpoint)
	requireEndpointError(t, err, StageNonce, status, "temporarily_unavailable")

	_, err = receiver.ExchangeAuthorizationCodeWithDpopRetry(endpoint, types.AuthorizationCodeTokenRequest{Code: "code-1"}, types.OAuthClientAttestationHeaders{}, noopProofFactory)
	requireEndpointError(t, err, StageToken, status, "temporarily_unavailable")

	_, err = receiver.ExchangePreAuthorizedCodeWithDpopAndAttestationRetry(context.Background(), endpoint, types.PreAuthorizedCodeTokenRequest{PreAuthorizedCode: "pre-1"}, func() (types.OAuthClientAttestationHeaders, error) {
		return types.OAuthClientAttestationHeaders{}, nil
	}, noopProofFactory)
	requireEndpointError(t, err, StageToken, status, "temporarily_unavailable")
}

// The token endpoint's RFC 6749 §5.2 error code is reported structurally, and
// the issuer's response body is not kept on the error.
func TestEndpointErrorReportsTheOAuthErrorWithoutTheBody(t *testing.T) {
	secret := "leaked-authorization-details"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": secret,
		})
	}))
	defer server.Close()
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}

	_, err := receiver.ExchangeAuthorizationCodeWithDpopRetry(mustURIField(t, server.URL), types.AuthorizationCodeTokenRequest{Code: "code-1"}, types.OAuthClientAttestationHeaders{}, noopProofFactory)
	requireEndpointError(t, err, StageToken, http.StatusBadRequest, "invalid_grant")
	var endpointError *EndpointError
	_ = errors.As(err, &endpointError)
	// A report built from the fields alone — which is what a wallet renders and
	// logs — carries the stage and the error code and nothing from the body.
	report := fmt.Sprintf("%s %d %s", endpointError.Stage, endpointError.StatusCode, endpointError.OAuthError)
	if strings.Contains(report, secret) {
		t.Errorf("the endpoint error fields must not carry the response body: %s", report)
	}
}

// A failure with no HTTP response of its own still names its stage, and the
// sentinels underneath it stay reachable through the wrapper.
func TestEndpointErrorKeepsTheUnderlyingCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://elsewhere.example/metadata")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}

	_, err := receiver.FetchAuthorizationServerMetadata(mustURIField(t, server.URL), types.Oid4vci)
	requireEndpointError(t, err, StageAuthorizationServerMetadata, 0, "")
	if !errors.Is(err, ErrHTTPRedirectNotAllowed) {
		t.Fatalf("errors.Is(ErrHTTPRedirectNotAllowed) = false, err = %v", err)
	}
}
