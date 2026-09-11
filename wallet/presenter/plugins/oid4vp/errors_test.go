package oid4vp

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// TestClassifyRequestObjectFailureSentinels pins each authentication failure
// this package can emit to the sentinel a caller branches on, and that the
// classification never rewrites the original message.
func TestClassifyRequestObjectFailureSentinels(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		sentinel error
	}{
		{"typ missing", "request object JWT must include 'typ' header parameter", ErrRequestObjectTypInvalid},
		{"typ wrong", "request object JWT 'typ' header must be 'oauth-authz-req+jwt'", ErrRequestObjectTypInvalid},
		{"protected header", "request object JWT must have one protected header", ErrRequestObjectTypInvalid},
		{"x509 hash mismatch", "x509_hash client_id mismatch", ErrX509HashMismatch},
		{"signature invalid", "failed to verify request object with x5c certificate: bad signature", ErrRequestObjectSignatureInvalid},
		{"jwt parse", "failed to parse request object JWT: malformed", ErrRequestObjectSignatureInvalid},
		{"audience absent", "request object audience is required", ErrRequestObjectAudienceMismatch},
		{"audience wrong", "request object audience does not identify this Wallet", ErrRequestObjectAudienceMismatch},
		{"audience malformed", "invalid audience claim", ErrRequestObjectAudienceMismatch},
		{"expired", "request object is outside its exp validity", ErrRequestObjectExpired},
		{"not yet valid", "request object is outside its nbf validity", ErrRequestObjectExpired},
		{"missing exp", "request object is missing exp", ErrRequestObjectExpired},
		{"max age", "request object exp is 1h0m0s in the future, exceeding the configured maximum of 10m0s", ErrRequestObjectExpired},
		{"outer client_id", "outer client_id does not match request object client_id", ErrRequestObjectClientIDMismatch},
		{"san mismatch", "SAN of the certificate and client_id did not match", ErrRequestObjectClientIDMismatch},
		{"origin mismatch", "redirect_uri/response_uri and client_id (origin) must be same", ErrRequestObjectClientIDMismatch},
		{"haip request_uri", "HAIP profile requires a signed Authorization Request delivered by request_uri", ErrHAIPRequestURIRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := classifyRequestObjectFailure(errors.New(tt.message))
			if !errors.Is(err, tt.sentinel) {
				t.Fatalf("classify(%q) does not wrap %v", tt.message, tt.sentinel)
			}
			if got := err.Error(); got != tt.message {
				t.Fatalf("classify changed the message: %q", got)
			}
		})
	}

	t.Run("unrelated error is unchanged", func(t *testing.T) {
		original := errors.New("dcql_query is required")
		if got := classifyRequestObjectFailure(original); got != original {
			t.Fatalf("unrelated error was rewritten: %v", got)
		}
	})
}

// TestParsePresentationRequestReturnsRequestObjectSentinels drives four of the
// authentication failures through the public API, so the sentinels are proven
// reachable end to end and not only by classifyRequestObjectFailure.
func TestParsePresentationRequestReturnsRequestObjectSentinels(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["exp"] = f.now.Add(-time.Second).Unix()
		if _, err := f.parse(t, claims); !errors.Is(err, ErrRequestObjectExpired) {
			t.Fatalf("expired Request Object: %v", err)
		}
	})

	t.Run("audience mismatch", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["aud"] = "another-wallet"
		if _, err := f.parse(t, claims); !errors.Is(err, ErrRequestObjectAudienceMismatch) {
			t.Fatalf("audience mismatch: %v", err)
		}
	})

	t.Run("outer client_id mismatch", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["client_id"] = "x509_hash:not-the-object-client-id"
		if _, err := f.parse(t, claims); !errors.Is(err, ErrRequestObjectClientIDMismatch) {
			t.Fatalf("client_id mismatch: %v", err)
		}
	})

	t.Run("x509_hash mismatch", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		wrong := "x509_hash:" + base64.RawURLEncoding.EncodeToString([]byte("wrong-leaf-hash"))
		claims := f.claims()
		claims["client_id"] = wrong
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {wrong},
			"request":   {f.sign(t, claims, nil)},
		}.Encode()
		if _, err := f.presenter().ParsePresentationRequest(uri); !errors.Is(err, ErrX509HashMismatch) {
			t.Fatalf("x509_hash mismatch: %v", err)
		}
	})

	t.Run("typ invalid", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		options := (&jose.SignerOptions{}).
			WithType("JWT").
			WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {f.clientID()},
			"request":   {f.sign(t, f.claims(), options)},
		}.Encode()
		if _, err := f.presenter().ParsePresentationRequest(uri); !errors.Is(err, ErrRequestObjectTypInvalid) {
			t.Fatalf("typ invalid: %v", err)
		}
	})

	t.Run("signature invalid", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		other := newRequestObjectFixture(t)
		// Present f's certificate in x5c so the client_id binding passes, but
		// sign with other's key so verification fails.
		options := (&jose.SignerOptions{}).
			WithType("oauth-authz-req+jwt").
			WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: other.key}, options)
		require.NoError(t, err)
		token, err := jwt.Signed(signer).Claims(f.claims()).Serialize()
		require.NoError(t, err)
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {f.clientID()},
			"request":   {token},
		}.Encode()
		if _, err := f.presenter().ParsePresentationRequest(uri); !errors.Is(err, ErrRequestObjectSignatureInvalid) {
			t.Fatalf("signature invalid: %v", err)
		}
	})

	t.Run("haip request_uri required", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		p := f.presenterWith(requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByValue})
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {f.clientID()},
			"request":   {f.sign(t, f.claims(), nil)},
		}.Encode()
		if _, err := p.ParsePresentationRequest(uri); !errors.Is(err, ErrHAIPRequestURIRequired) {
			t.Fatalf("HAIP request_uri required: %v", err)
		}
	})
}

// TestPresentDCQLSendsEmptyVPTokenObject covers OID4VP 1.0 §8.1: a holder that
// declines every optional credential query answers with the empty vp_token
// object {}, not an omitted or null value.
func TestPresentDCQLSendsEmptyVPTokenObject(t *testing.T) {
	p, endpoint, forms, calls := dcqlTransportEndpoint(t)
	redirect, err := p.PresentDCQL(types.Oid4vp, endpoint, map[string][]string{}, &types.PresentationRequest{})
	require.NoError(t, err)
	require.Equal(t, "https://verifier.example/complete", redirect)
	form := requireDCQLForm(t, forms, calls)
	require.Equal(t, "{}", form.Get("vp_token"))
	require.Len(t, form, 1)
}

// TestPresentDCQLVerifierResponseErrorHidesBody covers ADR-0013: a non-200
// verifier response becomes a *VerifierResponseError that carries only the
// status and the normalized OAuth error code, never the body.
func TestPresentDCQLVerifierResponseErrorHidesBody(t *testing.T) {
	const secret = "response-code-and-state-echoed-by-the-verifier"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid-Request!!","secret":"` + secret + `"}`))
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	require.NoError(t, err)

	p := &Oid4vpPresenter{}
	_, err = p.PresentDCQL(types.Oid4vp, *endpoint, map[string][]string{"identity": {"presentation"}}, &types.PresentationRequest{})
	require.Error(t, err)

	var verifierErr *VerifierResponseError
	require.ErrorAs(t, err, &verifierErr)
	require.Equal(t, http.StatusBadRequest, verifierErr.StatusCode)
	require.Equal(t, "invalidrequest", verifierErr.OAuthError)
	require.Equal(t, "verifier returned status 400 (invalidrequest)", verifierErr.Error())
	require.NotContains(t, err.Error(), secret)
	require.NotContains(t, err.Error(), "secret")
}

// TestVerifierResponseErrorFormatting pins the two shapes of the diagnostic
// string: with and without an OAuth error code.
func TestVerifierResponseErrorFormatting(t *testing.T) {
	require.Equal(t, "verifier returned status 400 (invalid_request)",
		(&VerifierResponseError{StatusCode: 400, OAuthError: "invalid_request"}).Error())
	require.Equal(t, "verifier returned status 502",
		(&VerifierResponseError{StatusCode: 502}).Error())
}

// TestNormalizeOAuthErrorCode pins the [a-z_]{1,64} normalization.
func TestNormalizeOAuthErrorCode(t *testing.T) {
	require.Equal(t, "invalid_request", normalizeOAuthErrorCode("invalid_request"))
	require.Equal(t, "invalidrequest", normalizeOAuthErrorCode("invalid-Request 1"))
	require.Equal(t, "", normalizeOAuthErrorCode("日本語"))
	require.Len(t, normalizeOAuthErrorCode(strings.Repeat("a", 200)), 64)
}

// TestSubmitAuthorizationErrorResponse covers the standalone error response
// transport: it posts error, error_description and state, and returns the
// redirect_uri the verifier answered with.
func TestSubmitAuthorizationErrorResponse(t *testing.T) {
	captured := &url.Values{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		*captured = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example/complete"}`))
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	require.NoError(t, err)

	p := &Oid4vpPresenter{AllowHTTP: true}
	redirect, err := p.SubmitAuthorizationErrorResponse(*endpoint, "access_denied", "user declined", "state-1")
	require.NoError(t, err)
	require.Equal(t, "https://verifier.example/complete", redirect)
	require.Equal(t, "access_denied", captured.Get("error"))
	require.Equal(t, "user declined", captured.Get("error_description"))
	require.Equal(t, "state-1", captured.Get("state"))
	require.Empty(t, captured.Get("vp_token"))
}

// TestSubmitAuthorizationErrorResponseRejectsPlaintextHTTP covers the endpoint
// scheme guard: without AllowHTTP the error response must not be sent over
// plain HTTP.
func TestSubmitAuthorizationErrorResponseRejectsPlaintextHTTP(t *testing.T) {
	endpoint, err := url.Parse("http://verifier.example/response")
	require.NoError(t, err)
	p := &Oid4vpPresenter{}
	_, err = p.SubmitAuthorizationErrorResponse(*endpoint, "access_denied", "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "https")
}
