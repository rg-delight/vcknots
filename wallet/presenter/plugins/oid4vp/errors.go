package oid4vp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Sentinel errors the OID4VP Final Request Object authentication path returns.
// A caller branches on the condition that made the Wallet terminate request
// processing with errors.Is instead of matching message text, which lets the
// library reword an error without silently collapsing a verifier rejection into
// a generic one. The errors themselves stay unexported implementation detail;
// the values below are the stable identifiers.
var (
	// ErrRequestObjectTypInvalid reports that the Request Object JWT does not
	// carry exactly one protected header or its typ header is not
	// "oauth-authz-req+jwt" (OID4VP 1.0 §5.10.1, RFC 9101 §5.2).
	ErrRequestObjectTypInvalid = errors.New("request object typ header is not oauth-authz-req+jwt")
	// ErrRequestObjectSignatureInvalid reports that the Request Object
	// signature could not be verified with the certificate the client
	// identifier authenticates.
	ErrRequestObjectSignatureInvalid = errors.New("request object signature could not be verified")
	// ErrRequestObjectAudienceMismatch reports that the Request Object audience
	// does not identify this Wallet (OID4VP 1.0 §5.10.1).
	ErrRequestObjectAudienceMismatch = errors.New("request object audience does not identify this wallet")
	// ErrRequestObjectExpired reports that the Request Object is outside its
	// exp/nbf validity window, is missing an exp the configured policy
	// requires, or exceeds the configured maximum lifetime.
	ErrRequestObjectExpired = errors.New("request object is outside its validity")
	// ErrRequestObjectClientIDMismatch reports that the authenticated Request
	// Object's client identifier does not bind to the outer Authorization
	// Request or to the response endpoint (OID4VP 1.0 §5.9.3, §5.10.1).
	ErrRequestObjectClientIDMismatch = errors.New("request object client_id does not match the authenticated request")
	// ErrX509HashMismatch reports that the x509_hash Client Identifier does not
	// match the leaf certificate that signed the Request Object (OID4VP 1.0
	// §5.9.3).
	ErrX509HashMismatch = errors.New("request object x509_hash client_id does not match the signing certificate")
	// ErrHAIPRequestURIRequired reports that the HAIP profile requires a signed
	// Authorization Request delivered through request_uri, and this request did
	// not arrive that way (HAIP 1.0 §5.1).
	ErrHAIPRequestURIRequired = errors.New("HAIP requires the Authorization Request delivered by request_uri")
)

// VerifierResponseError reports a non-200 response from the Verifier's
// Response Endpoint. It deliberately retains only the HTTP status and the
// OAuth 2.0 error code normalized from the response body: the body is under
// the Verifier's control and may echo protocol state or secrets, so it never
// becomes part of the error text (ADR-0013).
type VerifierResponseError struct {
	// StatusCode is the HTTP status the Verifier returned.
	StatusCode int
	// OAuthError is the RFC 6749 §4.1.2.1 error member of the response body,
	// normalized to [a-z_]{1,64}. It is empty when the body was absent,
	// malformed, or carried no usable error member.
	OAuthError string
}

// Error implements error without exposing the Verifier's response body.
func (e *VerifierResponseError) Error() string {
	if e.OAuthError == "" {
		return fmt.Sprintf("verifier returned status %d", e.StatusCode)
	}
	return fmt.Sprintf("verifier returned status %d (%s)", e.StatusCode, e.OAuthError)
}

// maxOAuthErrorCodeLength bounds the OAuth error code retained from a Verifier
// response, so a hostile endpoint cannot grow the diagnostic string.
const maxOAuthErrorCodeLength = 64

// oauthErrorCodeFromResponseBody extracts the string "error" member of a
// Verifier response body and normalizes it to [a-z_]{1,64}. Anything else -
// a non-object body, a missing or non-string member, or a value with no
// allowed character - yields the empty string. The body itself is never kept.
func oauthErrorCodeFromResponseBody(body []byte) string {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	raw, ok := payload["error"]
	if !ok {
		return ""
	}
	var code string
	if err := json.Unmarshal(raw, &code); err != nil {
		return ""
	}
	return normalizeOAuthErrorCode(code)
}

// normalizeOAuthErrorCode lowercases code, drops every character outside
// [a-z_], and truncates the result to maxOAuthErrorCodeLength runes.
func normalizeOAuthErrorCode(code string) string {
	var normalized strings.Builder
	for _, character := range strings.ToLower(code) {
		if normalized.Len() >= maxOAuthErrorCodeLength {
			break
		}
		if (character >= 'a' && character <= 'z') || character == '_' {
			normalized.WriteRune(character)
		}
	}
	return normalized.String()
}

// SubmitAuthorizationErrorResponse posts an OAuth 2.0 error authorization
// response (error, error_description and state) to the Verifier's Response
// Endpoint as application/x-www-form-urlencoded, and returns the redirect_uri
// the Verifier answered with, if any.
//
// It is the single transport for a Wallet that decides on the rejection before
// it holds a CredentialPresentationRequest. OID4VP 1.0 §8.3.1 permits the error
// response to be sent unencrypted, so this form is always plaintext. The
// endpoint must use https unless the presenter enables AllowHTTP for a local
// test. A non-200 answer is reported as a *VerifierResponseError that does not
// carry the response body.
func (p *Oid4vpPresenter) SubmitAuthorizationErrorResponse(endpoint url.URL, code, description, state string) (string, error) {
	if _, err := parseResponseURI(endpoint.String(), p.AllowHTTP); err != nil {
		return "", err
	}

	formData := url.Values{}
	formData.Set("error", code)
	if description != "" {
		formData.Set("error_description", description)
	}
	if state != "" {
		formData.Set("state", state)
	}

	body, err := p.postAuthorizationResponse(endpoint.String(), formData)
	if err != nil {
		return "", err
	}
	if len(body) == 0 {
		return "", nil
	}

	var verifierResponse struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal(body, &verifierResponse); err != nil {
		return "", nil
	}
	return verifierResponse.RedirectURI, nil
}

// requestObjectFailureSignature maps one Request Object authentication failure
// to the sentinel a caller branches on. The authentication checks in this
// package return plain errors; the fragment is the wording they emit, so a
// change to that wording fails the sentinel tests instead of collapsing a
// verifier rejection into a generic error.
type requestObjectFailureSignature struct {
	fragment string
	sentinel error
}

var requestObjectFailureSignatures = []requestObjectFailureSignature{
	{"'typ' header", ErrRequestObjectTypInvalid},
	{"must have one protected header", ErrRequestObjectTypInvalid},
	{"x509_hash client_id mismatch", ErrX509HashMismatch},
	{"failed to verify request object with x5c certificate", ErrRequestObjectSignatureInvalid},
	{"failed to verify JWT signature", ErrRequestObjectSignatureInvalid},
	{"failed to parse request object JWT", ErrRequestObjectSignatureInvalid},
	{"invalid audience claim", ErrRequestObjectAudienceMismatch},
	{"request object audience", ErrRequestObjectAudienceMismatch},
	{"request object is outside its exp validity", ErrRequestObjectExpired},
	{"request object is outside its nbf validity", ErrRequestObjectExpired},
	{"request object is missing exp", ErrRequestObjectExpired},
	{"exceeding the configured maximum", ErrRequestObjectExpired},
	{"outer client_id does not match request object client_id", ErrRequestObjectClientIDMismatch},
	{"SAN of the certificate and client_id did not match", ErrRequestObjectClientIDMismatch},
	{"redirect_uri/response_uri and client_id (origin) must be same", ErrRequestObjectClientIDMismatch},
	{"delivered by request_uri", ErrHAIPRequestURIRequired},
}

// classifyRequestObjectFailure attaches the sentinel that names err's
// authentication failure, if any. The returned error keeps err's message
// (and its original chain) so existing diagnostics do not change, while
// errors.Is finds the sentinel and errors.As still reaches an underlying
// *AuthorizationRequestError. An error that matches no signature is returned
// unchanged.
func classifyRequestObjectFailure(err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	for _, signature := range requestObjectFailureSignatures {
		if !strings.Contains(message, signature.fragment) {
			continue
		}
		if errors.Is(err, signature.sentinel) {
			return err
		}
		return &requestObjectFailureError{sentinel: signature.sentinel, err: err}
	}
	return err
}

// requestObjectFailureError pairs a sentinel with the plain error the
// authentication check produced. Error preserves the original message while
// Unwrap exposes both errors, so errors.Is and errors.As see either one.
type requestObjectFailureError struct {
	sentinel error
	err      error
}

// Error returns the wrapped error's message unchanged.
func (e *requestObjectFailureError) Error() string {
	return e.err.Error()
}

// Unwrap exposes the sentinel and the original error to errors.Is and
// errors.As.
func (e *requestObjectFailureError) Unwrap() []error {
	return []error{e.sentinel, e.err}
}
