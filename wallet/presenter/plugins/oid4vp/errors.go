package oid4vp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
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
	ErrRequestObjectTypInvalid = common.NewCodedError("request_object_typ_invalid", "request object typ header is not oauth-authz-req+jwt")
	// ErrRequestObjectSignatureInvalid reports that the Request Object
	// signature could not be verified with the certificate the client
	// identifier authenticates.
	ErrRequestObjectSignatureInvalid = common.NewCodedError("request_object_signature_invalid", "request object signature could not be verified")
	// ErrRequestObjectAudienceMismatch reports that the Request Object audience
	// does not identify this Wallet (OID4VP 1.0 §5.10.1).
	ErrRequestObjectAudienceMismatch = common.NewCodedError("request_object_audience_mismatch", "request object audience does not identify this wallet")
	// ErrRequestObjectExpired reports that the Request Object is outside its
	// exp/nbf validity window, is missing an exp the configured policy
	// requires, or exceeds the configured maximum lifetime.
	ErrRequestObjectExpired = common.NewCodedError("request_object_expired", "request object is outside its validity")
	// ErrRequestObjectClientIDMismatch reports that the authenticated Request
	// Object's client identifier does not bind to the outer Authorization
	// Request or to the response endpoint (OID4VP 1.0 §5.9.3, §5.10.1).
	ErrRequestObjectClientIDMismatch = common.NewCodedError("request_object_client_id_mismatch", "request object client_id does not match the authenticated request")
	// ErrX509HashMismatch reports that the x509_hash Client Identifier does not
	// match the leaf certificate that signed the Request Object (OID4VP 1.0
	// §5.9.3).
	ErrX509HashMismatch = common.NewCodedError("x509_hash_mismatch", "request object x509_hash client_id does not match the signing certificate")
	// ErrHAIPRequestURIRequired reports that the HAIP profile requires a signed
	// Authorization Request delivered through request_uri, and this request did
	// not arrive that way (HAIP 1.0 §5.1).
	ErrHAIPRequestURIRequired = common.NewCodedError("haip_request_uri_required", "HAIP requires the Authorization Request delivered by request_uri")
	// ErrResponseURIInvalid reports that a response_uri is not a usable
	// Response Endpoint: absent, unparseable, without an authority, or not
	// https while the presenter does not allow plain http.
	ErrResponseURIInvalid = common.NewCodedError("response_uri_invalid", "response_uri is not a usable Response Endpoint")
	// ErrErrorDescriptionInvalid reports an error_description outside the
	// character set RFC 6749 §4.1.2.1 defines for it.
	ErrErrorDescriptionInvalid = common.NewCodedError("error_description_invalid", "error_description is outside the RFC 6749 4.1.2.1 character set")
	// ErrClientIDPrefixReserved reports a Client Identifier whose Client
	// Identifier Prefix only the Wallet itself may mint: "origin", which
	// OID4VP 1.0 §5.9.3 forbids a Wallet to accept in requests, and
	// "web-origin", the effective identifier a Wallet derives for itself from
	// the platform-authenticated Origin of an unsigned Digital Credentials API
	// request (Appendix A.2).
	ErrClientIDPrefixReserved = common.NewCodedError("client_id_prefix_reserved", "client_id prefix is reserved for the wallet and is not accepted in requests")
	// ErrRequestObjectSignatureRequired reports an Authorization Request in
	// plain parameters from a Verifier that can only be authenticated by a
	// signed Request Object: the x509_san_dns, x509_hash and
	// verifier_attestation prefixes (OID4VP 1.0 §5.9.3), openid_federation
	// unless FederationTrustOptions.AllowUnsignedRequests is set, and a
	// pre-registered client with RequireSignedRequestObject.
	ErrRequestObjectSignatureRequired = common.NewCodedError("request_object_signature_required", "this client identifier requires a signed Request Object")
)

// ErrErrorResponseEndpointUnbound reports that a refused Authorization Request
// names no Response URI the Wallet may send an error authorization response
// to (see AuthorizationRequestError.ResponseURI).
var ErrErrorResponseEndpointUnbound = common.NewCodedError("error_response_endpoint_unbound", "the refused request names no Response URI the wallet may answer")

// errorResponseTarget is the Response URI and request state an error
// authorization response for a refused request is sent with.
type errorResponseTarget struct {
	responseURI  string
	responseMode OAuthAuthzReqResponseMode
	state        string
	metadata     *VerifierMetadata
	haip         bool
}

// ResponseURI returns the Response URI an error authorization response for
// this refusal may be sent to, or "" when there is none. Only an unsigned
// direct_post or direct_post.jwt request whose Client Identifier has the
// redirect_uri prefix names one: that prefix binds the Response URI to the
// Client Identifier (OID4VP 1.0 §5.9.3). It authenticates nobody, so sending
// is the caller's decision.
func (e *AuthorizationRequestError) ResponseURI() string {
	if e.response == nil {
		return ""
	}
	return e.response.responseURI
}

// SendErrorResponse posts the error authorization response for this refusal
// (OID4VP 1.0 §8.5, RFC 6749 §4.1.2.1) to ResponseURI. A direct_post.jwt
// request is answered encrypted when its metadata allows it, and in plaintext
// otherwise (§8.3.1). Redirects are not followed. A nil client uses a default
// client. It returns ErrErrorResponseEndpointUnbound when ResponseURI is "".
func (e *AuthorizationRequestError) SendErrorResponse(ctx context.Context, client *http.Client) error {
	if e.response == nil {
		return ErrErrorResponseEndpointUnbound
	}
	target := e.response
	values := map[string]string{"error": string(e.Code)}
	if e.Err != nil {
		values["error_description"] = sanitizeOAuthErrorDescription(e.Err.Error())
	}
	if target.state != "" {
		values["state"] = target.state
	}
	formData := url.Values{}
	if target.responseMode == OAuthAuthzReqResponseModeDirectPostJWT {
		if payload, err := json.Marshal(values); err == nil {
			if token, err := encryptAuthorizationResponse(payload, target.metadata, target.haip); err == nil {
				formData.Set("response", token)
			}
		}
	}
	if formData.Get("response") == "" {
		for name, value := range values {
			formData.Set(name, value)
		}
	}
	if _, err := postAuthorizationResponse(ctx, client, target.responseURI, formData); err != nil {
		return fmt.Errorf("failed to send error authorization response: %w", err)
	}
	return nil
}

// attachErrorResponseTarget records on the refusal in err where an error
// authorization response may be sent, when b's request binds one.
func (b *requestCore) attachErrorResponseTarget(err error) {
	var authzErr *AuthorizationRequestError
	if !b.errorResponseAllowed || !errors.As(err, &authzErr) || !isDirectPostMode(b.req.ResponseMode) {
		return
	}
	if _, parseErr := parseResponseURI(b.req.ResponseURI, b.allowHTTP); parseErr != nil {
		return
	}
	authzErr.response = &errorResponseTarget{
		responseURI:  b.req.ResponseURI,
		responseMode: b.req.ResponseMode,
		state:        b.req.State,
		metadata:     b.req.ClientMetadata,
		haip:         b.haipRequestObjectPolicy(),
	}
}

// sanitizeOAuthErrorDescription replaces every character outside the RFC 6749
// §4.1.2.1 error_description set with a space.
func sanitizeOAuthErrorDescription(description string) string {
	return strings.Map(func(character rune) rune {
		if validateOAuthErrorDescription(string(character)) != nil {
			return ' '
		}
		return character
	}, description)
}

// ErrDCQLSelectionUnsatisfied reports that credentials chosen outside this
// library do not answer the DCQL query: a selected credential does not satisfy
// its credential query, the disclosed claims are not one of the claim sets that
// query offers (OID4VP 1.0 Section 6.3), a required credential_set has no fully
// answered option (Section 6.2), or a credential outside every answered option
// would be disclosed. A caller branches on it with errors.Is to tell a consent
// decision the request cannot accept from a transport or serialization failure.
var ErrDCQLSelectionUnsatisfied = common.NewCodedError("dcql_selection_unsatisfied", "DCQL credential selection does not satisfy the query")

// VerifierResponseError reports a non-2xx response from the Verifier's
// Response Endpoint. It deliberately retains only the HTTP status and the
// OAuth 2.0 error code normalized from the response body: the body is under
// the Verifier's control and may echo protocol state or secrets, so it never
// becomes part of the error text.
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

// ErrorCode names the outcome: the Verifier's Response Endpoint refused the
// Authorization Response. OAuthError carries the error the Verifier reported;
// this names what happened.
func (e *VerifierResponseError) ErrorCode() string {
	return "verifier_response_rejected"
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
// test. A non-2xx answer is reported as a *VerifierResponseError that does not
// carry the response body.
//
// The two caller-supplied values that reach the wire are checked before
// anything is sent: the endpoint through parseResponseURI (ErrResponseURIInvalid)
// and description against the RFC 6749 §4.1.2.1 character set
// (ErrErrorDescriptionInvalid), so an integrator branches on the refusal with
// errors.Is instead of reproducing either rule ahead of the call.
func (p *Oid4vpPresenter) SubmitAuthorizationErrorResponse(endpoint url.URL, code, description, state string) (string, error) {
	if _, err := parseResponseURI(endpoint.String(), p.AllowHTTP); err != nil {
		return "", err
	}
	if err := validateOAuthErrorDescription(description); err != nil {
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

// validateOAuthErrorDescription checks error_description against the production
// RFC 6749 §4.1.2.1 gives it:
//
//	error_description = 1*NQSCHAR
//	NQSCHAR           = %x20-21 / %x23-5B / %x5D-7E
//
// which is printable US-ASCII without the double quote and the backslash. A
// value outside it cannot be carried by the Authorization Error Response, so it
// is refused rather than silently reshaped into something the Verifier reads
// differently.
func validateOAuthErrorDescription(description string) error {
	for index, character := range description {
		switch {
		case character >= 0x20 && character <= 0x21,
			character >= 0x23 && character <= 0x5B,
			character >= 0x5D && character <= 0x7E:
			continue
		}
		return fmt.Errorf(
			"%w: character at byte %d is not allowed (%%x20-21 / %%x23-5B / %%x5D-7E): %q",
			ErrErrorDescriptionInvalid, index, character,
		)
	}
	return nil
}
