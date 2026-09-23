package oid4vci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// This file carries the OpenID4VCI Draft 13 wire shapes that differ from
// OpenID4VCI 1.0. Two of them matter:
//
//   - the Credential Request names the credential with `format` plus a
//     format-specific member, or with `credential_identifier`, and carries a
//     single `proof` object (Draft 13 Section 7.2). Final 1.0 replaced that with
//     `credential_configuration_id` and a `proofs` array (Section 8.1).
//   - the Credential Error Response may carry a fresh `c_nonce` (Draft 13
//     Section 7.3.2), which is how a wallet recovers from `invalid_proof`.
//     Final 1.0 moved that to the Nonce Endpoint and the error no longer
//     carries one.
//
// Everything else — the deferred credential request of Section 9 and the
// notification of Section 10 — has the same body in both versions, so the
// difference is only which error shape comes back.

// Draft13Proof is the Draft 13 Section 7.2.1 `proof` object of a Credential
// Request. Draft 13 carries exactly one proof; the plural `proofs` member is a
// Final 1.0 addition.
type Draft13Proof struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt"`
}

// Draft13CredentialRequest is the Draft 13 Section 7.2 Credential Request. A
// request either names a `credential_identifier` the Token Response supplied,
// or the `format` and the format-specific members that identify the credential;
// Section 7.2 forbids sending both.
type Draft13CredentialRequest struct {
	Format               string                      `json:"format,omitempty"`
	VCT                  string                      `json:"vct,omitempty"`
	CredentialDefinition *types.CredentialDefinition `json:"credential_definition,omitempty"`
	CredentialIdentifier string                      `json:"credential_identifier,omitempty"`
	Proof                *Draft13Proof               `json:"proof,omitempty"`
}

// Draft13CredentialResponse is the Draft 13 Section 7.3 Credential Response and
// the Section 9.1 Deferred Credential Response, which share a shape. Exactly one
// of Credential and TransactionID is set on a well-formed response.
type Draft13CredentialResponse struct {
	// Credential is the issued credential, in the format the request named.
	Credential string
	// TransactionID is the Section 7.3 `transaction_id` of a deferred issuance.
	TransactionID string
	// NotificationID is the Section 7.3 `notification_id` the Section 10
	// notification refers to.
	NotificationID string
	// CNonce and CNonceExpiresIn are the Section 7.3 `c_nonce` members, which
	// Draft 13 lets the Credential Response carry for the next request.
	CNonce          string
	CNonceExpiresIn *int
	// Interval is the polling interval in seconds an issuer names next to a
	// transaction_id. Draft 13 defines none on the Credential Response; OpenID4VCI
	// 1.0 Section 8.3 added `interval` there, and an issuer that already sends it
	// is telling the wallet something worth keeping. Zero when absent.
	Interval int
}

// Draft13NotificationRequest is the Draft 13 Section 10.1 Notification Request
// body.
type Draft13NotificationRequest struct {
	NotificationID string `json:"notification_id"`
	// Event is credential_accepted, credential_failure or credential_deleted.
	Event string `json:"event"`
	// EventDescription is the OPTIONAL human-readable event_description.
	EventDescription string `json:"event_description,omitempty"`
}

// Draft13CredentialEndpointError is a Draft 13 Section 7.3.1 Credential Error
// Response, a Section 9.2 Deferred Credential Error Response or a Section 10.2
// Notification Error Response.
//
// It is a distinct type from types.CredentialEndpointError because Draft 13
// puts a fresh `c_nonce` in the error body: Section 7.3.2 says the Credential
// Issuer returns `invalid_proof` "along with a new `c_nonce`" and the wallet
// "SHOULD retry with the new nonce". Final 1.0 removed that member, so the
// Final error type has nowhere to keep it and a caller reading Final's type
// would silently lose the only nonce a Draft 13 issuer offers.
type Draft13CredentialEndpointError struct {
	// StatusCode is the HTTP status the endpoint answered with.
	StatusCode int
	// Code is the `error` member, such as invalid_proof or issuance_pending.
	Code string
	// Description is the optional `error_description`.
	Description string
	// CNonce and CNonceExpiresIn are the fresh nonce a Section 7.3.2
	// invalid_proof response carries, empty when the issuer sent none.
	CNonce          string
	CNonceExpiresIn *int
	// Interval is the Section 9.2 `interval`: the seconds to wait before
	// polling a deferred transaction again.
	Interval int
	// DPoPNonce is the RFC 9449 Section 8.2 DPoP-Nonce response header, kept so
	// a caller can build a corrected request.
	DPoPNonce string
}

// Draft 13 error codes this package names, so a caller branches on a condition
// rather than on the issuer's spelling of it.
var (
	// ErrDraft13InvalidProof is the Section 7.3.1 `invalid_proof` error. The
	// error may carry a fresh c_nonce to retry with.
	ErrDraft13InvalidProof = common.NewCodedError("draft13_credential_invalid_proof", "invalid_proof")
	// ErrDraft13IssuancePending is the Section 9.2 `issuance_pending` error of
	// the Deferred Credential Endpoint.
	ErrDraft13IssuancePending = common.NewCodedError("draft13_credential_issuance_pending", "issuance_pending")
)

// ErrorCode names the condition: the specific Draft 13 error codes this package
// acts on get their own code, and everything else reports the endpoint refusal.
func (e *Draft13CredentialEndpointError) ErrorCode() string {
	if e == nil {
		return "draft13_credential_endpoint_failed"
	}
	switch e.Code {
	case "invalid_proof":
		return "draft13_credential_invalid_proof"
	case "issuance_pending":
		return "draft13_credential_issuance_pending"
	default:
		return "draft13_credential_endpoint_failed"
	}
}

func (e *Draft13CredentialEndpointError) Error() string {
	if e == nil {
		return "draft13 credential endpoint error"
	}
	switch {
	case e.Code != "" && e.Description != "":
		return fmt.Sprintf("draft13 credential endpoint returned HTTP %d %s: %s", e.StatusCode, e.Code, e.Description)
	case e.Code != "":
		return fmt.Sprintf("draft13 credential endpoint returned HTTP %d %s", e.StatusCode, e.Code)
	default:
		return fmt.Sprintf("draft13 credential endpoint returned HTTP %d", e.StatusCode)
	}
}

// Is lets a caller write errors.Is(err, ErrDraft13InvalidProof) instead of
// comparing the issuer's error string.
func (e *Draft13CredentialEndpointError) Is(target error) bool {
	if e == nil {
		return false
	}
	switch target {
	case ErrDraft13InvalidProof:
		return e.Code == "invalid_proof"
	case ErrDraft13IssuancePending:
		return e.Code == "issuance_pending"
	default:
		return false
	}
}

// RequestOID4VCIDraft13Credential posts a Draft 13 Section 7.2 Credential
// Request. It owns the RFC 9449 Section 8 DPoP nonce retry, and reports a
// refusal as *Draft13CredentialEndpointError so the caller can read the fresh
// c_nonce a Section 7.3.2 invalid_proof response carries.
func (o *Oid4vciReceiver) RequestOID4VCIDraft13Credential(
	ctx context.Context,
	endpoint common.URIField,
	accessToken types.CredentialIssuanceAccessToken,
	request Draft13CredentialRequest,
	proofFactory types.DPoPProofFactory,
) (*Draft13CredentialResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to encode draft13 credential request: %w", err)
	}
	return o.postDraft13CredentialEndpoint(observe.WithEndpoint(ctx, observe.EndpointCredential), endpoint, accessToken, body, proofFactory)
}

// RequestOID4VCIDraft13DeferredCredential posts a Draft 13 Section 9 Deferred
// Credential Request for transactionID.
func (o *Oid4vciReceiver) RequestOID4VCIDraft13DeferredCredential(
	ctx context.Context,
	endpoint common.URIField,
	accessToken types.CredentialIssuanceAccessToken,
	transactionID string,
	proofFactory types.DPoPProofFactory,
) (*Draft13CredentialResponse, error) {
	if strings.TrimSpace(transactionID) == "" {
		return nil, fmt.Errorf("transaction_id is required for a deferred credential request")
	}
	body, err := json.Marshal(map[string]string{"transaction_id": transactionID})
	if err != nil {
		return nil, fmt.Errorf("failed to encode draft13 deferred credential request: %w", err)
	}
	return o.postDraft13CredentialEndpoint(observe.WithEndpoint(ctx, observe.EndpointDeferredCredential), endpoint, accessToken, body, proofFactory)
}

// SendOID4VCIDraft13Notification posts a Draft 13 Section 10.1 Notification
// Request. The endpoint answers 204 with no body on success.
func (o *Oid4vciReceiver) SendOID4VCIDraft13Notification(
	ctx context.Context,
	endpoint common.URIField,
	accessToken types.CredentialIssuanceAccessToken,
	notification Draft13NotificationRequest,
	proofFactory types.DPoPProofFactory,
) error {
	if strings.TrimSpace(notification.NotificationID) == "" {
		return fmt.Errorf("notification_id is required for a notification request")
	}
	body, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to encode draft13 notification request: %w", err)
	}
	_, _, err = o.doDraft13ProtectedPost(observe.WithEndpoint(ctx, observe.EndpointNotification), endpoint, accessToken, body, proofFactory)
	return err
}

func (o *Oid4vciReceiver) postDraft13CredentialEndpoint(
	ctx context.Context,
	endpoint common.URIField,
	accessToken types.CredentialIssuanceAccessToken,
	body []byte,
	proofFactory types.DPoPProofFactory,
) (*Draft13CredentialResponse, error) {
	responseBody, _, err := o.doDraft13ProtectedPost(ctx, endpoint, accessToken, body, proofFactory)
	if err != nil {
		return nil, err
	}
	return decodeDraft13CredentialResponse(responseBody)
}

// doDraft13ProtectedPost posts body to a token-protected Draft 13 endpoint and
// owns the RFC 9449 Section 8 DPoP nonce retry, exactly as the Final path does.
// It is written here rather than shared with the Final helper because the two
// versions disagree about the error body, and the retry and the error parsing
// are the same piece of code.
func (o *Oid4vciReceiver) doDraft13ProtectedPost(
	ctx context.Context,
	endpoint common.URIField,
	accessToken types.CredentialIssuanceAccessToken,
	body []byte,
	proofFactory types.DPoPProofFactory,
) ([]byte, string, error) {
	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, "", fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}
	scheme := authorizationScheme(accessToken.TokenType)
	if scheme == dpopAuthorizationScheme && proofFactory == nil {
		return nil, "", fmt.Errorf("%w: a DPoP-bound access token needs a DPoP proof factory", ErrDPoPRequired)
	}

	dpopNonce := o.dpopNonceFor(endpointURL)
	var last *Draft13CredentialEndpointError
	for attempt := 0; attempt < 2; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL.String(), bytes.NewReader(body))
		if err != nil {
			return nil, "", err
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", scheme+" "+accessToken.Token)
		if scheme == dpopAuthorizationScheme {
			proof, err := proofFactory(dpopNonce)
			if err != nil {
				return nil, "", err
			}
			request.Header.Set("DPoP", proof)
		}

		response, err := o.httpClient().Do(request)
		if err != nil {
			return nil, "", err
		}
		responseBody, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			return nil, "", readErr
		}
		if closeErr != nil {
			return nil, "", closeErr
		}
		nonce := response.Header.Get("DPoP-Nonce")
		o.rememberDPoPNonce(endpointURL, nonce)
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return responseBody, response.Header.Get("Content-Type"), nil
		}
		// An endpoint may demand a DPoP proof the wallet cannot build when the
		// access token is not DPoP-bound. Reporting that is more useful than
		// repeating a request that carried no proof.
		if scheme != dpopAuthorizationScheme && dpopChallengeRequested(nonce, response.Header.Get("WWW-Authenticate")) {
			return nil, "", ErrDPoPRequired
		}
		endpointError := newDraft13CredentialEndpointError(response.StatusCode, response.Header.Get("Content-Type"), responseBody, nonce)
		// RFC 9449 Section 8: a 400/401 carrying a DPoP-Nonce is the server's
		// challenge, and the request is retried once with that nonce. An
		// invalid_proof is not a DPoP condition and is handed to the caller,
		// which owns the Section 7.3.2 retry with the fresh c_nonce.
		if scheme == dpopAuthorizationScheme &&
			endpointError.Code != "invalid_proof" &&
			(response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized) &&
			nonce != "" {
			dpopNonce = nonce
			last = endpointError
			continue
		}
		return nil, "", endpointError
	}
	if last != nil {
		return nil, "", last
	}
	return nil, "", fmt.Errorf("DPoP nonce retry exhausted for %s", endpointURL.String())
}

// newDraft13CredentialEndpointError reads a non-2xx Draft 13 endpoint response.
// A JSON body is parsed for the Section 7.3.1 members; any other content type
// leaves Code empty and only the status is reported, because an unparsed body
// is attacker-influenced text this library does not carry further.
func newDraft13CredentialEndpointError(statusCode int, contentType string, body []byte, dpopNonce string) *Draft13CredentialEndpointError {
	endpointError := &Draft13CredentialEndpointError{
		StatusCode: statusCode,
		DPoPNonce:  strings.TrimSpace(dpopNonce),
	}
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return endpointError
	}
	var payload struct {
		Error           string `json:"error"`
		Description     string `json:"error_description"`
		CNonce          string `json:"c_nonce"`
		CNonceExpiresIn *int   `json:"c_nonce_expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return endpointError
	}
	endpointError.Code = payload.Error
	endpointError.Description = payload.Description
	endpointError.CNonce = payload.CNonce
	endpointError.CNonceExpiresIn = payload.CNonceExpiresIn
	endpointError.Interval = payload.Interval
	return endpointError
}

// decodeDraft13CredentialResponse reads a Draft 13 Section 7.3 Credential
// Response. The singular `credential` member is the Draft 13 shape; the
// `credentials` array a Final-shaped issuer may answer with is accepted when it
// holds exactly one entry, because refusing it would only turn a credential the
// wallet can read into a failure.
func decodeDraft13CredentialResponse(body []byte) (*Draft13CredentialResponse, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("credential response is empty")
	}
	var payload struct {
		Credential      any    `json:"credential"`
		Credentials     []any  `json:"credentials"`
		TransactionID   string `json:"transaction_id"`
		NotificationID  string `json:"notification_id"`
		CNonce          string `json:"c_nonce"`
		CNonceExpiresIn *int   `json:"c_nonce_expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse credential response: %w", err)
	}
	response := &Draft13CredentialResponse{
		TransactionID:   payload.TransactionID,
		NotificationID:  payload.NotificationID,
		CNonce:          payload.CNonce,
		CNonceExpiresIn: payload.CNonceExpiresIn,
		Interval:        payload.Interval,
	}
	raw := payload.Credential
	if raw == nil && len(payload.Credentials) > 0 {
		if len(payload.Credentials) != 1 {
			return nil, fmt.Errorf("credential response carries %d credentials, but a draft13 request asks for one", len(payload.Credentials))
		}
		entry := payload.Credentials[0]
		if object, ok := entry.(map[string]any); ok {
			raw = object["credential"]
		} else {
			raw = entry
		}
	}
	if raw == nil {
		return response, nil
	}
	credential, err := draft13CredentialString(raw)
	if err != nil {
		return nil, err
	}
	response.Credential = credential
	return response, nil
}

// draft13CredentialString renders the `credential` member. A string is the
// SD-JWT VC and JWT VC case; an object is the W3C Data Integrity case, which
// travels as the JSON document itself.
func draft13CredentialString(raw any) (string, error) {
	if text, ok := raw.(string); ok {
		return text, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("failed to re-encode credential: %w", err)
	}
	return string(encoded), nil
}
