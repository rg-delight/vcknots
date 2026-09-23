package oid4vp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// sendAuthorizationErrorResponse posts the OAuth 2.0 error authorization
// response (error, error_description and state) to the Verifier's
// response_uri. For response_mode=direct_post.jwt the error is encrypted into
// the "response" JWE member when the verifier's encryption metadata is usable;
// OID4VP 1.0 §8.3.1 permits plaintext when the Wallet is unable to generate an
// encrypted response. It is a no-op when the partially parsed request has no
// usable response_uri. Callers must have established that the request was
// authenticated before allowing an outbound POST (see errorResponseAllowed).
func (p *Oid4vpPresenter) sendAuthorizationErrorResponse(req *CredentialPresentationRequest, authzErr *AuthorizationRequestError) error {
	if req == nil || req.ResponseURI == "" {
		return nil
	}
	encrypted := req.ResponseMode == OAuthAuthzReqResponseModeDirectPostJWT
	if req.ResponseMode != OAuthAuthzReqResponseModeDirectPost && !encrypted {
		return nil
	}

	responseURI, err := parseResponseURI(req.ResponseURI, p.AllowHTTP)
	if err != nil {
		return err
	}

	formData := url.Values{}
	if encrypted {
		errorValues := map[string]any{"error": string(authzErr.Code)}
		if authzErr.Err != nil {
			errorValues["error_description"] = authzErr.Err.Error()
		}
		if req.State != "" {
			errorValues["state"] = req.State
		}
		metadata := req.ClientMetadata
		if payload, marshalErr := json.Marshal(errorValues); marshalErr == nil {
			if token, encErr := p.encryptAuthorizationResponseJWE(payload, metadata); encErr == nil {
				formData.Set("response", token)
			}
		}
	}

	// Plaintext error response, used for direct_post and, per §8.3.1, as the
	// fallback when an encrypted response cannot be generated.
	if formData.Get("response") == "" {
		formData.Set("error", string(authzErr.Code))
		if authzErr.Err != nil {
			formData.Set("error_description", authzErr.Err.Error())
		}
		if req.State != "" {
			formData.Set("state", req.State)
		}
	}

	if _, err := p.postAuthorizationResponse(responseURI.String(), formData); err != nil {
		return fmt.Errorf("failed to send error authorization response: %w", err)
	}

	return nil
}

// parseResponseURI parses a response_uri and enforces what OID4VP 1.0 requires
// of the Response Endpoint: an absolute URL whose scheme is https, unless http
// is explicitly allowed for testing. A relative reference or an authority-less
// URL ("https:///callback") never addresses a Verifier, so it is refused here
// rather than handed to an HTTP client that would resolve it against nothing.
//
// Every refusal wraps ErrResponseURIInvalid, so an integrator that has to tell
// a caller mistake from a Verifier or network failure branches with errors.Is
// instead of reproducing these rules ahead of the call.
func parseResponseURI(responseURI string, allowHTTP bool) (*url.URL, error) {
	if responseURI == "" {
		return nil, fmt.Errorf("%w: response_uri is required", ErrResponseURIInvalid)
	}
	parsed, err := url.Parse(responseURI)
	if err != nil {
		return nil, fmt.Errorf("%w: response_uri must be URI: %w", ErrResponseURIInvalid, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: response_uri must be an absolute URL", ErrResponseURIInvalid)
	}
	if !allowHTTP && !strings.EqualFold(parsed.Scheme, "https") {
		return nil, fmt.Errorf("%w: response_uri must use https scheme", ErrResponseURIInvalid)
	}
	return parsed, nil
}

// maxVerifierResponseBodySize bounds how much of a verifier response body the
// wallet reads; the endpoint is derived from request input.
const maxVerifierResponseBodySize = 1 << 20 // 1 MiB
// postAuthorizationResponse form-POSTs an authorization response (or error
// response) to the verifier and returns the response body on HTTP 200.
func (p *Oid4vpPresenter) postAuthorizationResponse(endpoint string, formData url.Values) ([]byte, error) {
	// A JWE travels in the "response" member (OpenID4VP 1.0 Section 8.3); the
	// form itself looks the same either way, so the fact is stated for an
	// observer rather than left to be inferred from the wire.
	encrypted := formData.Get("response") != ""
	resp, err := p.postResponseForm(endpoint, formData, encrypted)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxVerifierResponseBodySize))
	if resp.StatusCode != http.StatusOK {
		// The response body is controlled by the Verifier and may echo state or
		// secrets; retain only the OAuth error code.
		return nil, &VerifierResponseError{
			StatusCode: resp.StatusCode,
			OAuthError: oauthErrorCodeFromResponseBody(body),
		}
	}
	if readErr != nil {
		return nil, fmt.Errorf("failed to read verifier response: %w", readErr)
	}
	return body, nil
}

// postResponseForm sends one form to the verifier's Response Endpoint, labelled
// for an observe.Transport with the endpoint role and whether it carries an
// encrypted Authorization Response.
func (p *Oid4vpPresenter) postResponseForm(endpoint string, formData url.Values, encrypted bool) (*http.Response, error) {
	ctx := observe.WithResponseEncryption(observe.WithEndpoint(context.Background(), observe.EndpointResponse), encrypted)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return p.httpClient().Do(request)
}

// Present sends the presentation to the verifier.
// The vp_token is a JSON object keyed by the DCQL Credential Query id, as
// defined in OID4VP 1.0 Section 8.1:
// {"<credential query id>": ["<presentation>"]}
func (p *Oid4vpPresenter) Present(protocol types.SupportedPresentationProtocol, endpoint url.URL, serializedPresentation []byte, request *types.PresentationRequest) (string, error) {
	if request == nil || request.CredentialQueryID == "" {
		return "", fmt.Errorf("credential query id is required to build vp_token")
	}
	return p.PresentDCQL(protocol, endpoint, map[string][]string{
		request.CredentialQueryID: {string(serializedPresentation)},
	}, request)
}

// PresentDCQL sends one authorization response containing all selected DCQL
// queries. The existing Present API remains a single-query convenience wrapper.
func (p *Oid4vpPresenter) PresentDCQL(protocol types.SupportedPresentationProtocol, endpoint url.URL, vpToken map[string][]string, request *types.PresentationRequest) (string, error) {
	if protocol != types.Oid4vp {
		return "", fmt.Errorf("plugin type mismatch")
	}
	// A nil vp_token is a caller mistake: json.Marshal would send the JSON
	// literal null, which is not the object OID4VP 1.0 §8.1 defines. An empty
	// non-nil map is the answer to a request whose optional credential_sets the
	// holder declined for every query (OID4VP 1.0 §6.4.2) and must be sent as
	// the empty object {}.
	if request == nil || vpToken == nil {
		return "", fmt.Errorf("presentation request and vp_token are required")
	}
	for id, tokens := range vpToken {
		if id == "" || len(tokens) == 0 {
			return "", fmt.Errorf("vp_token query id and presentations must not be empty")
		}
		for _, token := range tokens {
			if token == "" {
				return "", fmt.Errorf("vp_token presentation must not be empty")
			}
		}
	}
	vpTokenJSON, err := json.Marshal(vpToken)
	if err != nil {
		return "", fmt.Errorf("failed to marshal vp_token: %w", err)
	}

	// OID4VP 1.0 §8.3: a direct_post.jwt request carries the verifier's
	// response-encryption metadata (client_metadata.jwks and/or
	// encrypted_response_enc_values_supported), while a direct_post request
	// does not. When encryption is requested the response MUST be encrypted;
	// there is no plaintext fallback.
	verifierMetadata, _ := request.ClientMetadata.(*VerifierMetadata)
	var encryptResponse bool
	switch request.ResponseMode {
	case string(OAuthAuthzReqResponseModeDirectPostJWT):
		// The response mode is authoritative: direct_post.jwt is never
		// answered in plaintext, even when the verifier omitted its metadata.
		encryptResponse = true
	case string(OAuthAuthzReqResponseModeDirectPost):
		encryptResponse = false
	case "":
		encryptResponse = verifierEncryptionRequested(verifierMetadata)
	default:
		return "", fmt.Errorf("response_mode %q is not supported by PresentDCQL", request.ResponseMode)
	}

	// OID4VP direct_post requires application/x-www-form-urlencoded
	formData := url.Values{}

	if encryptResponse {
		// Encrypted response: the JWE is sent as the "response" parameter.
		jarmToken, err := p.createJARMResponse(vpTokenJSON, request, verifierMetadata)
		if err != nil {
			return "", fmt.Errorf("failed to create encrypted authorization response: %w", err)
		}
		formData.Set("response", jarmToken)
	} else {
		// Standard response: Send the vp_token JSON object directly
		formData.Set("vp_token", string(vpTokenJSON))

		// Add state if present in the original request
		if request.State != "" {
			formData.Set("state", request.State)
		}
	}

	respBody, err := p.postAuthorizationResponse(endpoint.String(), formData)
	if err != nil {
		return "", fmt.Errorf("failed to send presentation to verifier: %w", err)
	}
	if len(respBody) == 0 {
		return "", nil
	}
	var verifierResponse struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal(respBody, &verifierResponse); err != nil {
		return "", nil
	}

	return verifierResponse.RedirectURI, nil
}
