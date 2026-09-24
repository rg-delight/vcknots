package oid4vp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

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

// postAuthorizationResponse form-POSTs an authorization response (or error
// response) to the Verifier with the presenter's client and returns the
// response body of a 2xx answer.
func (p *Oid4vpPresenter) postAuthorizationResponse(endpoint string, formData url.Values) ([]byte, error) {
	return postAuthorizationResponse(context.Background(), p.httpClient(), endpoint, formData)
}

// postAuthorizationResponse form-POSTs to the Verifier's Response Endpoint
// without following redirects: a redirect could move the response to another
// host or to plain http. The response body is read up to
// httpfetch.DefaultBodyLimit; a non-200 status keeps only the OAuth error code,
// because the body is under the Verifier's control.
func postAuthorizationResponse(ctx context.Context, client *http.Client, endpoint string, formData url.Values) ([]byte, error) {
	// A JWE travels in the "response" member (OID4VP 1.0 §8.3).
	encrypted := formData.Get("response") != ""
	ctx = observe.WithResponseEncryption(observe.WithEndpoint(ctx, observe.EndpointResponse), encrypted)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpfetch.NoRedirect(client).Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, readErr := httpfetch.ReadLimited(resp, httpfetch.DefaultBodyLimit)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
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
