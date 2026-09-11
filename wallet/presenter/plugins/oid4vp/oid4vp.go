package oid4vp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

type Oid4vpPresenter struct {
	HTTPClient *http.Client
	// AllowHTTP permits HTTP response endpoints for a local test verifier.
	AllowHTTP           bool
	X509TrustChainRoots *x509.CertPool
	// RequestObjectValidation selects explicit trust, time and signing policy
	// for Final. X509TrustChainRoots remains available for existing consumers.
	RequestObjectValidation *RequestObjectValidationOptions
	// InsecureSkipX509Verify skips certificate verification for testing purposes.
	// WARNING: This should NEVER be set to true in production environments.
	// This is only for conformance testing with self-signed or non-standard certificates.
	InsecureSkipX509Verify bool
}

func (p *Oid4vpPresenter) httpClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// ParsePresentationRequest parses the presentation request URI and returns a CredentialPresentationRequest,
// following the flow defined in the OID4VP specification and RFC9101 (OAuth 2.0 with JAR).
//
// Verifier may provide an Authorization Request using either of three options:
// 1. request_uri (preferred): A URI that points to a JWT-encoded Authorization Request.
// 2. request: A JWT-encoded Authorization Request directly in the query parameter.
// 3. Query parameters: Individual parameters in the query string.
//
// This function detect which option is used and passes that to the proper handlers to obtain the CredentialPresentationRequest.
func (p *Oid4vpPresenter) ParsePresentationRequest(uriString string) (*CredentialPresentationRequest, error) {
	return p.parsePresentationRequest(uriString, false)
}

// ParseDraft24PresentationRequest accepts the existing Draft24 Presentation Exchange and DCQL request forms.
// New Final integrations must use ParsePresentationRequest.
func (p *Oid4vpPresenter) ParseDraft24PresentationRequest(uriString string) (*CredentialPresentationRequest, error) {
	return p.parsePresentationRequest(uriString, true)
}

func (p *Oid4vpPresenter) parsePresentationRequest(uriString string, draft24 bool) (*CredentialPresentationRequest, error) {
	parsedURL, err := url.Parse(uriString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}
	queryParams := parsedURL.Query()
	// Reject malformed outer identifiers before dereferencing request_uri.
	if clientID := strings.TrimSpace(queryParams.Get("client_id")); clientID != "" {
		if _, err := parseOID4VPClientID(clientID); err != nil {
			return nil, fmt.Errorf("invalid client_id in initial request: %w", err)
		}
	}

	builder := NewRequestBuilder()
	builder.draft24 = draft24
	builder.httpClient = p.httpClient()
	builder.allowHTTP = p.AllowHTTP
	builder.x509TrustChainRoots = p.X509TrustChainRoots
	builder.insecureSkipX509Verify = p.InsecureSkipX509Verify
	builder.expectedClientID = strings.TrimSpace(queryParams.Get("client_id"))
	if p.RequestObjectValidation != nil {
		builder.WithRequestObjectValidation(*p.RequestObjectValidation)
	}

	// Request Object by Reference
	if requestURI := queryParams.Get("request_uri"); requestURI != "" {
		method := RequestURIMethodGET // Default to GET if not specified
		if m := queryParams.Get("request_uri_method"); m != "" {
			switch strings.ToLower(m) {
			case "get":
				method = RequestURIMethodGET
			case "post":
				method = RequestURIMethodPOST
			default:
				return nil, fmt.Errorf("unsupported request_uri_method: %s", m)
			}
		}
		builder = builder.WithRequestObjectURI(requestURI, method)
	} else if requestObj := queryParams.Get("request"); requestObj != "" {
		builder = builder.WithRequestObject(requestObj)
	} else {
		builder = builder.WithQueryParams(queryParams)
	}

	req, err := builder.Build()
	if err != nil {
		// OID4VP: when the Authorization Request is rejected with an OAuth
		// error code and response_mode=direct_post, deliver the error
		// authorization response to the Verifier's response_uri. Requests
		// received as Request Objects are excluded: their validation fails
		// before the signature is verified, so the response_uri is not yet
		// trustworthy (see requestBuilder.errorResponseAllowed).
		var authzErr *AuthorizationRequestError
		if errors.As(err, &authzErr) && builder.errorResponseAllowed {
			if sendErr := p.sendAuthorizationErrorResponse(builder.req, authzErr); sendErr != nil {
				return nil, fmt.Errorf("failed to build CredentialPresentationRequest: %w (also failed to send error authorization response: %v)", err, sendErr)
			}
		}
		return nil, fmt.Errorf("failed to build CredentialPresentationRequest: %w", err)
	}

	return req, nil
}

// sendAuthorizationErrorResponse posts the OAuth 2.0 error authorization
// response (error, error_description and state) to the Verifier's
// response_uri when response_mode=direct_post. It is a no-op when the
// partially parsed request has no usable direct_post response_uri.
func (p *Oid4vpPresenter) sendAuthorizationErrorResponse(req *CredentialPresentationRequest, authzErr *AuthorizationRequestError) error {
	if req == nil || req.ResponseMode != OAuthAuthzReqResponseModeDirectPost || req.ResponseURI == "" {
		return nil
	}

	responseURI, err := parseResponseURI(req.ResponseURI, p.AllowHTTP)
	if err != nil {
		return err
	}

	formData := url.Values{}
	formData.Set("error", string(authzErr.Code))
	if authzErr.Err != nil {
		formData.Set("error_description", authzErr.Err.Error())
	}
	if req.State != "" {
		formData.Set("state", req.State)
	}

	if _, err := p.postAuthorizationResponse(responseURI.String(), formData); err != nil {
		return fmt.Errorf("failed to send error authorization response: %w", err)
	}

	return nil
}

// parseResponseURI parses a response_uri and enforces the https scheme unless
// http is explicitly allowed for testing.
func parseResponseURI(responseURI string, allowHTTP bool) (*url.URL, error) {
	if responseURI == "" {
		return nil, fmt.Errorf("response_uri is required")
	}
	parsed, err := url.Parse(responseURI)
	if err != nil {
		return nil, fmt.Errorf("response_uri must be URI: %w", err)
	}
	if !allowHTTP && !strings.EqualFold(parsed.Scheme, "https") {
		return nil, fmt.Errorf("response_uri must use https scheme")
	}
	return parsed, nil
}

// maxVerifierResponseBodySize bounds how much of a verifier response body the
// wallet reads; the endpoint is derived from request input.
const maxVerifierResponseBodySize = 1 << 20 // 1 MiB

// postAuthorizationResponse form-POSTs an authorization response (or error
// response) to the verifier and returns the response body on HTTP 200.
func (p *Oid4vpPresenter) postAuthorizationResponse(endpoint string, formData url.Values) ([]byte, error) {
	client := p.httpClient()
	resp, err := client.Post(endpoint, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxVerifierResponseBodySize))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verifier returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
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
	if request == nil || len(vpToken) == 0 {
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

	// Check if JARM (JWT-Secured Authorization Response Mode) is required
	var useJARM bool
	var encryptionAlg, encryptionEnc string
	var verifierJWKS *jose.JSONWebKeySet

	if request.ClientMetadata != nil {
		if metadata, ok := request.ClientMetadata.(*VerifierMetadata); ok {
			if metadata.AuthorizationEncryptedResponseAlg != "" {
				useJARM = true
				encryptionAlg = metadata.AuthorizationEncryptedResponseAlg
				encryptionEnc = metadata.AuthorizationEncryptedResponseEnc
				verifierJWKS = &metadata.Jwks
			}
		}
	}

	// OID4VP direct_post requires application/x-www-form-urlencoded
	formData := url.Values{}

	if useJARM {
		// JARM: Create JWT with response parameters, encrypt it, and send as "response" parameter
		jarmToken, err := p.createJARMResponse(vpTokenJSON, request, encryptionAlg, encryptionEnc, verifierJWKS)
		if err != nil {
			return "", fmt.Errorf("failed to create JARM response: %w", err)
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

// CreateEncryptedAuthorizationResponse creates an OID4VP Final direct_post.jwt
// authorization response JWE. The authzResponse map is the JSON object that the
// verifier receives after decrypting the form field named "response".
func (p *Oid4vpPresenter) CreateEncryptedAuthorizationResponse(authzResponse map[string]any, metadata *VerifierMetadata) (string, error) {
	if metadata == nil {
		return "", fmt.Errorf("verifier metadata is required for encrypted authorization response")
	}

	payloadBytes, err := json.Marshal(authzResponse)
	if err != nil {
		return "", fmt.Errorf("failed to marshal authorization response: %w", err)
	}

	encryptionKey, err := selectVerifierEncryptionKey(&metadata.Jwks)
	if err != nil {
		return "", err
	}

	alg := encryptionKey.Algorithm
	if alg == "" {
		alg = metadata.AuthorizationEncryptedResponseAlg
	}
	if alg == "" {
		alg = "ECDH-ES"
	}

	enc := ""
	if len(metadata.EncryptedResponseEncValuesSupported) > 0 {
		enc = metadata.EncryptedResponseEncValuesSupported[0]
	}
	if enc == "" {
		enc = metadata.AuthorizationEncryptedResponseEnc
	}
	if enc == "" {
		enc = "A128GCM"
	}

	keyAlg, err := parseJWEKeyAlgorithm(alg)
	if err != nil {
		return "", err
	}
	contentEnc, err := parseJWEContentEncryption(enc)
	if err != nil {
		return "", err
	}

	options := (&jose.EncrypterOptions{}).WithContentType("json")
	encrypter, err := jose.NewEncrypter(
		contentEnc,
		jose.Recipient{
			Algorithm: keyAlg,
			Key:       encryptionKey.Key,
			KeyID:     encryptionKey.KeyID,
		},
		options,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(payloadBytes)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt authorization response: %w", err)
	}

	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize authorization response JWE: %w", err)
	}

	return serialized, nil
}

// SubmitEncryptedAuthorizationResponse encrypts an OID4VP Final authorization
// response and submits it to the verifier response_uri using the direct_post.jwt
// form field named "response". It returns the verifier response body so callers
// can perform browser-driver follow-up such as opening a returned redirect URI.
func (p *Oid4vpPresenter) SubmitEncryptedAuthorizationResponse(endpoint url.URL, authzResponse map[string]any, metadata *VerifierMetadata) (string, error) {
	encryptedResponse, err := p.CreateEncryptedAuthorizationResponse(authzResponse, metadata)
	if err != nil {
		return "", err
	}

	formData := url.Values{"response": []string{encryptedResponse}}
	resp, err := p.httpClient().Post(endpoint.String(), "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to submit encrypted authorization response: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read authorization response submission body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("verifier returned non-2xx status: %d, body: %s", resp.StatusCode, string(body))
	}
	return string(body), nil
}

// createJARMResponse creates a JWT-Secured Authorization Response (JARM)
func (p *Oid4vpPresenter) createJARMResponse(vpTokenJSON []byte, request *types.PresentationRequest, encAlg, encEnc string, verifierJWKS *jose.JSONWebKeySet) (string, error) {
	// Create the response payload; vp_token is embedded as a JSON object.
	payload := map[string]interface{}{
		"vp_token": json.RawMessage(vpTokenJSON),
	}

	// Add state if present
	if request != nil && request.State != "" {
		payload["state"] = request.State
	}

	return p.encryptJARMPayload(payload, encAlg, encEnc, verifierJWKS)
}

func (p *Oid4vpPresenter) encryptJARMPayload(payload map[string]interface{}, encAlg, encEnc string, verifierJWKS *jose.JSONWebKeySet) (string, error) {
	// Marshal payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JARM payload: %w", err)
	}

	encryptionKey, err := selectVerifierEncryptionKey(verifierJWKS)
	if err != nil {
		return "", err
	}

	keyAlg, err := parseJWEKeyAlgorithm(encAlg)
	if err != nil {
		return "", err
	}
	contentEnc, err := parseJWEContentEncryption(encEnc)
	if err != nil {
		return "", err
	}

	// Create encrypter
	encrypter, err := jose.NewEncrypter(
		contentEnc,
		jose.Recipient{
			Algorithm: keyAlg,
			Key:       encryptionKey.Key,
			KeyID:     encryptionKey.KeyID,
		},
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	// Encrypt the payload
	jwe, err := encrypter.Encrypt(payloadBytes)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt JARM payload: %w", err)
	}

	// Serialize to compact form
	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWE: %w", err)
	}

	return serialized, nil
}

func selectVerifierEncryptionKey(verifierJWKS *jose.JSONWebKeySet) (*jose.JSONWebKey, error) {
	if verifierJWKS == nil || len(verifierJWKS.Keys) == 0 {
		return nil, fmt.Errorf("verifier JWKS not available for encryption")
	}

	for i := range verifierJWKS.Keys {
		key := &verifierJWKS.Keys[i]
		if key.Use == "enc" {
			return key, nil
		}
	}

	return &verifierJWKS.Keys[0], nil
}

func parseJWEKeyAlgorithm(alg string) (jose.KeyAlgorithm, error) {
	switch alg {
	case "ECDH-ES":
		return jose.ECDH_ES, nil
	case "ECDH-ES+A128KW":
		return jose.ECDH_ES_A128KW, nil
	case "ECDH-ES+A192KW":
		return jose.ECDH_ES_A192KW, nil
	case "ECDH-ES+A256KW":
		return jose.ECDH_ES_A256KW, nil
	default:
		return "", fmt.Errorf("unsupported encryption algorithm: %s", alg)
	}
}

func parseJWEContentEncryption(enc string) (jose.ContentEncryption, error) {
	switch enc {
	case "A128GCM":
		return jose.A128GCM, nil
	case "A192GCM":
		return jose.A192GCM, nil
	case "A256GCM":
		return jose.A256GCM, nil
	case "A128CBC-HS256":
		return jose.A128CBC_HS256, nil
	case "A192CBC-HS384":
		return jose.A192CBC_HS384, nil
	case "A256CBC-HS512":
		return jose.A256CBC_HS512, nil
	default:
		return "", fmt.Errorf("unsupported encryption encoding: %s", enc)
	}
}

type requestBuilder struct {
	req                     *CredentialPresentationRequest
	httpClient              *http.Client
	allowHTTP               bool
	draft24                 bool
	x509TrustChainRoots     *x509.CertPool
	insecureSkipX509Verify  bool
	requestObjectValidation *RequestObjectValidationOptions
	expectedClientID        string
	errValidation           error
	// errorResponseAllowed marks that the request parameters came from plain
	// query parameters (user-initiated URI). Validation failures on the
	// Request Object paths occur before the object's signature is verified,
	// so their response_uri is unauthenticated and must not receive an error
	// authorization response (unauthenticated outbound POST / SSRF primitive).
	errorResponseAllowed bool
}

func NewRequestBuilder() *requestBuilder {
	return &requestBuilder{
		req: &CredentialPresentationRequest{
			OAuthAuthzRequest: &OAuthAuthzRequest{},
			ClientMetadata:    &VerifierMetadata{},
		},
		x509TrustChainRoots:    nil,
		insecureSkipX509Verify: false,
	}
}

// NewDraft24RequestBuilder creates a builder for Presentation Exchange requests.
func NewDraft24RequestBuilder() *requestBuilder {
	b := NewRequestBuilder()
	b.draft24 = true
	return b
}

// WithHTTPAllowed enables HTTP response endpoints for local tests only.
func (b *requestBuilder) WithHTTPAllowed(allow bool) *requestBuilder {
	b.allowHTTP = allow
	return b
}

func (b *requestBuilder) validate() error {
	if b.errValidation != nil {
		return b.errValidation
	}

	if b.draft24 {
		if (b.req.PresentationDefinition == nil || b.req.PresentationDefinition.ID == "") && (b.req.DcqlQuery == nil || len(b.req.DcqlQuery.Credentials) == 0) {
			return newAuthorizationRequestError(InvalidRequestError, "presentation_definition or dcql_query is required for Draft24")
		}
	} else if b.req.DcqlQuery == nil || len(b.req.DcqlQuery.Credentials) == 0 {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query is required")
	}

	if b.req.ResponseType == "" {
		return fmt.Errorf("response_type is required")
	}

	if b.req.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}

	if b.req.ResponseMode != OAuthAuthzReqResponseModeDirectPost && b.req.ResponseMode != OAuthAuthzReqResponseModeDirectPostJWT && b.req.RedirectURI == "" {
		return fmt.Errorf("redirect_uri is required")
	}

	if b.req.Nonce == "" {
		return fmt.Errorf("nonce is required")
	}

	if b.req.ResponseMode == OAuthAuthzReqResponseModeDirectPost || b.req.ResponseMode == OAuthAuthzReqResponseModeDirectPostJWT {
		if _, err := parseResponseURI(b.req.ResponseURI, b.allowHTTP); err != nil {
			return err
		}
	}

	return nil
}

// validateRedirectAndResponseURIExclusivity returns an error when the
// redirect_uri and response_uri request parameters are both set. Per OID4VP
// they are mutually exclusive on the wire: response_uri is used with
// response_mode=direct_post (and its JWT variant), redirect_uri otherwise.
func validateRedirectAndResponseURIExclusivity(redirectURIFromParam, responseURIFromParam string) error {
	if redirectURIFromParam != "" && responseURIFromParam != "" {
		return fmt.Errorf("redirect_uri and response_uri must not both be present in the same request")
	}
	return nil
}

// setParamsWithInterfaceMap sets the CredentialPresentationRequest fields from a map of any parameters,
// tracking any missing required parameters.
// Missing required parameters are recorded in b.errValidation and set as empty strings.
func (b *requestBuilder) setParamsWithAnyMap(params map[string]any) {
	if b.errValidation != nil {
		return
	}

	// OID4VP specification: MUST ignore 'iss' claim if present in Request Object
	// Remove 'iss' claim from params to ensure it's not processed
	if _, exists := params["iss"]; exists {
		// Create a copy of params without 'iss' claim
		filteredParams := make(map[string]any)
		for k, v := range params {
			if k != "iss" {
				filteredParams[k] = v
			}
		}
		params = filteredParams
	}

	missing := []string{}

	getParam := func(key string, required bool) string {
		if val, exists := params[key]; exists {
			if strVal, ok := val.(string); ok {
				return strVal
			}
			if !b.draft24 {
				b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%s must be a string", key)
				return ""
			}
			// Convert non-string values to string representation if possible
			return fmt.Sprintf("%v", val)
		}

		if required {
			missing = append(missing, key)
		}

		return ""
	}

	b.req.ResponseType = getParam("response_type", true)
	b.req.ClientID = strings.TrimSpace(getParam("client_id", true))
	if b.expectedClientID != "" && b.req.ClientID != b.expectedClientID {
		b.errValidation = fmt.Errorf("outer client_id does not match request object client_id: %s != %s", b.expectedClientID, b.req.ClientID)
		return
	}

	redirectURIFromParam := getParam("redirect_uri", false) // redirect_uri may be emitted
	redirectURIFromClientID := ""
	if cid := b.req.ClientID; cid != "" {
		if parsedCID, err := parseOID4VPClientID(cid); err == nil {
			switch parsedCID.prefix {
			case OID4VPClientIDPrefixRedirectURI:
				redirectURIFromClientID = parsedCID.original
			case OID4VPClientIDPrefixX509SanDNS:
				if b.draft24 {
					redirectURIFromClientID = parsedCID.original
				}
			case OID4VPClientIDPrefixX509Hash:
				// x509_hash binds the request object to an x5c certificate hash,
				// so it does not derive a redirect URI from client_id.
			default: // unimplemented: other client_id prefixes
				b.errValidation = fmt.Errorf("unsupported client_id prefix: %s", parsedCID.prefix)
			}
		} else {
			b.errValidation = fmt.Errorf("invalid client_id: %w", err)
			return
		}
	}

	if redirectURIFromParam != "" && redirectURIFromClientID != "" && redirectURIFromParam != redirectURIFromClientID {
		b.errValidation = fmt.Errorf("redirect_uri mismatch between parameter and one derived from client_id")
		return
	}

	b.req.RedirectURI = redirectURIFromClientID
	if !b.draft24 && redirectURIFromParam != "" {
		b.req.RedirectURI = redirectURIFromParam
	}
	b.req.State = getParam("state", false)
	b.req.Nonce = getParam("nonce", true)
	if b.draft24 {
		b.req.Scope = getParam("scope", false)
	}

	b.req.ResponseMode = OAuthAuthzReqResponseMode(getParam("response_mode", true))

	responseURIFromParam := getParam("response_uri", b.req.ResponseMode == OAuthAuthzReqResponseModeDirectPost || b.req.ResponseMode == OAuthAuthzReqResponseModeDirectPostJWT)

	if err := validateRedirectAndResponseURIExclusivity(redirectURIFromParam, responseURIFromParam); err != nil {
		b.errValidation = err
		return
	}

	b.req.ResponseURI = responseURIFromParam

	if b.draft24 {
		raw, exists := params["presentation_definition"]
		if exists {
			var data []byte
			var err error
			if value, ok := raw.(string); ok {
				data = []byte(value)
			} else {
				data, err = json.Marshal(raw)
			}
			var definition PresentationDefinition
			if err == nil {
				err = json.Unmarshal(data, &definition)
			}
			if err != nil {
				b.errValidation = fmt.Errorf("invalid presentation_definition: %w", err)
				return
			}
			b.req.PresentationDefinition = &definition
		}
	} else {
		// Final uses DCQL. Keep Presentation Exchange behind the explicit Draft24 API.
		for _, unsupported := range []string{"presentation_definition", "presentation_definition_uri", "presentation_submission"} {
			if _, exists := params[unsupported]; exists {
				b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%s is not supported; use dcql_query instead", unsupported)
				return
			}
		}
	}

	// Requesting Credentials via the scope parameter is not supported by this wallet.
	if scope, exists := params["scope"]; exists && !b.draft24 {
		if scopeStr, ok := scope.(string); !ok || scopeStr != "" {
			b.errValidation = newAuthorizationRequestError(InvalidScopeError, "scope parameter is not supported; use dcql_query instead")
			return
		}
	}

	if rawDcqlQuery, exists := params["dcql_query"]; exists {
		parseQuery := parseDcqlQuery
		if b.draft24 {
			parseQuery = parseDraft24DcqlQuery
		}
		dcqlQuery, err := parseQuery(rawDcqlQuery)
		if err != nil {
			b.errValidation = err
			return
		}
		b.req.DcqlQuery = dcqlQuery
	} else if !b.draft24 {
		missing = append(missing, "dcql_query")
	}

	if cm, exists := params["client_metadata"]; exists && cm != nil {
		var clientMeta VerifierMetadata
		if cmMap, ok := cm.(map[string]any); ok {
			// Convert map to JSON and then unmarshal to struct
			jsonBytes, err := json.Marshal(cmMap)
			if err != nil {
				b.errValidation = fmt.Errorf("failed to marshal client_metadata: %w", err)
				return
			}
			if err := json.Unmarshal(jsonBytes, &clientMeta); err != nil {
				b.errValidation = fmt.Errorf("invalid client_metadata: %w", err)
				return
			}
		} else if cmStr, ok := cm.(string); ok {
			// Handle string format
			if err := json.Unmarshal([]byte(cmStr), &clientMeta); err != nil {
				b.errValidation = fmt.Errorf("invalid client_metadata: %w", err)
				return
			}
		} else {
			b.errValidation = fmt.Errorf("client_metadata must be a string or map")
			return
		}
		b.req.ClientMetadata = &clientMeta
	}

	if len(missing) > 0 {
		b.errValidation = newAuthorizationRequestError(InvalidRequestError, "missing required parameters: %s", strings.Join(missing, ", "))
	}

	if td, exists := params["transaction_data"]; exists && td != nil {
		switch v := td.(type) {
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					b.req.TransactionData = append(b.req.TransactionData, str)
				}
			}
		case []string:
			b.req.TransactionData = v
		}
	}

	b.req.TransactionDataHashesAlg = getParam("transaction_data_hashes_alg", false)
}

// WithQueryParams populates the CredentialPresentationRequest fields from URL query parameters.
func (b *requestBuilder) WithQueryParams(params map[string][]string) *requestBuilder {
	if b.errValidation != nil {
		return b
	}

	b.errorResponseAllowed = true

	singleParams := make(map[string]any)
	for key, values := range params {
		if len(values) > 1 {
			b.errValidation = fmt.Errorf("multiple values provided for parameter: %s", key)
			return b
		}
		singleParams[key] = values[0]
	}

	b.setParamsWithAnyMap(singleParams)
	if !b.draft24 && b.errValidation == nil {
		clientID, err := parseOID4VPClientID(b.req.ClientID)
		if err == nil && (clientID.prefix == OID4VPClientIDPrefixX509Hash || clientID.prefix == OID4VPClientIDPrefixX509SanDNS) {
			b.errorResponseAllowed = false
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "X.509 client identifiers require a signed Request Object")
			return b
		}
	}

	if err := b.validate(); err != nil {
		b.errValidation = err
		return b
	}

	return b
}

// WithRequestObjectURI constructs the CredentialPresentationRequest
// with fetching the request object from the given URI using the specified method,
// and validates its claims and signature as per OID4VP and RFC9101.
//
// Per OID4VP draft 24 §5.11, when method is POST the request MUST use the
// https scheme, set Content-Type: application/x-www-form-urlencoded and
// Accept: application/oauth-authz-req+jwt. The https requirement is also
// applied to the GET method for project-wide consistency with the same
// guard in wallet/receiver/plugins/oid4vci/oid4vci.go (Issue #29).
// It can be relaxed by setting the VCKNOTS_WALLET_HTTP_ALLOWED environment
// variable for testing.
func (b *requestBuilder) WithRequestObjectURI(uri string, method RequestURIMethod) *requestBuilder {
	if b.errValidation != nil {
		return b
	}

	parsedURI, err := url.Parse(uri)
	if err != nil {
		b.errValidation = fmt.Errorf("failed to parse request_uri %q: %w", uri, err)
		return b
	}
	scheme := parsedURI.Scheme
	if strings.EqualFold(scheme, "https") {
		// HTTPS is always allowed
	} else if strings.EqualFold(scheme, "http") {
		if !b.allowHTTP {
			b.errValidation = fmt.Errorf("unsupported URL scheme for request_uri: %q (https required; explicit HTTP policy required for local tests)", parsedURI.Scheme)
			return b
		}
	} else {
		b.errValidation = fmt.Errorf("unsupported URL scheme for request_uri: %q (https required; explicit HTTP policy required for local tests)", parsedURI.Scheme)
		return b
	}

	var req *http.Request

	switch method {
	case RequestURIMethodGET:
		req, err = http.NewRequest(http.MethodGet, parsedURI.String(), nil)
	case RequestURIMethodPOST:
		var body io.Reader
		if b.draft24 {
			body = strings.NewReader(url.Values{"wallet_metadata": []string{"{}"}}.Encode())
		}
		req, err = http.NewRequest(http.MethodPost, parsedURI.String(), body)
	default:
		b.errValidation = fmt.Errorf("unsupported request_uri_method: %s", method)
		return b
	}

	if err != nil {
		b.errValidation = fmt.Errorf("failed to create %s request to %s: %w", method, uri, err)
		return b
	}

	req.Header.Set("User-Agent", "")
	req.Header.Set("Accept", "application/oauth-authz-req+jwt")
	if b.draft24 {
		req.Header.Set("Accept", "application/oauth-authz-req+jwt, application/jwt, text/plain, */*")
	}
	if method == RequestURIMethodPOST {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	client := b.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		b.errValidation = fmt.Errorf("failed to send %s request to %s: %w", method, uri, err)
		return b
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b.errValidation = fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
		return b
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		b.errValidation = fmt.Errorf("failed to read response body: %w", err)
		return b
	}
	if len(body) > 1<<20 {
		b.errValidation = fmt.Errorf("request_uri response exceeds 1 MiB")
		return b
	}

	return b.WithRequestObject(string(body))
}

func parseX5CCertificatesFromJWT(obj string) ([]*x509.Certificate, error) {
	parts := strings.Split(obj, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}
	if len(header.X5C) == 0 {
		return nil, fmt.Errorf("x5c header is empty")
	}

	certificates := make([]*x509.Certificate, 0, len(header.X5C))
	for i, certB64 := range header.X5C {
		certDER, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode x5c certificate at index %d: %w", i, err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x5c certificate at index %d: %w", i, err)
		}
		certificates = append(certificates, cert)
	}

	return certificates, nil
}

func (b *requestBuilder) Build() (*CredentialPresentationRequest, error) {
	if b.errValidation != nil {
		return nil, b.errValidation
	}
	return b.req, nil
}

type OID4VPClientID struct {
	original string
	prefix   OID4VPClientIDPrefix
}

type OID4VPClientIDPrefix string

const (
	OID4VPClientIDPrefixRedirectURI         OID4VPClientIDPrefix = "redirect_uri"
	OID4VPClientIDPrefixOIDFederation       OID4VPClientIDPrefix = "openid_federation"
	OID4VPClientIDPrefixDID                 OID4VPClientIDPrefix = "decentralized_identifier"
	OID4VPClientIDPrefixVerifierAttestation OID4VPClientIDPrefix = "verifier_attestation"
	OID4VPClientIDPrefixX509SanDNS          OID4VPClientIDPrefix = "x509_san_dns"
	OID4VPClientIDPrefixX509Hash            OID4VPClientIDPrefix = "x509_hash"
	OID4VPClientIDPrefixOriginal            OID4VPClientIDPrefix = "origin"
)

// parseOID4VPClientID parses and validates the client_id according to OID4VP specification.
func parseOID4VPClientID(clientID string) (*OID4VPClientID, error) {
	// Syntax: <client_id_prefix>:<orig_client_id>

	// Trim whitespace from client_id
	clientID = strings.TrimSpace(clientID)

	parts := strings.SplitN(clientID, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid client_id format")
	}

	prefix := parts[0]
	origin := strings.TrimSpace(parts[1])

	// Detect duplicate prefix (e.g., "x509_san_dns:x509_san_dns:...")
	if strings.HasPrefix(origin, prefix+":") {
		return nil, fmt.Errorf("invalid client_id: duplicate prefix detected")
	}

	switch OID4VPClientIDPrefix(prefix) {
	case OID4VPClientIDPrefixRedirectURI,
		OID4VPClientIDPrefixOIDFederation,
		OID4VPClientIDPrefixDID,
		OID4VPClientIDPrefixVerifierAttestation,
		OID4VPClientIDPrefixX509SanDNS,
		OID4VPClientIDPrefixX509Hash:
		return &OID4VPClientID{
			original: origin,
			prefix:   OID4VPClientIDPrefix(prefix),
		}, nil
	case OID4VPClientIDPrefixOriginal:
		// The Wallet MUST NOT accept this Client Identifier Prefix in requests.
		return nil, fmt.Errorf("client_id prefix 'origin' is not allowed")
	default:
		return nil, fmt.Errorf("unsupported client_id prefix: %s", prefix)
	}
}
