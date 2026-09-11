package oid4vp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"github.com/trustknots/vcknots/wallet/profile"
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
	// Profile selects the OpenID4VP protocol policy. The zero value normalizes to
	// profile.Final, which applies no HAIP constraints. Set it to profile.HAIP to
	// enforce HAIP 1.0 on the Final path; the Draft24 entrypoints ignore it.
	Profile profile.Profile
	// WalletMetadata, when non-nil, is serialized as the wallet_metadata form
	// parameter of a Final request_uri POST (OID4VP 1.0 §5.10). When nil the
	// parameter is omitted.
	WalletMetadata map[string]any
	// RequestURINonce generates the wallet_nonce sent with a Final request_uri
	// POST. A nil value uses 32 random bytes, base64url-encoded without padding.
	RequestURINonce func() (string, error)
	// SupportedTransactionDataTypes lists the transaction_data "type" values the
	// wallet can process. A nil or empty list means the wallet supports no
	// transaction_data type, so any request carrying transaction_data is
	// rejected with invalid_transaction_data (OID4VP 1.0 §5.1, §8.4).
	SupportedTransactionDataTypes []string
}

var _ profile.Carrier = (*Oid4vpPresenter)(nil)

func (p *Oid4vpPresenter) httpClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// ProtocolProfile reports the normalized OpenID4VP profile this presenter
// enforces.
func (p *Oid4vpPresenter) ProtocolProfile() profile.Profile {
	normalized, err := p.Profile.Normalize()
	if err != nil {
		return p.Profile
	}
	return normalized
}

// SetProtocolProfile is used by the wallet root to propagate its profile to the
// default presenter plugin it constructs itself.
func (p *Oid4vpPresenter) SetProtocolProfile(value profile.Profile) {
	p.Profile = value
}

// SetSupportedTransactionDataTypes is used by the wallet root to propagate its
// supported transaction_data types to the default presenter plugin.
func (p *Oid4vpPresenter) SetSupportedTransactionDataTypes(types []string) {
	p.SupportedTransactionDataTypes = types
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
	// Normalize the profile once per parse so an unknown value fails closed
	// before any network access and every checkpoint reads a validated value.
	normalizedProfile, err := p.Profile.Normalize()
	if err != nil {
		return nil, fmt.Errorf("invalid OID4VP profile: %w", err)
	}
	if !draft24 && normalizedProfile.IsHAIP() && (p.AllowHTTP || p.InsecureSkipX509Verify) {
		// HAIP §5: the profile requires TLS verifier endpoints and verified
		// X.509 request signing; the test-only escapes must not weaken it. The
		// Draft24 entrypoints are exempt from the HAIP policy.
		return nil, newAuthorizationRequestError(InvalidRequestError, "HAIP profile does not permit AllowHTTP or InsecureSkipX509Verify")
	}

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
	builder.profile = normalizedProfile
	builder.httpClient = p.httpClient()
	builder.allowHTTP = p.AllowHTTP
	builder.x509TrustChainRoots = p.X509TrustChainRoots
	builder.insecureSkipX509Verify = p.InsecureSkipX509Verify
	builder.expectedClientID = strings.TrimSpace(queryParams.Get("client_id"))
	builder.walletMetadata = p.WalletMetadata
	builder.requestURINonce = p.RequestURINonce
	builder.supportedTransactionDataTypes = p.SupportedTransactionDataTypes
	if p.RequestObjectValidation != nil {
		builder.WithRequestObjectValidation(*p.RequestObjectValidation)
	}

	requestURI := queryParams.Get("request_uri")
	requestObj := queryParams.Get("request")
	requestURIMethod := queryParams.Get("request_uri_method")
	if !draft24 {
		// RFC 9101 §5: "If this parameter is present in the authorization
		// request, request_uri MUST NOT be present." The reciprocal sentence
		// applies to request_uri. OID4VP 1.0 §5.10.2 requires terminating.
		if requestURI != "" && requestObj != "" {
			return nil, newAuthorizationRequestError(InvalidRequestError, "request and request_uri must not both be present in the same request")
		}
	}

	// Request Object by Reference
	if requestURI != "" {
		method := RequestURIMethodGET // Default to GET if not specified
		if requestURIMethod != "" {
			if draft24 {
				switch strings.ToLower(requestURIMethod) {
				case "get":
					method = RequestURIMethodGET
				case "post":
					method = RequestURIMethodPOST
				default:
					return nil, fmt.Errorf("unsupported request_uri_method: %s", requestURIMethod)
				}
			} else {
				// OID4VP 1.0 §5.1: the two valid values are case-sensitive
				// get and post; anything else is invalid_request_uri_method
				// (OID4VP 1.0 §8.5).
				switch requestURIMethod {
				case "get":
					method = RequestURIMethodGET
				case "post":
					method = RequestURIMethodPOST
				default:
					return nil, newAuthorizationRequestError(InvalidRequestURIMethodError, "request_uri_method must be 'get' or 'post' (case-sensitive), got %q", requestURIMethod)
				}
			}
		}
		builder = builder.WithRequestObjectURI(requestURI, method)
	} else if requestObj != "" {
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

	return p.encryptAuthorizationResponseJWE(payloadBytes, metadata)
}

// encryptAuthorizationResponseJWE selects a usable verifier encryption key and
// encrypts payload as an OID4VP 1.0 §8.3 authorization response JWE. It is the
// single selection path shared by PresentDCQL and
// CreateEncryptedAuthorizationResponse so both behave identically.
func (p *Oid4vpPresenter) encryptAuthorizationResponseJWE(payloadBytes []byte, metadata *VerifierMetadata) (string, error) {
	selection, err := p.selectResponseEncryption(metadata)
	if err != nil {
		return "", err
	}

	options := (&jose.EncrypterOptions{}).WithContentType("json")
	encrypter, err := jose.NewEncrypter(
		selection.enc,
		jose.Recipient{
			Algorithm: selection.alg,
			Key:       selection.key.Key,
			KeyID:     selection.key.KeyID,
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

// responseEncryption is the selected verifier key agreement and content
// encryption for one authorization response.
type responseEncryption struct {
	key *jose.JSONWebKey
	alg jose.KeyAlgorithm
	enc jose.ContentEncryption
}

// jweContentEncryptions are the content encryption algorithms the library
// supports. HAIP permits only A128GCM and A256GCM (HAIP §5).
var (
	jweContentEncryptions = map[string]jose.ContentEncryption{
		"A128GCM":       jose.A128GCM,
		"A192GCM":       jose.A192GCM,
		"A256GCM":       jose.A256GCM,
		"A128CBC-HS256": jose.A128CBC_HS256,
		"A192CBC-HS384": jose.A192CBC_HS384,
		"A256CBC-HS512": jose.A256CBC_HS512,
	}
	haipJWEOnlyContentEncryptions = map[string]jose.ContentEncryption{
		"A128GCM": jose.A128GCM,
		"A256GCM": jose.A256GCM,
	}
)

// selectResponseEncryption applies OID4VP 1.0 §8.3 and RFC 7517 §5 key
// selection, then enforces the HAIP combination when the profile is HAIP:
// ECDH-ES with a P-256 key and A128GCM or A256GCM content encryption.
func (p *Oid4vpPresenter) selectResponseEncryption(metadata *VerifierMetadata) (*responseEncryption, error) {
	if metadata == nil {
		return nil, fmt.Errorf("verifier metadata is required for encrypted authorization response")
	}
	haip := p.Profile.IsHAIP()
	allowedEncryptions := jweContentEncryptions
	if haip {
		allowedEncryptions = haipJWEOnlyContentEncryptions
	}

	key := selectUsableVerifierEncryptionKey(&metadata.Jwks, haip, metadata.AuthorizationEncryptedResponseAlg)
	if key == nil {
		return nil, fmt.Errorf("no usable verifier encryption key in client_metadata.jwks")
	}

	// The key's own alg wins; authorization_encrypted_response_alg is retained
	// only as a compatibility fallback, then ECDH-ES is the default.
	algName := key.Algorithm
	if algName == "" {
		algName = metadata.AuthorizationEncryptedResponseAlg
	}
	if algName == "" {
		algName = "ECDH-ES"
	}
	if haip && algName != "ECDH-ES" {
		return nil, fmt.Errorf("HAIP profile requires ECDH-ES for response encryption, got %q", algName)
	}
	alg, err := parseJWEKeyAlgorithm(algName)
	if err != nil {
		return nil, err
	}

	var enc jose.ContentEncryption
	if len(metadata.EncryptedResponseEncValuesSupported) > 0 {
		for _, candidate := range metadata.EncryptedResponseEncValuesSupported {
			if value, ok := allowedEncryptions[candidate]; ok {
				enc = value
				break
			}
		}
		if enc == "" {
			// §8.3 default does not rescue an explicit list with no usable
			// value; the verifier offered only unsupported algorithms.
			return nil, fmt.Errorf("encrypted_response_enc_values_supported has no supported content encryption")
		}
	} else {
		// §8.3: absent list defaults to A128GCM.
		enc = jose.A128GCM
	}

	return &responseEncryption{key: key, alg: alg, enc: enc}, nil
}

// selectUsableVerifierEncryptionKey iterates client_metadata.jwks.keys in order
// and returns the first key usable for response encryption, skipping unusable
// keys silently (RFC 7517 §5, "ignore unusable keys").
func selectUsableVerifierEncryptionKey(set *jose.JSONWebKeySet, haip bool, legacyAlg string) *jose.JSONWebKey {
	if set == nil {
		return nil
	}
	for i := range set.Keys {
		key := &set.Keys[i]
		if usableVerifierEncryptionKey(key, haip, legacyAlg) {
			return key
		}
	}
	return nil
}

// usableVerifierEncryptionKey reports whether key supports ECDH-ES response
// encryption. use must be "enc" or empty, the key must be EC (P-256, plus
// P-384/P-521 under Final only) and alg must be present (OID4VP 1.0 §8.3:
// "The `alg` parameter MUST be present in the JWKs.") and a supported key
// agreement algorithm.
func usableVerifierEncryptionKey(key *jose.JSONWebKey, haip bool, legacyAlg string) bool {
	if key == nil || key.Key == nil {
		return false
	}
	if key.Use != "" && key.Use != "enc" {
		return false
	}
	publicKey, ok := key.Key.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	switch publicKey.Curve {
	case elliptic.P256():
	case elliptic.P384(), elliptic.P521():
		if haip {
			return false
		}
	default:
		return false
	}
	algName := key.Algorithm
	if algName == "" {
		// OID4VP 1.0 §8.3 requires alg on every JWK used for encryption. A
		// verifier that still advertises the draft-era
		// authorization_encrypted_response_alg member instead is accepted on the
		// Final profile for interoperability; HAIP keeps the strict rule.
		if haip || legacyAlg == "" {
			return false
		}
		algName = legacyAlg
	}
	if _, err := parseJWEKeyAlgorithm(algName); err != nil {
		return false
	}
	if haip && algName != "ECDH-ES" {
		return false
	}
	return true
}

// verifierEncryptionRequested reports whether client_metadata asks for an
// encrypted authorization response. In the Final flow the direct_post.jwt
// response mode is the only one that carries response-encryption metadata.
func verifierEncryptionRequested(metadata *VerifierMetadata) bool {
	if metadata == nil {
		return false
	}
	return len(metadata.Jwks.Keys) > 0 ||
		len(metadata.EncryptedResponseEncValuesSupported) > 0 ||
		metadata.AuthorizationEncryptedResponseAlg != "" ||
		metadata.AuthorizationEncryptedResponseEnc != ""
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVerifierResponseBodySize))
	if err != nil {
		return "", fmt.Errorf("failed to read authorization response submission body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("verifier returned non-2xx status: %d, body: %s", resp.StatusCode, string(body))
	}
	return string(body), nil
}

// createJARMResponse creates the encrypted JWE authorization response for a
// direct_post.jwt request, embedding vp_token and state.
func (p *Oid4vpPresenter) createJARMResponse(vpTokenJSON []byte, request *types.PresentationRequest, metadata *VerifierMetadata) (string, error) {
	// Create the response payload; vp_token is embedded as a JSON object.
	payload := map[string]interface{}{
		"vp_token": json.RawMessage(vpTokenJSON),
	}

	// Add state if present
	if request != nil && request.State != "" {
		payload["state"] = request.State
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal authorization response payload: %w", err)
	}
	return p.encryptAuthorizationResponseJWE(payloadBytes, metadata)
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
	profile                 profile.Profile
	x509TrustChainRoots     *x509.CertPool
	insecureSkipX509Verify  bool
	requestObjectValidation *RequestObjectValidationOptions
	expectedClientID        string
	walletMetadata          map[string]any
	requestURINonce         func() (string, error)
	// supportedTransactionDataTypes is copied from the presenter for the Final
	// transaction_data validation.
	supportedTransactionDataTypes []string
	// sentWalletNonce records the wallet_nonce sent with a Final request_uri
	// POST so the returned Request Object can be required to echo it
	// (OID4VP 1.0 §5.10.1). It is empty for GET and when no nonce was sent.
	sentWalletNonce string
	errValidation   error
	// requestSource records how the Authorization Request parameters arrived:
	// "query" for plain query parameters, "value" for a Request Object supplied
	// with the request= parameter, and "reference" for a Request Object fetched
	// through request_uri. HAIP §5.1 requires reference.
	requestSource string
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
		return newAuthorizationRequestError(InvalidRequestError, "response_type is required")
	}

	if !b.draft24 && b.req.ResponseType != "vp_token" {
		// OID4VP 1.0 §5.6 defines the Response Type vp_token; §8 Table 1 leaves
		// the VP Token behavior unspecified for any other value. This wallet
		// presents vp_token only and rejects the others as invalid_request.
		return newAuthorizationRequestError(InvalidRequestError, "response_type must be vp_token, got %q", b.req.ResponseType)
	}

	if b.req.ClientID == "" {
		return newAuthorizationRequestError(InvalidRequestError, "client_id is required")
	}

	// OID4VP 1.0 Appendix A.2: dc_api and dc_api.jwt return the response through
	// the platform, so no redirect_uri is required. The response endpoint is the
	// DC API, validated where the response is built.
	if b.req.ResponseMode != OAuthAuthzReqResponseModeDirectPost &&
		b.req.ResponseMode != OAuthAuthzReqResponseModeDirectPostJWT &&
		b.req.ResponseMode != OAuthAuthzReqResponseModeDCAPI &&
		b.req.ResponseMode != OAuthAuthzReqResponseModeDCAPIJWT &&
		b.req.RedirectURI == "" {
		return newAuthorizationRequestError(InvalidRequestError, "redirect_uri is required")
	}

	if b.req.Nonce == "" {
		return newAuthorizationRequestError(InvalidRequestError, "nonce is required")
	}

	if b.req.ResponseMode == OAuthAuthzReqResponseModeDirectPost || b.req.ResponseMode == OAuthAuthzReqResponseModeDirectPostJWT {
		if _, err := parseResponseURI(b.req.ResponseURI, b.allowHTTP); err != nil {
			return newAuthorizationRequestError(InvalidRequestError, "%v", err)
		}
	}

	return nil
}

// validateRedirectAndResponseURIExclusivity returns an error when the
// redirect_uri and response_uri request parameters are both set. Per OID4VP
// 1.0 §5.1/§8.2 they are mutually exclusive when response_mode is direct_post
// (or direct_post.jwt); the Wallet MUST return an invalid_request Authorization
// Response error. Callers scope this check to the direct_post modes.
func validateRedirectAndResponseURIExclusivity(redirectURIFromParam, responseURIFromParam string) error {
	if redirectURIFromParam != "" && responseURIFromParam != "" {
		return newAuthorizationRequestError(InvalidRequestError, "redirect_uri and response_uri must not both be present in the same request")
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
			case OID4VPClientIDPrefixWebOrigin:
				// The DC API effective client identifier uses the platform
				// Origin; no redirect URI is derived (OID4VP 1.0 Appendix A.2).
			case OID4VPClientIDPrefixPreRegistered:
				// OID4VP 1.0 §5.9.2: "If a `:` character is not present in the
				// Client Identifier, the Wallet MUST treat the Client Identifier
				// as referencing a pre-registered client." No Verifier
				// authentication is performed. A signed pre-registered Request
				// Object would need a caller-resolved key; that is left
				// unsupported and refused on the Request Object path.
				if b.draft24 {
					b.errValidation = fmt.Errorf("invalid client_id format")
					return
				}
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

	// OID4VP 1.0 §8.2: redirect_uri and response_uri are mutually exclusive
	// when response_mode is direct_post (or direct_post.jwt).
	if b.req.ResponseMode == OAuthAuthzReqResponseModeDirectPost || b.req.ResponseMode == OAuthAuthzReqResponseModeDirectPostJWT {
		if err := validateRedirectAndResponseURIExclusivity(redirectURIFromParam, responseURIFromParam); err != nil {
			b.errValidation = err
			return
		}
	}

	b.req.ResponseURI = responseURIFromParam

	// OID4VP 1.0 Appendix A.2: the response is returned through the DC API, so
	// response_uri and redirect_uri MUST be absent from the request. This is
	// enforced on the DC API delivery paths only; a request_uri-delivered
	// dc_api.jwt request is a different (rejected) delivery and keeps its own
	// profile error.
	if (b.requestSource == "dcapi-unsigned" || b.requestSource == "dcapi-signed") &&
		(b.req.ResponseMode == OAuthAuthzReqResponseModeDCAPI || b.req.ResponseMode == OAuthAuthzReqResponseModeDCAPIJWT) {
		if redirectURIFromParam != "" || responseURIFromParam != "" {
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "redirect_uri and response_uri must not be present with response_mode %s", b.req.ResponseMode)
			return
		}
		b.req.RedirectURI = ""
		b.req.ResponseURI = ""
	}

	if b.requestSource == "query" && !b.draft24 {
		if _, hasMethod := params["request_uri_method"]; hasMethod {
			// OID4VP 1.0 §5.1: "request_uri_method parameter MUST NOT be
			// present if a request_uri parameter is not present." This path is
			// only reached when request_uri and request are both absent.
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "request_uri_method must not be present without request_uri")
			return
		}
	}

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

	if rawDcqlQuery, exists := params["dcql_query"]; exists {
		var dcqlQuery *DcqlQuery
		var err error
		if b.draft24 {
			dcqlQuery, err = parseDraft24DcqlQuery(rawDcqlQuery)
		} else {
			// The HAIP format restriction is applied where the Final DCQL query
			// is validated (dcql.go), not by re-parsing after the fact.
			dcqlQuery, err = parseDcqlQueryWithHAIP(rawDcqlQuery, b.profile.IsHAIP())
		}
		if err != nil {
			b.errValidation = err
			return
		}
		b.req.DcqlQuery = dcqlQuery
	} else if !b.draft24 {
		missing = append(missing, "dcql_query")
	}

	if len(missing) > 0 {
		b.errValidation = newAuthorizationRequestError(InvalidRequestError, "missing required parameters: %s", strings.Join(missing, ", "))
	}

	if td, exists := params["transaction_data"]; exists && td != nil {
		if b.draft24 {
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
		} else {
			switch v := td.(type) {
			case []interface{}:
				for _, item := range v {
					str, ok := item.(string)
					if !ok {
						b.errValidation = newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data entries must be base64url strings")
						return
					}
					b.req.TransactionData = append(b.req.TransactionData, str)
				}
			case []string:
				b.req.TransactionData = v
			case string:
				// application/x-www-form-urlencoded transfers the array as a
				// JSON-serialized string.
				var entries []string
				if err := json.Unmarshal([]byte(v), &entries); err != nil {
					b.errValidation = newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data must be a JSON array of strings")
					return
				}
				b.req.TransactionData = entries
			default:
				b.errValidation = newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data must be an array of strings")
				return
			}
		}
	}

	if b.draft24 {
		b.req.TransactionDataHashesAlg = getParam("transaction_data_hashes_alg", false)
	}
	// The Final profile carries transaction_data_hashes_alg inside each
	// transaction_data object (OID4VP 1.0 Appendix B.3.3.1); it is resolved and
	// set by validateFinalTransactionData below. A top-level value is not
	// defined by the Final specification and is ignored.

	if !b.draft24 && b.errValidation == nil && len(b.req.TransactionData) > 0 {
		if err := b.validateFinalTransactionData(); err != nil {
			b.errValidation = err
			return
		}
	}
}

// validateFinalTransactionData enforces OID4VP 1.0 §5.1 and §8.4/§8.5 for the
// Final path: every transaction_data entry must be base64url-encoded JSON with
// a supported type and a non-empty credential_ids array referencing the DCQL
// queries. Any failure is invalid_transaction_data.
func (b *requestBuilder) validateFinalTransactionData() error {
	supported := make(map[string]bool, len(b.supportedTransactionDataTypes))
	for _, dataType := range b.supportedTransactionDataTypes {
		supported[dataType] = true
	}
	queryIDs := make(map[string]bool)
	if b.req.DcqlQuery != nil {
		for _, query := range b.req.DcqlQuery.Credentials {
			queryIDs[query.ID] = true
		}
	}
	resolvedAlg := ""
	for i, encoded := range b.req.TransactionData {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d] is not base64url-encoded JSON: %v", i, err)
		}
		var entry map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&entry); err != nil {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d] is not a JSON object: %v", i, err)
		}
		dataType, ok := entry["type"].(string)
		if !ok || dataType == "" {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].type is required and must be a string", i)
		}
		if !supported[dataType] {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].type %q is not supported", i, dataType)
		}
		credentialIDs, ok := entry["credential_ids"].([]any)
		if !ok || len(credentialIDs) == 0 {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].credential_ids must be a non-empty array", i)
		}
		for _, rawID := range credentialIDs {
			id, ok := rawID.(string)
			if !ok || !queryIDs[id] {
				return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].credential_ids references an unknown credential query", i)
			}
		}
		// OID4VP 1.0 Appendix B.3.3.1 places transaction_data_hashes_alg in the
		// transaction_data object alongside type and credential_ids, not at the
		// Authorization Request top level. The Wallet picks the first algorithm
		// it supports from each object's array, defaulting to sha-256.
		entryAlg, err := selectTransactionDataHashesAlg(i, entry)
		if err != nil {
			return err
		}
		if resolvedAlg == "" {
			resolvedAlg = entryAlg
		} else if resolvedAlg != entryAlg {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data objects request conflicting transaction_data_hashes_alg values")
		}
	}
	b.req.TransactionDataHashesAlg = resolvedAlg
	return nil
}

// selectTransactionDataHashesAlg returns the first hash algorithm supported by
// this wallet from one transaction_data object's transaction_data_hashes_alg
// array, or sha-256 when the array is absent (OID4VP 1.0 Appendix B.3.3.1).
func selectTransactionDataHashesAlg(index int, entry map[string]any) (string, error) {
	rawAlg, exists := entry["transaction_data_hashes_alg"]
	if !exists || rawAlg == nil {
		return "sha-256", nil
	}
	algs, ok := rawAlg.([]any)
	if !ok || len(algs) == 0 {
		return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].transaction_data_hashes_alg must be a non-empty array of strings", index)
	}
	for _, rawName := range algs {
		name, ok := rawName.(string)
		if !ok || name == "" {
			return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].transaction_data_hashes_alg must contain only non-empty strings", index)
		}
		switch strings.ToLower(name) {
		case "sha-256", "sha-384", "sha-512":
			return strings.ToLower(name), nil
		}
	}
	return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].transaction_data_hashes_alg has no supported hash algorithm", index)
}

// WithQueryParams populates the CredentialPresentationRequest fields from URL query parameters.
func (b *requestBuilder) WithQueryParams(params map[string][]string) *requestBuilder {
	if b.errValidation != nil {
		return b
	}

	b.errorResponseAllowed = true
	b.requestSource = "query"

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
		formData := url.Values{}
		if b.draft24 {
			formData.Set("wallet_metadata", "{}")
		} else {
			// OID4VP 1.0 §5.10: the Final POST always carries a fresh
			// wallet_nonce and includes wallet_metadata only when the Wallet has
			// metadata to convey.
			nonce, nonceErr := b.newRequestURINonce()
			if nonceErr != nil {
				b.errValidation = fmt.Errorf("failed to generate wallet_nonce: %w", nonceErr)
				return b
			}
			b.sentWalletNonce = nonce
			formData.Set("wallet_nonce", nonce)
			if b.walletMetadata != nil {
				metadataJSON, marshalErr := json.Marshal(b.walletMetadata)
				if marshalErr != nil {
					b.errValidation = fmt.Errorf("failed to marshal wallet_metadata: %w", marshalErr)
					return b
				}
				formData.Set("wallet_metadata", string(metadataJSON))
			}
		}
		req, err = http.NewRequest(http.MethodPost, parsedURI.String(), strings.NewReader(formData.Encode()))
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

	b.WithRequestObject(string(body))
	// The Request Object arrived by reference; HAIP §5.1 distinguishes this from
	// a Request Object supplied by value in the request= parameter.
	b.requestSource = "reference"
	return b
}

// newRequestURINonce returns the wallet_nonce for a Final request_uri POST. It
// delegates to the presenter-supplied generator when present and otherwise
// generates 32 cryptographically random bytes, base64url-encoded without
// padding (OID4VP 1.0 §5.10).
func (b *requestBuilder) newRequestURINonce() (string, error) {
	if b.requestURINonce != nil {
		return b.requestURINonce()
	}
	return defaultRequestURINonce()
}

func defaultRequestURINonce() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
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

// AuthorityKeyIdentifiersFromCredential returns the base64url-encoded Authority
// Key Identifiers (RFC 5280 Section 4.2.1.1) of the certificates in the issuer
// JWT header x5c chain of an SD-JWT VC (or JWT VC) wire value. It lets the
// wallet evaluate DCQL aki trusted_authorities queries (OID4VP 1.0 Section
// 6.1.1.1), which HAIP 1.0 section 5 requires.
func AuthorityKeyIdentifiersFromCredential(rawCredential string) []string {
	issuerJWT := rawCredential
	if separator := strings.IndexByte(issuerJWT, '~'); separator >= 0 {
		issuerJWT = issuerJWT[:separator]
	}
	certificates, err := parseX5CCertificatesFromJWT(issuerJWT)
	if err != nil {
		return nil
	}
	identifiers := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		if len(certificate.AuthorityKeyId) == 0 {
			continue
		}
		identifiers = append(identifiers, base64.RawURLEncoding.EncodeToString(certificate.AuthorityKeyId))
	}
	return identifiers
}

func (b *requestBuilder) Build() (*CredentialPresentationRequest, error) {
	if b.errValidation != nil {
		return nil, b.errValidation
	}
	if err := b.enforceHAIPProfile(); err != nil {
		return nil, err
	}
	return b.req, nil
}

// enforceHAIPProfile applies the HAIP 1.0 constraints that can only be checked
// once the Final Authorization Request parameters have been assembled. It is
// deliberately inert on the Draft24 path and for the Final profile.
func (b *requestBuilder) enforceHAIPProfile() error {
	// Record how this process observed the Request Object and whether the
	// caller's DeliveredByReference attestation was accepted. A caller
	// attestation lets an application that fetched the signed Request Object
	// through request_uri at admission time and re-submits the stored JWT with
	// request= satisfy HAIP §5.1 although this process cannot observe the
	// original delivery. It is scoped to the HAIP delivery check only; the
	// wallet_nonce echo stays bound to an actual request_uri POST.
	deliveryAttested := b.profile.IsHAIP() && b.requestSource == "value" &&
		b.requestObjectValidation != nil && b.requestObjectValidation.DeliveredByReference
	if b.req.RequestObjectVerification != nil {
		b.req.RequestObjectVerification.Delivery = b.requestSource
		b.req.RequestObjectVerification.DeliveryAttested = deliveryAttested
	}
	if b.draft24 || !b.profile.IsHAIP() {
		return nil
	}
	// HAIP §5.2: "The Wallet MUST support the Response Mode dc_api.jwt" and
	// "The Wallet MUST support unsigned, signed, and multi-signed requests as
	// defined in Appendices A.3.1 and A.3.2". The request_uri encryption rule
	// of §5.1 is therefore relaxed for DC API modes.
	if b.requestSource == "dcapi-unsigned" || b.requestSource == "dcapi-signed" {
		switch b.req.ResponseMode {
		case OAuthAuthzReqResponseModeDCAPI, OAuthAuthzReqResponseModeDCAPIJWT:
		default:
			return newAuthorizationRequestError(InvalidRequestError, "HAIP DC API requires response_mode dc_api or dc_api.jwt")
		}
		if b.requestSource == "dcapi-unsigned" {
			// An unsigned request has no Verifier client_id to authenticate.
			return nil
		}
		clientID, err := parseOID4VPClientID(b.req.ClientID)
		if err != nil {
			return err
		}
		if clientID.prefix != OID4VPClientIDPrefixX509Hash {
			// HAIP §5: "For signed requests, the Verifier MUST use, and the
			// Wallet MUST accept the Client Identifier Prefix x509_hash".
			return newAuthorizationRequestError(InvalidRequestError, "HAIP profile requires the x509_hash Client Identifier Prefix")
		}
		return nil
	}
	if b.requestSource != "reference" && !deliveryAttested {
		// HAIP §5.1: "Signed Authorization Requests MUST be used by utilizing
		// JAR with the request_uri parameter".
		return newAuthorizationRequestError(InvalidRequestError, "HAIP profile requires a signed Authorization Request delivered by request_uri")
	}
	switch b.req.ResponseMode {
	case OAuthAuthzReqResponseModeDirectPostJWT:
		// HAIP §5.1: response encryption MUST use direct_post.jwt.
	case OAuthAuthzReqResponseModeDCAPI, OAuthAuthzReqResponseModeDCAPIJWT:
		// DC API requests are not delivered through request_uri; they are
		// handled by ParseDCAPIRequest. Reaching this path means a
		// request_uri-delivered DC API response mode, which is rejected.
		return newAuthorizationRequestError(InvalidRequestError, "dc_api.jwt is not implemented for request_uri delivery")
	default:
		// HAIP §5.1: "Response encryption MUST be used by utilizing response
		// mode direct_post.jwt".
		return newAuthorizationRequestError(InvalidRequestError, "HAIP profile requires response_mode direct_post.jwt")
	}
	clientID, err := parseOID4VPClientID(b.req.ClientID)
	if err != nil {
		return err
	}
	if clientID.prefix != OID4VPClientIDPrefixX509Hash {
		// HAIP §5: "For signed requests, the Verifier MUST use, and the Wallet
		// MUST accept the Client Identifier Prefix x509_hash".
		return newAuthorizationRequestError(InvalidRequestError, "HAIP profile requires the x509_hash Client Identifier Prefix")
	}
	return nil
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
	// OID4VPClientIDPrefixPreRegistered is the pseudo-prefix used when the
	// client_id contains no ":" character (OID4VP 1.0 §5.9.2).
	OID4VPClientIDPrefixPreRegistered OID4VPClientIDPrefix = "pre-registered"
)

// parseOID4VPClientID parses and validates the client_id according to OID4VP specification.
func parseOID4VPClientID(clientID string) (*OID4VPClientID, error) {
	// Syntax: <client_id_prefix>:<orig_client_id>

	// Trim whitespace from client_id
	clientID = strings.TrimSpace(clientID)

	parts := strings.SplitN(clientID, ":", 2)
	if len(parts) != 2 {
		// OID4VP 1.0 §5.9.2: "If a `:` character is not present in the Client
		// Identifier, the Wallet MUST treat the Client Identifier as
		// referencing a pre-registered client."
		if clientID == "" {
			return nil, fmt.Errorf("invalid client_id format")
		}
		return &OID4VPClientID{original: clientID, prefix: OID4VPClientIDPrefixPreRegistered}, nil
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
		OID4VPClientIDPrefixX509Hash,
		OID4VPClientIDPrefixWebOrigin:
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
