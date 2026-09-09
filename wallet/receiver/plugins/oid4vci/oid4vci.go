package oid4vci

import (
	"bytes"
	"crypto/sha256"
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
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

type Oid4vciReceiver struct {
	HTTPClient *http.Client
	// AllowHTTP permits HTTP endpoints for a local test issuer. The zero value requires HTTPS.
	AllowHTTP bool
}

var _ types.OID4VCIFinalReceiver = (*Oid4vciReceiver)(nil)

type DPoPProofFactory = types.DPoPProofFactory

type OAuthClientAttestationHeadersFactory = types.OAuthClientAttestationHeadersFactory

type CredentialEndpointHTTPResponse = types.CredentialEndpointHTTPResponse

func (o *Oid4vciReceiver) httpClient() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return oid4vciHTTPClient
}

const (
	wellKnownCredentialIssuer    = "/.well-known/openid-credential-issuer"
	wellKnownAuthorizationServer = "/.well-known/oauth-authorization-server"
)

type credentialNonceResponse struct {
	CNonce *string `json:"c_nonce"`
	Nonce  *string `json:"nonce"`
}

const maxNonceResponseBodyBytes int64 = 4 << 10

var oid4vciHTTPClient = &http.Client{Timeout: 15 * time.Second}

// rejectTokenRedirect refuses to follow redirects. The token request carries the
// client_assertion in its body, and a 307 or 308 response would make the HTTP
// client replay that body against whatever origin the redirect names. Token
// endpoints do not redirect, so failing is the safe reading.
func rejectTokenRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("token endpoint redirected to %s: redirects are not followed for token requests", req.URL.Redacted())
}

// OID4VCICredentialFormatToSerializationFlavor maps OID4VCI credential format identifiers
// to wallet serialization flavors.
func OID4VCICredentialFormatToSerializationFlavor(format string) (credential.SupportedSerializationFlavor, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "jwt_vc_json", "jwt_vc", string(credential.JwtVc):
		return credential.JwtVc, nil
	case "dc+sd-jwt", string(credential.SDJwtVC):
		return credential.SDJwtVC, nil
	default:
		return "", fmt.Errorf("unsupported credential format: %q", format)
	}
}

// doRequest performs an HTTP request and unmarshals the JSON response into target.
// It handles common patterns: URL construction, status checking, body reading, and JSON parsing.
func (o *Oid4vciReceiver) doRequest(method string, endpoint common.URIField, path string, body io.Reader, target interface{}) error {
	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	if path == "/.well-known/oauth-authorization-server" {
		// Special handling for metadata discovery as per RFC 8414 §3
		// The well-known string MUST be inserted between the host component and the path component.
		// RFC 8414 §3.1 excludes the trailing slash from the AS path component.
		originalPath := strings.TrimSuffix(endpointURL.Path, "/")
		if !strings.HasPrefix(originalPath, path) {
			endpointURL.Path = path + originalPath
		}
	} else {
		// OID4VCI Draft 13 (ID1) §11.2.2, etc...
		if !strings.HasSuffix(endpointURL.Path, path) {
			endpointURL = *endpointURL.JoinPath(path)
		}
	}

	return o.doRequestURL(method, endpointURL, body, target)
}

func (o *Oid4vciReceiver) doRequestURL(method string, endpointURL url.URL, body io.Reader, target interface{}) error {
	if method != http.MethodGet && method != http.MethodPost {
		return fmt.Errorf("unsupported HTTP method: %s", method)
	}
	if method == "POST" && body == nil {
		return fmt.Errorf("POST request requires a body")
	}
	req, err := http.NewRequest(method, endpointURL.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return &metadataHTTPStatusError{statusCode: resp.StatusCode, body: string(bodyBytes)}
	}

	if len(bodyBytes) == 0 {
		return fmt.Errorf("empty response body")
	}
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	return nil
}

func (o *Oid4vciReceiver) FetchIssuerMetadata(endpoint common.URIField, receivingTypes types.SupportedReceivingTypes) (*types.CredentialIssuerMetadata, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported serialization flavor")
	}

	var finalMetadata types.CredentialIssuerMetadata
	err := o.fetchFinalIssuerMetadata(endpoint, &finalMetadata)
	if err == nil {
		return &finalMetadata, nil
	}
	// Keep the legacy discovery path only for local test issuers that explicitly
	// report the Final endpoint missing. Never retry malformed or forbidden metadata,
	// and never repeat the same URL. Each attempt decodes into a fresh value.
	endpointURL := url.URL(endpoint)
	var statusError *metadataHTTPStatusError
	if !o.AllowHTTP || !strings.EqualFold(endpointURL.Scheme, "http") ||
		strings.Trim(endpointURL.Path, "/") == "" ||
		strings.Contains(endpointURL.Path, "/.well-known/openid-credential-issuer") ||
		!errors.As(err, &statusError) || statusError.statusCode != http.StatusNotFound {
		return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
	}
	var metadata types.CredentialIssuerMetadata
	if err := o.doRequest("GET", endpoint, wellKnownCredentialIssuer, nil, &metadata); err != nil {
		return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
	}

	return &metadata, nil
}

type metadataHTTPStatusError struct {
	statusCode int
	body       string
}

func (e *metadataHTTPStatusError) Error() string {
	return fmt.Sprintf("unexpected status code: %d, body: %s", e.statusCode, e.body)
}

func (o *Oid4vciReceiver) fetchFinalIssuerMetadata(endpoint common.URIField, target interface{}) error {
	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}
	originalPath := endpointURL.Path
	if originalPath == "/" {
		originalPath = ""
	}
	if strings.HasPrefix(originalPath, "/.well-known/openid-credential-issuer") {
		return o.doRequestURL("GET", endpointURL, nil, target)
	}
	endpointURL.Path = "/.well-known/openid-credential-issuer" + originalPath
	return o.doRequestURL("GET", endpointURL, nil, target)
}

func (o *Oid4vciReceiver) FetchAuthorizationServerMetadata(endpoint common.URIField, receivingTypes types.SupportedReceivingTypes) (*types.AuthorizationServerMetadata, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}

	var metadata types.AuthorizationServerMetadata
	if err := o.doRequest("GET", endpoint, wellKnownAuthorizationServer, nil, &metadata); err != nil {
		return nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}

	return &metadata, nil
}

func (o *Oid4vciReceiver) FetchAccessToken(
	receivingTypes types.SupportedReceivingTypes,
	endpoint common.URIField,
	authzCode string,
	txCode string,
	opts ...types.TokenRequestOption,
) (*types.CredentialIssuanceAccessToken, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}
	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	formData.Set("pre-authorized_code", authzCode)
	if txCode != "" {
		formData.Set("tx_code", txCode)
	}
	requestConfig := types.NewTokenRequestConfig(opts...)
	if requestConfig.ClientAssertion != "" {
		// private_key_jwt identifies the client by client_id, and an empty one
		// would only be rejected at the authorization server, where the cause
		// is far harder to see.
		if strings.TrimSpace(requestConfig.ClientID) == "" {
			return nil, fmt.Errorf("client_id is required when a client assertion is sent")
		}
		formData.Set("client_assertion", requestConfig.ClientAssertion)
		formData.Set("client_assertion_type", types.ClientAssertionTypeJWTBearer)
	}
	// Sent for both authenticated and unauthenticated requests: client_id is
	// OPTIONAL for the pre-authorized code grant, so it is included whenever the
	// caller configured one.
	if strings.TrimSpace(requestConfig.ClientID) != "" {
		formData.Set("client_id", requestConfig.ClientID)
	}
	endpointURLString := types.ResolveTokenEndpointURL(endpoint)
	endpointURL, err := url.Parse(endpointURLString)
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint URL: %w", err)
	}

	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	// A client assertion proves possession of the registered client key, and
	// RFC 6749 section 10.8 requires client credentials never to travel in the
	// clear. VCKNOTS_WALLET_HTTP_ALLOWED exists so that the local samples can
	// talk to a development server on this machine, which is why loopback
	// stays permitted; it is not a licence to send the assertion across a
	// network unprotected.
	if requestConfig.ClientAssertion != "" &&
		!strings.EqualFold(endpointURL.Scheme, "https") &&
		!common.IsLoopbackHost(endpointURL.Hostname()) {
		return nil, fmt.Errorf(
			"refusing to send a client assertion to %q over %q: https is required for any host other than loopback",
			endpointURL.Host, endpointURL.Scheme)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpointURL.String(),
		strings.NewReader(formData.Encode()),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if requestConfig.DPoPProof != "" {
		req.Header.Set("DPoP", requestConfig.DPoPProof)
	}
	tokenClient := *o.httpClient()
	tokenClient.CheckRedirect = rejectTokenRedirect
	resp, err := tokenClient.Do(req)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if isUseDPoPNonceResponse(resp, bodyBytes) {
			return nil, types.NewDPoPNonceError(resp.Header.Get("DPoP-Nonce"), types.ErrTokenRequestFailed)
		}
		if resp.StatusCode == http.StatusBadRequest {
			if errorCode := tokenErrorCode(bodyBytes); errorCode != "" {
				return nil, fmt.Errorf(
					"token request failed: %s; status: %d; response: %s: %w",
					errorCode,
					resp.StatusCode,
					string(bodyBytes),
					types.ErrTokenRequestFailed,
				)
			}
		}
		return nil, fmt.Errorf(
			"unexpected status code: %d response: %s",
			resp.StatusCode,
			string(bodyBytes),
		)
	}

	var accessToken types.CredentialIssuanceAccessToken
	if err := json.Unmarshal(bodyBytes, &accessToken); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return &accessToken, nil

}

func (o *Oid4vciReceiver) FetchNonce(receivingTypes types.SupportedReceivingTypes, endpoint common.URIField) (*string, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}

	nonceEndpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(nonceEndpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", nonceEndpointURL.Scheme)
	}

	req, err := http.NewRequest(http.MethodPost, nonceEndpointURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxNonceResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read nonce response: %w", err)
	}

	if int64(len(bodyBytes)) > maxNonceResponseBodyBytes {
		return nil, fmt.Errorf("nonce endpoint response exceeds %d bytes", maxNonceResponseBodyBytes)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("nonce endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("nonce endpoint returned empty response")
	}

	var nonceResponse credentialNonceResponse
	if err := json.Unmarshal(bodyBytes, &nonceResponse); err != nil {
		return nil, fmt.Errorf("failed to parse nonce response: %w", err)
	}

	if nonceResponse.CNonce != nil && *nonceResponse.CNonce != "" {
		return nonceResponse.CNonce, nil
	}
	if nonceResponse.Nonce != nil && *nonceResponse.Nonce != "" {
		return nonceResponse.Nonce, nil
	}

	return nil, fmt.Errorf("nonce response does not contain c_nonce or nonce")
}

func (o *Oid4vciReceiver) PushAuthorizationRequest(endpoint common.URIField, request types.PushedAuthorizationRequest, headers types.OAuthClientAttestationHeaders) (*types.PushedAuthorizationResponse, error) {
	formData := url.Values{}
	formData.Set("response_type", request.ResponseType)
	formData.Set("client_id", request.ClientID)
	formData.Set("redirect_uri", request.RedirectURI)
	formData.Set("scope", request.Scope)
	formData.Set("state", request.State)
	formData.Set("code_challenge", request.CodeChallenge)
	formData.Set("code_challenge_method", request.CodeChallengeMethod)
	if request.IssuerState != "" {
		formData.Set("issuer_state", request.IssuerState)
	}

	var response types.PushedAuthorizationResponse
	if err := o.doFinalRequest(http.MethodPost, endpoint, strings.NewReader(formData.Encode()), "application/x-www-form-urlencoded", headersToMap(headers), &response); err != nil {
		return nil, fmt.Errorf("failed to push authorization request: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) ExchangeAuthorizationCode(endpoint common.URIField, request types.AuthorizationCodeTokenRequest, headers types.OAuthClientAttestationHeaders, dpopProof string) (*types.CredentialIssuanceAccessToken, error) {
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", request.Code)
	formData.Set("redirect_uri", request.RedirectURI)
	formData.Set("code_verifier", request.CodeVerifier)
	formData.Set("client_id", request.ClientID)

	requestHeaders := headersToMap(headers)
	if dpopProof != "" {
		requestHeaders["DPoP"] = dpopProof
	}

	var response types.CredentialIssuanceAccessToken
	if err := o.doFinalRequest(http.MethodPost, endpoint, strings.NewReader(formData.Encode()), "application/x-www-form-urlencoded", requestHeaders, &response); err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) ExchangeAuthorizationCodeWithDpopRetry(endpoint common.URIField, request types.AuthorizationCodeTokenRequest, headers types.OAuthClientAttestationHeaders, proofFactory DPoPProofFactory) (*types.CredentialIssuanceAccessToken, error) {
	return o.ExchangeAuthorizationCodeWithDpopAndAttestationRetry(endpoint, request, func() (types.OAuthClientAttestationHeaders, error) {
		return headers, nil
	}, proofFactory)
}

func (o *Oid4vciReceiver) ExchangeAuthorizationCodeWithDpopAndAttestationRetry(endpoint common.URIField, request types.AuthorizationCodeTokenRequest, headersFactory OAuthClientAttestationHeadersFactory, proofFactory DPoPProofFactory) (*types.CredentialIssuanceAccessToken, error) {
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", request.Code)
	formData.Set("redirect_uri", request.RedirectURI)
	formData.Set("code_verifier", request.CodeVerifier)
	formData.Set("client_id", request.ClientID)

	var response types.CredentialIssuanceAccessToken
	if err := o.doFormRequestWithDpopAndAttestationRetry(endpoint, strings.NewReader(formData.Encode()), headersFactory, proofFactory, &response); err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code with DPoP retry: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) FetchClientAttestationChallenge(endpoint common.URIField) (*types.ClientAttestationChallengeResponse, error) {
	var response types.ClientAttestationChallengeResponse
	if err := o.doFinalRequest(http.MethodPost, endpoint, nil, "", nil, &response); err != nil {
		return nil, fmt.Errorf("failed to fetch client attestation challenge: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) FetchNonceResponse(endpoint common.URIField) (*types.NonceResponse, error) {
	var response types.NonceResponse
	if err := o.doFinalRequest(http.MethodPost, endpoint, nil, "", nil, &response); err != nil {
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) RequestCredential(endpoint common.URIField, accessToken string, credentialRequest types.CredentialRequest, dpopProof string) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequest(endpoint, accessToken, credentialRequest, dpopProof, &response); err != nil {
		return nil, fmt.Errorf("failed to request credential: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) RequestCredentialWithDpopRetry(endpoint common.URIField, accessToken string, credentialRequest types.CredentialRequest, proofFactory DPoPProofFactory) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequestWithDpopRetry(endpoint, accessToken, credentialRequest, proofFactory, &response); err != nil {
		return nil, fmt.Errorf("failed to request credential with DPoP retry: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) PostCredentialEndpointWithDpopRetry(endpoint common.URIField, accessToken string, body []byte, contentType string, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, error) {
	responseBody, responseContentType, err := o.doBearerRequestWithDpopRetry(endpoint, accessToken, body, contentType, proofFactory)
	if err != nil {
		return nil, fmt.Errorf("failed to post credential endpoint request with DPoP retry: %w", err)
	}
	return &CredentialEndpointHTTPResponse{
		Body:        responseBody,
		ContentType: responseContentType,
	}, nil
}

func (o *Oid4vciReceiver) RequestDeferredCredential(endpoint common.URIField, accessToken string, deferredRequest types.DeferredCredentialRequest, dpopProof string) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequest(endpoint, accessToken, deferredRequest, dpopProof, &response); err != nil {
		return nil, fmt.Errorf("failed to request deferred credential: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) RequestDeferredCredentialWithDpopRetry(endpoint common.URIField, accessToken string, deferredRequest types.DeferredCredentialRequest, proofFactory DPoPProofFactory) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequestWithDpopRetry(endpoint, accessToken, deferredRequest, proofFactory, &response); err != nil {
		return nil, fmt.Errorf("failed to request deferred credential with DPoP retry: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) SendCredentialNotification(endpoint common.URIField, accessToken string, notification types.NotificationRequest, dpopProof string) error {
	return o.doBearerJSONRequest(endpoint, accessToken, notification, dpopProof, nil)
}

func (o *Oid4vciReceiver) SendCredentialNotificationWithDpopRetry(endpoint common.URIField, accessToken string, notification types.NotificationRequest, proofFactory DPoPProofFactory) error {
	return o.doBearerJSONRequestWithDpopRetry(endpoint, accessToken, notification, proofFactory, nil)
}

func (o *Oid4vciReceiver) EncodeCredentialRequest(request any, issuerMetadata *types.CredentialIssuerMetadata) ([]byte, string, error) {
	if issuerMetadata == nil || issuerMetadata.CredentialRequestEncryption == nil {
		body, err := json.Marshal(request)
		if err != nil {
			return nil, "", err
		}
		return body, "application/json", nil
	}

	encryptionKey, err := selectEncryptionKey(&issuerMetadata.CredentialRequestEncryption.Jwks)
	if err != nil {
		return nil, "", err
	}
	alg := encryptionKey.Algorithm
	if alg == "" {
		alg = firstOrDefault(issuerMetadata.CredentialRequestEncryption.AlgValuesSupported, "ECDH-ES")
	}
	enc := firstOrDefault(issuerMetadata.CredentialRequestEncryption.EncValuesSupported, "A128GCM")

	keyAlg, err := parseJWEKeyAlgorithm(alg)
	if err != nil {
		return nil, "", err
	}
	contentEnc, err := parseJWEContentEncryption(enc)
	if err != nil {
		return nil, "", err
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return nil, "", err
	}

	encrypter, err := jose.NewEncrypter(
		contentEnc,
		jose.Recipient{
			Algorithm: keyAlg,
			Key:       encryptionKey.Key,
			KeyID:     encryptionKey.KeyID,
		},
		(&jose.EncrypterOptions{}).WithContentType("json"),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create credential request encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(payload)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt credential request: %w", err)
	}
	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return nil, "", fmt.Errorf("failed to serialize credential request JWE: %w", err)
	}
	return []byte(serialized), "application/jwt", nil
}

func (o *Oid4vciReceiver) DecodeCredentialResponse(body []byte, contentType string, decryptionKey any) (*types.CredentialResponse, error) {
	payload := body
	if strings.Contains(strings.ToLower(contentType), "application/jwt") {
		if decryptionKey == nil {
			return nil, fmt.Errorf("decryption key is required for encrypted credential response")
		}
		jwe, err := jose.ParseEncrypted(string(body), supportedJWEKeyAlgorithms(), supportedJWEContentEncryptions())
		if err != nil {
			return nil, fmt.Errorf("failed to parse credential response JWE: %w", err)
		}
		payload, err = jwe.Decrypt(decryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt credential response JWE: %w", err)
		}
	}

	var response types.CredentialResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, fmt.Errorf("failed to parse credential response JSON: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) CreateDpopProof(key jose.JSONWebKey, method string, rawURL string, nonce string, accessToken string) (string, error) {
	htu, err := dpopHTU(rawURL)
	if err != nil {
		return "", err
	}

	payload := map[string]any{
		"htm": strings.ToUpper(method),
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": uuid.NewString(),
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}
	if accessToken != "" {
		ath := sha256.Sum256([]byte(accessToken))
		payload["ath"] = base64.RawURLEncoding.EncodeToString(ath[:])
	}

	token, err := signJWTWithPublicJWKHeader(key, "dpop+jwt", payload)
	if err != nil {
		return "", fmt.Errorf("failed to create DPoP proof: %w", err)
	}
	return token, nil
}

func (o *Oid4vciReceiver) CreateCredentialRequestJWTProof(key jose.JSONWebKey, audience string, nonce string) (string, error) {
	payload := map[string]any{
		"aud": audience,
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}

	token, err := signJWTWithPublicJWKHeader(key, "openid4vci-proof+jwt", payload)
	if err != nil {
		return "", fmt.Errorf("failed to create credential request JWT proof: %w", err)
	}
	return token, nil
}

func (o *Oid4vciReceiver) CreateClientAttestation(clientKey jose.JSONWebKey, attesterKey jose.JSONWebKey, attesterIssuer string, clientID string, lifetime time.Duration) (string, error) {
	if lifetime == 0 {
		lifetime = 5 * time.Minute
	}
	now := time.Now()
	clientPublicJWK := clientKey.Public()
	clientPublicJWK.Algorithm = firstOrDefault([]string{clientPublicJWK.Algorithm}, "ES256")
	clientPublicJWK.Use = firstOrDefault([]string{clientPublicJWK.Use}, "sig")
	clientPublicJWK.KeyID = firstOrDefault([]string{clientPublicJWK.KeyID}, clientKey.KeyID)

	payload := map[string]any{
		"iss": attesterIssuer,
		"sub": clientID,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
		"cnf": map[string]any{
			"jwk": clientPublicJWK,
		},
	}

	token, err := signJWT(attesterKey, "oauth-client-attestation+jwt", payload, x5cHeaders(attesterKey))
	if err != nil {
		return "", fmt.Errorf("failed to create client attestation JWT: %w", err)
	}
	return token, nil
}

func (o *Oid4vciReceiver) CreateClientAttestationPop(clientKey jose.JSONWebKey, clientID string, authorizationServerIssuer string, attestationChallenge string, lifetime time.Duration) (string, error) {
	if lifetime == 0 {
		lifetime = 5 * time.Minute
	}
	now := time.Now()
	payload := map[string]any{
		"iss": clientID,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
		"aud": authorizationServerIssuer,
		"jti": uuid.NewString(),
	}
	if attestationChallenge != "" {
		payload["challenge"] = attestationChallenge
	}

	token, err := signJWT(clientKey, "oauth-client-attestation-pop+jwt", payload, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create client attestation PoP JWT: %w", err)
	}
	return token, nil
}

func (o *Oid4vciReceiver) doBearerJSONRequest(endpoint common.URIField, accessToken string, payload any, dpopProof string, target any) error {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	headers := map[string]string{
		"Authorization": "DPoP " + accessToken,
		"DPoP":          dpopProof,
	}

	return o.doFinalRequest(http.MethodPost, endpoint, bytes.NewReader(bodyBytes), "application/json", headers, target)
}

func (o *Oid4vciReceiver) doBearerJSONRequestWithDpopRetry(endpoint common.URIField, accessToken string, payload any, proofFactory DPoPProofFactory, target any) error {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	respBody, _, err := o.doBearerRequestWithDpopRetry(endpoint, accessToken, bodyBytes, "application/json", proofFactory)
	if err != nil {
		return err
	}
	if target == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	return nil
}

func (o *Oid4vciReceiver) doBearerRequestWithDpopRetry(endpoint common.URIField, accessToken string, bodyBytes []byte, contentType string, proofFactory DPoPProofFactory) ([]byte, string, error) {
	if proofFactory == nil {
		return nil, "", fmt.Errorf("DPoP proof factory is required")
	}

	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, "", fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	var dpopNonce string
	for attempt := 0; attempt < 2; attempt++ {
		dpopProof, err := proofFactory(dpopNonce)
		if err != nil {
			return nil, "", err
		}
		req, err := http.NewRequest(http.MethodPost, endpointURL.String(), bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Accept", "application/json")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Authorization", "DPoP "+accessToken)
		req.Header.Set("DPoP", dpopProof)

		resp, err := o.httpClient().Do(req)
		if err != nil {
			return nil, "", err
		}
		respBody, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			return nil, "", readErr
		}
		if closeErr != nil {
			return nil, "", closeErr
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return respBody, resp.Header.Get("Content-Type"), nil
		}
		nonce := resp.Header.Get("DPoP-Nonce")
		if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized) && nonce != "" {
			dpopNonce = nonce
			continue
		}
		return nil, "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(respBody))
	}

	return nil, "", fmt.Errorf("DPoP nonce retry exhausted for %s", endpointURL.String())
}

func (o *Oid4vciReceiver) doFormRequestWithDpopAndAttestationRetry(endpoint common.URIField, body io.Reader, headersFactory OAuthClientAttestationHeadersFactory, proofFactory DPoPProofFactory, target any) error {
	if headersFactory == nil {
		return fmt.Errorf("OAuth client attestation headers factory is required")
	}
	return o.doFormRequestWithDpopAndHeadersRetry(endpoint, body, func() (map[string]string, error) {
		headers, err := headersFactory()
		if err != nil {
			return nil, err
		}
		return headersToMap(headers), nil
	}, proofFactory, target)
}

func (o *Oid4vciReceiver) doFormRequestWithDpopAndHeadersRetry(endpoint common.URIField, body io.Reader, headersFactory func() (map[string]string, error), proofFactory DPoPProofFactory, target any) error {
	if proofFactory == nil {
		return fmt.Errorf("DPoP proof factory is required")
	}
	if headersFactory == nil {
		return fmt.Errorf("headers factory is required")
	}

	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	var dpopNonce string
	for attempt := 0; attempt < 2; attempt++ {
		dpopProof, err := proofFactory(dpopNonce)
		if err != nil {
			return err
		}
		headers, err := headersFactory()
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodPost, endpointURL.String(), bytes.NewReader(bodyBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", dpopProof)
		for key, value := range headers {
			if value != "" {
				req.Header.Set(key, value)
			}
		}

		resp, err := o.httpClient().Do(req)
		if err != nil {
			return err
		}
		respBody, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if target == nil || len(respBody) == 0 {
				return nil
			}
			if err := json.Unmarshal(respBody, target); err != nil {
				return fmt.Errorf("failed to parse JSON: %w", err)
			}
			return nil
		}
		nonce := resp.Header.Get("DPoP-Nonce")
		if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized) && nonce != "" {
			dpopNonce = nonce
			continue
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(respBody))
	}

	return fmt.Errorf("DPoP nonce retry exhausted for %s", endpointURL.String())
}

func headersToMap(headers types.OAuthClientAttestationHeaders) map[string]string {
	result := map[string]string{}
	if headers.ClientAttestation != "" {
		result["OAuth-Client-Attestation"] = headers.ClientAttestation
	}
	if headers.ClientAttestationPop != "" {
		result["OAuth-Client-Attestation-PoP"] = headers.ClientAttestationPop
	}
	return result
}

func (o *Oid4vciReceiver) doFinalRequest(method string, endpoint common.URIField, body io.Reader, contentType string, headers map[string]string, target any) error {
	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	req, err := http.NewRequest(method, endpointURL.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for key, value := range headers {
		if value != "" {
			req.Header.Set(key, value)
		}
	}

	resp, err := o.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}
	if target == nil || len(bodyBytes) == 0 {
		return nil
	}
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	return nil
}

func selectEncryptionKey(jwks *jose.JSONWebKeySet) (*jose.JSONWebKey, error) {
	if jwks == nil || len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("encryption JWKS does not contain a key")
	}
	for i := range jwks.Keys {
		if jwks.Keys[i].Use == "enc" {
			return &jwks.Keys[i], nil
		}
	}
	return &jwks.Keys[0], nil
}

func firstOrDefault(values []string, fallback string) string {
	if len(values) > 0 && values[0] != "" {
		return values[0]
	}
	return fallback
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

func supportedJWEKeyAlgorithms() []jose.KeyAlgorithm {
	return []jose.KeyAlgorithm{jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW}
}

func supportedJWEContentEncryptions() []jose.ContentEncryption {
	return []jose.ContentEncryption{jose.A128GCM, jose.A192GCM, jose.A256GCM, jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512}
}

func dpopHTU(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse DPoP htu URL: %w", err)
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func signJWTWithPublicJWKHeader(key jose.JSONWebKey, typ string, payload map[string]any) (string, error) {
	publicJWK := key.Public()
	publicJWK.Algorithm = firstOrDefault([]string{publicJWK.Algorithm}, "ES256")
	if publicJWK.Use == "" {
		publicJWK.Use = "sig"
	}
	if publicJWK.KeyID == "" {
		publicJWK.KeyID = key.KeyID
	}
	alg := jose.SignatureAlgorithm(key.Algorithm)
	if alg == "" {
		alg = jose.ES256
	}
	options := (&jose.SignerOptions{}).
		WithType(jose.ContentType(typ)).
		WithHeader("jwk", publicJWK)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key.Key}, options)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(payload).Serialize()
}

func signJWT(key jose.JSONWebKey, typ string, payload map[string]any, extraHeaders map[string]any) (string, error) {
	alg := jose.SignatureAlgorithm(key.Algorithm)
	if alg == "" {
		alg = jose.ES256
	}

	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	if key.KeyID != "" {
		options = options.WithHeader("kid", key.KeyID)
	}
	for name, value := range extraHeaders {
		options = options.WithHeader(jose.HeaderKey(name), value)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, options)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(payload).Serialize()
}

func x5cHeaders(key jose.JSONWebKey) map[string]any {
	if len(key.Certificates) == 0 {
		return nil
	}
	values := make([]string, 0, len(key.Certificates))
	for _, cert := range key.Certificates {
		values = append(values, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	return map[string]any{"x5c": values}
}

func (o *Oid4vciReceiver) ReceiveCredential(
	receivingTypes types.SupportedReceivingTypes,
	endpoint common.URIField,
	credentialConfigurationID string,
	credentialIdentifier *string,
	accessToken types.CredentialIssuanceAccessToken,
	credentialDefinition *types.CredentialDefinition,
	jwtProof *string,
	options ...*types.CredentialRequestOptions,
) (*string, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}

	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	// Prepare credential request body
	reqBody := map[string]interface{}{}
	if credentialIdentifier != nil && *credentialIdentifier != "" {
		reqBody["credential_identifier"] = *credentialIdentifier
	} else {
		reqBody["credential_configuration_id"] = credentialConfigurationID
	}

	if jwtProof != nil {
		reqBody["proofs"] = map[string]interface{}{
			"jwt": []string{*jwtProof},
		}
	}

	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", endpointURL.String(), bytes.NewReader(reqBodyBytes))
	if err != nil {
		return nil, err
	}

	requestOptions := firstCredentialRequestOptions(options)

	// Set headers
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	tokenType := authorizationScheme(accessToken.TokenType)
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken.Token))
	if strings.EqualFold(accessToken.TokenType, "DPoP") {
		if requestOptions == nil || requestOptions.DPoPProofJWT == nil || *requestOptions.DPoPProofJWT == "" {
			return nil, fmt.Errorf("DPoP proof JWT is required for DPoP access token")
		}
		req.Header.Set("DPoP", *requestOptions.DPoPProofJWT)
	}
	req.Header.Set("Accept", "application/json")
	req.ContentLength = int64(len(reqBodyBytes))

	// Execute request
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		if isUseDPoPNonceResponse(resp, bodyBytes) {
			return nil, fmt.Errorf(
				"%w; status: %d; endpoint: %s; response: %s",
				types.NewDPoPNonceError(resp.Header.Get("DPoP-Nonce"), types.ErrUseDPoPNonce),
				resp.StatusCode,
				endpointURL.String(),
				string(bodyBytes),
			)
		}
		return nil, fmt.Errorf("failed to receive credential; status: %d; endpoint: %s; response: %s", resp.StatusCode, endpointURL.String(), string(bodyBytes))
	}

	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("credential response is empty")
	}

	// Extract credential from response
	var credentialResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &credentialResponse); err != nil {
		return nil, err
	}

	var credential interface{}

	credentialsRaw, hasCredentials := credentialResponse["credentials"]
	if hasCredentials {
		credentials, ok := credentialsRaw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("credentials response has invalid type")
		}
		if len(credentials) != 1 {
			return nil, fmt.Errorf("credentials response must contain exactly one credential, got %d", len(credentials))
		}
		credentialWrapper, ok := credentials[0].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("first credential entry has invalid format")
		}
		var found bool
		credential, found = credentialWrapper["credential"]
		if !found {
			return nil, fmt.Errorf("credential field missing in first credentials entry")
		}
	} else {
		var ok bool
		credential, ok = credentialResponse["credential"]
		if !ok {
			return nil, fmt.Errorf("no credential found in response")
		}
	}

	credentialStr, ok := credential.(string)
	if !ok {
		// If credential is not a string, marshal it back to JSON
		credentialBytes, err := json.Marshal(credential)
		if err != nil {
			return nil, err
		}
		credentialStr = string(credentialBytes)
	}

	return &credentialStr, nil
}

func firstCredentialRequestOptions(options []*types.CredentialRequestOptions) *types.CredentialRequestOptions {
	for _, option := range options {
		if option != nil {
			return option
		}
	}
	return nil
}

func authorizationScheme(tokenType string) string {
	switch {
	case strings.EqualFold(tokenType, "bearer"):
		return "Bearer"
	case strings.EqualFold(tokenType, "dpop"):
		return "DPoP"
	default:
		return cases.Title(language.English).String(strings.ToLower(tokenType))
	}
}

func tokenErrorCode(bodyBytes []byte) string {
	var errorResponse struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errorResponse); err != nil {
		return ""
	}
	return strings.TrimSpace(errorResponse.Error)
}

func isUseDPoPNonceError(bodyBytes []byte) bool {
	return tokenErrorCode(bodyBytes) == "use_dpop_nonce"
}

func isUseDPoPNonceResponse(resp *http.Response, bodyBytes []byte) bool {
	if isUseDPoPNonceError(bodyBytes) {
		return true
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "use_dpop_nonce")
}
