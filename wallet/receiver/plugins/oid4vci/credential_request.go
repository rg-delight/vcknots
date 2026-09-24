package oid4vci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/receiver/oid4vcisign"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

type CredentialEndpointHTTPResponse = types.CredentialEndpointHTTPResponse

type CredentialRequestBodyFactory = types.CredentialRequestBodyFactory

type credentialNonceResponse struct {
	CNonce *string `json:"c_nonce"`
	Nonce  *string `json:"nonce"`
}

const maxNonceResponseBodyBytes int64 = 4 << 10

// ErrProofAlgorithmNotSupported reports that the holder key cannot produce any
// of the algorithms the Credential Issuer lists in
// proof_signing_alg_values_supported. It is the oid4vcisign sentinel of the
// same name, so errors.Is matches either.
var ErrProofAlgorithmNotSupported = oid4vcisign.ErrProofAlgorithmNotSupported

// FetchNonce fetches a c_nonce from the Section 7 Nonce Endpoint. It is a
// types.Receiver method and carries no context; it binds its request to
// context.Background().
func (o *Oid4vciReceiver) FetchNonce(receivingTypes types.SupportedReceivingTypes, endpoint common.URIField) (*string, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}
	if _, err := o.normalizedProfile(); err != nil {
		return nil, err
	}

	response, err := o.do(observe.WithEndpoint(context.Background(), observe.EndpointNonce), exchange{
		method: http.MethodPost,
		url:    url.URL(endpoint),
		limit:  maxNonceResponseBodyBytes,
	})
	if errors.Is(err, httpfetch.ErrBodyTooLarge) {
		return nil, fmt.Errorf("nonce endpoint response exceeds %d bytes: %w", maxNonceResponseBodyBytes, err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}
	if !response.ok() {
		if code := response.statusError().oauthError; code != "" {
			return nil, fmt.Errorf("nonce endpoint returned status %d, error: %s", response.statusCode, code)
		}
		return nil, fmt.Errorf("nonce endpoint returned status %d", response.statusCode)
	}
	if len(response.body) == 0 {
		return nil, fmt.Errorf("nonce endpoint returned empty response")
	}

	var nonceResponse credentialNonceResponse
	if err := json.Unmarshal(response.body, &nonceResponse); err != nil {
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

// FetchNonceResponse performs the Section 7.1 Nonce Request and returns the
// Section 7.2 Nonce Response. Besides the c_nonce body member it surfaces the
// RFC 9449 Section 8.2 DPoP-Nonce response header, which Section 7.2 makes
// binding on the next credential request: "The Credential Issuer MAY provide a
// DPoP nonce in an HTTP header as defined in Section 8.2 of [@!RFC9449]. In this
// case, the Wallet uses the new nonce value in the DPoP proof when presenting an
// access token at the Credential Endpoint." The value is also recorded in this
// receiver's per-server nonce store, so the next DPoP proof this plugin builds
// for that server already carries it. ctx bounds the request.
func (o *Oid4vciReceiver) FetchNonceResponse(ctx context.Context, endpoint common.URIField) (*types.NonceResponse, error) {
	exchanged, err := o.do(observe.WithEndpoint(ctx, observe.EndpointNonce), exchange{method: http.MethodPost, url: url.URL(endpoint)})
	if err == nil && !exchanged.ok() {
		err = exchanged.statusError()
	}
	var response types.NonceResponse
	if err == nil && len(exchanged.body) > 0 {
		if decodeErr := json.Unmarshal(exchanged.body, &response); decodeErr != nil {
			err = fmt.Errorf("failed to parse JSON: %w", decodeErr)
		}
	}
	if err != nil {
		return nil, stageError(StageNonce, fmt.Errorf("failed to fetch nonce: %w", err))
	}
	// OpenID4VCI 1.0 §7.2: "c_nonce: REQUIRED. String containing a challenge to
	// be used when creating a proof of possession of the key." A 2xx Nonce
	// Response that omits it, or returns it empty, hands the wallet no nonce to
	// put in the proof, so it fails closed instead of proceeding without one.
	if strings.TrimSpace(response.CNonce) == "" {
		return nil, fmt.Errorf("nonce response does not contain a c_nonce: %w", types.ErrNonceResponseInvalid)
	}
	response.DPoPNonce = strings.TrimSpace(exchanged.header.Get("DPoP-Nonce"))
	return &response, nil
}

func (o *Oid4vciReceiver) postCredentialEndpointForToken(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, body []byte, contentType string, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, error) {
	response, err := o.postProtected(ctx, endpoint, accessToken, body, contentType, proofFactory, httpfetch.CredentialBodyLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to post credential endpoint request: %w", err)
	}
	return &CredentialEndpointHTTPResponse{
		Body:        response.body,
		ContentType: response.header.Get("Content-Type"),
	}, nil
}

// PostCredentialEndpointWithNonceRetryForToken posts the Credential Request (or
// Deferred Credential Request) body build returns for the current c_nonce. The
// access token is sent with the scheme its token_type names: Bearer (RFC 6750
// Section 2.1) or DPoP with a proof (RFC 9449 Section 7.1).
//
// On the Section 8.3.1.2 "invalid_nonce" error it fetches a fresh c_nonce from
// nonceEndpoint, rebuilds the body and posts once more; with a nil
// nonceEndpoint the error is returned as is. It returns the response and the
// c_nonce the accepted request was built with. ctx bounds every request.
func (o *Oid4vciReceiver) PostCredentialEndpointWithNonceRetryForToken(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, nonceEndpoint *common.URIField, initialCNonce string, build CredentialRequestBodyFactory, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, string, error) {
	return o.postCredentialEndpointWithNonceRetry(ctx, endpoint, accessToken, nonceEndpoint, initialCNonce, build, proofFactory)
}

// SendCredentialNotificationWithDpopRetryForToken sends the Section 11
// Notification Request with the access token's scheme, as
// PostCredentialEndpointWithNonceRetryForToken does. ctx bounds every request.
func (o *Oid4vciReceiver) SendCredentialNotificationWithDpopRetryForToken(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, notification types.NotificationRequest, proofFactory DPoPProofFactory) error {
	body, err := json.Marshal(notification)
	if err != nil {
		return err
	}
	_, err = o.postProtected(observe.WithEndpoint(ctx, observe.EndpointNotification), endpoint, accessToken, body, "application/json", proofFactory, httpfetch.DefaultBodyLimit)
	return err
}

func (o *Oid4vciReceiver) postCredentialEndpointWithNonceRetry(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, nonceEndpoint *common.URIField, initialCNonce string, build CredentialRequestBodyFactory, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, string, error) {
	if build == nil {
		return nil, initialCNonce, fmt.Errorf("credential request body factory is required")
	}

	body, contentType, err := build(initialCNonce)
	if err != nil {
		return nil, initialCNonce, err
	}

	response, err := o.postCredentialEndpointForToken(ctx, endpoint, accessToken, body, contentType, proofFactory)
	if err == nil {
		return response, initialCNonce, nil
	}
	if !errors.Is(err, types.ErrInvalidNonce) || nonceEndpoint == nil {
		return nil, initialCNonce, err
	}

	nonceResponse, err := o.FetchNonceResponse(ctx, *nonceEndpoint)
	if err != nil {
		return nil, initialCNonce, fmt.Errorf("failed to refresh c_nonce after invalid_nonce: %w", err)
	}
	freshCNonce := nonceResponse.CNonce

	body, contentType, err = build(freshCNonce)
	if err != nil {
		return nil, freshCNonce, err
	}

	response, err = o.postCredentialEndpointForToken(ctx, endpoint, accessToken, body, contentType, proofFactory)
	if err != nil {
		return nil, freshCNonce, err
	}
	return response, freshCNonce, nil
}

// EncodeCredentialRequest serializes a Credential Request or Deferred Credential
// Request, encrypting it when the Credential Issuer advertises
// credential_request_encryption (OpenID4VCI 1.0 Section 8.1 and Section 9.1:
// "When performing Credential Request encryption, the Client MUST encode the
// information in the Credential Request in a JWT as specified by
// [Encrypted Messages], using the parameters from the
// `credential_request_encryption` object in the Credential Issuer Metadata").
//
// It fails closed when the request asks for an encrypted response that it cannot
// protect: Section 8.2 states that "Credential Request encryption MUST be used if
// the `credential_response_encryption` parameter is included, to prevent it being
// substituted by an attacker", so a request carrying that parameter in the clear
// hands an attacker the wallet's response encryption key to replace.
func (o *Oid4vciReceiver) EncodeCredentialRequest(request any, issuerMetadata *types.CredentialIssuerMetadata) ([]byte, string, error) {
	plaintext, err := json.Marshal(request)
	if err != nil {
		return nil, "", err
	}
	if issuerMetadata == nil || issuerMetadata.CredentialRequestEncryption == nil {
		if requestCarriesResponseEncryption(plaintext) {
			return nil, "", fmt.Errorf("credential_response_encryption was requested but the issuer does not advertise credential_request_encryption")
		}
		return plaintext, "application/json", nil
	}

	encryptionKey, err := selectEncryptionKey(&issuerMetadata.CredentialRequestEncryption.Jwks)
	if err != nil {
		return nil, "", err
	}
	// Section 10 (Encrypted Credential Requests and Responses): "The `alg`
	// parameter MUST be present. The JWE `alg` algorithm used MUST be equal to
	// the `alg` value of the chosen JWK." The JWE alg therefore comes from the
	// key, never from the metadata: Section 12.2.4 defines no
	// alg_values_supported member on credential_request_encryption.
	alg, err := credentialRequestEncryptionAlgorithm(encryptionKey)
	if err != nil {
		return nil, "", err
	}
	enc, err := selectSupportedEnc(issuerMetadata.CredentialRequestEncryption.EncValuesSupported)
	if err != nil {
		return nil, "", fmt.Errorf("credential request encryption: %w", err)
	}

	keyAlg, err := parseJWEKeyAlgorithm(alg)
	if err != nil {
		return nil, "", err
	}
	contentEnc, err := parseJWEContentEncryption(enc)
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

	jwe, err := encrypter.Encrypt(plaintext)
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
		// OpenID4VCI 1.0 §8.2 / §10 (Encrypted Credential Requests and Responses)
		// permits the issuer to signal DEFLATE with the JWE protected "zip":"DEF"
		// header. go-jose v4 (>= 4.1.4) inflates the plaintext inside Decrypt when
		// that header is present, so no manual flate step is required here;
		// TestOid4vciReceiver_DecodeCredentialResponseZip pins that behavior.
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

// ProofOptions carries the inputs of an OpenID4VCI 1.0 Section 8.2.1.1 jwt key
// proof. It is an alias of types.ProofOptions, which the OID4VCIFinalSigner
// interface names, so a plugin outside this repository can build the same proof
// without importing this package.
type ProofOptions = types.ProofOptions

// postProtected posts body to a Credential, Deferred Credential or
// Notification Endpoint with the access token and, for a DPoP-bound token, a
// DPoP proof per attempt. A non-2xx response is returned as the Section
// 8.3.1.2 *types.CredentialEndpointError, or as ErrDPoPRequired when a request
// sent with a Bearer token is asked for DPoP. An invalid_nonce refusal is
// reported as such first, so the caller can refresh the c_nonce.
func (o *Oid4vciReceiver) postProtected(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, body []byte, contentType string, proofFactory DPoPProofFactory, limit int64) (*exchangeResponse, error) {
	response, err := o.postWithAccessToken(ctx, endpoint, accessToken, body, contentType, proofFactory, limit)
	if err != nil {
		return nil, err
	}
	if response.ok() {
		return response, nil
	}
	responseContentType := response.header.Get("Content-Type")
	dpopNonce := response.header.Get("DPoP-Nonce")
	if isCredentialNonceError(responseContentType, response.body) {
		return nil, newCredentialEndpointError(response.statusCode, responseContentType, response.body, dpopNonce)
	}
	if bearerTokenChallenged(&accessToken, response) {
		return nil, ErrDPoPRequired
	}
	return nil, newCredentialEndpointError(response.statusCode, responseContentType, response.body, dpopNonce)
}

// postWithAccessToken posts body with the access token in the scheme its
// token_type names. A DPoP-bound token takes a proof from proofFactory for each
// attempt; a Bearer token carries none (RFC 9449 Section 7.1 pairs the proof
// with the DPoP scheme). The response is returned whatever its status.
func (o *Oid4vciReceiver) postWithAccessToken(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, body []byte, contentType string, proofFactory DPoPProofFactory, limit int64) (*exchangeResponse, error) {
	ex := exchange{
		method:      http.MethodPost,
		url:         url.URL(endpoint),
		contentType: contentType,
		body:        func() ([]byte, error) { return body, nil },
		accessToken: &accessToken,
		limit:       limit,
	}
	if authorizationScheme(accessToken.TokenType) == dpopAuthorizationScheme {
		if proofFactory == nil {
			return nil, fmt.Errorf("%w: a DPoP-bound access token needs a DPoP proof factory", ErrDPoPRequired)
		}
		ex.dpop = proofFactory
	}
	return o.do(ctx, ex)
}

// newCredentialEndpointError converts a non-2xx credential, deferred credential
// or notification response into the OpenID4VCI 1.0 §8.3.1.2 typed error (see
// also §9.2 and §11.3 for the deferred and notification error responses). The
// HTTP status is always retained. For 4xx responses served as JSON, the
// "error", "error_description" and "interval" members are parsed so callers can
// use errors.Is; any other content type (or unparseable body) leaves Code empty.
func newCredentialEndpointError(statusCode int, contentType string, body []byte, dpopNonce string) *types.CredentialEndpointError {
	credentialErr := &types.CredentialEndpointError{
		StatusCode: statusCode,
		DPoPNonce:  strings.TrimSpace(dpopNonce),
	}
	if statusCode < 400 || statusCode >= 500 || !strings.Contains(strings.ToLower(contentType), "json") {
		return credentialErr
	}
	var payload struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		Interval    int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return credentialErr
	}
	credentialErr.Code = sanitizeErrorText(payload.Error, maxErrorCodeLength)
	credentialErr.Description = sanitizeErrorText(payload.Description, maxErrorDescriptionLength)
	credentialErr.Interval = payload.Interval
	return credentialErr
}

func firstCredentialRequestOptions(options []*types.CredentialRequestOptions) *types.CredentialRequestOptions {
	for _, option := range options {
		if option != nil {
			return option
		}
	}
	return nil
}

// isCredentialNonceError reports whether a non-2xx Credential Endpoint response
// is the OpenID4VCI 1.0 §8.3.1.2 "invalid_nonce" Credential Error Response. The
// error is read from the body, so a response that also carries a DPoP-Nonce
// header is still recognised as the c_nonce failure it names. A body that is not
// JSON cannot be a §8.3.1.2 error object.
func isCredentialNonceError(contentType string, body []byte) bool {
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return false
	}
	return oauthErrorCode(body) == types.ErrInvalidNonce.Error()
}
