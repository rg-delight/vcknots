package oid4vci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
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
// proof_signing_alg_values_supported. It is the oid4vcisign sentinel of the same
// name, re-exported here because the key proof used to be built by this package;
// errors.Is matches either spelling.
var ErrProofAlgorithmNotSupported = oid4vcisign.ErrProofAlgorithmNotSupported

// FetchNonce fetches a c_nonce from the Section 7 Nonce Endpoint. It is a
// legacy Draft 13 types.Receiver method and therefore carries no context; it
// binds its request to context.Background().
func (o *Oid4vciReceiver) FetchNonce(receivingTypes types.SupportedReceivingTypes, endpoint common.URIField) (*string, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}
	if _, err := o.normalizedProfile(); err != nil {
		return nil, err
	}

	nonceEndpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(nonceEndpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", nonceEndpointURL.Scheme)
	}

	req, err := http.NewRequestWithContext(observe.WithEndpoint(context.Background(), observe.EndpointNonce), http.MethodPost, nonceEndpointURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}
	defer resp.Body.Close()
	// Section 7.2 Nonce Response: "The Credential Issuer MAY provide a DPoP
	// nonce in an HTTP header as defined in Section 8.2 of [@!RFC9449]. In this
	// case, the Wallet uses the new nonce value in the DPoP proof when
	// presenting an access token at the Credential Endpoint."
	o.rememberDPoPNonce(nonceEndpointURL, resp.Header.Get("DPoP-Nonce"))

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
	var response types.NonceResponse
	responseHeader, err := o.doFinalRequestWithResponseHeader(observe.WithEndpoint(ctx, observe.EndpointNonce), http.MethodPost, endpoint, nil, "", nil, &response)
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
	response.DPoPNonce = strings.TrimSpace(responseHeader.Get("DPoP-Nonce"))
	return &response, nil
}

// RequestCredential posts a single Section 8 Credential Request with a
// pre-built DPoP proof. It is not part of types.OID4VCIFinalTransport and
// carries no context; it binds its request to context.Background().
func (o *Oid4vciReceiver) RequestCredential(endpoint common.URIField, accessToken string, credentialRequest types.CredentialRequest, dpopProof string) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequest(observe.WithEndpoint(context.Background(), observe.EndpointCredential), endpoint, dpopBoundToken(accessToken), credentialRequest, dpopProof, &response); err != nil {
		return nil, fmt.Errorf("failed to request credential: %w", err)
	}
	return &response, nil
}

// RequestCredentialWithDpopRetry posts a Section 8 Credential Request with the
// RFC 9449 Section 8 nonce retry. It is not part of
// types.OID4VCIFinalTransport and carries no context; it binds its requests to
// context.Background().
func (o *Oid4vciReceiver) RequestCredentialWithDpopRetry(endpoint common.URIField, accessToken string, credentialRequest types.CredentialRequest, proofFactory DPoPProofFactory) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequestWithDpopRetry(observe.WithEndpoint(context.Background(), observe.EndpointCredential), endpoint, dpopBoundToken(accessToken), credentialRequest, proofFactory, &response); err != nil {
		return nil, fmt.Errorf("failed to request credential with DPoP retry: %w", err)
	}
	return &response, nil
}

// PostCredentialEndpointWithDpopRetry posts a pre-encoded Credential Request
// body with the RFC 9449 Section 8 nonce retry. It is not part of
// types.OID4VCIFinalTransport and carries no context; it binds its requests to
// context.Background().
func (o *Oid4vciReceiver) PostCredentialEndpointWithDpopRetry(endpoint common.URIField, accessToken string, body []byte, contentType string, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, error) {
	return o.postCredentialEndpointForToken(observe.WithEndpoint(context.Background(), observe.EndpointCredential), endpoint, dpopBoundToken(accessToken), body, contentType, proofFactory)
}

func (o *Oid4vciReceiver) postCredentialEndpointForToken(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, body []byte, contentType string, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, error) {
	responseBody, responseContentType, err := o.doBearerRequestWithDpopRetry(ctx, endpoint, accessToken, body, contentType, proofFactory)
	if err != nil {
		return nil, fmt.Errorf("failed to post credential endpoint request with DPoP retry: %w", err)
	}
	return &CredentialEndpointHTTPResponse{
		Body:        responseBody,
		ContentType: responseContentType,
	}, nil
}

// PostCredentialEndpointWithNonceRetryForToken is
// PostCredentialEndpointWithNonceRetry taking the parsed token response instead
// of the bare access token string, so that the Authorization header carries the
// scheme the authorization server issued. A Credential Issuer that returns
// token_type "Bearer" (RFC 6750 Section 2.1) must be addressed with the Bearer
// scheme; only a DPoP-bound token (RFC 9449 Section 7.1) takes the DPoP scheme
// and an accompanying DPoP proof header. Callers that still pass a bare string
// keep the DPoP scheme this plugin has always sent. ctx bounds every attempt,
// the Nonce Endpoint refresh included.
func (o *Oid4vciReceiver) PostCredentialEndpointWithNonceRetryForToken(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, nonceEndpoint *common.URIField, initialCNonce string, build CredentialRequestBodyFactory, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, string, error) {
	return o.postCredentialEndpointWithNonceRetry(ctx, endpoint, accessToken, nonceEndpoint, initialCNonce, build, proofFactory)
}

// SendCredentialNotificationWithDpopRetryForToken is
// SendCredentialNotificationWithDpopRetry taking the parsed token response, for
// the same reason as PostCredentialEndpointWithNonceRetryForToken.
// ctx bounds every attempt.
func (o *Oid4vciReceiver) SendCredentialNotificationWithDpopRetryForToken(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, notification types.NotificationRequest, proofFactory DPoPProofFactory) error {
	return o.doBearerJSONRequestWithDpopRetry(observe.WithEndpoint(ctx, observe.EndpointNotification), endpoint, accessToken, notification, proofFactory, nil)
}

// PostCredentialEndpointWithNonceRetry posts the credential request body built
// for the current c_nonce. OpenID4VCI 1.0 §8.3.1 requires the wallet to include
// the latest c_nonce in the proof, and §8.3.1.2 defines the "invalid_nonce"
// error an issuer returns when the proof carries a stale one; the wallet SHOULD
// obtain a fresh c_nonce from the nonce endpoint and retry. Exactly one such
// retry is performed so a misbehaving issuer cannot keep the wallet in a loop.
// DPoP challenges are still handled by PostCredentialEndpointWithDpopRetry
// underneath. It returns the response and the c_nonce actually used; when
// nonceEndpoint is nil the invalid_nonce error is returned without a retry.
// It is not part of types.OID4VCIFinalTransport and carries no context; it
// binds its requests to context.Background().
func (o *Oid4vciReceiver) PostCredentialEndpointWithNonceRetry(endpoint common.URIField, accessToken string, nonceEndpoint *common.URIField, initialCNonce string, build CredentialRequestBodyFactory, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, string, error) {
	return o.postCredentialEndpointWithNonceRetry(observe.WithEndpoint(context.Background(), observe.EndpointCredential), endpoint, dpopBoundToken(accessToken), nonceEndpoint, initialCNonce, build, proofFactory)
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

// RequestDeferredCredential posts a single Section 9 Deferred Credential
// Request with a pre-built DPoP proof. It is not part of
// types.OID4VCIFinalTransport and carries no context; it binds its request to
// context.Background().
func (o *Oid4vciReceiver) RequestDeferredCredential(endpoint common.URIField, accessToken string, deferredRequest types.DeferredCredentialRequest, dpopProof string) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequest(observe.WithEndpoint(context.Background(), observe.EndpointDeferredCredential), endpoint, dpopBoundToken(accessToken), deferredRequest, dpopProof, &response); err != nil {
		return nil, fmt.Errorf("failed to request deferred credential: %w", err)
	}
	return &response, nil
}

// RequestDeferredCredentialWithDpopRetry posts a Section 9 Deferred Credential
// Request with the RFC 9449 Section 8 nonce retry. It is not part of
// types.OID4VCIFinalTransport and carries no context; it binds its requests to
// context.Background().
func (o *Oid4vciReceiver) RequestDeferredCredentialWithDpopRetry(endpoint common.URIField, accessToken string, deferredRequest types.DeferredCredentialRequest, proofFactory DPoPProofFactory) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequestWithDpopRetry(observe.WithEndpoint(context.Background(), observe.EndpointDeferredCredential), endpoint, dpopBoundToken(accessToken), deferredRequest, proofFactory, &response); err != nil {
		return nil, fmt.Errorf("failed to request deferred credential with DPoP retry: %w", err)
	}
	return &response, nil
}

// SendCredentialNotification sends a single Section 11 notification with a
// pre-built DPoP proof. It is not part of types.OID4VCIFinalTransport and
// carries no context; it binds its request to context.Background().
func (o *Oid4vciReceiver) SendCredentialNotification(endpoint common.URIField, accessToken string, notification types.NotificationRequest, dpopProof string) error {
	return o.doBearerJSONRequest(observe.WithEndpoint(context.Background(), observe.EndpointNotification), endpoint, dpopBoundToken(accessToken), notification, dpopProof, nil)
}

// SendCredentialNotificationWithDpopRetry sends a Section 11 notification with
// the RFC 9449 Section 8 nonce retry. It is not part of
// types.OID4VCIFinalTransport and carries no context; it binds its requests to
// context.Background().
func (o *Oid4vciReceiver) SendCredentialNotificationWithDpopRetry(endpoint common.URIField, accessToken string, notification types.NotificationRequest, proofFactory DPoPProofFactory) error {
	return o.doBearerJSONRequestWithDpopRetry(observe.WithEndpoint(context.Background(), observe.EndpointNotification), endpoint, dpopBoundToken(accessToken), notification, proofFactory, nil)
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
	enc := firstOrDefault(issuerMetadata.CredentialRequestEncryption.EncValuesSupported, "A128GCM")

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

// SelectProofSigningAlgorithm returns the algorithm to sign a jwt key proof
// with, honouring the Credential Configuration's
// proof_signing_alg_values_supported.
//
// Deprecated: use oid4vcisign.SelectProofSigningAlgorithm, which this function
// calls.
func SelectProofSigningAlgorithm(key jose.JSONWebKey, supported []jose.SignatureAlgorithm) (jose.SignatureAlgorithm, error) {
	return oid4vcisign.SelectProofSigningAlgorithm(key, supported)
}

func (o *Oid4vciReceiver) doBearerJSONRequest(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, payload any, dpopProof string, target any) error {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	scheme := authorizationScheme(accessToken.TokenType)
	headers := map[string]string{"Authorization": scheme + " " + accessToken.Token}
	if scheme == dpopAuthorizationScheme {
		headers["DPoP"] = dpopProof
	}

	return o.doFinalRequest(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes), "application/json", headers, target)
}

func (o *Oid4vciReceiver) doBearerJSONRequestWithDpopRetry(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, payload any, proofFactory DPoPProofFactory, target any) error {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	respBody, _, err := o.doBearerRequestWithDpopRetry(ctx, endpoint, accessToken, bodyBytes, "application/json", proofFactory)
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

// doBearerRequestWithDpopRetry posts bodyBytes to a protected endpoint and owns
// the RFC 9449 Section 8 DPoP nonce retry. The first proof is built for the
// nonce this receiver already holds for that server, so a server that has
// already issued one is not made to reject a proof it cannot accept; the
// challenge retry remains the fallback for the first contact and for a rotated
// nonce. ctx bounds every attempt.
func (o *Oid4vciReceiver) doBearerRequestWithDpopRetry(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, bodyBytes []byte, contentType string, proofFactory DPoPProofFactory) ([]byte, string, error) {
	if proofFactory == nil {
		return nil, "", fmt.Errorf("DPoP proof factory is required")
	}
	scheme := authorizationScheme(accessToken.TokenType)

	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, "", fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	dpopNonce := o.dpopNonceFor(endpointURL)
	var lastStatus int
	var lastContentType string
	var lastBody []byte
	var lastNonce string
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL.String(), bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Accept", "application/json")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Authorization", scheme+" "+accessToken.Token)
		// RFC 9449 Section 7.1 pairs the DPoP proof header with the DPoP
		// scheme. A bearer token is not bound to the wallet key, so a proof
		// alongside it would prove nothing and is not built at all.
		if scheme == dpopAuthorizationScheme {
			dpopProof, err := proofFactory(dpopNonce)
			if err != nil {
				return nil, "", err
			}
			req.Header.Set("DPoP", dpopProof)
		}

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
		o.rememberDPoPNonce(endpointURL, resp.Header.Get("DPoP-Nonce"))
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return respBody, resp.Header.Get("Content-Type"), nil
		}
		responseContentType := resp.Header.Get("Content-Type")
		nonce := resp.Header.Get("DPoP-Nonce")
		// OpenID4VCI 1.0 §8.3.1.2: an "invalid_nonce" error means the proof
		// carried a stale c_nonce, and the wallet has to refresh it from the
		// Nonce Endpoint. It takes priority over the RFC 9449 §8 DPoP challenge
		// below: an issuer may set a DPoP-Nonce header on the same response, and
		// treating that as the challenge would spend the one retry on a DPoP
		// proof instead of the c_nonce the error actually named.
		if isCredentialNonceError(responseContentType, respBody) {
			return nil, "", newCredentialEndpointError(resp.StatusCode, responseContentType, respBody, nonce)
		}
		// A response may also demand a DPoP proof the wallet cannot build when
		// the access token is not DPoP-bound. Failing closed here reports the
		// real reason instead of repeating a request that carried no proof.
		if scheme != dpopAuthorizationScheme && dpopChallengeRequested(nonce, resp.Header.Get("WWW-Authenticate")) {
			return nil, "", ErrDPoPRequired
		}
		if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized) && nonce != "" {
			dpopNonce = nonce
			lastStatus, lastContentType, lastBody, lastNonce = resp.StatusCode, responseContentType, respBody, nonce
			continue
		}
		return nil, "", newCredentialEndpointError(resp.StatusCode, responseContentType, respBody, nonce)
	}

	if lastStatus != 0 {
		return nil, "", newCredentialEndpointError(lastStatus, lastContentType, lastBody, lastNonce)
	}
	return nil, "", fmt.Errorf("DPoP nonce retry exhausted for %s", endpointURL.String())
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
	credentialErr.Code = payload.Error
	credentialErr.Description = payload.Description
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
	return tokenErrorCode(body) == types.ErrInvalidNonce.Error()
}
