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
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

type OAuthClientAttestationHeadersFactory = types.OAuthClientAttestationHeadersFactory

// preAuthorizedCodeGrantType is the OpenID4VCI 1.0 §4.1.1 grant type of the
// Pre-Authorized Code Flow, registered in §16.4.
const preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// FetchAccessToken performs the pre-authorized code token request. It is a
// legacy Draft 13 types.Receiver method and therefore carries no context; it
// binds its request to context.Background().
func (o *Oid4vciReceiver) FetchAccessToken(
	receivingTypes types.SupportedReceivingTypes,
	endpoint common.URIField,
	authzCode string,
	txCode string,
	opts ...types.TokenRequestOption,
) (*types.CredentialIssuanceAccessToken, error) {
	ctx := context.Background()
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
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

	if requestConfig.ClientAssertion != "" {
		if err := requireSecureClientAssertionTransport(*endpointURL); err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(
		ctx,
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
	resp, err := o.httpClient().Do(req)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	defer resp.Body.Close()
	o.rememberDPoPNonce(*endpointURL, resp.Header.Get("DPoP-Nonce"))
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
	if err := requireDPoPTokenType(normalized, accessToken.TokenType); err != nil {
		return nil, err
	}
	return &accessToken, nil

}

// PushAuthorizationRequest sends the RFC 9126 Pushed Authorization Request of
// OpenID4VCI 1.0 Section 5.1. ctx bounds the request.
func (o *Oid4vciReceiver) PushAuthorizationRequest(ctx context.Context, endpoint common.URIField, request types.PushedAuthorizationRequest, headers types.OAuthClientAttestationHeaders) (*types.PushedAuthorizationResponse, error) {
	if _, err := o.normalizedProfile(); err != nil {
		return nil, err
	}
	formData := url.Values{}
	formData.Set("response_type", request.ResponseType)
	formData.Set("client_id", request.ClientID)
	formData.Set("redirect_uri", request.RedirectURI)
	// OpenID4VCI 1.0 §5.1.1/§5.1.2: scope and authorization_details are
	// alternative ways to select the requested Credential Configuration; an
	// empty value omits the parameter so the other method is unambiguous.
	if request.Scope != "" {
		formData.Set("scope", request.Scope)
	}
	if len(request.AuthorizationDetails) > 0 {
		encoded, err := json.Marshal(request.AuthorizationDetails)
		if err != nil {
			return nil, fmt.Errorf("failed to encode authorization_details: %w", err)
		}
		formData.Set("authorization_details", string(encoded))
	}
	formData.Set("state", request.State)
	formData.Set("code_challenge", request.CodeChallenge)
	formData.Set("code_challenge_method", request.CodeChallengeMethod)
	if request.IssuerState != "" {
		formData.Set("issuer_state", request.IssuerState)
	}
	// RFC 9126 §2: a PAR request carries the token endpoint's client
	// authentication. Client attestation headers and a client assertion are
	// different mechanisms and may coexist on the wire, but a deployment uses
	// one of them.
	setClientAssertionForm(formData, request.ClientAssertion, request.ClientAssertionType)

	var response types.PushedAuthorizationResponse
	if err := o.doFinalRequest(ctx, http.MethodPost, endpoint, strings.NewReader(formData.Encode()), "application/x-www-form-urlencoded", headersToMap(headers), &response); err != nil {
		return nil, stageError(StagePAR, fmt.Errorf("failed to push authorization request: %w", err))
	}
	return &response, nil
}

// ExchangeAuthorizationCode performs a single Section 6.1 token request with a
// pre-built DPoP proof. It is not part of types.OID4VCIFinalTransport and
// carries no context; it binds its request to context.Background(). Use
// ExchangeAuthorizationCodeWithDpopAndAttestationRetry, which owns the RFC 9449
// Section 8 nonce retry and takes a context.
func (o *Oid4vciReceiver) ExchangeAuthorizationCode(endpoint common.URIField, request types.AuthorizationCodeTokenRequest, headers types.OAuthClientAttestationHeaders, dpopProof string) (*types.CredentialIssuanceAccessToken, error) {
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
	}
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", request.Code)
	formData.Set("redirect_uri", request.RedirectURI)
	formData.Set("code_verifier", request.CodeVerifier)
	formData.Set("client_id", request.ClientID)
	setClientAssertionForm(formData, request.ClientAssertion, request.ClientAssertionType)

	requestHeaders := headersToMap(headers)
	if dpopProof != "" {
		requestHeaders["DPoP"] = dpopProof
	}

	var response types.CredentialIssuanceAccessToken
	if err := o.doFinalRequest(context.Background(), http.MethodPost, endpoint, strings.NewReader(formData.Encode()), "application/x-www-form-urlencoded", requestHeaders, &response); err != nil {
		return nil, stageError(StageToken, fmt.Errorf("failed to exchange authorization code: %w", err))
	}
	if err := requireDPoPTokenType(normalized, response.TokenType); err != nil {
		return nil, err
	}
	return &response, nil
}

// ExchangeAuthorizationCodeWithDpopRetry exchanges the authorization code with
// fixed Client Attestation headers. It is not part of
// types.OID4VCIFinalTransport and carries no context; it binds its requests to
// context.Background().
func (o *Oid4vciReceiver) ExchangeAuthorizationCodeWithDpopRetry(endpoint common.URIField, request types.AuthorizationCodeTokenRequest, headers types.OAuthClientAttestationHeaders, proofFactory DPoPProofFactory) (*types.CredentialIssuanceAccessToken, error) {
	return o.ExchangeAuthorizationCodeWithDpopAndAttestationRetry(context.Background(), endpoint, request, func() (types.OAuthClientAttestationHeaders, error) {
		return headers, nil
	}, proofFactory)
}

// ExchangeAuthorizationCodeWithDpopAndAttestationRetry exchanges the
// authorization code at the Section 6.1 Token Endpoint and owns the RFC 9449
// Section 8 DPoP nonce retry: both factories are called once per attempt, so a
// re-sent request carries a freshly signed proof and freshly built attestation
// headers rather than a replayed jti. ctx bounds every attempt.
func (o *Oid4vciReceiver) ExchangeAuthorizationCodeWithDpopAndAttestationRetry(ctx context.Context, endpoint common.URIField, request types.AuthorizationCodeTokenRequest, headersFactory OAuthClientAttestationHeadersFactory, proofFactory DPoPProofFactory) (*types.CredentialIssuanceAccessToken, error) {
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
	}
	// The form is rebuilt for every attempt so a fresh client_assertion
	// (unique jti, RFC 7523 §3) accompanies each re-sent request.
	buildBody := func() ([]byte, error) {
		assertion := request.ClientAssertion
		if request.ClientAssertionFactory != nil {
			fresh, err := request.ClientAssertionFactory()
			if err != nil {
				return nil, fmt.Errorf("failed to generate client assertion: %w", err)
			}
			assertion = fresh
		}
		formData := url.Values{}
		formData.Set("grant_type", "authorization_code")
		formData.Set("code", request.Code)
		formData.Set("redirect_uri", request.RedirectURI)
		formData.Set("code_verifier", request.CodeVerifier)
		formData.Set("client_id", request.ClientID)
		setClientAssertionForm(formData, assertion, request.ClientAssertionType)
		return []byte(formData.Encode()), nil
	}

	var response types.CredentialIssuanceAccessToken
	if err := o.doFormRequestWithDpopAndAttestationRetry(ctx, endpoint, buildBody, headersFactory, proofFactory, &response); err != nil {
		return nil, stageError(StageToken, fmt.Errorf("failed to exchange authorization code with DPoP retry: %w", err))
	}
	if err := requireDPoPTokenType(normalized, response.TokenType); err != nil {
		return nil, err
	}
	return &response, nil
}

// ExchangePreAuthorizedCodeWithDpopAndAttestationRetry exchanges the
// Section 4.1.1 pre-authorized_code at the Section 6.1 Token Endpoint. It is the
// Pre-Authorized Code counterpart of
// ExchangeAuthorizationCodeWithDpopAndAttestationRetry and owns the same RFC
// 9449 Section 8 DPoP nonce retry: both factories are called once per attempt,
// so a re-sent request carries a freshly signed proof, freshly built
// OAuth-Client-Attestation headers and a fresh client_assertion rather than a
// replayed jti. ctx bounds every attempt.
//
// Section 6.1 makes client authentication OPTIONAL for this grant
// ("authentication of the Client is OPTIONAL"), so a nil headersFactory sends
// no attestation headers and a nil proofFactory sends no DPoP proof.
func (o *Oid4vciReceiver) ExchangePreAuthorizedCodeWithDpopAndAttestationRetry(ctx context.Context, endpoint common.URIField, request types.PreAuthorizedCodeTokenRequest, headersFactory OAuthClientAttestationHeadersFactory, proofFactory DPoPProofFactory) (*types.CredentialIssuanceAccessToken, error) {
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(request.PreAuthorizedCode) == "" {
		return nil, fmt.Errorf("pre-authorized_code is required")
	}
	// Metadata token_endpoint values are complete URLs; resolving here keeps
	// the transport guards and the request itself on the same normalized URL.
	resolvedURL, err := url.Parse(types.ResolveTokenEndpointURL(endpoint))
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint URL: %w", err)
	}
	if request.ClientAssertion != "" || request.ClientAssertionFactory != nil {
		// private_key_jwt identifies the client by client_id, and an empty one
		// would only be rejected at the authorization server, where the cause
		// is far harder to see.
		if strings.TrimSpace(request.ClientID) == "" {
			return nil, fmt.Errorf("client_id is required when a client assertion is sent")
		}
		if err := requireSecureClientAssertionTransport(*resolvedURL); err != nil {
			return nil, err
		}
	}
	// The form is rebuilt for every attempt so a fresh client_assertion
	// (unique jti, RFC 7523 §3) accompanies each re-sent request.
	buildBody := func() ([]byte, error) {
		assertion := request.ClientAssertion
		if request.ClientAssertionFactory != nil {
			fresh, err := request.ClientAssertionFactory()
			if err != nil {
				return nil, fmt.Errorf("failed to generate client assertion: %w", err)
			}
			assertion = fresh
		}
		formData := url.Values{}
		formData.Set("grant_type", preAuthorizedCodeGrantType)
		formData.Set("pre-authorized_code", request.PreAuthorizedCode)
		if request.TxCode != "" {
			formData.Set("tx_code", request.TxCode)
		}
		// Sent for both authenticated and unauthenticated requests: client_id
		// is OPTIONAL for this grant, so it is included whenever the caller
		// configured one and omitted otherwise.
		if clientID := strings.TrimSpace(request.ClientID); clientID != "" {
			formData.Set("client_id", clientID)
		}
		setClientAssertionForm(formData, assertion, request.ClientAssertionType)
		return []byte(formData.Encode()), nil
	}
	if headersFactory == nil {
		headersFactory = func() (types.OAuthClientAttestationHeaders, error) {
			return types.OAuthClientAttestationHeaders{}, nil
		}
	}
	if proofFactory == nil {
		proofFactory = func(string) (string, error) { return "", nil }
	}

	var response types.CredentialIssuanceAccessToken
	if err := o.doFormRequestWithDpopAndAttestationRetry(ctx, common.URIField(*resolvedURL), buildBody, headersFactory, proofFactory, &response); err != nil {
		return nil, stageError(StageToken, fmt.Errorf("failed to exchange the pre-authorized code with DPoP retry: %w", err))
	}
	if err := requireDPoPTokenType(normalized, response.TokenType); err != nil {
		return nil, err
	}
	return &response, nil
}

// FetchClientAttestationChallenge fetches a challenge from the authorization
// server's challenge endpoint. ctx bounds the request.
func (o *Oid4vciReceiver) FetchClientAttestationChallenge(ctx context.Context, endpoint common.URIField) (*types.ClientAttestationChallengeResponse, error) {
	var response types.ClientAttestationChallengeResponse
	if err := o.doFinalRequest(ctx, http.MethodPost, endpoint, nil, "", nil, &response); err != nil {
		return nil, fmt.Errorf("failed to fetch client attestation challenge: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) doFormRequestWithDpopAndAttestationRetry(ctx context.Context, endpoint common.URIField, bodyFactory func() ([]byte, error), headersFactory OAuthClientAttestationHeadersFactory, proofFactory DPoPProofFactory, target any) error {
	if headersFactory == nil {
		return fmt.Errorf("OAuth client attestation headers factory is required")
	}
	return o.doFormRequestWithDpopAndHeadersRetry(ctx, endpoint, bodyFactory, func() (map[string]string, error) {
		headers, err := headersFactory()
		if err != nil {
			return nil, err
		}
		return headersToMap(headers), nil
	}, proofFactory, target)
}

// doFormRequestWithDpopAndHeadersRetry posts a form-encoded body and owns the
// RFC 9449 Section 8 DPoP nonce retry, rebuilding the proof, the headers and the
// body on every attempt so no jti is replayed. Like the bearer path, the first
// proof is seeded with the nonce this receiver already holds for that server.
// ctx bounds every attempt.
func (o *Oid4vciReceiver) doFormRequestWithDpopAndHeadersRetry(ctx context.Context, endpoint common.URIField, bodyFactory func() ([]byte, error), headersFactory func() (map[string]string, error), proofFactory DPoPProofFactory, target any) error {
	if proofFactory == nil {
		return fmt.Errorf("DPoP proof factory is required")
	}
	if headersFactory == nil {
		return fmt.Errorf("headers factory is required")
	}
	if bodyFactory == nil {
		return fmt.Errorf("body factory is required")
	}

	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	dpopNonce := o.dpopNonceFor(endpointURL)
	for attempt := 0; attempt < 2; attempt++ {
		dpopProof, err := proofFactory(dpopNonce)
		if err != nil {
			return err
		}
		headers, err := headersFactory()
		if err != nil {
			return err
		}
		bodyBytes, err := bodyFactory()
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL.String(), bytes.NewReader(bodyBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// An empty proof is how a caller says the request carries no DPoP: the
		// Pre-Authorized Code grant of OpenID4VCI 1.0 §6.1 may go out without
		// one, and an empty DPoP header is not a proof a server could accept.
		if dpopProof != "" {
			req.Header.Set("DPoP", dpopProof)
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
		respBody, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		o.rememberDPoPNonce(endpointURL, resp.Header.Get("DPoP-Nonce"))
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
		return &httpStatusError{statusCode: resp.StatusCode, body: string(respBody)}
	}

	return fmt.Errorf("DPoP nonce retry exhausted for %s", endpointURL.String())
}

// requireSecureClientAssertionTransport refuses to send a client assertion over
// an unprotected connection. The assertion proves possession of the registered
// client key, and RFC 6749 §10.8 requires client credentials never to travel in
// the clear. The AllowHTTP escape (VCKNOTS_WALLET_HTTP_ALLOWED) exists so that
// the local samples can talk to a development server on this machine, which is
// why loopback stays permitted; it is not a licence to send the assertion
// across a network unprotected.
func requireSecureClientAssertionTransport(endpointURL url.URL) error {
	if strings.EqualFold(endpointURL.Scheme, "https") || common.IsLoopbackHost(endpointURL.Hostname()) {
		return nil
	}
	return fmt.Errorf(
		"refusing to send a client assertion to %q over %q: https is required for any host other than loopback",
		endpointURL.Host, endpointURL.Scheme)
}

// setClientAssertionForm adds the RFC 7523 §2.2 private_key_jwt client
// authentication parameters to a form. Both members are omitted when no
// assertion is present, so an unauthenticated request carries no client
// authentication parameters. A supplied assertion without an explicit type is
// sent with the JWT bearer value, the only type private_key_jwt uses.
func setClientAssertionForm(formData url.Values, clientAssertion, clientAssertionType string) {
	if strings.TrimSpace(clientAssertion) == "" {
		return
	}
	if strings.TrimSpace(clientAssertionType) == "" {
		clientAssertionType = types.ClientAssertionTypeJWTBearer
	}
	formData.Set("client_assertion", clientAssertion)
	formData.Set("client_assertion_type", clientAssertionType)
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

func tokenErrorCode(bodyBytes []byte) string {
	var errorResponse struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errorResponse); err != nil {
		return ""
	}
	return strings.TrimSpace(errorResponse.Error)
}
