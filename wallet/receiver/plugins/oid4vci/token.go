package oid4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
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
	ctx := observe.WithEndpoint(context.Background(), observe.EndpointToken)
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
	endpointURL, err := url.Parse(types.ResolveTokenEndpointURL(endpoint))
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint URL: %w", err)
	}
	if requestConfig.ClientAssertion != "" {
		if err := requireSecureClientAssertionTransport(*endpointURL); err != nil {
			return nil, err
		}
	}

	body := []byte(formData.Encode())
	response, err := o.do(ctx, exchange{
		method:      http.MethodPost,
		url:         *endpointURL,
		contentType: "application/x-www-form-urlencoded",
		body:        func() ([]byte, error) { return body, nil },
		header: func(header http.Header) error {
			if requestConfig.DPoPProof != "" {
				header.Set("DPoP", requestConfig.DPoPProof)
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if response.statusCode != http.StatusOK {
		if isUseDPoPNonce(response) {
			return nil, types.NewDPoPNonceError(response.header.Get("DPoP-Nonce"), types.ErrTokenRequestFailed)
		}
		if response.statusCode == http.StatusBadRequest {
			if errorCode := oauthErrorCode(response.body); errorCode != "" {
				return nil, fmt.Errorf(
					"token request failed: %s; status: %d; response: %s: %w",
					errorCode,
					response.statusCode,
					string(response.body),
					types.ErrTokenRequestFailed,
				)
			}
		}
		return nil, fmt.Errorf(
			"unexpected status code: %d response: %s",
			response.statusCode,
			string(response.body),
		)
	}

	var accessToken types.CredentialIssuanceAccessToken
	if err := json.Unmarshal(response.body, &accessToken); err != nil {
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

	body := []byte(formData.Encode())
	var response types.PushedAuthorizationResponse
	if err := o.doJSON(observe.WithEndpoint(ctx, observe.EndpointPushedAuthorization), exchange{
		method:      http.MethodPost,
		url:         url.URL(endpoint),
		contentType: "application/x-www-form-urlencoded",
		body:        func() ([]byte, error) { return body, nil },
		header: func(header http.Header) error {
			setAttestationHeaders(header, headers)
			return nil
		},
	}, &response); err != nil {
		return nil, stageError(StagePAR, fmt.Errorf("failed to push authorization request: %w", err))
	}
	return &response, nil
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
	if err := o.postTokenRequest(ctx, url.URL(endpoint), buildBody, headersFactory, proofFactory, &response); err != nil {
		return nil, stageError(StageToken, fmt.Errorf("failed to exchange authorization code: %w", err))
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
	var response types.CredentialIssuanceAccessToken
	if err := o.postTokenRequest(ctx, *resolvedURL, buildBody, headersFactory, proofFactory, &response); err != nil {
		return nil, stageError(StageToken, fmt.Errorf("failed to exchange the pre-authorized code: %w", err))
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
	if err := o.doJSON(observe.WithEndpoint(ctx, observe.EndpointAttestationChallenge), exchange{method: http.MethodPost, url: url.URL(endpoint)}, &response); err != nil {
		return nil, fmt.Errorf("failed to fetch client attestation challenge: %w", err)
	}
	return &response, nil
}

// postTokenRequest posts a form to the Token Endpoint (Section 6.1). The body,
// the client attestation headers and the DPoP proof are rebuilt for each
// attempt; a nil factory sends none. ctx bounds every attempt.
func (o *Oid4vciReceiver) postTokenRequest(ctx context.Context, endpoint url.URL, buildBody func() ([]byte, error), headersFactory OAuthClientAttestationHeadersFactory, proofFactory DPoPProofFactory, target any) error {
	return o.doJSON(observe.WithEndpoint(ctx, observe.EndpointToken), exchange{
		method:      http.MethodPost,
		url:         endpoint,
		contentType: "application/x-www-form-urlencoded",
		body:        buildBody,
		header: func(header http.Header) error {
			if headersFactory == nil {
				return nil
			}
			headers, err := headersFactory()
			if err != nil {
				return err
			}
			setAttestationHeaders(header, headers)
			return nil
		},
		dpop: proofFactory,
	}, target)
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

// setAttestationHeaders adds the OAuth-Client-Attestation headers of
// draft-ietf-oauth-attestation-based-client-auth Section 6.1; empty values are
// omitted.
func setAttestationHeaders(header http.Header, headers types.OAuthClientAttestationHeaders) {
	if headers.ClientAttestation != "" {
		header.Set("OAuth-Client-Attestation", headers.ClientAttestation)
	}
	if headers.ClientAttestationPop != "" {
		header.Set("OAuth-Client-Attestation-PoP", headers.ClientAttestationPop)
	}
}

// oauthErrorCode returns the RFC 6749 Section 5.2 `error` member of a JSON
// error response, or "" when the body is not one.
func oauthErrorCode(bodyBytes []byte) string {
	var errorResponse struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errorResponse); err != nil {
		return ""
	}
	return strings.TrimSpace(errorResponse.Error)
}
