package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet/common"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// BeginOID4VCIDraft13Authorization builds the Draft 13 Section 3.4
// authorization request of the Authorization Code Flow and stops. The caller
// opens AuthorizationURL in the holder's browser and resumes with
// ResumeOID4VCIDraft13Authorization once the browser comes back.
//
// The library never drives the authorization endpoint itself: an issuer that
// authenticates the holder answers it with a login page, not a redirect, so
// there is nothing a headless request could do with the response.
//
// The RFC 9126 pushed authorization request is used when the authorization
// server advertises a pushed_authorization_request_endpoint, and the
// authorization request parameters travel inline otherwise. PKCE is always
// applied: Section 3.4 requires it.
func (w *Wallet) BeginOID4VCIDraft13Authorization(ctx context.Context, req OID4VCIDraft13ReceiveRequest) (*OID4VCIDraft13Authorization, error) {
	if err := requireOID4VCIContext(ctx, "issuer metadata discovery"); err != nil {
		return nil, err
	}
	if req.CredentialOffer == nil {
		return nil, ErrDraft13OfferMissing
	}
	if err := w.validateDraft13CredentialIssuer(req.CredentialOffer.CredentialIssuer); err != nil {
		return nil, err
	}
	grant := req.CredentialOffer.Grants["authorization_code"]
	if grant == nil {
		return nil, ErrDraft13AuthorizationCodeGrantMissing
	}
	if strings.TrimSpace(req.ClientID) == "" {
		return nil, fmt.Errorf("client_id is required for the authorization code flow")
	}
	if strings.TrimSpace(req.RedirectURI) == "" {
		return nil, fmt.Errorf("redirect_uri is required for the authorization code flow")
	}

	transport, err := w.draft13Transport(req.Type)
	if err != nil {
		return nil, err
	}
	issuerMetadata, authorizationServerMetadata, err := w.discoverDraft13Metadata(transport, req, grant)
	if err != nil {
		return nil, err
	}
	if authorizationServerMetadata.AuthorizationEndpoint == nil {
		return nil, ErrDraft13AuthorizationEndpointMissing
	}
	configurationID, configuration, err := selectDraft13CredentialConfiguration(req, issuerMetadata)
	if err != nil {
		return nil, err
	}

	codeVerifier, err := randomBase64URL(32)
	if err != nil {
		return nil, err
	}
	state, err := randomBase64URL(16)
	if err != nil {
		return nil, err
	}
	codeChallenge := sha256.Sum256([]byte(codeVerifier))

	// Section 5.1.1/5.1.2: the Credential Configuration is requested either
	// with scope or with authorization_details. The Draft 13 flow is never
	// HAIP, which is a constraint on OpenID4VCI 1.0, so the wallet's own rule
	// applies: scope when the configuration advertises one.
	scope, authorizationDetails, err := oid4vciAuthorizationRequestParameters(req.AuthorizationRequestType, configurationID, configuration, false)
	if err != nil {
		return nil, err
	}
	if len(authorizationDetails) > 0 && len(issuerMetadata.AuthorizationServers) > 0 {
		// Section 5.1.1: with authorization_servers in the issuer metadata the
		// authorization detail's locations field MUST name the Credential
		// Issuer Identifier.
		for _, detail := range authorizationDetails {
			detail["locations"] = []string{issuerMetadata.CredentialIssuer}
		}
	}

	authorizationRequest := receiverTypes.PushedAuthorizationRequest{
		ResponseType:         "code",
		ClientID:             req.ClientID,
		RedirectURI:          req.RedirectURI,
		Scope:                scope,
		AuthorizationDetails: authorizationDetails,
		State:                state,
		CodeChallenge:        base64.RawURLEncoding.EncodeToString(codeChallenge[:]),
		CodeChallengeMethod:  "S256",
		IssuerState:          grant.IssuerState,
	}

	authorization := &OID4VCIDraft13Authorization{
		State:                         state,
		CodeVerifier:                  codeVerifier,
		RedirectURI:                   req.RedirectURI,
		ClientID:                      req.ClientID,
		IssuerMetadata:                issuerMetadata,
		AuthorizationServerMetadata:   authorizationServerMetadata,
		CredentialConfigurationID:     configurationID,
		AuthorizationDetailsRequested: len(authorizationDetails) > 0,
	}

	if authorizationServerMetadata.PushedAuthorizationRequestEndpoint != nil {
		if err := requireOID4VCIContext(ctx, "the pushed authorization request"); err != nil {
			return nil, err
		}
		if method, ok := resolveClientAuthMethod(w.clientAuth, authorizationServerMetadata); ok && method == receiverTypes.PrivateKeyJwt {
			audience := resolveClientAssertionAudience(w.clientAuth, authorizationServerMetadata, receiverTypes.ResolveTokenEndpointURL(*authorizationServerMetadata.TokenEndpoint))
			assertion, err := w.generateClientAssertion(w.clientAuth.Key, w.clientAuth.ClientID, audience, w.clientAuth.signatureAlgorithm())
			if err != nil {
				return nil, fmt.Errorf("failed to generate PAR client assertion: %w", err)
			}
			authorizationRequest.ClientAssertion = assertion
			authorizationRequest.ClientAssertionType = receiverTypes.ClientAssertionTypeJWTBearer
		}
		pushed, err := flowPushAuthorizationRequest(ctx, transport, *authorizationServerMetadata.PushedAuthorizationRequestEndpoint, authorizationRequest)
		if err != nil {
			return nil, err
		}
		authorization.RequestURI = pushed.RequestURI
		if pushed.ExpiresIn > 0 {
			authorization.ExpiresAt = time.Now().Add(time.Duration(pushed.ExpiresIn) * time.Second)
		}
	}

	authorization.AuthorizationURL = oid4vciAuthorizationRequestURL(
		authorizationServerMetadata.AuthorizationEndpoint,
		req.ClientID,
		authorizationRequest,
		authorization.RequestURI,
	)
	if authorization.RequestURI == "" && len(issuerMetadata.AuthorizationServers) > 0 {
		resourceURL, err := withDraft13ResourceIndicator(authorization.AuthorizationURL, issuerMetadata.CredentialIssuer)
		if err != nil {
			return nil, err
		}
		authorization.AuthorizationURL = resourceURL
	}
	return authorization, nil
}

// withDraft13ResourceIndicator adds the RFC 8707 resource parameter naming the
// Credential Issuer to an inline authorization request. Draft 13 Section 5.1.2
// recommends it when the issuer delegates to authorization_servers, so an
// authorization server shared by several issuers can tell which one the access
// token is for. A pushed request carries its parameters in the PAR body, whose
// shape this library shares with OpenID4VCI 1.0, and is left as it is.
func withDraft13ResourceIndicator(authorizationURL string, credentialIssuer string) (string, error) {
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse the authorization request URL: %w", err)
	}
	query := parsed.Query()
	query.Set("resource", credentialIssuer)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func flowPushAuthorizationRequest(
	ctx context.Context,
	transport OID4VCIDraft13Transport,
	endpoint common.URIField,
	request receiverTypes.PushedAuthorizationRequest,
) (*receiverTypes.PushedAuthorizationResponse, error) {
	pushed, err := transport.PushAuthorizationRequest(ctx, endpoint, request, receiverTypes.OAuthClientAttestationHeaders{})
	if err != nil {
		return nil, fmt.Errorf("failed to push authorization request: %w", err)
	}
	return pushed, nil
}

// ResumeOID4VCIDraft13Authorization consumes the redirect the holder's browser
// delivered, exchanges the authorization code for an access token and requests
// the credential.
//
// redirectURL is the whole callback URL, not its parsed parts. The library is
// the authority on what the redirect means — RFC 6749 Section 4.1.2 for the
// error response and the state, RFC 9207 Section 2.4 for iss — and a caller
// that took the URL apart first would hide from it the one fact it cannot
// recover, that a parameter was absent.
func (w *Wallet) ResumeOID4VCIDraft13Authorization(
	ctx context.Context,
	req OID4VCIDraft13ReceiveRequest,
	auth *OID4VCIDraft13Authorization,
	redirectURL string,
) (*OID4VCIDraft13ReceiveResult, error) {
	if auth == nil {
		return nil, ErrDraft13AuthorizationStateMissing
	}
	if err := requireOID4VCIContext(ctx, "the token request"); err != nil {
		return nil, err
	}
	if auth.AuthorizationServerMetadata == nil || auth.AuthorizationServerMetadata.TokenEndpoint == nil {
		return nil, ErrDraft13TokenEndpointMissing
	}
	if auth.IssuerMetadata == nil {
		return nil, fmt.Errorf("authorization state carries no issuer metadata: %w", ErrDraft13AuthorizationStateMissing)
	}

	transport, err := w.draft13Transport(req.Type)
	if err != nil {
		return nil, err
	}

	// RFC 9207 Section 2.4: an iss that is present MUST identify the
	// authorization server; when the server advertises support the parameter
	// MUST be present, so a mix-up cannot simply omit it.
	advertised := auth.AuthorizationServerMetadata.AuthorizationResponseIssParameterSupported
	issuerPolicy := authorizationResponseIssuerPolicy{
		expected: auth.AuthorizationServerMetadata.Issuer.String(),
		required: advertised != nil && *advertised,
	}
	code, err := validateOID4VCIAuthorizationRedirect(redirectURL, auth.AuthorizationURL, auth.State, auth.RedirectURI, issuerPolicy)
	if err != nil {
		return nil, err
	}

	configuration, ok := auth.IssuerMetadata.CredentialConfigurationSupported[auth.CredentialConfigurationID]
	if !ok {
		return nil, fmt.Errorf("credential configuration %q: %w", auth.CredentialConfigurationID, ErrDraft13CredentialConfigurationUnknown)
	}
	flow := &oid4vciDraft13Flow{
		transport:                   transport,
		issuerMetadata:              auth.IssuerMetadata,
		authorizationServerMetadata: auth.AuthorizationServerMetadata,
		credentialConfigurationID:   auth.CredentialConfigurationID,
		credentialConfiguration:     configuration,
	}

	tokenEndpoint := *auth.AuthorizationServerMetadata.TokenEndpoint
	tokenEndpointURL := receiverTypes.ResolveTokenEndpointURL(tokenEndpoint)
	// The transport's authorization code exchange always asks for a proof; one
	// that returns nothing sends the request without a DPoP header, which is
	// what a server that never advertised DPoP gets.
	proofFactory := receiverTypes.DPoPProofFactory(func(string) (string, error) { return "", nil })
	if w.draft13DPoPEnabled(auth.AuthorizationServerMetadata) {
		proofFactory = w.draft13DPoPProofFactory(w.dpop.Key, http.MethodPost, tokenEndpointURL, "")
	}

	tokenRequest := receiverTypes.AuthorizationCodeTokenRequest{
		Code:         code,
		RedirectURI:  auth.RedirectURI,
		CodeVerifier: auth.CodeVerifier,
		ClientID:     auth.ClientID,
	}
	if method, ok := resolveClientAuthMethod(w.clientAuth, auth.AuthorizationServerMetadata); ok && method == receiverTypes.PrivateKeyJwt {
		audience := resolveClientAssertionAudience(w.clientAuth, auth.AuthorizationServerMetadata, tokenEndpointURL)
		tokenRequest.ClientAssertionFactory = func() (string, error) {
			return w.generateClientAssertion(w.clientAuth.Key, w.clientAuth.ClientID, audience, w.clientAuth.signatureAlgorithm())
		}
	}
	accessToken, err := transport.ExchangeAuthorizationCodeWithDpopAndAttestationRetry(ctx, tokenEndpoint, tokenRequest, noDraft13ClientAttestation, proofFactory)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	resumed := req
	resumed.CredentialConfigurationID = auth.CredentialConfigurationID
	if auth.AuthorizationDetailsRequested {
		// Section 6.2 makes authorization_details REQUIRED in the Token
		// Response when the authorization request used it, so a response
		// without a usable entry is a protocol failure rather than a request
		// that names the configuration instead.
		if _, err := CredentialIdentifierForConfiguration(accessToken, auth.CredentialConfigurationID, AuthorizationDetailsRequired); err != nil {
			return nil, err
		}
	}
	return w.requestDraft13Credential(ctx, flow, resumed, accessToken)
}

// noDraft13ClientAttestation is the headers factory of a token request that
// carries no OAuth 2.0 Attestation-Based Client Authentication: Draft 13
// predates it, and a wallet client authenticates with private_key_jwt or not
// at all.
func noDraft13ClientAttestation() (receiverTypes.OAuthClientAttestationHeaders, error) {
	return receiverTypes.OAuthClientAttestationHeaders{}, nil
}
