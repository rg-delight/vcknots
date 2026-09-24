package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// OID4VCIFinalReceiveRequest.AuthorizationRequestType selects how the selected
// Credential Configuration is requested at the authorization endpoint as
// defined by OpenID4VCI 1.0 §5.1.1 (authorization_details) and §5.1.2 (scope).
// The empty value lets the wallet choose: scope when the Credential
// Configuration advertises one, authorization_details otherwise.
const (
	OID4VCIAuthorizationRequestTypeScope                = "scope"
	OID4VCIAuthorizationRequestTypeAuthorizationDetails = "authorization_details"
)

// AuthorizationResponseError is the RFC 6749 §4.1.2 / RFC 9207 §2.4 error
// redirect payload returned to the wallet's registered redirect_uri. It is
// recovered with errors.As from AuthorizeOID4VCIFinalToken and
// ResumeOID4VCIFinalAuthorization, so a caller reports the authorization
// server's own error code rather than a generic authorization failure.
type AuthorizationResponseError struct {
	// Code is the RFC 6749 §4.1.2.1 error code, such as access_denied.
	Code string
	// Description is the optional error_description that accompanied it.
	Description string
	// State is the state the error redirect echoed. It always equals the
	// authorization request's state: a redirect without it is refused with
	// ErrAuthorizationStateMismatch before it is read as an error.
	State string
}

// ErrorCode names the outcome: the authorization server answered the
// authorization request with an RFC 6749 Section 4.1.2.1 error redirect. Code
// carries the error the server reported; this names what happened.
func (e *AuthorizationResponseError) ErrorCode() string {
	return "authorization_error_response"
}

func (e *AuthorizationResponseError) Error() string {
	if e == nil {
		return "authorization response error"
	}
	if e.Description == "" {
		return fmt.Sprintf("authorization response error: %s", e.Code)
	}
	return fmt.Sprintf("authorization response error: %s: %s", e.Code, e.Description)
}

// OID4VCIFinalAuthorization is the state a caller holds between
// BeginOID4VCIFinalAuthorization and ResumeOID4VCIFinalAuthorization or
// AuthorizeOID4VCIFinalToken. It is JSON-serialisable so it can survive a
// process restart.
//
// The state is confidential: CodeVerifier is the RFC 7636 verifier that
// redeems the authorization code. Keep it where only the wallet can read it,
// protect it against modification, and resume from it once. Resuming checks it
// against the request and re-fetches the issuer and authorization server
// metadata; no endpoint is taken from the state.
type OID4VCIFinalAuthorization struct {
	// AuthorizationURL is the §5.2 authorization request the caller must open
	// in the system browser.
	AuthorizationURL string `json:"authorization_url"`
	// State is the RFC 6749 §4.1.1 state parameter the redirect must echo.
	State string `json:"state"`
	// CodeVerifier is the RFC 7636 PKCE verifier for the token request.
	CodeVerifier string `json:"code_verifier"`
	// RequestURI is the RFC 9126 PAR request_uri, empty when the authorization
	// request was sent with its parameters inline.
	RequestURI string `json:"request_uri,omitempty"`
	// ExpiresAt is the §5.1.4 request_uri expiry measured from the PAR
	// response; the zero value disables the check.
	ExpiresAt time.Time `json:"expires_at"`
	// CredentialIssuer is the Credential Issuer Identifier of the issuance.
	CredentialIssuer string `json:"credential_issuer"`
	// AuthorizationServer is the RFC 8414 issuer identifier of the
	// authorization server the request was sent to.
	AuthorizationServer       string `json:"authorization_server"`
	CredentialConfigurationID string `json:"credential_configuration_id"`
	// ClientID and RedirectURI are those of the authorization request; the
	// resuming request must name the same.
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	// AuthorizationDetailsRequested records that the request used
	// authorization_details rather than scope, which decides how the Token
	// Response is read (§6.2).
	AuthorizationDetailsRequested bool `json:"authorization_details_requested,omitempty"`
}

// requireFor checks that the state is complete and belongs to req.
func (a *OID4VCIFinalAuthorization) requireFor(req OID4VCIFinalReceiveRequest) error {
	for name, value := range map[string]string{
		"state":                       a.State,
		"code_verifier":               a.CodeVerifier,
		"credential_issuer":           a.CredentialIssuer,
		"authorization_server":        a.AuthorizationServer,
		"credential_configuration_id": a.CredentialConfigurationID,
		"client_id":                   a.ClientID,
		"redirect_uri":                a.RedirectURI,
	} {
		if value == "" {
			return fmt.Errorf("authorization state is missing %s: %w", name, ErrIssuanceStateInvalid)
		}
	}
	if req.ClientID != a.ClientID || req.RedirectURI != a.RedirectURI {
		return fmt.Errorf("the request names another client_id or redirect_uri than the authorization state: %w", ErrIssuanceStateInvalid)
	}
	return requireOID4VCIIssuanceTarget(req, a.CredentialIssuer, a.CredentialConfigurationID)
}

// requireOID4VCIIssuanceTarget checks that the Credential Issuer and Credential
// Configuration req names, through its offer or directly, are the ones the
// resumed state was created for. A request that names neither is not checked.
func requireOID4VCIIssuanceTarget(req OID4VCIFinalReceiveRequest, credentialIssuer, credentialConfigurationID string) error {
	switch {
	case req.CredentialOffer != nil && req.CredentialOffer.CredentialIssuer != nil:
		if req.CredentialOffer.CredentialIssuer.String() != credentialIssuer ||
			!slices.Contains(req.CredentialOffer.CredentialConfigurationIDs, credentialConfigurationID) {
			return fmt.Errorf("the credential offer names another issuance than the resumed state: %w", ErrIssuanceStateInvalid)
		}
	case req.CredentialIssuer != nil:
		if req.CredentialIssuer.String() != credentialIssuer ||
			strings.TrimSpace(req.CredentialConfigurationID) != credentialConfigurationID {
			return fmt.Errorf("the request names another issuance than the resumed state: %w", ErrIssuanceStateInvalid)
		}
	}
	return nil
}

// RequestURIExpired reports whether the RFC 9126 §2.2 request_uri lifetime has
// run out at now, so the authorization request can no longer be sent to the
// authorization endpoint. A zero ExpiresAt — a PAR response without expires_in,
// or an authorization request whose parameters travelled inline — is never
// expired, because no deadline was stated and the wallet does not invent one.
//
// The lifetime bounds the use of the request_uri at the authorization endpoint
// and nothing after it: the authorization code arrives whenever the user
// finishes authenticating, which may well be later than the request_uri would
// have been accepted. AuthorizeOID4VCIFinalToken therefore does not refuse a
// callback on this ground; a wallet that wants to bound how long a started
// issuance stays resumable owns that policy and applies it here.
func (a *OID4VCIFinalAuthorization) RequestURIExpired(now time.Time) bool {
	if a == nil || a.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(a.ExpiresAt)
}

// issuerPolicy is the RFC 9207 expectation the authorization response must meet.
func (f *oid4vciFinalFlow) issuerPolicy(haip bool) authorizationResponseIssuerPolicy {
	advertised := f.authorizationServerMetadata.AuthorizationResponseIssParameterSupported
	return authorizationResponseIssuerPolicy{
		expected: f.authorizationServerIssuer,
		required: haip || (advertised != nil && *advertised),
	}
}

func (w *Wallet) beginOID4VCIFinalAuthorization(ctx context.Context, req OID4VCIFinalReceiveRequest) (*OID4VCIFinalAuthorization, *oid4vciFinalFlow, error) {
	if err := validateOID4VCIFinalAuthorizationRequest(req); err != nil {
		return nil, nil, err
	}
	if err := requireOID4VCIContext(ctx, "issuer metadata discovery"); err != nil {
		return nil, nil, err
	}

	// OpenID4VCI 1.0 §5: "The Wallet can also start the issuance without a
	// Credential Offer". With an offer the authorization_code grant supplies
	// the configuration list, the issuer_state and the authorization_server
	// hint; wallet-initiated issuance has none of them and takes the
	// configuration and issuer from the request.
	var (
		credentialConfigurationID string
		issuerIdentifier          string
		issuerState               string
		authCodeGrant             *CredentialOfferGrant
	)
	if req.CredentialOffer != nil {
		authCodeGrant = req.CredentialOffer.Grants["authorization_code"]
		if authCodeGrant == nil {
			return nil, nil, fmt.Errorf("authorization_code grant is not included in the offer")
		}
		credentialConfigurationID = req.CredentialOffer.CredentialConfigurationIDs[0]
		issuerIdentifier = req.CredentialOffer.CredentialIssuer.String()
		issuerState = authCodeGrant.IssuerState
	} else {
		credentialConfigurationID = strings.TrimSpace(req.CredentialConfigurationID)
		issuerIdentifier = req.CredentialIssuer.String()
	}

	if err := w.requireHAIPClientAuthentication(req); err != nil {
		return nil, nil, err
	}

	finalReceiver, err := w.receiver.OID4VCITransport(req.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}

	discovery, err := discoverOID4VCIIssuer(ctx, finalReceiver, issuerIdentifier, nil, offeredAuthorizationServer(authCodeGrant))
	if err != nil {
		return nil, nil, err
	}
	issuerMetadata := discovery.issuerMetadata
	authorizationServerMetadata := discovery.authorizationServerMetadata
	if authorizationServerMetadata.AuthorizationEndpoint == nil {
		return nil, nil, fmt.Errorf("authorization endpoint is missing on authorization server")
	}

	flow, err := w.newOID4VCIFinalFlow(req, finalReceiver, discovery, credentialConfigurationID, false)
	if err != nil {
		return nil, nil, err
	}

	// HAIP §4 ("Pushed Authorization Requests (PAR): Only required when using
	// the Authorization Endpoint") makes PAR a HAIP obligation, not an
	// OpenID4VCI one. A Final issuer that publishes no
	// pushed_authorization_request_endpoint gets the authorization request
	// parameters inline instead of being refused.
	usePAR := authorizationServerMetadata.PushedAuthorizationRequestEndpoint != nil
	if !usePAR && w.profile.IsHAIP() {
		return nil, nil, fmt.Errorf("HAIP requires a pushed authorization request endpoint on the authorization server")
	}

	codeVerifier, err := randomBase64URL(32)
	if err != nil {
		return nil, nil, err
	}
	state, err := randomBase64URL(16)
	if err != nil {
		return nil, nil, err
	}
	codeChallengeBytes := sha256.Sum256([]byte(codeVerifier))
	// §5.1.1/§5.1.2: the Credential Configuration is requested either with
	// scope or with authorization_details. An explicit scope on a
	// configuration that does not advertise one fails here, before PAR.
	scope, authorizationDetails, err := oid4vciAuthorizationRequestParameters(
		req.AuthorizationRequestType,
		credentialConfigurationID,
		flow.credentialConfiguration,
		w.profile.IsHAIP(),
	)
	if err != nil {
		return nil, nil, err
	}
	if len(authorizationDetails) > 0 && len(issuerMetadata.AuthorizationServers) > 0 {
		// OpenID4VCI 1.0 §5.1.1: "locations: OPTIONAL ... If the Credential
		// Issuer metadata contains an authorization_servers parameter, the
		// authorization detail's locations field MUST be set to the Credential
		// Issuer Identifier."
		for _, detail := range authorizationDetails {
			detail["locations"] = []string{issuerMetadata.CredentialIssuer}
		}
	}
	parRequest := receiverTypes.PushedAuthorizationRequest{
		ResponseType:         "code",
		ClientID:             req.ClientID,
		RedirectURI:          req.RedirectURI,
		Scope:                scope,
		AuthorizationDetails: authorizationDetails,
		State:                state,
		CodeChallenge:        base64.RawURLEncoding.EncodeToString(codeChallengeBytes[:]),
		CodeChallengeMethod:  "S256",
		IssuerState:          issuerState,
	}

	if err := requireOID4VCIContext(ctx, "the authorization request"); err != nil {
		return nil, nil, err
	}
	if len(authorizationDetails) > 0 {
		flow.authorizationDetailsMode = AuthorizationDetailsRequired
	}
	authorization := &OID4VCIFinalAuthorization{
		State:                         state,
		CodeVerifier:                  codeVerifier,
		CredentialIssuer:              issuerMetadata.CredentialIssuer,
		AuthorizationServer:           discovery.authorizationServer,
		CredentialConfigurationID:     credentialConfigurationID,
		ClientID:                      req.ClientID,
		RedirectURI:                   req.RedirectURI,
		AuthorizationDetailsRequested: len(authorizationDetails) > 0,
	}
	if usePAR {
		attestationHeaders, _, err := w.createOID4VCIAttestationHeaders(ctx, finalReceiver, req, authorizationServerMetadata, flow.authorizationServerIssuer)
		if err != nil {
			return nil, nil, err
		}
		parAuth := receiverTypes.ClientAuthentication{
			ClientAttestation: func() (receiverTypes.OAuthClientAttestationHeaders, error) { return attestationHeaders, nil },
		}
		if flow.usePrivateKeyJwt {
			parAuth.ClientAssertion = flow.generateClientAssertion
		}
		parResponse, err := finalReceiver.PushAuthorizationRequest(ctx, *authorizationServerMetadata.PushedAuthorizationRequestEndpoint, parRequest, parAuth)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to push authorization request: %w", err)
		}
		authorization.RequestURI = parResponse.RequestURI
		// §5.1.4: the request_uri expiry is measured from the PAR response time.
		if parResponse.ExpiresIn > 0 {
			authorization.ExpiresAt = time.Now().Add(time.Duration(parResponse.ExpiresIn) * time.Second)
		}
	}
	authorization.AuthorizationURL = oid4vciAuthorizationRequestURL(authorizationServerMetadata.AuthorizationEndpoint, req.ClientID, parRequest, authorization.RequestURI)
	return authorization, flow, nil
}

// requireHAIPClientAuthentication applies HAIP §4.4.1: "Wallets MUST use ...
// an OAuth2 Client authentication mechanism at OAuth2 Endpoints that support
// client authentication (such as the PAR and Token Endpoints)".
func (w *Wallet) requireHAIPClientAuthentication(req OID4VCIFinalReceiveRequest) error {
	if w.profile.IsHAIP() && w.clientAttestation == nil && req.AttesterKey.Key == nil && !clientAuthenticationConfigured(w.clientAuth) {
		return fmt.Errorf("HAIP requires an OAuth2 client authentication mechanism")
	}
	return nil
}

// oid4vciAuthorizationRequestParameters resolves how the selected Credential
// Configuration is requested at the authorization endpoint. OpenID4VCI 1.0
// §5.1.1 defines the authorization_details member and §5.1.2 the scope member.
// The default uses scope when the configuration advertises one, because
// §12.2.4 says "If scope is absent, the only way to request the Credential is
// using authorization_details"; otherwise it sends an openid_credential entry
// carrying credential_configuration_id.
//
// haip narrows that to scope only. HAIP §4.2: "For Grant Type
// `authorization_code`, the Issuer MUST include a scope value ... The Wallet
// MUST use that value in the `scope` Authorization parameter", and §4.3: the
// Wallet "MUST use the `scope` parameter to communicate Credential Type(s)".
func oid4vciAuthorizationRequestParameters(requestedType, credentialConfigurationID string, config receiverTypes.CredentialConfiguration, haip bool) (string, []map[string]any, error) {
	scope := strings.TrimSpace(config.Scope)
	authorizationDetails := []map[string]any{
		{
			"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
			"credential_configuration_id": credentialConfigurationID,
		},
	}
	normalized := strings.TrimSpace(requestedType)
	if haip {
		switch normalized {
		case "", OID4VCIAuthorizationRequestTypeScope:
			if scope == "" {
				return "", nil, fmt.Errorf("HAIP requires the credential configuration %q to advertise a scope", credentialConfigurationID)
			}
			return config.Scope, nil, nil
		case OID4VCIAuthorizationRequestTypeAuthorizationDetails:
			return "", nil, fmt.Errorf("HAIP requires the scope authorization request type")
		default:
			return "", nil, fmt.Errorf("unsupported authorization request type %q", requestedType)
		}
	}
	switch normalized {
	case "":
		if scope != "" {
			return config.Scope, nil, nil
		}
		return "", authorizationDetails, nil
	case OID4VCIAuthorizationRequestTypeScope:
		if scope == "" {
			return "", nil, fmt.Errorf("authorization request type %q requires the credential configuration %q to advertise a scope", OID4VCIAuthorizationRequestTypeScope, credentialConfigurationID)
		}
		return config.Scope, nil, nil
	case OID4VCIAuthorizationRequestTypeAuthorizationDetails:
		return "", authorizationDetails, nil
	default:
		return "", nil, fmt.Errorf("unsupported authorization request type %q", requestedType)
	}
}

// AuthorizationDetailsMode records how the authorization request asked for the
// Credential Configuration. It is what lets the Token Response be judged against
// the request that produced it: OpenID4VCI 1.0 §6.2 makes
// `authorization_details` in the Token Response "REQUIRED when the
// `authorization_details` parameter ... is used in either the Authorization
// Request or Token Request. OPTIONAL when `scope` parameter was used".
type AuthorizationDetailsMode int

const (
	// AuthorizationDetailsOptional accepts a Token Response that carries no
	// usable openid_credential authorization_details, because the request used
	// scope and §6.2 makes the member OPTIONAL there.
	AuthorizationDetailsOptional AuthorizationDetailsMode = iota
	// AuthorizationDetailsRequired demands a usable openid_credential entry,
	// because the request used authorization_details and §6.2 makes the member
	// REQUIRED there.
	AuthorizationDetailsRequired
)

// ErrAuthorizationDetailsMissing reports a Token Response that carries no
// usable openid_credential authorization_details for the requested Credential
// Configuration even though the authorization request used authorization_details.
// OpenID4VCI 1.0 §6.2 makes the member REQUIRED in that case, and §8.1 makes
// `credential_configuration_id` unusable once a `credential_identifiers` array
// was returned, so a request that falls back to the configuration id would be
// rejected by the issuer anyway.
var ErrAuthorizationDetailsMissing = common.NewCodedError("authorization_details_missing", "token response carries no usable authorization_details")

// CredentialIdentifierForConfiguration selects the credential_identifier to put
// in the Credential Request. OpenID4VCI 1.0 §6.2 binds each
// authorization_details entry of the token response to its own
// credential_configuration_id and lists that entry's credential_identifiers
// under it, so an identifier is only usable for the configuration whose entry
// carried it. A token response with no openid_credential entry yields no
// identifier and the request names the configuration instead (§8.1) when the
// mode is AuthorizationDetailsOptional; under AuthorizationDetailsRequired that
// absence, a foreign configuration, an empty credential_identifiers array or
// more than one identifier is ErrAuthorizationDetailsMissing. It is exported so
// integrators can apply the library's single
// implementation of the §6.2 mapping instead of copying it.
func CredentialIdentifierForConfiguration(accessToken *receiverTypes.CredentialIssuanceAccessToken, credentialConfigurationID string, mode AuthorizationDetailsMode) (*string, error) {
	if accessToken == nil {
		if mode == AuthorizationDetailsRequired {
			return nil, fmt.Errorf("token response is missing an access token with authorization_details for %q: %w", credentialConfigurationID, ErrAuthorizationDetailsMissing)
		}
		return nil, nil
	}
	entries := 0
	for _, detail := range accessToken.AuthorizationDetails {
		if detail.Type != receiverTypes.AuthorizationDetailTypeOpenIDCredential {
			continue
		}
		entries++
		if detail.CredentialConfigurationID != credentialConfigurationID {
			continue
		}
		identifiers := nonEmptyCredentialIdentifiers(detail.CredentialIdentifiers)
		if len(identifiers) == 0 {
			if mode == AuthorizationDetailsRequired {
				return nil, fmt.Errorf("authorization_details entry for credential_configuration_id %q carries no credential_identifiers: %w", credentialConfigurationID, ErrAuthorizationDetailsMissing)
			}
			// The entry matched but carries no identifier: the Credential
			// Request names the configuration, as it does without
			// authorization_details.
			return nil, nil
		}
		if len(identifiers) > 1 && mode == AuthorizationDetailsRequired {
			return nil, fmt.Errorf("authorization_details entry for credential_configuration_id %q carries %d credential_identifiers, but this wallet requests exactly one credential: %w", credentialConfigurationID, len(identifiers), ErrAuthorizationDetailsMissing)
		}
		selected := identifiers[0]
		return &selected, nil
	}
	if entries == 0 {
		if mode == AuthorizationDetailsRequired {
			return nil, fmt.Errorf("token response for credential_configuration_id %q carries no authorization_details: %w", credentialConfigurationID, ErrAuthorizationDetailsMissing)
		}
		return nil, nil
	}
	if mode == AuthorizationDetailsRequired {
		return nil, fmt.Errorf("token response authorization_details carries no entry for credential_configuration_id %q: %w", credentialConfigurationID, ErrAuthorizationDetailsMissing)
	}
	return nil, fmt.Errorf("access token authorization_details contains no entry for credential_configuration_id %q", credentialConfigurationID)
}

// nonEmptyCredentialIdentifiers drops the blank strings a malformed entry may
// contain, so only a real identifier is ever selected.
func nonEmptyCredentialIdentifiers(identifiers []string) []string {
	usable := identifiers[:0:0]
	for _, identifier := range identifiers {
		if strings.TrimSpace(identifier) != "" {
			usable = append(usable, identifier)
		}
	}
	return usable
}

// authorizationResponseIssuerPolicy is the RFC 9207 expectation for the
// authorization response: expected is the authorization server's issuer
// identifier; required is true when the server advertises
// authorization_response_iss_parameter_supported or the profile is HAIP (FAPI
// 2.0 §5.3.2.2 requires clients to check iss).
type authorizationResponseIssuerPolicy struct {
	expected string
	required bool
}

// oid4vciAuthorizationRequestURL builds the §5.2 authorization request URL. With
// a PAR request_uri only client_id and request_uri travel in the query, as RFC
// 9126 §4 prescribes. Without one — which OpenID4VCI permits outside HAIP, since
// HAIP §4 makes PAR "only required when using the Authorization Endpoint" — the
// §5.1 authorization request parameters are sent inline instead.
func oid4vciAuthorizationRequestURL(endpoint *common.URIField, clientID string, request receiverTypes.PushedAuthorizationRequest, requestURI string) string {
	authorizationURL := url.URL(*endpoint)
	query := authorizationURL.Query()
	query.Set("client_id", clientID)
	if requestURI != "" {
		query.Set("request_uri", requestURI)
		authorizationURL.RawQuery = query.Encode()
		return authorizationURL.String()
	}
	query.Set("response_type", request.ResponseType)
	query.Set("redirect_uri", request.RedirectURI)
	query.Set("state", request.State)
	query.Set("code_challenge", request.CodeChallenge)
	query.Set("code_challenge_method", request.CodeChallengeMethod)
	if request.Scope != "" {
		query.Set("scope", request.Scope)
	}
	if len(request.AuthorizationDetails) > 0 {
		if encoded, err := json.Marshal(request.AuthorizationDetails); err == nil {
			query.Set("authorization_details", string(encoded))
		}
	}
	if request.IssuerState != "" {
		query.Set("issuer_state", request.IssuerState)
	}
	authorizationURL.RawQuery = query.Encode()
	return authorizationURL.String()
}

// followOID4VCIAuthorizationEndpoint issues the §5.2 authorization request as a
// bare GET and returns the Location it redirects to. Only an issuer that needs
// no user interaction answers that way, which is why
// OID4VCIFinalReceiveRequest.AllowSelfDrivenAuthorization gates it. A nil
// client uses one with a timeout.
func followOID4VCIAuthorizationEndpoint(ctx context.Context, client *http.Client, auth *OID4VCIFinalAuthorization) (string, error) {
	if auth.RequestURIExpired(time.Now()) {
		return "", fmt.Errorf("the authorization request cannot be sent: %w", ErrAuthorizationRequestURIExpired)
	}
	request, err := http.NewRequestWithContext(observe.WithEndpoint(ctx, observe.EndpointAuthorization), http.MethodGet, auth.AuthorizationURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to request authorization endpoint: %w", err)
	}
	response, err := httpfetch.NoRedirect(client).Do(request)
	if err != nil {
		return "", fmt.Errorf("failed to request authorization endpoint: %w", err)
	}
	defer response.Body.Close()
	location := response.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("authorization endpoint did not redirect: %d", response.StatusCode)
	}
	return location, nil
}

// validateOID4VCIAuthorizationRedirect applies the RFC 6749 §4.1.2 / RFC 9207
// §2.4 checks to the redirect the user agent delivered and returns the
// authorization code. The redirect URI, state and iss are checked before the
// response is read as an error, so a forged error redirect cannot abort the
// issuance (RFC 6749 §4.1.2.1 and §10.12). authorizationURL is the request the
// redirect answers, used only to resolve a relative Location.
func validateOID4VCIAuthorizationRedirect(location string, authorizationURL string, expectedState string, registeredRedirectURI string, issuer authorizationResponseIssuerPolicy) (string, error) {
	redirectURL, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("failed to parse authorization redirect: %w: %w", ErrAuthorizationRedirectInvalid, err)
	}
	if !redirectURL.IsAbs() {
		base, err := url.Parse(authorizationURL)
		if err != nil {
			return "", fmt.Errorf("failed to parse authorization endpoint URL: %w: %w", ErrAuthorizationRedirectInvalid, err)
		}
		redirectURL = base.ResolveReference(redirectURL)
	}
	registeredRedirect, err := url.Parse(registeredRedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse registered redirect URI: %w: %w", ErrAuthorizationRedirectURIMismatch, err)
	}
	if !sameOriginAndPath(registeredRedirect, redirectURL) {
		return "", ErrAuthorizationRedirectURIMismatch
	}
	query := redirectURL.Query()
	if query.Get("state") != expectedState {
		return "", ErrAuthorizationStateMismatch
	}
	// RFC 9207 §2.4: a present iss MUST equal the authorization server's issuer
	// identifier, and MUST be present when the server advertises support or
	// the profile requires it.
	if iss, present := query["iss"]; present {
		if len(iss) != 1 || iss[0] != issuer.expected {
			return "", ErrAuthorizationIssMismatch
		}
	} else if issuer.required {
		return "", ErrAuthorizationIssMissing
	}
	if errorCode := query.Get("error"); errorCode != "" {
		return "", &AuthorizationResponseError{
			Code:        errorCode,
			Description: query.Get("error_description"),
			State:       query.Get("state"),
		}
	}
	code := query.Get("code")
	if code == "" {
		return "", ErrAuthorizationCodeMissing
	}
	return code, nil
}

func sameOriginAndPath(registered, actual *url.URL) bool {
	return strings.EqualFold(registered.Scheme, actual.Scheme) &&
		strings.EqualFold(registered.Host, actual.Host) &&
		registered.Path == actual.Path
}
