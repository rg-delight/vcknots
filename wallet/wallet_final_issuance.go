package wallet

import (
	"bytes"
	"context"
	"crypto"
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
	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/env"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// maxCredentialOfferResponseBytes bounds the §4.1.1 credential_offer_uri
// response so a hostile issuer cannot exhaust wallet memory during offer
// resolution.
const maxCredentialOfferResponseBytes int64 = 64 << 10

// maxDeferredInterval caps the §9.2 deferred credential polling interval the
// Credential Issuer chooses. The specification puts no upper bound on the
// interval member, so without a cap an issuer could hold a polling goroutine
// for an arbitrary time. OID4VCIFinalDeferredRequest.MaxInterval overrides it
// per request.
const maxDeferredInterval = 60 * time.Second

// defaultDeferredInterval is the wait between §9 deferred polls when neither
// the issuer nor the caller named one.
const defaultDeferredInterval = 5 * time.Second

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
// redirect payload returned to the wallet's registered redirect_uri.
type AuthorizationResponseError struct {
	Code        string
	Description string
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

// OID4VCIFinalNotificationRequest is the OpenID4VCI 1.0 §11 notification
// endpoint input for events the wallet sends after the initial credential
// response (credential_deleted).
type OID4VCIFinalNotificationRequest struct {
	Type           receiverTypes.SupportedReceivingTypes
	IssuerMetadata *receiverTypes.CredentialIssuerMetadata
	AccessToken    *receiverTypes.CredentialIssuanceAccessToken
	ClientKey      jose.JSONWebKey
	NotificationID string
}

// OID4VCIFinalDeferredRequest lets a restarted wallet resume a §9 deferred
// credential transaction from the transaction_id and access token returned by
// an IssuancePending result.
type OID4VCIFinalDeferredRequest struct {
	Type                            receiverTypes.SupportedReceivingTypes
	IssuerMetadata                  *receiverTypes.CredentialIssuerMetadata
	IssuerURL                       *url.URL
	CredentialConfigurationID       string
	AccessToken                     *receiverTypes.CredentialIssuanceAccessToken
	TransactionID                   string
	HolderKey                       jose.JSONWebKey
	AdditionalHolderKeys            []jose.JSONWebKey
	ClientKey                       jose.JSONWebKey
	CredentialResponseEncryptionKey *jose.JSONWebKey
	DeferredPollAttempts            int
	Interval                        time.Duration
	// MaxInterval caps the polling interval, including one the issuer names in
	// its §9.2 issuance_pending response. Zero uses maxDeferredInterval.
	MaxInterval time.Duration
}

// parseCredentialOfferJSON decodes the §4.1.1 Credential Offer JSON shared by
// the by-value and by-reference offer variants.
func parseCredentialOfferJSON(rawOffer string) (*CredentialOffer, error) {
	var raw struct {
		CredentialIssuer           string                           `json:"credential_issuer"`
		CredentialConfigurationIDs []string                         `json:"credential_configuration_ids"`
		Grants                     map[string]*CredentialOfferGrant `json:"grants"`
	}
	if err := json.Unmarshal([]byte(rawOffer), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse credential_offer JSON: %w", err)
	}
	issuer, err := url.Parse(raw.CredentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential issuer: %w", err)
	}
	return &CredentialOffer{
		CredentialIssuer:           issuer,
		CredentialConfigurationIDs: raw.CredentialConfigurationIDs,
		Grants:                     raw.Grants,
	}, nil
}

// ResolveCredentialOffer resolves an openid-credential-offer:// URI in either
// the §4.1.1 by-value (credential_offer) or by-reference (credential_offer_uri)
// form. A URI carrying both parameters is rejected.
func (w *Wallet) ResolveCredentialOffer(rawURL string) (*CredentialOffer, error) {
	return w.ResolveCredentialOfferContext(context.Background(), rawURL)
}

// ResolveCredentialOfferContext resolves an openid-credential-offer:// URI in
// either the §4.1.1 by-value (credential_offer) or by-reference
// (credential_offer_uri) form. ctx bounds the by-reference fetch.
func (w *Wallet) ResolveCredentialOfferContext(ctx context.Context, rawURL string) (*CredentialOffer, error) {
	offerURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential offer URL: %w", err)
	}
	rawOffer := offerURL.Query().Get("credential_offer")
	rawOfferURI := offerURL.Query().Get("credential_offer_uri")
	if rawOffer != "" && rawOfferURI != "" {
		return nil, fmt.Errorf("credential offer must not contain both credential_offer and credential_offer_uri")
	}
	switch {
	case rawOffer != "":
		return parseCredentialOfferJSON(rawOffer)
	case rawOfferURI != "":
		body, err := w.fetchCredentialOfferJSON(ctx, rawOfferURI)
		if err != nil {
			return nil, err
		}
		return parseCredentialOfferJSON(body)
	default:
		return nil, fmt.Errorf("credential_offer or credential_offer_uri query parameter is required")
	}
}

func (w *Wallet) fetchCredentialOfferJSON(ctx context.Context, credentialOfferURI string) (string, error) {
	parsedURI, err := url.Parse(credentialOfferURI)
	if err != nil {
		return "", fmt.Errorf("invalid credential_offer_uri: %w", err)
	}
	client, allowHTTP := w.credentialOfferHTTPClient()
	if !strings.EqualFold(parsedURI.Scheme, "https") && !(allowHTTP || env.IsHTTPAllowed()) {
		return "", fmt.Errorf("credential_offer_uri must use https")
	}
	if client == nil {
		client = http.DefaultClient
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURI.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to build credential_offer_uri request: %w", err)
	}
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("failed to fetch credential_offer_uri: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxCredentialOfferResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("failed to read credential_offer_uri response: %w", err)
	}
	if int64(len(body)) > maxCredentialOfferResponseBytes {
		return "", fmt.Errorf("credential_offer_uri response exceeds %d bytes", maxCredentialOfferResponseBytes)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("credential_offer_uri request failed: status=%d", response.StatusCode)
	}
	if strings.TrimSpace(string(body)) == "" {
		return "", fmt.Errorf("credential_offer_uri response body is empty")
	}
	return string(body), nil
}

// credentialOfferHTTPClient returns the OID4VCI receiver's configured HTTP
// client (and its AllowHTTP test escape) so offer resolution uses the same
// transport policy as the rest of the receiving flow.
func (w *Wallet) credentialOfferHTTPClient() (*http.Client, bool) {
	if w.receiver == nil {
		return nil, false
	}
	for _, plugin := range w.receiver.Plugins() {
		oid4vciPlugin, ok := plugin.(*receiverOid4vci.Oid4vciReceiver)
		if !ok {
			continue
		}
		return oid4vciPlugin.HTTPClient, oid4vciPlugin.AllowHTTP
	}
	return nil, false
}

// OID4VCIFinalAuthorization is the state a caller holds between the two halves
// of the OpenID4VCI 1.0 §5 authorization code flow: BeginOID4VCIFinalAuthorization
// produces it, the caller sends the user to AuthorizationURL in a browser, and
// ResumeOID4VCIFinalAuthorization consumes it together with the redirect the
// browser came back with. Every member is JSON-serialisable so the state can
// survive a process restart.
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
	ExpiresAt                   time.Time                                  `json:"expires_at"`
	IssuerMetadata              *receiverTypes.CredentialIssuerMetadata    `json:"issuer_metadata"`
	AuthorizationServerMetadata *receiverTypes.AuthorizationServerMetadata `json:"authorization_server_metadata"`
	CredentialConfigurationID   string                                     `json:"credential_configuration_id"`
}

// oid4vciFinalFlow is the part of an in-flight Final issuance that is not
// serialisable: the receiver plugin, the holder keys and the signing decisions
// taken from the wallet configuration. Begin builds it; Resume rebuilds it from
// the request and the persisted OID4VCIFinalAuthorization.
type oid4vciFinalFlow struct {
	receiver                    receiverTypes.OID4VCIFinalTransport
	signer                      receiverTypes.OID4VCIFinalSigner
	issuerMetadata              *receiverTypes.CredentialIssuerMetadata
	authorizationServerMetadata *receiverTypes.AuthorizationServerMetadata
	authorizationServerIssuer   string
	credentialConfigurationID   string
	credentialConfiguration     receiverTypes.CredentialConfiguration
	holderKeys                  []jose.JSONWebKey
	keyAttestation              *oid4vciKeyAttestationPlan
	usePrivateKeyJwt            bool
	generateClientAssertion     func() (string, error)
}

// issuerPolicy is the RFC 9207 expectation the authorization response must meet.
func (f *oid4vciFinalFlow) issuerPolicy(haip bool) authorizationResponseIssuerPolicy {
	advertised := f.authorizationServerMetadata.AuthorizationResponseIssParameterSupported
	return authorizationResponseIssuerPolicy{
		expected: f.authorizationServerIssuer,
		required: haip || (advertised != nil && *advertised),
	}
}

// ReceiveOID4VCIFinalCredential implements the OpenID4VCI 1.0 Final/HAIP
// authorization-code credential issuance flow. It is
// ReceiveOID4VCIFinalCredentialContext with a background context.
func (w *Wallet) ReceiveOID4VCIFinalCredential(req OID4VCIFinalReceiveRequest) (*OID4VCIFinalReceiveResult, error) {
	return w.ReceiveOID4VCIFinalCredentialContext(context.Background(), req)
}

// ReceiveOID4VCIFinalCredentialContext runs the whole OpenID4VCI 1.0 Final/HAIP
// authorization-code flow in one call, including the §5.2 authorization
// endpoint. Driving the authorization endpoint from the wallet process only
// works against an issuer that answers the bare GET with a redirect carrying
// the code, so it is gated behind
// OID4VCIFinalReceiveRequest.AllowSelfDrivenAuthorization; a wallet with a user
// calls BeginOID4VCIFinalAuthorization and ResumeOID4VCIFinalAuthorization
// around a system browser instead.
//
// ctx bounds every request the flow makes and cancels deferred credential
// polling.
func (w *Wallet) ReceiveOID4VCIFinalCredentialContext(ctx context.Context, req OID4VCIFinalReceiveRequest) (*OID4VCIFinalReceiveResult, error) {
	if err := validateOID4VCIFinalReceiveRequest(req); err != nil {
		return nil, err
	}
	if !req.AllowSelfDrivenAuthorization {
		// Checked before anything is sent, so a caller that has to migrate does
		// not first consume a pushed authorization request_uri.
		return nil, fmt.Errorf("the authorization code flow requires a browser: use BeginOID4VCIFinalAuthorization, or set AllowSelfDrivenAuthorization for a test issuer")
	}
	authorization, flow, err := w.beginOID4VCIFinalAuthorization(ctx, req)
	if err != nil {
		return nil, err
	}
	redirectURL, err := followOID4VCIAuthorizationEndpoint(req.HTTPClient, authorization)
	if err != nil {
		return nil, err
	}
	return w.resumeOID4VCIFinalAuthorization(ctx, req, authorization, flow, redirectURL)
}

// BeginOID4VCIFinalAuthorization performs everything the OpenID4VCI 1.0 §5
// authorization code flow does before the user agent is involved: it resolves
// the issuer and authorization server metadata, validates the selected
// Credential Configuration, pushes the authorization request when the flow uses
// RFC 9126 PAR, and returns the authorization URL to open in a browser together
// with the state the caller must hand back to
// ResumeOID4VCIFinalAuthorization.
func (w *Wallet) BeginOID4VCIFinalAuthorization(ctx context.Context, req OID4VCIFinalReceiveRequest) (*OID4VCIFinalAuthorization, error) {
	authorization, _, err := w.beginOID4VCIFinalAuthorization(ctx, req)
	if err != nil {
		return nil, err
	}
	return authorization, nil
}

// ResumeOID4VCIFinalAuthorization continues the flow from the redirect the
// browser delivered to the wallet's registered redirect_uri. It validates the
// RFC 6749 §4.1.2 / RFC 9207 authorization response against auth, exchanges the
// code at the token endpoint and performs the §8 credential request. req must
// carry the same client, redirect_uri and holder keys the matching
// BeginOID4VCIFinalAuthorization call used.
func (w *Wallet) ResumeOID4VCIFinalAuthorization(ctx context.Context, req OID4VCIFinalReceiveRequest, auth *OID4VCIFinalAuthorization, redirectURL string) (*OID4VCIFinalReceiveResult, error) {
	if auth == nil {
		return nil, fmt.Errorf("authorization state is required")
	}
	flow, err := w.restoreOID4VCIFinalFlow(req, auth)
	if err != nil {
		return nil, err
	}
	return w.resumeOID4VCIFinalAuthorization(ctx, req, auth, flow, redirectURL)
}

// requireOID4VCIContext reports a cancelled context at an issuance step
// boundary, naming the step that was about to start.
//
// It is not what stops a request in flight: every OID4VCIFinalTransport method
// that performs I/O now takes the flow context and binds its HTTP requests to
// it, so cancelling ctx aborts the request that is running. This check adds the
// part a bound request cannot give: it stops the flow between steps, before any
// key proof, DPoP proof, client assertion or key attestation is signed for a
// request that would be abandoned anyway, and it names the step in the error
// instead of surfacing a bare transport failure.
func requireOID4VCIContext(ctx context.Context, step string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("OpenID4VCI issuance cancelled before %s: %w", step, err)
	}
	return nil
}

func (w *Wallet) beginOID4VCIFinalAuthorization(ctx context.Context, req OID4VCIFinalReceiveRequest) (*OID4VCIFinalAuthorization, *oid4vciFinalFlow, error) {
	if err := validateOID4VCIFinalReceiveRequest(req); err != nil {
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

	// HAIP §4.4.1: "Wallets MUST use ... an OAuth2 Client authentication
	// mechanism at OAuth2 Endpoints that support client authentication".
	if w.profile.IsHAIP() && w.clientAttestation == nil && req.AttesterKey.Key == nil && !clientAuthenticationConfigured(w.clientAuth) {
		return nil, nil, fmt.Errorf("HAIP requires an OAuth2 client authentication mechanism")
	}

	finalReceiver, err := w.receiver.OID4VCIFinalTransport(req.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}

	issuerEndpoint, err := common.ParseURIField(issuerIdentifier)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse credential issuer endpoint: %w", err)
	}
	issuerMetadata, err := finalReceiver.FetchIssuerMetadata(*issuerEndpoint, req.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
	}
	// §12.2.2/§12.2.4: the credential_issuer value in the metadata MUST match
	// the credential issuer the wallet requested exactly; the wallet performs
	// no normalization.
	if issuerMetadata.CredentialIssuer != issuerIdentifier {
		if req.CredentialOffer != nil {
			return nil, nil, fmt.Errorf(
				"credential issuer metadata identifier %q does not match the credential offer credential_issuer %q",
				issuerMetadata.CredentialIssuer, issuerIdentifier)
		}
		return nil, nil, fmt.Errorf(
			"credential issuer metadata identifier %q does not match the requested credential issuer %q",
			issuerMetadata.CredentialIssuer, issuerIdentifier)
	}

	if _, err := requireOfferedCredentialConfiguration(issuerMetadata, credentialConfigurationID); err != nil {
		return nil, nil, err
	}

	// §12.3: select the authorization server. A grant authorization_server hint
	// MUST be listed in authorization_servers; otherwise the first listed server
	// is used, falling back to the credential issuer when the list is empty.
	authorizationServerEndpoint, err := SelectOID4VCIAuthorizationServer(issuerMetadata, authCodeGrant, *issuerEndpoint)
	if err != nil {
		return nil, nil, err
	}

	authorizationServerMetadata, err := finalReceiver.FetchAuthorizationServerMetadata(authorizationServerEndpoint, req.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}
	if authorizationServerMetadata.AuthorizationEndpoint == nil {
		return nil, nil, fmt.Errorf("authorization endpoint is missing on authorization server")
	}
	if authorizationServerMetadata.TokenEndpoint == nil {
		return nil, nil, fmt.Errorf("token endpoint is missing on authorization server")
	}
	// RFC 8414 §3.3: the issuer identifier in the metadata MUST be identical to
	// the authorization server identifier used to fetch it. The verified value
	// is the attestation PoP audience.
	if authorizationServerMetadata.Issuer.String() != authorizationServerEndpoint.String() {
		return nil, nil, fmt.Errorf(
			"authorization server metadata issuer %q does not match the selected authorization server %q",
			authorizationServerMetadata.Issuer.String(), authorizationServerEndpoint.String())
	}

	flow, err := w.newOID4VCIFinalFlow(req, finalReceiver, issuerMetadata, authorizationServerMetadata, credentialConfigurationID)
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
	authorization := &OID4VCIFinalAuthorization{
		State:                       state,
		CodeVerifier:                codeVerifier,
		IssuerMetadata:              issuerMetadata,
		AuthorizationServerMetadata: authorizationServerMetadata,
		CredentialConfigurationID:   credentialConfigurationID,
	}
	if usePAR {
		attestationHeaders, _, err := w.createOID4VCIAttestationHeaders(ctx, finalReceiver, req, authorizationServerMetadata, flow.authorizationServerIssuer)
		if err != nil {
			return nil, nil, err
		}
		if flow.usePrivateKeyJwt {
			assertion, err := flow.generateClientAssertion()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate PAR client assertion: %w", err)
			}
			parRequest.ClientAssertion = assertion
			parRequest.ClientAssertionType = receiverTypes.ClientAssertionTypeJWTBearer
		}
		parResponse, err := finalReceiver.PushAuthorizationRequest(ctx, *authorizationServerMetadata.PushedAuthorizationRequestEndpoint, parRequest, attestationHeaders)
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

// restoreOID4VCIFinalFlow rebuilds the non-serialisable half of an issuance
// from the request and the persisted authorization state. The issuer and
// authorization server metadata come from the state, not from a fresh fetch, so
// a restarted wallet continues against exactly the metadata the authorization
// request was built from.
func (w *Wallet) restoreOID4VCIFinalFlow(req OID4VCIFinalReceiveRequest, auth *OID4VCIFinalAuthorization) (*oid4vciFinalFlow, error) {
	if err := validateOID4VCIFinalReceiveRequest(req); err != nil {
		return nil, err
	}
	if auth.IssuerMetadata == nil {
		return nil, fmt.Errorf("authorization state is missing the issuer metadata")
	}
	if auth.AuthorizationServerMetadata == nil {
		return nil, fmt.Errorf("authorization state is missing the authorization server metadata")
	}
	if auth.AuthorizationServerMetadata.TokenEndpoint == nil {
		return nil, fmt.Errorf("token endpoint is missing on authorization server")
	}
	finalReceiver, err := w.receiver.OID4VCIFinalTransport(req.Type)
	if err != nil {
		return nil, fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}
	return w.newOID4VCIFinalFlow(req, finalReceiver, auth.IssuerMetadata, auth.AuthorizationServerMetadata, auth.CredentialConfigurationID)
}

// requireOfferedCredentialConfiguration resolves the selected Credential
// Configuration. §12.2.4 makes credential_configurations_supported the list of
// every Credential Configuration the Credential Issuer offers, so one that is
// absent cannot be requested, and saying so here keeps an authorization request
// for it off the wire entirely.
func requireOfferedCredentialConfiguration(issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string) (receiverTypes.CredentialConfiguration, error) {
	config, ok := issuerMetadata.CredentialConfigurationSupported[credentialConfigurationID]
	if !ok {
		return receiverTypes.CredentialConfiguration{}, fmt.Errorf(
			"credential issuer %q does not offer credential_configuration_id %q: %w",
			issuerMetadata.CredentialIssuer, credentialConfigurationID, ErrUnknownCredentialConfiguration)
	}
	return config, nil
}

// newOID4VCIFinalFlow validates the selected Credential Configuration against
// the wallet profile, plans the key attestation and resolves how the client
// authenticates at the PAR and token endpoints.
func (w *Wallet) newOID4VCIFinalFlow(
	req OID4VCIFinalReceiveRequest,
	finalReceiver receiverTypes.OID4VCIFinalTransport,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	authorizationServerMetadata *receiverTypes.AuthorizationServerMetadata,
	credentialConfigurationID string,
) (*oid4vciFinalFlow, error) {
	holderKeys, err := resolveOID4VCIFinalHolderKeys(req)
	if err != nil {
		return nil, err
	}

	config, err := requireOfferedCredentialConfiguration(issuerMetadata, credentialConfigurationID)
	if err != nil {
		return nil, err
	}

	// HAIP §4.1 constraints on the issuer metadata and the selected credential
	// configuration are enforced before PAR so an unsupported issuer never sees
	// an authorization request.
	profileValidator, _ := finalReceiver.(oid4vciProfileValidator)
	if w.profile.IsHAIP() && profileValidator == nil {
		return nil, fmt.Errorf("HAIP requires a receiver plugin that validates issuer metadata against the profile")
	}
	if profileValidator != nil {
		if err := profileValidator.ValidateIssuerMetadataForProfile(issuerMetadata); err != nil {
			return nil, fmt.Errorf("issuer metadata does not satisfy the wallet profile: %w", err)
		}
		if err := profileValidator.ValidateCredentialConfigurationForProfile(config); err != nil {
			return nil, fmt.Errorf("credential configuration does not satisfy the wallet profile: %w", err)
		}
	}

	// OpenID4VCI 1.0 Appendix D / HAIP §4.5.1: a provider must be available
	// before anything is sent to the issuer when the selected configuration
	// requires a key attestation.
	keyAttestation, err := w.planOID4VCIKeyAttestation(issuerMetadata, credentialConfigurationID, req.IncludeKeyAttestation)
	if err != nil {
		return nil, err
	}

	// §14.6: never request more proofs than the issuer's batch_size.
	if len(holderKeys) > issuerMetadata.BatchSize() {
		return nil, fmt.Errorf("requested %d credentials but the issuer batch_size is %d", len(holderKeys), issuerMetadata.BatchSize())
	}

	// RFC 9126 §2 / HAIP §4.3: the PAR and token endpoints authenticate the
	// client the same way. When private_key_jwt is configured, each endpoint
	// gets its own freshly signed assertion because RFC 7523 §3 requires a
	// unique jti. The authorization server must advertise the method before any
	// request leaves the wallet.
	authorizationServerIssuer := authorizationServerMetadata.Issuer.String()
	tokenEndpointURL := receiverTypes.ResolveTokenEndpointURL(*authorizationServerMetadata.TokenEndpoint)
	clientAssertionAudience := resolveClientAssertionAudience(w.clientAuth, authorizationServerMetadata, tokenEndpointURL)
	usePrivateKeyJwt := false
	// Attestation-based client authentication (Appendix E) and private_key_jwt
	// are alternative mechanisms; a wallet uses one per issuance. When an
	// attestation provider is in use it authenticates the client, so a
	// ClientAuth configured for other flows is not sent and the authorization
	// server need not advertise private_key_jwt.
	attestationInUse := w.clientAttestation != nil || req.AttesterKey.Key != nil
	if !attestationInUse && w.clientAuth.Method == receiverTypes.PrivateKeyJwt {
		if !asMetadataSupportsAuthMethod(authorizationServerMetadata, receiverTypes.PrivateKeyJwt) {
			return nil, fmt.Errorf("authorization server metadata does not advertise the configured private_key_jwt client authentication method")
		}
		if _, ok := resolveClientAuthMethod(w.clientAuth, authorizationServerMetadata); !ok {
			return nil, errNoUsableClientAuthMethod
		}
		usePrivateKeyJwt = true
	}

	return &oid4vciFinalFlow{
		receiver:                    finalReceiver,
		signer:                      w.oid4vciFinalSigner(finalReceiver),
		issuerMetadata:              issuerMetadata,
		authorizationServerMetadata: authorizationServerMetadata,
		authorizationServerIssuer:   authorizationServerIssuer,
		credentialConfigurationID:   credentialConfigurationID,
		credentialConfiguration:     config,
		holderKeys:                  holderKeys,
		keyAttestation:              keyAttestation,
		usePrivateKeyJwt:            usePrivateKeyJwt,
		generateClientAssertion: func() (string, error) {
			return w.generateClientAssertion(
				w.clientAuth.Key,
				w.clientAuth.ClientID,
				clientAssertionAudience,
				w.clientAuth.signatureAlgorithm(),
			)
		},
	}, nil
}

func (w *Wallet) resumeOID4VCIFinalAuthorization(
	ctx context.Context,
	req OID4VCIFinalReceiveRequest,
	auth *OID4VCIFinalAuthorization,
	flow *oid4vciFinalFlow,
	redirectURL string,
) (*OID4VCIFinalReceiveResult, error) {
	code, err := validateOID4VCIAuthorizationRedirect(redirectURL, auth.AuthorizationURL, auth.State, req.RedirectURI, flow.issuerPolicy(w.profile.IsHAIP()))
	if err != nil {
		return nil, err
	}

	if err := requireOID4VCIContext(ctx, "the token request"); err != nil {
		return nil, err
	}
	attestationHeaders, attestationChallenge, err := w.createOID4VCIAttestationHeaders(ctx, flow.receiver, req, flow.authorizationServerMetadata, flow.authorizationServerIssuer)
	if err != nil {
		return nil, err
	}

	tokenRequest := receiverTypes.AuthorizationCodeTokenRequest{
		Code:         code,
		RedirectURI:  req.RedirectURI,
		CodeVerifier: auth.CodeVerifier,
		ClientID:     req.ClientID,
	}
	if flow.usePrivateKeyJwt {
		// The factory is invoked once per HTTP attempt, so a DPoP nonce retry
		// re-sends the token request with a fresh client_assertion (new jti)
		// rather than replaying the first one.
		tokenRequest.ClientAssertionType = receiverTypes.ClientAssertionTypeJWTBearer
		tokenRequest.ClientAssertionFactory = flow.generateClientAssertion
	}
	token, err := flow.receiver.ExchangeAuthorizationCodeWithDpopAndAttestationRetry(
		ctx,
		*flow.authorizationServerMetadata.TokenEndpoint,
		tokenRequest,
		func() (receiverTypes.OAuthClientAttestationHeaders, error) {
			tokenAttestationHeaders := attestationHeaders
			if attestationHeaders.ClientAttestation != "" {
				tokenPop, err := flow.signer.CreateClientAttestationPop(req.ClientKey, req.ClientID, flow.authorizationServerIssuer, attestationChallenge, 5*time.Minute)
				if err != nil {
					return receiverTypes.OAuthClientAttestationHeaders{}, err
				}
				tokenAttestationHeaders.ClientAttestationPop = tokenPop
			}
			return tokenAttestationHeaders, nil
		},
		func(nonce string) (string, error) {
			return flow.signer.CreateDpopProof(req.ClientKey, http.MethodPost, flow.authorizationServerMetadata.TokenEndpoint.String(), nonce, "")
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	return w.receiveOID4VCIFinalCredentials(ctx, flow, token, req.ClientKey, req.CredentialResponseEncryptionKey, req.DeferredPollAttempts, req.MaxDeferredInterval)
}

// receiveOID4VCIFinalCredentials performs the §8 credential request (with §14.6
// batch proofs, §8.2 response encryption and §6.2 credential_identifier), the
// §9 deferred flow and the §11 notification bookkeeping.
func (w *Wallet) receiveOID4VCIFinalCredentials(
	ctx context.Context,
	flow *oid4vciFinalFlow,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	encryptionKey *jose.JSONWebKey,
	deferredPollAttempts int,
	maxInterval time.Duration,
) (*OID4VCIFinalReceiveResult, error) {
	issuerMetadata := flow.issuerMetadata
	// §8.2 / §10: build the credential_response_encryption request parameter and
	// fail closed when the issuer requires encryption but no key is supplied.
	encryptionParams, err := receiverOid4vci.CredentialResponseEncryptionParameters(issuerMetadata, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("credential response encryption: %w", err)
	}

	credentialIdentifier, err := credentialIdentifierForConfiguration(token, flow.credentialConfigurationID)
	if err != nil {
		return nil, err
	}
	build := oid4vciFinalCredentialRequestBodyFactory(ctx, flow, credentialIdentifier, encryptionParams)

	// §7: the nonce endpoint is OPTIONAL. Only fetch c_nonce when the issuer
	// advertises one; otherwise the proof is built without a nonce.
	nonceEndpoint := issuerMetadata.NonceEndpoint
	initialNonce := ""
	if nonceEndpoint != nil {
		nonceResponse, err := flow.receiver.FetchNonceResponse(ctx, *nonceEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch credential nonce: %w", err)
		}
		initialNonce = nonceResponse.CNonce
	}

	if err := requireOID4VCIContext(ctx, "the credential request"); err != nil {
		return nil, err
	}
	credentialEndpoint := issuerMetadata.CredentialEndpoint
	rawResponse, _, err := flow.receiver.PostCredentialEndpointWithNonceRetryForToken(
		ctx,
		credentialEndpoint,
		*token,
		nonceEndpoint,
		initialNonce,
		build,
		oid4vciFinalDpopProofFactory(flow.signer, clientKey, credentialEndpoint, token.Token),
	)
	if err != nil {
		// CredentialEndpointError is retained so callers can branch with
		// errors.Is (invalid_proof, credential_request_denied, ...).
		return nil, fmt.Errorf("failed to receive credential: %w", err)
	}
	if encryptionParams != nil && !strings.Contains(strings.ToLower(rawResponse.ContentType), "application/jwt") {
		return nil, fmt.Errorf("credential response encryption was requested but the credential endpoint returned %q", rawResponse.ContentType)
	}
	credentialResponse, err := decodeOID4VCIFinalCredentialResponse(flow.receiver, rawResponse, encryptionKey)
	if err != nil {
		return nil, err
	}

	if credentialResponse.TransactionID != "" {
		return w.handleOID4VCIFinalDeferredResponse(ctx, flow, token, clientKey, encryptionKey, encryptionParams, credentialResponse, deferredPollAttempts, maxInterval)
	}
	return w.storeAndNotifyOID4VCIFinalCredentials(ctx, flow, token, clientKey, credentialResponse)
}

func (w *Wallet) handleOID4VCIFinalDeferredResponse(
	ctx context.Context,
	flow *oid4vciFinalFlow,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	encryptionKey *jose.JSONWebKey,
	encryptionParams map[string]any,
	credentialResponse *receiverTypes.CredentialResponse,
	deferredPollAttempts int,
	maxInterval time.Duration,
) (*OID4VCIFinalReceiveResult, error) {
	if flow.issuerMetadata.DeferredCredentialEndpoint == nil {
		return nil, fmt.Errorf("deferred credential endpoint is missing on credential issuer")
	}
	if deferredPollAttempts <= 0 {
		// §9: do not report success with zero credentials. Hand the caller the
		// transaction_id and access token so it can resume after a restart.
		return pendingOID4VCIFinalResult(flow.issuerMetadata, flow.credentialConfigurationID, token, credentialResponse), newOID4VCIFinalIssuancePendingError(credentialResponse.Interval)
	}
	interval := clampDeferredInterval(time.Duration(credentialResponse.Interval)*time.Second, maxInterval)
	if interval <= 0 {
		interval = defaultDeferredInterval
	}
	return w.pollOID4VCIFinalDeferredCredential(ctx, flow, token, clientKey, encryptionKey, encryptionParams, credentialResponse.TransactionID, credentialResponse.NotificationID, deferredPollAttempts, interval, maxInterval)
}

// ResumeOID4VCIFinalDeferredCredential resumes polling the §9 deferred
// credential endpoint using a transaction_id returned by an IssuancePending
// result. It is ResumeOID4VCIFinalDeferredCredentialContext with a background
// context, so its polling cannot be cancelled.
func (w *Wallet) ResumeOID4VCIFinalDeferredCredential(req OID4VCIFinalDeferredRequest) (*OID4VCIFinalReceiveResult, error) {
	return w.ResumeOID4VCIFinalDeferredCredentialContext(context.Background(), req)
}

// ResumeOID4VCIFinalDeferredCredentialContext resumes polling the §9 deferred
// credential endpoint using a transaction_id returned by an IssuancePending
// result. The issuer metadata may be supplied directly or refetched from
// IssuerURL. Cancelling ctx stops the polling between attempts.
func (w *Wallet) ResumeOID4VCIFinalDeferredCredentialContext(ctx context.Context, req OID4VCIFinalDeferredRequest) (*OID4VCIFinalReceiveResult, error) {
	if req.Type != receiverTypes.Oid4vci {
		return nil, fmt.Errorf("unsupported OID4VCI Final receiving type: %v", req.Type)
	}
	if req.AccessToken == nil {
		return nil, fmt.Errorf("access token is required")
	}
	if strings.TrimSpace(req.TransactionID) == "" {
		return nil, fmt.Errorf("transaction ID is required")
	}
	finalReceiver, err := w.receiver.OID4VCIFinalTransport(req.Type)
	if err != nil {
		return nil, fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}

	issuerMetadata := req.IssuerMetadata
	if issuerMetadata == nil {
		if req.IssuerURL == nil {
			return nil, fmt.Errorf("issuer metadata or issuer URL is required")
		}
		issuerEndpoint, err := common.ParseURIField(req.IssuerURL.String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse credential issuer endpoint: %w", err)
		}
		issuerMetadata, err = finalReceiver.FetchIssuerMetadata(*issuerEndpoint, req.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
		}
		if issuerMetadata.CredentialIssuer != req.IssuerURL.String() {
			return nil, fmt.Errorf(
				"credential issuer metadata identifier %q does not match the credential offer credential_issuer %q",
				issuerMetadata.CredentialIssuer, req.IssuerURL.String())
		}
	}
	if issuerMetadata.DeferredCredentialEndpoint == nil {
		return nil, fmt.Errorf("deferred credential endpoint is missing on credential issuer")
	}

	holderKeys, err := resolveOID4VCIFinalHolderKeys(OID4VCIFinalReceiveRequest{
		HolderKey:            req.HolderKey,
		AdditionalHolderKeys: req.AdditionalHolderKeys,
	})
	if err != nil {
		return nil, err
	}
	if len(holderKeys) > issuerMetadata.BatchSize() {
		return nil, fmt.Errorf("requested %d credentials but the issuer batch_size is %d", len(holderKeys), issuerMetadata.BatchSize())
	}

	encryptionParams, err := receiverOid4vci.CredentialResponseEncryptionParameters(issuerMetadata, req.CredentialResponseEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("credential response encryption: %w", err)
	}

	attempts := req.DeferredPollAttempts
	if attempts <= 0 {
		attempts = 1
	}
	interval := clampDeferredInterval(req.Interval, req.MaxInterval)
	if interval <= 0 {
		interval = defaultDeferredInterval
	}
	flow := &oid4vciFinalFlow{
		receiver:                  finalReceiver,
		signer:                    w.oid4vciFinalSigner(finalReceiver),
		issuerMetadata:            issuerMetadata,
		credentialConfigurationID: req.CredentialConfigurationID,
		credentialConfiguration:   issuerMetadata.CredentialConfigurationSupported[req.CredentialConfigurationID],
		holderKeys:                holderKeys,
	}
	return w.pollOID4VCIFinalDeferredCredential(ctx, flow, req.AccessToken, req.ClientKey, req.CredentialResponseEncryptionKey, encryptionParams, req.TransactionID, "", attempts, interval, req.MaxInterval)
}

func pendingOID4VCIFinalResult(issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string, token *receiverTypes.CredentialIssuanceAccessToken, response *receiverTypes.CredentialResponse) *OID4VCIFinalReceiveResult {
	transactionID := ""
	notificationID := ""
	if response != nil {
		transactionID = response.TransactionID
		notificationID = response.NotificationID
	}
	return &OID4VCIFinalReceiveResult{
		CredentialResponse:        response,
		AccessToken:               token,
		TransactionID:             transactionID,
		NotificationID:            notificationID,
		IssuerMetadata:            issuerMetadata,
		CredentialConfigurationID: credentialConfigurationID,
	}
}

func (w *Wallet) pollOID4VCIFinalDeferredCredential(
	ctx context.Context,
	flow *oid4vciFinalFlow,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	encryptionKey *jose.JSONWebKey,
	encryptionParams map[string]any,
	transactionID string,
	notificationID string,
	attempts int,
	interval time.Duration,
	maxInterval time.Duration,
) (*OID4VCIFinalReceiveResult, error) {
	issuerMetadata := flow.issuerMetadata
	endpoint := *issuerMetadata.DeferredCredentialEndpoint
	pending := &OID4VCIFinalReceiveResult{
		AccessToken:               token,
		TransactionID:             transactionID,
		NotificationID:            notificationID,
		IssuerMetadata:            issuerMetadata,
		CredentialConfigurationID: flow.credentialConfigurationID,
	}

	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 && interval > 0 {
			if err := waitForDeferredInterval(ctx, interval); err != nil {
				return nil, err
			}
		}
		if err := requireOID4VCIContext(ctx, "the deferred credential request"); err != nil {
			return nil, err
		}
		// §9.1: "Deferred Credential Request encryption MUST be used if the
		// `credential_response_encryption` parameter is included in the
		// Deferred Credential Request... If it is not included encryption will
		// not be performed." The wallet repeats the parameter it sent with the
		// Credential Request so the deferred response is encrypted to the same
		// key, and §8.1's "Credential Request encryption MUST be used if the
		// `credential_response_encryption` parameter is included, to prevent it
		// being substituted by an attacker" is honoured by routing the body
		// through EncodeCredentialRequest, which fails closed when the issuer
		// advertises no credential_request_encryption.
		request := map[string]any{"transaction_id": transactionID}
		if encryptionParams != nil {
			request["credential_response_encryption"] = encryptionParams
		}
		body, contentType, err := flow.receiver.EncodeCredentialRequest(request, issuerMetadata)
		if err != nil {
			return nil, fmt.Errorf("failed to encode deferred credential request: %w", err)
		}
		rawResponse, _, err := flow.receiver.PostCredentialEndpointWithNonceRetryForToken(
			ctx,
			endpoint,
			*token,
			nil,
			"",
			func(string) ([]byte, string, error) { return body, contentType, nil },
			oid4vciFinalDpopProofFactory(flow.signer, clientKey, endpoint, token.Token),
		)
		if err != nil {
			// §9.2: an issuance_pending error means poll again after the
			// interval the issuer advertised.
			if errors.Is(err, receiverTypes.ErrIssuancePending) {
				interval = deferredIntervalFromError(err, interval, maxInterval)
				continue
			}
			return nil, fmt.Errorf("failed to receive deferred credential: %w", err)
		}
		if encryptionParams != nil && !strings.Contains(strings.ToLower(rawResponse.ContentType), "application/jwt") {
			return nil, fmt.Errorf("credential response encryption was requested but the deferred credential endpoint returned %q", rawResponse.ContentType)
		}
		credentialResponse, err := decodeOID4VCIFinalCredentialResponse(flow.receiver, rawResponse, encryptionKey)
		if err != nil {
			return nil, err
		}
		if credentialHasNoCredentials(credentialResponse) {
			if credentialResponse.Interval > 0 {
				interval = clampDeferredInterval(time.Duration(credentialResponse.Interval)*time.Second, maxInterval)
			}
			continue
		}
		result, err := w.storeAndNotifyOID4VCIFinalCredentials(ctx, flow, token, clientKey, credentialResponse)
		if err != nil {
			return nil, err
		}
		result.TransactionID = transactionID
		return result, nil
	}
	return pending, newOID4VCIFinalIssuancePendingError(int(interval / time.Second))
}

// waitForDeferredInterval sleeps for interval, or returns as soon as ctx is
// cancelled. A wallet polling a §9 deferred transaction must be able to give up
// while it waits, which time.Sleep does not allow.
func waitForDeferredInterval(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	select {
	case <-ctx.Done():
		timer.Stop()
		return fmt.Errorf("deferred credential polling cancelled: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

// clampDeferredInterval bounds a polling interval that the Credential Issuer
// chose. OpenID4VCI 1.0 §9.2 lets the issuer name the interval and sets no
// upper bound, so an issuer could otherwise pin a polling goroutine for an
// arbitrary time. maxInterval of zero or less uses maxDeferredInterval.
func clampDeferredInterval(interval, maxInterval time.Duration) time.Duration {
	if maxInterval <= 0 {
		maxInterval = maxDeferredInterval
	}
	if interval > maxInterval {
		return maxInterval
	}
	return interval
}

func credentialHasNoCredentials(response *receiverTypes.CredentialResponse) bool {
	if response == nil {
		return true
	}
	return response.Credential == nil && len(response.Credentials) == 0
}

func deferredIntervalFromError(err error, fallback time.Duration, maxInterval time.Duration) time.Duration {
	var endpointError *receiverTypes.CredentialEndpointError
	if errors.As(err, &endpointError) && endpointError.Interval > 0 {
		return clampDeferredInterval(time.Duration(endpointError.Interval)*time.Second, maxInterval)
	}
	return clampDeferredInterval(fallback, maxInterval)
}

func newOID4VCIFinalIssuancePendingError(intervalSeconds int) error {
	return fmt.Errorf("credential issuance is pending: %w", &receiverTypes.CredentialEndpointError{
		StatusCode: http.StatusAccepted,
		Code:       "issuance_pending",
		Interval:   intervalSeconds,
	})
}

func (w *Wallet) storeAndNotifyOID4VCIFinalCredentials(
	ctx context.Context,
	flow *oid4vciFinalFlow,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	credentialResponse *receiverTypes.CredentialResponse,
) (*OID4VCIFinalReceiveResult, error) {
	issuerMetadata := flow.issuerMetadata
	result := pendingOID4VCIFinalResult(issuerMetadata, flow.credentialConfigurationID, token, credentialResponse)
	savedCredentials, storeErr := w.storeOID4VCIFinalCredentialResponseBatch(ctx, credentialResponse, issuerMetadata, flow.credentialConfigurationID, flow.holderKeys)
	if storeErr != nil {
		// §11: a credential that failed verification/storage is reported with
		// credential_failure (best effort); the original failure is returned.
		if notifyErr := notifyOID4VCIFinalCredential(ctx, flow.receiver, flow.signer, issuerMetadata, token, clientKey, result.NotificationID, "credential_failure"); notifyErr != nil {
			return nil, errors.Join(storeErr, fmt.Errorf("failed to send credential_failure notification: %w", notifyErr))
		}
		return nil, storeErr
	}
	result.SavedCredentials = savedCredentials
	// §11: credential_accepted MUST only be sent after the credential was
	// successfully stored.
	if result.NotificationID != "" && issuerMetadata.NotificationEndpoint != nil {
		if notifyErr := notifyOID4VCIFinalCredential(ctx, flow.receiver, flow.signer, issuerMetadata, token, clientKey, result.NotificationID, "credential_accepted"); notifyErr != nil {
			return nil, fmt.Errorf("failed to send credential_accepted notification: %w", notifyErr)
		}
	}
	return result, nil
}

// NotifyOID4VCIFinalCredentialDeleted sends the §11 credential_deleted
// notification for a credential the wallet removed from storage. It is
// NotifyOID4VCIFinalCredentialDeletedContext with a background context.
func (w *Wallet) NotifyOID4VCIFinalCredentialDeleted(req OID4VCIFinalNotificationRequest) error {
	return w.NotifyOID4VCIFinalCredentialDeletedContext(context.Background(), req)
}

// NotifyOID4VCIFinalCredentialDeletedContext sends the §11 credential_deleted
// notification for a credential the wallet removed from storage.
func (w *Wallet) NotifyOID4VCIFinalCredentialDeletedContext(ctx context.Context, req OID4VCIFinalNotificationRequest) error {
	if err := requireOID4VCIContext(ctx, "the notification request"); err != nil {
		return err
	}
	if req.Type != receiverTypes.Oid4vci {
		return fmt.Errorf("unsupported OID4VCI Final receiving type: %v", req.Type)
	}
	if strings.TrimSpace(req.NotificationID) == "" {
		return fmt.Errorf("notification ID is required")
	}
	if req.AccessToken == nil {
		return fmt.Errorf("access token is required")
	}
	if req.IssuerMetadata == nil || req.IssuerMetadata.NotificationEndpoint == nil {
		return fmt.Errorf("notification endpoint is missing on credential issuer")
	}
	finalReceiver, err := w.receiver.OID4VCIFinalTransport(req.Type)
	if err != nil {
		return fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}
	return notifyOID4VCIFinalCredential(ctx, finalReceiver, w.oid4vciFinalSigner(finalReceiver), req.IssuerMetadata, req.AccessToken, req.ClientKey, req.NotificationID, "credential_deleted")
}

func notifyOID4VCIFinalCredential(
	ctx context.Context,
	finalReceiver receiverTypes.OID4VCIFinalTransport,
	signer receiverTypes.OID4VCIFinalSigner,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	notificationID string,
	event string,
) error {
	if notificationID == "" || issuerMetadata == nil || issuerMetadata.NotificationEndpoint == nil || token == nil {
		return nil
	}
	endpoint := *issuerMetadata.NotificationEndpoint
	return finalReceiver.SendCredentialNotificationWithDpopRetryForToken(
		ctx,
		endpoint,
		*token,
		receiverTypes.NotificationRequest{NotificationID: notificationID, Event: event},
		oid4vciFinalDpopProofFactory(signer, clientKey, endpoint, token.Token),
	)
}

func oid4vciFinalCredentialRequestBodyFactory(
	ctx context.Context,
	flow *oid4vciFinalFlow,
	credentialIdentifier *string,
	encryptionParams map[string]any,
) receiverTypes.CredentialRequestBodyFactory {
	issuerMetadata := flow.issuerMetadata
	return func(cNonce string) ([]byte, string, error) {
		keyAttestationJWT := ""
		if flow.keyAttestation != nil {
			request := KeyAttestationRequest{
				Keys:     flow.holderKeys,
				Nonce:    cNonce,
				Audience: issuerMetadata.CredentialIssuer,
			}
			attestation, err := flow.keyAttestation.provider.KeyAttestation(ctx, request)
			if err != nil {
				return nil, "", fmt.Errorf("failed to obtain key attestation: %w", err)
			}
			if err := ValidateKeyAttestation(ctx, attestation, request, flow.keyAttestation.policy); err != nil {
				return nil, "", err
			}
			keyAttestationJWT = attestation.JWT
		}
		// §8.2.1.1: "the `alg` JWT header of the key proof ... MUST match one
		// of the values listed in the `proof_signing_alg_values_supported`
		// metadata parameter", which §12.2.4.1 publishes per Credential
		// Configuration.
		proofOptions := receiverTypes.ProofOptions{
			Audience:         issuerMetadata.CredentialIssuer,
			Nonce:            cNonce,
			KeyAttestation:   keyAttestationJWT,
			SigningAlgValues: proofSigningAlgValues(flow.credentialConfiguration),
		}
		proofs := make([]string, 0, len(flow.holderKeys))
		for _, key := range flow.holderKeys {
			proof, err := flow.signer.CreateCredentialRequestJWTProofWithOptions(key, proofOptions)
			if err != nil {
				return nil, "", fmt.Errorf("failed to create credential request proof: %w", err)
			}
			proofs = append(proofs, proof)
		}
		payload := map[string]any{"proofs": map[string]any{"jwt": proofs}}
		// §6.2/§8.2: when the token response carries credential_identifiers the
		// credential_identifier member is sent instead of
		// credential_configuration_id.
		if credentialIdentifier != nil && *credentialIdentifier != "" {
			payload["credential_identifier"] = *credentialIdentifier
		} else {
			payload["credential_configuration_id"] = flow.credentialConfigurationID
		}
		if encryptionParams != nil {
			payload["credential_response_encryption"] = encryptionParams
		}
		body, contentType, err := flow.receiver.EncodeCredentialRequest(payload, issuerMetadata)
		if err != nil {
			return nil, "", fmt.Errorf("failed to encode credential request: %w", err)
		}
		return body, contentType, nil
	}
}

// proofSigningAlgValues reads the "jwt" proof type's
// proof_signing_alg_values_supported from a Credential Configuration.
// OpenID4VCI 1.0 §12.2.4.1 makes it "REQUIRED. A non-empty array of algorithm
// identifiers that the Issuer supports for this proof type. The Wallet uses one
// of them to sign the proof"; a configuration that publishes none imposes no
// constraint.
func proofSigningAlgValues(config receiverTypes.CredentialConfiguration) []jose.SignatureAlgorithm {
	if config.ProofTypesSupported == nil {
		return nil
	}
	jwtProof, ok := (*config.ProofTypesSupported)["jwt"]
	if !ok {
		return nil
	}
	return jwtProof.ProofSigningAlgValuesSupported
}

func oid4vciFinalDpopProofFactory(signer receiverTypes.OID4VCIFinalSigner, clientKey jose.JSONWebKey, endpoint common.URIField, accessToken string) receiverTypes.DPoPProofFactory {
	return func(nonce string) (string, error) {
		return signer.CreateDpopProof(clientKey, http.MethodPost, endpoint.String(), nonce, accessToken)
	}
}

func decodeOID4VCIFinalCredentialResponse(receiver receiverTypes.OID4VCIFinalTransport, raw *receiverTypes.CredentialEndpointHTTPResponse, key *jose.JSONWebKey) (*receiverTypes.CredentialResponse, error) {
	var decryptionKey any
	if key != nil {
		decryptionKey = key.Key
	}
	response, err := receiver.DecodeCredentialResponse(raw.Body, raw.ContentType, decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode credential response: %w", err)
	}
	return response, nil
}

// oid4vciAuthorizationRequestParameters resolves how the selected Credential
// Configuration is requested at the authorization endpoint. OpenID4VCI 1.0
// §5.1.1 defines the authorization_details member and §5.1.2 the scope member.
// The default uses scope when the configuration advertises one, because
// §12.2.4 says "If scope is absent, the only way to request the Credential is
// using authorization_details"; otherwise it sends an openid_credential entry
// carrying credential_configuration_id.
//
// haip narrows that to scope only. HAIP §4.1: "For Grant Type
// `authorization_code`, the Issuer MUST include a scope value ... The Wallet
// MUST use that value in the `scope` Authorization parameter", and §4.2: the
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

// credentialIdentifierForConfiguration selects the credential_identifier to put
// in the Credential Request. OpenID4VCI 1.0 §6.2 binds each
// authorization_details entry of the token response to its own
// credential_configuration_id and lists that entry's credential_identifiers
// under it, so an identifier is only usable for the configuration whose entry
// carried it. A token response with no openid_credential entry yields no
// identifier, and the request names the configuration instead (§8.1); a token
// response that has entries but none for the requested configuration is an
// error rather than a guess.
func credentialIdentifierForConfiguration(accessToken *receiverTypes.CredentialIssuanceAccessToken, credentialConfigurationID string) (*string, error) {
	if accessToken == nil {
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
		for _, identifier := range detail.CredentialIdentifiers {
			if identifier != "" {
				selected := identifier
				return &selected, nil
			}
		}
		// The entry matched but carries no identifier: the Credential Request
		// names the configuration, as it does without authorization_details.
		return nil, nil
	}
	if entries == 0 {
		return nil, nil
	}
	return nil, fmt.Errorf("access token authorization_details contains no entry for credential_configuration_id %q", credentialConfigurationID)
}

func resolveOID4VCIFinalHolderKeys(req OID4VCIFinalReceiveRequest) ([]jose.JSONWebKey, error) {
	if req.HolderKey.Key == nil {
		return nil, fmt.Errorf("holder key is required")
	}
	keys := make([]jose.JSONWebKey, 0, 1+len(req.AdditionalHolderKeys))
	keys = append(keys, req.HolderKey)
	for index, key := range req.AdditionalHolderKeys {
		if key.Key == nil {
			return nil, fmt.Errorf("additional holder key %d is missing a key", index)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func validateOID4VCIFinalReceiveRequest(req OID4VCIFinalReceiveRequest) error {
	if req.Type != receiverTypes.Oid4vci {
		return fmt.Errorf("unsupported OID4VCI Final receiving type: %v", req.Type)
	}
	if req.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if req.RedirectURI == "" {
		return fmt.Errorf("redirect URI is required")
	}
	if req.HolderKey.Key == nil {
		return fmt.Errorf("holder key is required")
	}
	if req.ClientKey.Key == nil {
		return fmt.Errorf("client key is required")
	}
	if req.CredentialOffer == nil {
		// OpenID4VCI 1.0 §5 wallet-initiated issuance: the caller must name
		// the credential issuer and the Credential Configuration because no
		// offer carries them.
		if req.CredentialIssuer == nil {
			return fmt.Errorf("credential issuer is required")
		}
		if strings.TrimSpace(req.CredentialConfigurationID) == "" {
			return fmt.Errorf("credential configuration ID is required")
		}
		return nil
	}
	if req.CredentialIssuer != nil || strings.TrimSpace(req.CredentialConfigurationID) != "" {
		return fmt.Errorf("credential issuer and credential configuration ID must be empty when a credential offer is provided")
	}
	if len(req.CredentialOffer.CredentialConfigurationIDs) == 0 {
		return fmt.Errorf("credential configuration IDs are empty")
	}
	if req.CredentialOffer.CredentialIssuer == nil {
		return fmt.Errorf("credential issuer is required")
	}
	return nil
}

// SelectOID4VCIAuthorizationServer chooses the authorization server for one
// OpenID4VCI issuance. The Credential Offer grant's authorization_server hint
// is a recommendation: "The value of this parameter MUST match with one of the
// values in the `authorization_servers` array obtained from the Credential
// Issuer metadata", so a hint that is not listed is rejected. Without a hint
// the wallet takes the first listed authorization server, or issuerEndpoint
// when the metadata lists none.
func SelectOID4VCIAuthorizationServer(issuerMetadata *receiverTypes.CredentialIssuerMetadata, grant *CredentialOfferGrant, issuerEndpoint common.URIField) (common.URIField, error) {
	if issuerMetadata == nil {
		return common.URIField{}, fmt.Errorf("issuer metadata is required")
	}
	// A wallet-initiated issuance has no grant and therefore no
	// authorization_server hint; it falls back to the first listed
	// authorization server or the credential issuer.
	hint := ""
	if grant != nil {
		hint = strings.TrimSpace(grant.AuthorizationServer)
	}
	if hint != "" {
		for _, server := range issuerMetadata.AuthorizationServers {
			if server.String() == hint {
				return server, nil
			}
		}
		return common.URIField{}, fmt.Errorf("authorization_server %q is not listed in the issuer metadata authorization_servers", hint)
	}
	if len(issuerMetadata.AuthorizationServers) > 0 {
		return issuerMetadata.AuthorizationServers[0], nil
	}
	return issuerEndpoint, nil
}

// oid4vciKeyAttestationPlan records that a key attestation must be attached to
// every credential request proof for this issuance.
type oid4vciKeyAttestationPlan struct {
	provider KeyAttestationProvider
	// policy authenticates what the provider returns: the attester signature
	// and, when anchors are configured, the x5c chain.
	policy AttestationTrustPolicy
}

// planOID4VCIKeyAttestation decides whether a key attestation is needed. It
// fails before any request is sent when the issuer requires one but the wallet
// has no provider, naming HAIP §4.5.1 under the HAIP profile.
func (w *Wallet) planOID4VCIKeyAttestation(metadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string, include bool) (*oid4vciKeyAttestationPlan, error) {
	required := IssuerRequiresKeyAttestation(metadata, credentialConfigurationID)
	if required && w.keyAttestation == nil {
		if w.profile.IsHAIP() {
			return nil, fmt.Errorf("HAIP §4.5.1 requires wallets to support key attestations: the issuer requires a key attestation but no KeyAttestation provider is configured")
		}
		return nil, fmt.Errorf("the issuer requires a key attestation but no KeyAttestation provider is configured")
	}
	if w.keyAttestation == nil || (!required && !include) {
		return nil, nil
	}
	return &oid4vciKeyAttestationPlan{provider: w.keyAttestation, policy: w.attestationPolicyFor(w.keyAttestation)}, nil
}

// IssuerRequiresKeyAttestation reports whether the selected credential
// configuration advertises proof_types_supported.jwt.key_attestations_required
// (OpenID4VCI 1.0 Appendix D). Presence of the object, even empty, is the
// signal.
func IssuerRequiresKeyAttestation(metadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string) bool {
	if metadata == nil || metadata.CredentialConfigurationSupported == nil {
		return false
	}
	config, ok := metadata.CredentialConfigurationSupported[credentialConfigurationID]
	if !ok || config.ProofTypesSupported == nil {
		return false
	}
	jwtProof, ok := (*config.ProofTypesSupported)["jwt"]
	if !ok {
		return false
	}
	return jwtProof.KeyAttestationsRequired != nil
}

// clientAttestationProvider resolves the provider for this request. A request
// AttesterKey is only used as a compatibility fallback when no provider is
// configured.
func (w *Wallet) clientAttestationProvider(req OID4VCIFinalReceiveRequest) (ClientAttestationProvider, error) {
	if w.clientAttestation != nil {
		return w.clientAttestation, nil
	}
	if req.AttesterKey.Key == nil {
		return nil, nil
	}
	if strings.TrimSpace(req.AttesterIssuer) == "" {
		return nil, fmt.Errorf("attester issuer is required when attester key is provided")
	}
	return &StaticClientAttester{Key: req.AttesterKey, Issuer: req.AttesterIssuer}, nil
}

func (w *Wallet) createOID4VCIAttestationHeaders(ctx context.Context, receiver receiverTypes.OID4VCIFinalTransport, req OID4VCIFinalReceiveRequest, authMetadata *receiverTypes.AuthorizationServerMetadata, authorizationServerIssuer string) (receiverTypes.OAuthClientAttestationHeaders, string, error) {
	provider, err := w.clientAttestationProvider(req)
	if err != nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", err
	}
	if provider == nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", nil
	}
	if authorizationServerIssuer == "" {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", fmt.Errorf("authorization server issuer is required for client attestation")
	}

	attestationRequest := ClientAttestationRequest{
		ClientID:            req.ClientID,
		ClientKey:           req.ClientKey,
		AuthorizationServer: authorizationServerIssuer,
	}
	// HAIP §4.4.1: authenticate the provider result before any request carrying
	// the attestation leaves the wallet. ValidateClientAttestation is the one
	// path the wallet uses: it establishes who signed the attestation (the x5c
	// leaf, the configured resolver, or the bundled attester's own key) and
	// only then checks the binding to this wallet instance.
	attestation, err := provider.ClientAttestation(ctx, attestationRequest)
	if err != nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", fmt.Errorf("failed to obtain client attestation: %w", err)
	}
	if err := ValidateClientAttestation(ctx, attestation, attestationRequest, w.attestationPolicyFor(provider)); err != nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", err
	}

	attestationChallenge := ""
	if authMetadata.ChallengeEndpoint != nil {
		challenge, err := receiver.FetchClientAttestationChallenge(ctx, *authMetadata.ChallengeEndpoint)
		if err != nil {
			return receiverTypes.OAuthClientAttestationHeaders{}, "", fmt.Errorf("failed to fetch client attestation challenge: %w", err)
		}
		attestationChallenge = challenge.AttestationChallenge
	}

	clientAttestationPop, err := w.oid4vciFinalSigner(receiver).CreateClientAttestationPop(req.ClientKey, req.ClientID, authorizationServerIssuer, attestationChallenge, 5*time.Minute)
	if err != nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", err
	}
	return receiverTypes.OAuthClientAttestationHeaders{
		ClientAttestation:    attestation.JWT,
		ClientAttestationPop: clientAttestationPop,
	}, attestationChallenge, nil
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

// followOID4VCIAuthorizationEndpoint drives the §5.2 authorization endpoint from
// inside the wallet process: it issues the bare GET and returns the Location the
// endpoint answers with. Only an issuer that needs no user interaction — a test
// or conformance issuer — behaves that way, which is why
// OID4VCIFinalReceiveRequest.AllowSelfDrivenAuthorization gates it. The client
// must read the 302 rather than follow it, so http.ErrUseLastResponse applies
// here instead of the blanket redirect refusal the other endpoints use.
func followOID4VCIAuthorizationEndpoint(client *http.Client, auth *OID4VCIFinalAuthorization) (string, error) {
	if !auth.ExpiresAt.IsZero() && !time.Now().Before(auth.ExpiresAt) {
		return "", fmt.Errorf("pushed authorization request_uri expired before use")
	}
	authClient := noRedirectHTTPClient(client)
	response, err := authClient.Get(auth.AuthorizationURL)
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
// authorization code. authorizationURL is the request the redirect answers, used
// only to resolve a relative Location.
func validateOID4VCIAuthorizationRedirect(location string, authorizationURL string, expectedState string, registeredRedirectURI string, issuer authorizationResponseIssuerPolicy) (string, error) {
	redirectURL, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("failed to parse authorization redirect: %w", err)
	}
	if !redirectURL.IsAbs() {
		base, err := url.Parse(authorizationURL)
		if err != nil {
			return "", fmt.Errorf("failed to parse authorization endpoint URL: %w", err)
		}
		redirectURL = base.ResolveReference(redirectURL)
	}
	registeredRedirect, err := url.Parse(registeredRedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse registered redirect URI: %w", err)
	}
	if !sameOriginAndPath(registeredRedirect, redirectURL) {
		return "", fmt.Errorf("authorization redirect does not match the registered redirect_uri")
	}
	if errorCode := redirectURL.Query().Get("error"); errorCode != "" {
		return "", &AuthorizationResponseError{Code: errorCode, Description: redirectURL.Query().Get("error_description")}
	}
	if state := redirectURL.Query().Get("state"); state != expectedState {
		return "", fmt.Errorf("authorization redirect state mismatch")
	}
	// RFC 9207 §2.4: an iss parameter that is present MUST equal the issuer
	// identifier of the authorization server that was used; when the server
	// advertises support (or the profile requires it) the parameter MUST be
	// present so a mix-up attack cannot omit it.
	if iss, present := redirectURL.Query()["iss"]; present {
		if len(iss) != 1 || iss[0] != issuer.expected {
			return "", fmt.Errorf("authorization redirect iss does not identify the authorization server")
		}
	} else if issuer.required {
		return "", fmt.Errorf("authorization redirect is missing the iss parameter required by the authorization server metadata")
	}
	code := redirectURL.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("authorization redirect code is missing")
	}
	return code, nil
}

func sameOriginAndPath(registered, actual *url.URL) bool {
	return strings.EqualFold(registered.Scheme, actual.Scheme) &&
		strings.EqualFold(registered.Host, actual.Host) &&
		registered.Path == actual.Path
}

func noRedirectHTTPClient(client *http.Client) *http.Client {
	transport := http.DefaultTransport
	timeout := time.Duration(0)
	if client != nil {
		if client.Transport != nil {
			transport = client.Transport
		}
		timeout = client.Timeout
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (w *Wallet) storeOID4VCIFinalCredentialResponse(ctx context.Context, response *receiverTypes.CredentialResponse, issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string, holderKey *jose.JSONWebKey) ([]*SavedCredential, error) {
	var holderKeys []jose.JSONWebKey
	if holderKey != nil {
		holderKeys = append(holderKeys, *holderKey)
	}
	return w.storeOID4VCIFinalCredentialResponseBatch(ctx, response, issuerMetadata, credentialConfigurationID, holderKeys)
}

// storeOID4VCIFinalCredentialResponseBatch verifies each returned credential
// against the holder key at the same index (§14.6 batch order) and stores
// nothing when any credential fails acceptance.
func (w *Wallet) storeOID4VCIFinalCredentialResponseBatch(ctx context.Context, response *receiverTypes.CredentialResponse, issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string, holderKeys []jose.JSONWebKey) ([]*SavedCredential, error) {
	if response == nil {
		return nil, fmt.Errorf("credential response is nil")
	}
	mimeType := mimeTypeForCredentialConfiguration(issuerMetadata, credentialConfigurationID)
	flavor, err := (&credstoreTypes.CredentialEntry{MimeType: mimeType}).SerializationFlavor()
	if err != nil {
		return nil, fmt.Errorf("unsupported credential serialization flavor: %w", err)
	}
	values := []any{}
	if response.Credential != nil {
		values = append(values, response.Credential)
	}
	values = append(values, response.Credentials...)
	if len(values) == 0 {
		return nil, nil
	}
	if len(holderKeys) > 0 && len(values) > len(holderKeys) {
		return nil, fmt.Errorf("credential response returned %d credentials but only %d holder keys were supplied", len(values), len(holderKeys))
	}

	saved := make([]*SavedCredential, 0, len(values))
	usedKeys := make([]bool, len(holderKeys))
	for _, value := range values {
		raw, err := rawCredentialBytes(value)
		if err != nil {
			return nil, err
		}
		// OpenID4VCI 1.0 §8.3 does not promise that the credentials array
		// follows the order of the proofs, so each credential is matched to the
		// holder key its cnf names; every supplied key may be used at most once.
		holderKey, err := matchBatchHolderKey(raw, flavor, holderKeys, usedKeys)
		if err != nil {
			return nil, err
		}
		// A credential arriving on the Final/HAIP issuance path has an issuer
		// identity the flow can check, so Config.CredentialAcceptance is
		// mandatory here rather than optional as on the Draft-13 path.
		parsedCredential, verification, err := w.verifyCredentialForAcceptanceContext(ctx, raw, flavor, holderKey, true)
		if err != nil {
			return nil, fmt.Errorf("failed to verify credential: %w", err)
		}
		entry := credstoreTypes.CredentialEntry{
			Id:         uuid.New().String(),
			ReceivedAt: time.Now(),
			Raw:        raw,
			MimeType:   mimeType,
		}
		saved = append(saved, &SavedCredential{
			Credential:   parsedCredential,
			Entry:        &entry,
			Verification: verification,
		})
	}

	for _, savedCredential := range saved {
		if err := w.credStore.SaveCredentialEntry(*savedCredential.Entry, credstoreTypes.SupportedCredStoreTypes(0)); err != nil {
			return nil, fmt.Errorf("failed to save credential entry: %w", err)
		}
	}
	return saved, nil
}

// matchBatchHolderKey selects the holder key whose RFC 7638 thumbprint equals
// the credential's cnf.jwk. A credential without cnf takes the first unused key
// (the acceptance rules then decide whether that is allowed); a cnf that names
// none of the supplied keys, or a key that was already consumed, is an error.
func matchBatchHolderKey(raw []byte, flavor credential.SupportedSerializationFlavor, holderKeys []jose.JSONWebKey, usedKeys []bool) (*jose.JSONWebKey, error) {
	if len(holderKeys) == 0 {
		return nil, nil
	}
	claimed, err := credentialConfirmationKey(raw, flavor)
	if err != nil {
		return nil, err
	}
	if claimed == nil {
		for index := range holderKeys {
			if !usedKeys[index] {
				usedKeys[index] = true
				publicKey := holderKeys[index].Public()
				return &publicKey, nil
			}
		}
		return nil, fmt.Errorf("credential response returned more credentials than holder keys")
	}
	claimedThumbprint, err := claimed.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("cnf jwk thumbprint failed: %w", err)
	}
	for index := range holderKeys {
		publicKey := holderKeys[index].Public()
		thumbprint, err := publicKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("holder key thumbprint failed: %w", err)
		}
		if !bytes.Equal(thumbprint, claimedThumbprint) {
			continue
		}
		if usedKeys[index] {
			return nil, fmt.Errorf("credential response bound two credentials to the same holder key")
		}
		usedKeys[index] = true
		return &publicKey, nil
	}
	return nil, fmt.Errorf("credential is bound to a holder key that was not part of the request")
}

// credentialConfirmationKey reads cnf.jwk from the issuer-signed JWT payload
// without verifying anything; nil when the credential carries no cnf.
func credentialConfirmationKey(raw []byte, flavor credential.SupportedSerializationFlavor) (*jose.JSONWebKey, error) {
	parts := strings.Split(issuerSignedJWT(flavor, raw), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("issuer JWT must have exactly three parts")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("issuer JWT payload is not base64url: %w", err)
	}
	var payload struct {
		Cnf *struct {
			JWK json.RawMessage `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("issuer JWT payload is not JSON: %w", err)
	}
	if payload.Cnf == nil || len(payload.Cnf.JWK) == 0 {
		return nil, nil
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(payload.Cnf.JWK); err != nil {
		return nil, fmt.Errorf("cnf jwk is invalid: %w", err)
	}
	return &key, nil
}

func rawCredentialBytes(value any) ([]byte, error) {
	switch credentialValue := value.(type) {
	case string:
		return []byte(credentialValue), nil
	case []byte:
		return credentialValue, nil
	case map[string]any:
		// OpenID4VCI 1.0 §8.3: "credentials" is an array of objects, each with
		// a "credential" member carrying the issued credential (a string for
		// JWT-based formats or a JSON object). Unwrap that envelope; any other
		// object is the credential itself.
		if inner, ok := credentialValue["credential"]; ok && len(credentialValue) == 1 {
			return rawCredentialBytes(inner)
		}
		raw, err := json.Marshal(credentialValue)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal credential value: %w", err)
		}
		return raw, nil
	default:
		raw, err := json.Marshal(credentialValue)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal credential value: %w", err)
		}
		return raw, nil
	}
}

func mimeTypeForCredentialConfiguration(issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string) string {
	if issuerMetadata != nil {
		if config, ok := issuerMetadata.CredentialConfigurationSupported[credentialConfigurationID]; ok {
			switch config.Format {
			case "dc+sd-jwt", "vc+sd-jwt":
				return string(credential.SDJwtVC)
			case "jwt_vc_json", "jwt_vc", "vc+jwt":
				return string(credential.JwtVc)
			}
		}
	}
	return string(credential.JwtVc)
}
