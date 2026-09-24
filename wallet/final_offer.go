package wallet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

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
	policy := w.oid4vciHTTPPolicy()
	if !strings.EqualFold(parsedURI.Scheme, "https") && !(policy.allowHTTP && strings.EqualFold(parsedURI.Scheme, "http")) {
		return "", fmt.Errorf("credential_offer_uri must use https")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURI.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to build credential_offer_uri request: %w", err)
	}
	request.Header.Set("Accept", "application/json")

	response, err := httpfetch.NoRedirect(policy.client).Do(request)
	if err != nil {
		return "", fmt.Errorf("failed to fetch credential_offer_uri: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("credential_offer_uri request failed: status=%d", response.StatusCode)
	}
	// §4.1.3: the Credential Offer Object MUST use the media type
	// application/json.
	if !httpfetch.MediaTypeIs(response.Header, "application/json") {
		return "", fmt.Errorf("credential_offer_uri response is not application/json")
	}
	body, err := httpfetch.ReadLimited(response, httpfetch.DefaultBodyLimit)
	if err != nil {
		return "", fmt.Errorf("failed to read credential_offer_uri response: %w", err)
	}
	if strings.TrimSpace(string(body)) == "" {
		return "", fmt.Errorf("credential_offer_uri response body is empty")
	}
	return string(body), nil
}

// oid4vciHTTPPolicy is the outbound HTTP configuration of the registered
// OpenID4VCI receiver, which the root-level fetches share.
type oid4vciHTTPPolicy struct {
	// client is the receiver's HTTP client; nil means a default one.
	client *http.Client
	// allowHTTP is the receiver's plain-HTTP escape for local test issuers.
	allowHTTP bool
}

// oid4vciHTTPPolicy reads the transport policy from the bundled OID4VCI
// receiver. A receiver of another type yields the default policy: a bounded
// client and no plain HTTP.
func (w *Wallet) oid4vciHTTPPolicy() oid4vciHTTPPolicy {
	if w.receiver == nil {
		return oid4vciHTTPPolicy{}
	}
	for _, plugin := range w.receiver.Plugins() {
		if receiver, ok := plugin.(*receiverOid4vci.Oid4vciReceiver); ok {
			return oid4vciHTTPPolicy{client: receiver.HTTPClient, allowHTTP: receiver.AllowHTTP}
		}
	}
	return oid4vciHTTPPolicy{}
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

// newOID4VCIFinalFlow builds the flow of an authorization code issuance: the
// credential stage of newOID4VCIFinalCredentialFlow plus how the client
// authenticates at the PAR and token endpoints. holderKeysRequired is false for
// the §5 authorization stage, which signs nothing with a holder key.
func (w *Wallet) newOID4VCIFinalFlow(
	req OID4VCIFinalReceiveRequest,
	finalReceiver receiverTypes.OID4VCIFinalTransport,
	discovery *oid4vciDiscovery,
	credentialConfigurationID string,
	holderKeysRequired bool,
) (*oid4vciFinalFlow, error) {
	authorizationServerMetadata := discovery.authorizationServerMetadata
	if authorizationServerMetadata.TokenEndpoint == nil {
		return nil, fmt.Errorf("token endpoint is missing on authorization server")
	}
	inputs := oid4vciFinalCredentialInputsFromRequest(req)
	inputs.holderKeysOptional = !holderKeysRequired
	flow, err := w.newOID4VCIFinalCredentialFlow(finalReceiver, discovery.issuerMetadata, credentialConfigurationID, inputs)
	if err != nil {
		return nil, err
	}
	flow.authorizationServerMetadata = authorizationServerMetadata
	flow.authorizationServerIssuer = discovery.authorizationServer

	// RFC 9126 §2 / HAIP §4.3: the PAR and token endpoints authenticate the
	// client the same way. Attestation-based client authentication (Appendix
	// E) and private_key_jwt are alternatives; with an attestation provider in
	// use no client_assertion is sent. private_key_jwt must be advertised by
	// the authorization server, and each request signs a fresh assertion
	// (RFC 7523 §3 unique jti).
	attestationInUse := w.clientAttestation != nil || req.AttesterKey.Key != nil
	if !attestationInUse && w.clientAuth.Method == receiverTypes.PrivateKeyJwt {
		if !asMetadataSupportsAuthMethod(authorizationServerMetadata, receiverTypes.PrivateKeyJwt) {
			return nil, fmt.Errorf("authorization server metadata does not advertise the configured private_key_jwt client authentication method")
		}
		if _, ok := resolveClientAuthMethod(w.clientAuth, authorizationServerMetadata); !ok {
			return nil, errNoUsableClientAuthMethod
		}
		tokenEndpointURL := receiverTypes.ResolveTokenEndpointURL(*authorizationServerMetadata.TokenEndpoint)
		clientAssertionAudience := resolveClientAssertionAudience(w.clientAuth, authorizationServerMetadata, tokenEndpointURL)
		flow.usePrivateKeyJwt = true
		flow.generateClientAssertion = func() (string, error) {
			return w.generateClientAssertion(
				w.clientAuth.Key,
				w.clientAuth.ClientID,
				clientAssertionAudience,
				w.clientAuth.signatureAlgorithm(),
			)
		}
	}

	// §6.2 judges the Token Response by whether the authorization request used
	// authorization_details (§5.1.1) or scope (§5.1.2).
	_, authorizationDetails, err := oid4vciAuthorizationRequestParameters(req.AuthorizationRequestType, credentialConfigurationID, flow.credentialConfiguration, w.profile.IsHAIP())
	if err != nil {
		return nil, err
	}
	if len(authorizationDetails) > 0 {
		flow.authorizationDetailsMode = AuthorizationDetailsRequired
	}
	return flow, nil
}

// oid4vciFinalCredentialInputsFromRequest collects the credential stage inputs
// of an authorization code request.
func oid4vciFinalCredentialInputsFromRequest(req OID4VCIFinalReceiveRequest) oid4vciFinalCredentialInputs {
	return oid4vciFinalCredentialInputs{
		holderKey:              req.HolderKey,
		additionalHolderKeys:   req.AdditionalHolderKeys,
		includeKeyAttestation:  req.IncludeKeyAttestation,
		externalKeyAttestation: req.ExternalKeyAttestation,
		keyAttestation:         req.KeyAttestation,
		policy: oid4vciFinalCredentialPolicy{
			encryption:                   req.CredentialEncryption,
			skipNotification:             req.SkipNotification,
			requireSingleCredential:      req.RequireSingleCredential,
			allowDraftCredentialResponse: req.AllowDraftCredentialResponse,
		},
	}
}

func validateOID4VCIFinalReceiveRequest(req OID4VCIFinalReceiveRequest) error {
	if req.HolderKey.Key == nil {
		return fmt.Errorf("holder key is required")
	}
	return validateOID4VCIFinalAuthorizationRequest(req)
}

// validateOID4VCIFinalAuthorizationRequest is the part of the request every
// stage needs: the receiving type, the client identity and redirect_uri that
// identify this wallet to the authorization server, and the credential to ask
// for. It is what BeginOID4VCIFinalAuthorization checks, because the §5
// authorization request carries no holder key — that one is only needed once the
// §8 Credential Request is built, which is after the browser has returned.
func validateOID4VCIFinalAuthorizationRequest(req OID4VCIFinalReceiveRequest) error {
	if req.Type != receiverTypes.Oid4vci {
		return fmt.Errorf("unsupported OID4VCI Final receiving type: %v", req.Type)
	}
	if req.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if req.RedirectURI == "" {
		return fmt.Errorf("redirect URI is required")
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
