package wallet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/env"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// maxCredentialOfferResponseBytes bounds the §4.1.1 credential_offer_uri
// response so a hostile issuer cannot exhaust wallet memory during offer
// resolution.
const maxCredentialOfferResponseBytes int64 = 64 << 10

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
// holderKeysRequired says whether the stage this flow is built for needs the
// holder keys. Only the §8 Credential Request and the Appendix D key attestation
// it may carry use them, so the §5 authorization stage passes false.
func (w *Wallet) newOID4VCIFinalFlow(
	req OID4VCIFinalReceiveRequest,
	finalReceiver receiverTypes.OID4VCIFinalTransport,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	authorizationServerMetadata *receiverTypes.AuthorizationServerMetadata,
	credentialConfigurationID string,
	holderKeysRequired bool,
) (*oid4vciFinalFlow, error) {
	holderKeys, err := resolveOID4VCIFinalHolderKeys(req, holderKeysRequired)
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
	// requires a key attestation, unless the caller declared that it mints the
	// attestation itself.
	keyAttestation, err := w.planOID4VCIKeyAttestation(
		issuerMetadata,
		credentialConfigurationID,
		req.IncludeKeyAttestation || req.KeyAttestation != nil,
		req.ExternalKeyAttestation || req.KeyAttestation != nil,
	)
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

	// §5.1.1/§5.1.2: record whether the request used authorization_details, so
	// the Token Response is judged against the §6.2 mode that matches the
	// request that produced it. The mode is derived here, from the same
	// oid4vciAuthorizationRequestParameters decision the PAR uses, rather than
	// being stored on the serialisable authorization state.
	_, authorizationDetails, err := oid4vciAuthorizationRequestParameters(req.AuthorizationRequestType, credentialConfigurationID, config, w.profile.IsHAIP())
	if err != nil {
		return nil, err
	}
	authorizationDetailsMode := AuthorizationDetailsOptional
	if len(authorizationDetails) > 0 {
		authorizationDetailsMode = AuthorizationDetailsRequired
	}

	return &oid4vciFinalFlow{
		receiver:                    finalReceiver,
		signer:                      w.oid4vciFinalSigner(finalReceiver),
		issuerMetadata:              issuerMetadata,
		authorizationServerMetadata: authorizationServerMetadata,
		authorizationServerIssuer:   authorizationServerIssuer,
		credentialConfigurationID:   credentialConfigurationID,
		credentialConfiguration:     config,
		authorizationDetailsMode:    authorizationDetailsMode,
		holderKeys:                  holderKeys,
		keyAttestation:              keyAttestation,
		suppliedKeyAttestation:      req.KeyAttestation,
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
