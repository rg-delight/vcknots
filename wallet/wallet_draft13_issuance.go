package wallet

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// OID4VCIDraft13Transport is the transport a Draft 13 issuance needs. The
// endpoints it names are the ones whose request or error body differs from
// OpenID4VCI 1.0 (the Credential, Deferred Credential and Notification
// Endpoints); everything else — metadata discovery, the RFC 9126 pushed
// authorization request and the Section 6.1 token request — is the same HTTP on
// both versions, so it is taken from the transport the library already defines
// rather than declared a second time.
type OID4VCIDraft13Transport interface {
	receiverTypes.OID4VCIFinalTransport

	// RequestOID4VCIDraft13Credential posts a Draft 13 Section 7.2 Credential
	// Request.
	RequestOID4VCIDraft13Credential(ctx context.Context, endpoint common.URIField, accessToken receiverTypes.CredentialIssuanceAccessToken, request receiverOid4vci.Draft13CredentialRequest, proofFactory receiverTypes.DPoPProofFactory) (*receiverOid4vci.Draft13CredentialResponse, error)
	// RequestOID4VCIDraft13DeferredCredential posts a Draft 13 Section 9
	// Deferred Credential Request.
	RequestOID4VCIDraft13DeferredCredential(ctx context.Context, endpoint common.URIField, accessToken receiverTypes.CredentialIssuanceAccessToken, transactionID string, proofFactory receiverTypes.DPoPProofFactory) (*receiverOid4vci.Draft13CredentialResponse, error)
	// SendOID4VCIDraft13Notification posts a Draft 13 Section 10.1
	// Notification Request.
	SendOID4VCIDraft13Notification(ctx context.Context, endpoint common.URIField, accessToken receiverTypes.CredentialIssuanceAccessToken, notification receiverOid4vci.Draft13NotificationRequest, proofFactory receiverTypes.DPoPProofFactory) error
}

// oid4vciDraft13Flow is the per-issuance state a Draft 13 receive carries: the
// transport, the documents discovery produced and the configuration that was
// selected. It exists so the Pre-Authorized and Authorization Code halves share
// one credential request implementation.
type oid4vciDraft13Flow struct {
	transport                   OID4VCIDraft13Transport
	issuerMetadata              *receiverTypes.CredentialIssuerMetadata
	authorizationServerMetadata *receiverTypes.AuthorizationServerMetadata
	credentialConfigurationID   string
	credentialConfiguration     receiverTypes.CredentialConfiguration
}

// draft13Transport resolves the Draft 13 transport of the receiver plugin
// registered for receivingType.
func (w *Wallet) draft13Transport(receivingType receiverTypes.SupportedReceivingTypes) (OID4VCIDraft13Transport, error) {
	transport, err := w.receiver.OID4VCIFinalTransport(receivingType)
	if err != nil {
		return nil, fmt.Errorf("OID4VCI transport capability is not available: %w", err)
	}
	draft13, ok := transport.(OID4VCIDraft13Transport)
	if !ok {
		return nil, fmt.Errorf("OID4VCI Draft 13 transport capability is not available: %w", receiverTypes.ErrUnsupportedProtocol)
	}
	return draft13, nil
}

// draft13DPoPEnabled reports whether this issuance uses RFC 9449 DPoP. The
// wallet has to hold a DPoP key, and the authorization server has to have
// advertised dpop_signing_alg_values_supported (RFC 9449 Section 5.1): sending
// a DPoP proof to a server that never said it accepts one turns a working token
// request into a rejected one, and a wallet that has a key but no advertisement
// has no way to know the server would accept it.
//
// DPoPConfig.Enabled forces it on for a server whose metadata is incomplete but
// which is known to accept DPoP.
func (w *Wallet) draft13DPoPEnabled(authorizationServerMetadata *receiverTypes.AuthorizationServerMetadata) bool {
	if w.dpop.Key == nil {
		return false
	}
	if w.dpop.Enabled {
		return true
	}
	if authorizationServerMetadata == nil || authorizationServerMetadata.DpopSigningAlgValuesSupported == nil {
		return false
	}
	return len(*authorizationServerMetadata.DpopSigningAlgValuesSupported) > 0
}

// draft13DPoPProofFactory builds the RFC 9449 proof for one endpoint. A nil key
// yields a nil factory, which the transport reads as "this request carries no
// DPoP proof".
func (w *Wallet) draft13DPoPProofFactory(key IKeyEntry, method string, endpoint string, accessToken string) receiverTypes.DPoPProofFactory {
	if key == nil {
		return nil
	}
	return func(nonce string) (string, error) {
		var noncePointer *string
		if nonce != "" {
			noncePointer = &nonce
		}
		return w.generateDPoPProof(key, method, endpoint, accessToken, noncePointer)
	}
}

// discoverDraft13Metadata resolves the Credential Issuer metadata (or checks
// the cached copy) and the metadata of the authorization server the offer
// selects, with the same identity checks as the Final path.
func (w *Wallet) discoverDraft13Metadata(
	transport OID4VCIDraft13Transport,
	req OID4VCIDraft13ReceiveRequest,
	grant *CredentialOfferGrant,
) (*oid4vciDiscovery, error) {
	if err := w.validateDraft13CredentialIssuer(req.CredentialOffer.CredentialIssuer); err != nil {
		return nil, err
	}
	discovery, err := discoverOID4VCIIssuer(transport, req.Type, req.CredentialOffer.CredentialIssuer.String(), req.CachedIssuerMetadata, offeredAuthorizationServer(grant))
	if err != nil {
		return nil, err
	}
	if err := w.validateCredentialConfigurationIDs(req.CredentialOffer, discovery.issuerMetadata); err != nil {
		return nil, err
	}
	if discovery.authorizationServerMetadata.TokenEndpoint == nil {
		return nil, ErrDraft13TokenEndpointMissing
	}
	return discovery, nil
}

// validateDraft13CredentialIssuer applies the Section 11.2.1 rule that the
// Credential Issuer Identifier is an https URL with no query or fragment. Plain
// http is accepted only where the wallet's OpenID4VCI receiver was configured to
// allow it, which is a per-wallet decision for local test issuers rather than a
// process-wide one.
func (w *Wallet) validateDraft13CredentialIssuer(issuer *url.URL) error {
	if issuer != nil && strings.EqualFold(issuer.Scheme, "http") {
		if w.oid4vciHTTPPolicy().allowHTTP {
			asHTTPS := *issuer
			asHTTPS.Scheme = "https"
			return validateCredentialIssuerIdentifier(&asHTTPS)
		}
	}
	return validateCredentialIssuerIdentifier(issuer)
}

// selectDraft13CredentialConfiguration picks the Credential Configuration this
// issuance requests: the one the caller named, or the first the offer lists.
func selectDraft13CredentialConfiguration(
	req OID4VCIDraft13ReceiveRequest,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
) (string, receiverTypes.CredentialConfiguration, error) {
	configurationID := strings.TrimSpace(req.CredentialConfigurationID)
	if configurationID == "" {
		if len(req.CredentialOffer.CredentialConfigurationIDs) == 0 {
			return "", receiverTypes.CredentialConfiguration{}, fmt.Errorf("credential configuration IDs are empty")
		}
		configurationID = req.CredentialOffer.CredentialConfigurationIDs[0]
	} else {
		offered := false
		for _, id := range req.CredentialOffer.CredentialConfigurationIDs {
			if id == configurationID {
				offered = true
				break
			}
		}
		if !offered {
			return "", receiverTypes.CredentialConfiguration{}, fmt.Errorf("credential configuration %q is not one the offer lists: %w", configurationID, ErrDraft13CredentialConfigurationUnknown)
		}
	}
	configuration, ok := issuerMetadata.CredentialConfigurationSupported[configurationID]
	if !ok {
		return "", receiverTypes.CredentialConfiguration{}, fmt.Errorf("credential configuration %q: %w", configurationID, ErrDraft13CredentialConfigurationUnknown)
	}
	return configurationID, configuration, nil
}

// ReceiveOID4VCIDraft13Credential runs the OpenID4VCI Draft 13 Pre-Authorized
// Code Flow: it discovers the metadata the offer points at, exchanges the
// pre-authorized code for an access token, and requests the credential with a
// Section 7.2.1 key proof.
//
// Unlike ReceiveCredential it reports the whole Credential Response — the
// deferred transaction_id, the notification_id and the refreshed c_nonce — so a
// wallet that owns its persistence can resume and notify later, and it writes
// to the credential store only when the request asks it to.
func (w *Wallet) ReceiveOID4VCIDraft13Credential(ctx context.Context, req OID4VCIDraft13ReceiveRequest) (*OID4VCIDraft13ReceiveResult, error) {
	if err := requireOID4VCIContext(ctx, "issuer metadata discovery"); err != nil {
		return nil, err
	}
	if req.CredentialOffer == nil {
		return nil, ErrDraft13OfferMissing
	}
	if err := w.validateDraft13CredentialIssuer(req.CredentialOffer.CredentialIssuer); err != nil {
		return nil, err
	}
	grant := req.CredentialOffer.Grants[preAuthorizedCodeGrantType]
	if grant == nil || strings.TrimSpace(grant.PreAuthorizedCode) == "" {
		return nil, ErrDraft13PreAuthorizedCodeGrantMissing
	}
	preAuthorizedCode := grant.PreAuthorizedCode

	transport, err := w.draft13Transport(req.Type)
	if err != nil {
		return nil, err
	}
	discovery, err := w.discoverDraft13Metadata(transport, req, grant)
	if err != nil {
		return nil, err
	}
	issuerMetadata, authorizationServerMetadata := discovery.issuerMetadata, discovery.authorizationServerMetadata
	configurationID, configuration, err := selectDraft13CredentialConfiguration(req, issuerMetadata)
	if err != nil {
		return nil, err
	}
	flow := &oid4vciDraft13Flow{
		transport:                   transport,
		issuerMetadata:              issuerMetadata,
		authorizationServerMetadata: authorizationServerMetadata,
		credentialConfigurationID:   configurationID,
		credentialConfiguration:     configuration,
	}

	if err := requireOID4VCIContext(ctx, "the token request"); err != nil {
		return nil, err
	}
	accessToken, err := w.exchangeDraft13PreAuthorizedCode(ctx, flow, req, preAuthorizedCode)
	if err != nil {
		return nil, err
	}
	return w.requestDraft13Credential(ctx, flow, req, accessToken)
}

// exchangeDraft13PreAuthorizedCode performs the Section 6.1 token request of the
// Pre-Authorized Code Flow.
func (w *Wallet) exchangeDraft13PreAuthorizedCode(
	ctx context.Context,
	flow *oid4vciDraft13Flow,
	req OID4VCIDraft13ReceiveRequest,
	preAuthorizedCode string,
) (*receiverTypes.CredentialIssuanceAccessToken, error) {
	tokenEndpoint := *flow.authorizationServerMetadata.TokenEndpoint
	tokenEndpointURL := receiverTypes.ResolveTokenEndpointURL(tokenEndpoint)

	var proofFactory receiverTypes.DPoPProofFactory
	if w.draft13DPoPEnabled(flow.authorizationServerMetadata) {
		proofFactory = w.draft13DPoPProofFactory(w.dpop.Key, http.MethodPost, tokenEndpointURL, "")
	}

	request := receiverTypes.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: preAuthorizedCode,
		TxCode:            req.TxCode,
		ClientID:          clientIDForDraft13TokenRequest(w.clientAuth, req),
	}
	if method, ok := resolveClientAuthMethod(w.clientAuth, flow.authorizationServerMetadata); ok && method == receiverTypes.PrivateKeyJwt {
		audience := resolveClientAssertionAudience(w.clientAuth, flow.authorizationServerMetadata, tokenEndpointURL)
		request.ClientID = w.clientAuth.ClientID
		request.ClientAssertionFactory = func() (string, error) {
			return w.generateClientAssertion(w.clientAuth.Key, w.clientAuth.ClientID, audience, w.clientAuth.signatureAlgorithm())
		}
	}

	accessToken, err := flow.transport.ExchangePreAuthorizedCodeWithDpopAndAttestationRetry(ctx, tokenEndpoint, request, nil, proofFactory)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch access token: %w", err)
	}
	return accessToken, nil
}

// clientIDForDraft13TokenRequest resolves the client_id of a Pre-Authorized Code
// token request. Section 6.1 makes it OPTIONAL for this grant, so it is sent
// only when the caller or the wallet configuration named one; an authorization
// server that never advertised anonymous access is told which client is asking.
func clientIDForDraft13TokenRequest(clientAuth ClientAuthConfig, req OID4VCIDraft13ReceiveRequest) string {
	if id := strings.TrimSpace(req.ClientID); id != "" {
		return id
	}
	return strings.TrimSpace(clientAuth.ClientID)
}

// requestDraft13Credential performs the Section 7.2 Credential Request and reads
// the response, including the Section 7.3.2 invalid_proof retry with the fresh
// c_nonce the error carries.
func (w *Wallet) requestDraft13Credential(
	ctx context.Context,
	flow *oid4vciDraft13Flow,
	req OID4VCIDraft13ReceiveRequest,
	accessToken *receiverTypes.CredentialIssuanceAccessToken,
) (*OID4VCIDraft13ReceiveResult, error) {
	if err := requireOID4VCIContext(ctx, "the credential request"); err != nil {
		return nil, err
	}
	endpoint := flow.issuerMetadata.CredentialEndpoint
	if endpoint.String() == "" {
		return nil, ErrDraft13CredentialEndpointMissing
	}

	credentialIdentifier, err := CredentialIdentifierForConfiguration(accessToken, flow.credentialConfigurationID, AuthorizationDetailsOptional)
	if err != nil {
		// A token response whose authorization_details name another
		// configuration is not a reason to refuse an issuance the request can
		// still express by naming the format.
		credentialIdentifier = nil
	}

	nonce := ""
	if accessToken != nil && accessToken.CNonce != nil {
		nonce = *accessToken.CNonce
	}

	var proofFactory receiverTypes.DPoPProofFactory
	if strings.EqualFold(accessToken.TokenType, "DPoP") {
		if w.dpop.Key == nil {
			return nil, fmt.Errorf("dpop key is required for a DPoP-bound access token")
		}
		proofFactory = w.draft13DPoPProofFactory(w.dpop.Key, http.MethodPost, endpoint.String(), accessToken.Token)
	}

	post := func(currentNonce string) (*receiverOid4vci.Draft13CredentialResponse, error) {
		request, err := w.buildDraft13CredentialRequest(flow, req, credentialIdentifier, currentNonce)
		if err != nil {
			return nil, err
		}
		return flow.transport.RequestOID4VCIDraft13Credential(ctx, endpoint, *accessToken, *request, proofFactory)
	}

	response, err := post(nonce)
	if err != nil {
		// Section 7.3.2: on invalid_proof the issuer returns a fresh c_nonce and
		// the wallet retries once. A second failure is the issuer's answer.
		var endpointError *receiverOid4vci.Draft13CredentialEndpointError
		if errors.As(err, &endpointError) && endpointError.Code == "invalid_proof" && endpointError.CNonce != "" && endpointError.CNonce != nonce {
			nonce = endpointError.CNonce
			response, err = post(nonce)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to receive credential: %w", err)
	}

	result := &OID4VCIDraft13ReceiveResult{
		RawCredential:             response.Credential,
		CredentialFormat:          flow.credentialConfiguration.Format,
		AccessToken:               accessToken,
		TransactionID:             response.TransactionID,
		NotificationID:            response.NotificationID,
		CNonce:                    response.CNonce,
		DeferredIntervalSeconds:   response.Interval,
		IssuerMetadata:            flow.issuerMetadata,
		CredentialConfigurationID: flow.credentialConfigurationID,
	}
	if response.Credential == "" {
		if response.TransactionID == "" {
			return nil, ErrDraft13CredentialResponseInvalid
		}
		return w.pollDraft13DeferredCredential(ctx, flow, req, result, proofFactory)
	}
	if err := w.storeDraft13Credential(ctx, req.StoreCredential, req.Key, flow.credentialConfiguration.Format, result); err != nil {
		return nil, err
	}
	return result, nil
}

// buildDraft13CredentialRequest builds the Section 7.2 Credential Request body,
// signing the Section 7.2.1 key proof for the c_nonce this attempt carries.
func (w *Wallet) buildDraft13CredentialRequest(
	flow *oid4vciDraft13Flow,
	req OID4VCIDraft13ReceiveRequest,
	credentialIdentifier *string,
	nonce string,
) (*receiverOid4vci.Draft13CredentialRequest, error) {
	request := &receiverOid4vci.Draft13CredentialRequest{}
	if credentialIdentifier != nil && *credentialIdentifier != "" {
		// Section 7.2: credential_identifier and format are mutually exclusive.
		request.CredentialIdentifier = *credentialIdentifier
	} else {
		request.Format = flow.credentialConfiguration.Format
		request.VCT = flow.credentialConfiguration.VCT
		request.CredentialDefinition = draft13RequestCredentialDefinition(flow.credentialConfiguration.CredentialDefinition)
	}

	proof, err := w.draft13KeyProof(flow, req, nonce)
	if err != nil {
		return nil, err
	}
	if proof != "" {
		request.Proof = &receiverOid4vci.Draft13Proof{ProofType: "jwt", JWT: proof}
	}
	return request, nil
}

// draft13RequestCredentialDefinition is the credential_definition a Draft 13
// Credential Request names a jwt_vc_json or ldp_vc credential with (Appendix
// A.1.1.5, A.1.2.5): the credential type. The metadata member of the same name
// also describes every claim for display, which is not something the request
// asks for, so only type is carried over.
func draft13RequestCredentialDefinition(metadata *receiverTypes.CredentialDefinition) *receiverTypes.CredentialDefinition {
	if metadata == nil || len(metadata.Type) == 0 {
		return nil
	}
	return &receiverTypes.CredentialDefinition{Type: append([]string(nil), metadata.Type...)}
}

// draft13KeyProof builds the Section 7.2.1 key proof, or returns the empty
// string when the Credential Configuration asks for none.
func (w *Wallet) draft13KeyProof(flow *oid4vciDraft13Flow, req OID4VCIDraft13ReceiveRequest, nonce string) (string, error) {
	if strings.TrimSpace(req.PreSignedProof) != "" {
		return req.PreSignedProof, nil
	}
	configuration := flow.credentialConfiguration
	if !shouldAttachCredentialRequestProof(ReceiveCredentialRequest{}, &configuration) {
		return "", nil
	}
	if err := ensureJWTProofSupported(&configuration); err != nil {
		return "", err
	}
	if req.Key == nil {
		return "", ErrDraft13HolderKeyMissing
	}

	bindingMethod := resolveCredentialRequestProofBindingMethod(&configuration)
	keyID := ""
	if bindingMethod == credentialRequestProofBindingMethodKID {
		generated, err := w.GenerateDID(DIDCreateOptions{TypeID: "did:key", PublicKey: req.Key.PublicKey()})
		if err != nil {
			return "", fmt.Errorf("failed to generate DID: %w", err)
		}
		keyID, err = didKeyVerificationMethod(generated)
		if err != nil {
			return "", err
		}
	}

	var noncePointer *string
	if nonce != "" {
		noncePointer = &nonce
	}
	var clientID *string
	// Section 7.2.1: iss is the client_id of a wallet the authorization server
	// knows. The anonymous Pre-Authorized Code Flow has no client_id and omits
	// the claim rather than inventing one.
	if id := strings.TrimSpace(req.ClientID); id != "" {
		clientID = &id
	}
	return w.generateJWTProofWithTransform(
		req.Key,
		keyID,
		noncePointer,
		flow.issuerMetadata.CredentialIssuer,
		clientID,
		bindingMethod,
		req.ProofTransform,
	)
}

// storeDraft13Credential verifies the credential against the wallet's
// acceptance policy and saves it, when the caller asked for that. Nothing is
// stored when verification fails.
func (w *Wallet) storeDraft13Credential(
	ctx context.Context,
	store bool,
	key IKeyEntry,
	format string,
	result *OID4VCIDraft13ReceiveResult,
) error {
	if !store || result.RawCredential == "" {
		return nil
	}
	flavor, err := receiverOid4vci.OID4VCICredentialFormatToSerializationFlavor(format)
	if err != nil {
		return fmt.Errorf("unsupported credential format %q: %w", format, err)
	}
	var holderKey *jose.JSONWebKey
	if key != nil {
		publicKey := key.PublicKey()
		holderKey = &publicKey
	}
	raw := result.RawCredential
	// Draft 13 leaves issuer key resolution to ecosystem policy, so the
	// acceptance policy is optional here, as on ReceiveCredential.
	saved, err := w.storeAndParseCredential(ctx, &raw, credential.SupportedSerializationFlavor(flavor), holderKey, false)
	if err != nil {
		return err
	}
	result.SavedCredential = saved
	return nil
}
