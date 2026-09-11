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
		body, err := w.fetchCredentialOfferJSON(rawOfferURI)
		if err != nil {
			return nil, err
		}
		return parseCredentialOfferJSON(body)
	default:
		return nil, fmt.Errorf("credential_offer or credential_offer_uri query parameter is required")
	}
}

func (w *Wallet) fetchCredentialOfferJSON(credentialOfferURI string) (string, error) {
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

	request, err := http.NewRequest(http.MethodGet, parsedURI.String(), nil)
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

// ReceiveOID4VCIFinalCredential implements the OpenID4VCI 1.0 Final/HAIP
// authorization-code credential issuance flow.
func (w *Wallet) ReceiveOID4VCIFinalCredential(req OID4VCIFinalReceiveRequest) (*OID4VCIFinalReceiveResult, error) {
	if err := validateOID4VCIFinalReceiveRequest(req); err != nil {
		return nil, err
	}
	authCodeGrant := req.CredentialOffer.Grants["authorization_code"]
	if authCodeGrant == nil {
		return nil, fmt.Errorf("authorization_code grant is not included in the offer")
	}

	// HAIP §4.4.1: "Wallets MUST use ... an OAuth2 Client authentication
	// mechanism at OAuth2 Endpoints that support client authentication".
	if w.profile.IsHAIP() && w.clientAttestation == nil && req.AttesterKey.Key == nil && !clientAuthenticationConfigured(w.clientAuth) {
		return nil, fmt.Errorf("HAIP requires an OAuth2 client authentication mechanism")
	}

	finalReceiver, err := w.receiver.OID4VCIFinalReceiver(req.Type)
	if err != nil {
		return nil, fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}

	credentialConfigurationID := req.CredentialOffer.CredentialConfigurationIDs[0]
	holderKeys, err := resolveOID4VCIFinalHolderKeys(req)
	if err != nil {
		return nil, err
	}

	issuerEndpoint, err := common.ParseURIField(req.CredentialOffer.CredentialIssuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential issuer endpoint: %w", err)
	}
	issuerMetadata, err := finalReceiver.FetchIssuerMetadata(*issuerEndpoint, req.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
	}
	// §12.2.2/§12.2.4: the credential_issuer value in the metadata MUST match
	// the credential_issuer from the offer exactly; the wallet performs no
	// normalization.
	if issuerMetadata.CredentialIssuer != req.CredentialOffer.CredentialIssuer.String() {
		return nil, fmt.Errorf(
			"credential issuer metadata identifier %q does not match the credential offer credential_issuer %q",
			issuerMetadata.CredentialIssuer, req.CredentialOffer.CredentialIssuer.String())
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
		if config, ok := issuerMetadata.CredentialConfigurationSupported[credentialConfigurationID]; ok {
			if err := profileValidator.ValidateCredentialConfigurationForProfile(config); err != nil {
				return nil, fmt.Errorf("credential configuration does not satisfy the wallet profile: %w", err)
			}
		}
	}

	// OpenID4VCI 1.0 Appendix D / HAIP §4.5.1: a provider must be available
	// before anything is sent to the issuer when the selected configuration
	// requires a key attestation.
	keyAttestation, err := w.planOID4VCIKeyAttestation(issuerMetadata, credentialConfigurationID, req.IncludeKeyAttestation)
	if err != nil {
		return nil, err
	}

	// §12.3: select the authorization server. A grant authorization_server hint
	// MUST be listed in authorization_servers; otherwise the first listed server
	// is used, falling back to the credential issuer when the list is empty.
	authorizationServerEndpoint, err := selectOID4VCIAuthorizationServer(issuerMetadata, authCodeGrant, *issuerEndpoint)
	if err != nil {
		return nil, err
	}
	// §14.6: never request more proofs than the issuer's batch_size.
	if len(holderKeys) > issuerMetadata.BatchSize() {
		return nil, fmt.Errorf("requested %d credentials but the issuer batch_size is %d", len(holderKeys), issuerMetadata.BatchSize())
	}

	authorizationServerMetadata, err := finalReceiver.FetchAuthorizationServerMetadata(authorizationServerEndpoint, req.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}
	if authorizationServerMetadata.AuthorizationEndpoint == nil {
		return nil, fmt.Errorf("authorization endpoint is missing on authorization server")
	}
	if authorizationServerMetadata.PushedAuthorizationRequestEndpoint == nil {
		return nil, fmt.Errorf("pushed authorization request endpoint is missing on authorization server")
	}
	if authorizationServerMetadata.TokenEndpoint == nil {
		return nil, fmt.Errorf("token endpoint is missing on authorization server")
	}
	// RFC 8414 §3.3: the issuer identifier in the metadata MUST be identical to
	// the authorization server identifier used to fetch it. The verified value
	// is the attestation PoP audience.
	authorizationServerIssuer := authorizationServerMetadata.Issuer.String()
	if authorizationServerIssuer != authorizationServerEndpoint.String() {
		return nil, fmt.Errorf(
			"authorization server metadata issuer %q does not match the selected authorization server %q",
			authorizationServerIssuer, authorizationServerEndpoint.String())
	}

	// RFC 9126 §2 / HAIP §4.3: the PAR and token endpoints authenticate the
	// client the same way. When private_key_jwt is configured, each endpoint
	// gets its own freshly signed assertion because RFC 7523 §3 requires a
	// unique jti. The authorization server must advertise the method before any
	// request leaves the wallet.
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
	generateClientAssertion := func() (string, error) {
		return w.generateClientAssertion(
			w.clientAuth.Key,
			w.clientAuth.ClientID,
			clientAssertionAudience,
			w.clientAuth.signatureAlgorithm(),
		)
	}

	attestationHeaders, attestationChallenge, err := w.createOID4VCIAttestationHeaders(finalReceiver, req, authorizationServerMetadata, authorizationServerIssuer)
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
	codeChallengeBytes := sha256.Sum256([]byte(codeVerifier))
	// §5.1.1/§5.1.2: the Credential Configuration is requested either with
	// scope or with authorization_details. An explicit scope on a
	// configuration that does not advertise one fails here, before PAR.
	scope, authorizationDetails, err := oid4vciAuthorizationRequestParameters(
		req.AuthorizationRequestType,
		credentialConfigurationID,
		issuerMetadata.CredentialConfigurationSupported[credentialConfigurationID],
	)
	if err != nil {
		return nil, err
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
		IssuerState:          authCodeGrant.IssuerState,
	}
	if usePrivateKeyJwt {
		assertion, err := generateClientAssertion()
		if err != nil {
			return nil, fmt.Errorf("failed to generate PAR client assertion: %w", err)
		}
		parRequest.ClientAssertion = assertion
		parRequest.ClientAssertionType = receiverTypes.ClientAssertionTypeJWTBearer
	}
	parResponse, err := finalReceiver.PushAuthorizationRequest(*authorizationServerMetadata.PushedAuthorizationRequestEndpoint, parRequest, attestationHeaders)
	if err != nil {
		return nil, fmt.Errorf("failed to push authorization request: %w", err)
	}
	// §5.1.4: the request_uri expiry is measured from the PAR response time.
	parExpiresAt := time.Time{}
	if parResponse.ExpiresIn > 0 {
		parExpiresAt = time.Now().Add(time.Duration(parResponse.ExpiresIn) * time.Second)
	}

	issuerPolicy := authorizationResponseIssuerPolicy{
		expected: authorizationServerIssuer,
		required: w.profile.IsHAIP() || (authorizationServerMetadata.AuthorizationResponseIssParameterSupported != nil && *authorizationServerMetadata.AuthorizationResponseIssParameterSupported),
	}
	code, err := requestOID4VCIAuthorizationCode(req.HTTPClient, authorizationServerMetadata.AuthorizationEndpoint, req.ClientID, parResponse.RequestURI, state, req.RedirectURI, parExpiresAt, issuerPolicy)
	if err != nil {
		return nil, err
	}

	tokenRequest := receiverTypes.AuthorizationCodeTokenRequest{
		Code:         code,
		RedirectURI:  req.RedirectURI,
		CodeVerifier: codeVerifier,
		ClientID:     req.ClientID,
	}
	if usePrivateKeyJwt {
		// The factory is invoked once per HTTP attempt, so a DPoP nonce retry
		// re-sends the token request with a fresh client_assertion (new jti)
		// rather than replaying the first one.
		tokenRequest.ClientAssertionType = receiverTypes.ClientAssertionTypeJWTBearer
		tokenRequest.ClientAssertionFactory = generateClientAssertion
	}
	token, err := finalReceiver.ExchangeAuthorizationCodeWithDpopAndAttestationRetry(
		*authorizationServerMetadata.TokenEndpoint,
		tokenRequest,
		func() (receiverTypes.OAuthClientAttestationHeaders, error) {
			tokenAttestationHeaders := attestationHeaders
			if attestationHeaders.ClientAttestation != "" {
				tokenPop, err := finalReceiver.CreateClientAttestationPop(req.ClientKey, req.ClientID, authorizationServerIssuer, attestationChallenge, 5*time.Minute)
				if err != nil {
					return receiverTypes.OAuthClientAttestationHeaders{}, err
				}
				tokenAttestationHeaders.ClientAttestationPop = tokenPop
			}
			return tokenAttestationHeaders, nil
		},
		func(nonce string) (string, error) {
			return finalReceiver.CreateDpopProof(req.ClientKey, http.MethodPost, authorizationServerMetadata.TokenEndpoint.String(), nonce, "")
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	return w.receiveOID4VCIFinalCredentials(finalReceiver, issuerMetadata, credentialConfigurationID, holderKeys, token, req.ClientKey, req.CredentialResponseEncryptionKey, req.DeferredPollAttempts, keyAttestation)
}

// receiveOID4VCIFinalCredentials performs the §8 credential request (with §14.6
// batch proofs, §8.2 response encryption and §6.2 credential_identifier), the
// §9 deferred flow and the §11 notification bookkeeping.
func (w *Wallet) receiveOID4VCIFinalCredentials(
	finalReceiver receiverTypes.OID4VCIFinalReceiver,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	credentialConfigurationID string,
	holderKeys []jose.JSONWebKey,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	encryptionKey *jose.JSONWebKey,
	deferredPollAttempts int,
	keyAttestation *oid4vciKeyAttestationPlan,
) (*OID4VCIFinalReceiveResult, error) {
	// §8.2 / §10: build the credential_response_encryption request parameter and
	// fail closed when the issuer requires encryption but no key is supplied.
	encryptionParams, err := receiverOid4vci.CredentialResponseEncryptionParameters(issuerMetadata, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("credential response encryption: %w", err)
	}
	encryptionRequested := encryptionParams != nil

	credentialIdentifier := credentialIdentifierForConfiguration(token, issuerMetadata, credentialConfigurationID)
	build := oid4vciFinalCredentialRequestBodyFactory(finalReceiver, issuerMetadata, holderKeys, credentialIdentifier, credentialConfigurationID, encryptionParams, keyAttestation)

	// §7: the nonce endpoint is OPTIONAL. Only fetch c_nonce when the issuer
	// advertises one; otherwise the proof is built without a nonce.
	nonceEndpoint := issuerMetadata.NonceEndpoint
	initialNonce := ""
	if nonceEndpoint != nil {
		nonceResponse, err := finalReceiver.FetchNonceResponse(*nonceEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch credential nonce: %w", err)
		}
		initialNonce = nonceResponse.CNonce
	}

	credentialEndpoint := issuerMetadata.CredentialEndpoint
	rawResponse, _, err := finalReceiver.PostCredentialEndpointWithNonceRetry(
		credentialEndpoint,
		token.Token,
		nonceEndpoint,
		initialNonce,
		build,
		oid4vciFinalDpopProofFactory(finalReceiver, clientKey, credentialEndpoint, token.Token),
	)
	if err != nil {
		// CredentialEndpointError is retained so callers can branch with
		// errors.Is (invalid_proof, credential_request_denied, ...).
		return nil, fmt.Errorf("failed to receive credential: %w", err)
	}
	if encryptionRequested && !strings.Contains(strings.ToLower(rawResponse.ContentType), "application/jwt") {
		return nil, fmt.Errorf("credential response encryption was requested but the credential endpoint returned %q", rawResponse.ContentType)
	}
	credentialResponse, err := decodeOID4VCIFinalCredentialResponse(finalReceiver, rawResponse, encryptionKey)
	if err != nil {
		return nil, err
	}

	if credentialResponse.TransactionID != "" {
		return w.handleOID4VCIFinalDeferredResponse(finalReceiver, issuerMetadata, credentialConfigurationID, holderKeys, token, clientKey, encryptionKey, encryptionRequested, credentialResponse, deferredPollAttempts)
	}
	return w.storeAndNotifyOID4VCIFinalCredentials(finalReceiver, issuerMetadata, credentialConfigurationID, holderKeys, token, clientKey, credentialResponse)
}

func (w *Wallet) handleOID4VCIFinalDeferredResponse(
	finalReceiver receiverTypes.OID4VCIFinalReceiver,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	credentialConfigurationID string,
	holderKeys []jose.JSONWebKey,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	encryptionKey *jose.JSONWebKey,
	encryptionRequested bool,
	credentialResponse *receiverTypes.CredentialResponse,
	deferredPollAttempts int,
) (*OID4VCIFinalReceiveResult, error) {
	if issuerMetadata.DeferredCredentialEndpoint == nil {
		return nil, fmt.Errorf("deferred credential endpoint is missing on credential issuer")
	}
	if deferredPollAttempts <= 0 {
		// §9: do not report success with zero credentials. Hand the caller the
		// transaction_id and access token so it can resume after a restart.
		return pendingOID4VCIFinalResult(issuerMetadata, credentialConfigurationID, token, credentialResponse), newOID4VCIFinalIssuancePendingError(credentialResponse.Interval)
	}
	interval := time.Duration(credentialResponse.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return w.pollOID4VCIFinalDeferredCredential(finalReceiver, issuerMetadata, credentialConfigurationID, holderKeys, token, clientKey, encryptionKey, encryptionRequested, credentialResponse.TransactionID, credentialResponse.NotificationID, deferredPollAttempts, interval)
}

// ResumeOID4VCIFinalDeferredCredential resumes polling the §9 deferred
// credential endpoint using a transaction_id returned by an IssuancePending
// result. The issuer metadata may be supplied directly or refetched from
// IssuerURL.
func (w *Wallet) ResumeOID4VCIFinalDeferredCredential(req OID4VCIFinalDeferredRequest) (*OID4VCIFinalReceiveResult, error) {
	if req.Type != receiverTypes.Oid4vci {
		return nil, fmt.Errorf("unsupported OID4VCI Final receiving type: %v", req.Type)
	}
	if req.AccessToken == nil {
		return nil, fmt.Errorf("access token is required")
	}
	if strings.TrimSpace(req.TransactionID) == "" {
		return nil, fmt.Errorf("transaction ID is required")
	}
	finalReceiver, err := w.receiver.OID4VCIFinalReceiver(req.Type)
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
	encryptionRequested := encryptionParams != nil

	attempts := req.DeferredPollAttempts
	if attempts <= 0 {
		attempts = 1
	}
	interval := req.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return w.pollOID4VCIFinalDeferredCredential(finalReceiver, issuerMetadata, req.CredentialConfigurationID, holderKeys, req.AccessToken, req.ClientKey, req.CredentialResponseEncryptionKey, encryptionRequested, req.TransactionID, "", attempts, interval)
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
	finalReceiver receiverTypes.OID4VCIFinalReceiver,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	credentialConfigurationID string,
	holderKeys []jose.JSONWebKey,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	encryptionKey *jose.JSONWebKey,
	encryptionRequested bool,
	transactionID string,
	notificationID string,
	attempts int,
	interval time.Duration,
) (*OID4VCIFinalReceiveResult, error) {
	endpoint := *issuerMetadata.DeferredCredentialEndpoint
	pending := &OID4VCIFinalReceiveResult{
		AccessToken:               token,
		TransactionID:             transactionID,
		NotificationID:            notificationID,
		IssuerMetadata:            issuerMetadata,
		CredentialConfigurationID: credentialConfigurationID,
	}

	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 && interval > 0 {
			time.Sleep(interval)
		}
		body, err := json.Marshal(map[string]any{"transaction_id": transactionID})
		if err != nil {
			return nil, fmt.Errorf("failed to encode deferred credential request: %w", err)
		}
		rawResponse, _, err := finalReceiver.PostCredentialEndpointWithNonceRetry(
			endpoint,
			token.Token,
			nil,
			"",
			func(string) ([]byte, string, error) { return body, "application/json", nil },
			oid4vciFinalDpopProofFactory(finalReceiver, clientKey, endpoint, token.Token),
		)
		if err != nil {
			// §9.2: an issuance_pending error means poll again after the
			// interval the issuer advertised.
			if errors.Is(err, receiverTypes.ErrIssuancePending) {
				interval = deferredIntervalFromError(err, interval)
				continue
			}
			return nil, fmt.Errorf("failed to receive deferred credential: %w", err)
		}
		if encryptionRequested && !strings.Contains(strings.ToLower(rawResponse.ContentType), "application/jwt") {
			return nil, fmt.Errorf("credential response encryption was requested but the deferred credential endpoint returned %q", rawResponse.ContentType)
		}
		credentialResponse, err := decodeOID4VCIFinalCredentialResponse(finalReceiver, rawResponse, encryptionKey)
		if err != nil {
			return nil, err
		}
		if credentialHasNoCredentials(credentialResponse) {
			if credentialResponse.Interval > 0 {
				interval = time.Duration(credentialResponse.Interval) * time.Second
			}
			continue
		}
		result, err := w.storeAndNotifyOID4VCIFinalCredentials(finalReceiver, issuerMetadata, credentialConfigurationID, holderKeys, token, clientKey, credentialResponse)
		if err != nil {
			return nil, err
		}
		result.TransactionID = transactionID
		return result, nil
	}
	return pending, newOID4VCIFinalIssuancePendingError(int(interval / time.Second))
}

func credentialHasNoCredentials(response *receiverTypes.CredentialResponse) bool {
	if response == nil {
		return true
	}
	return response.Credential == nil && len(response.Credentials) == 0
}

func deferredIntervalFromError(err error, fallback time.Duration) time.Duration {
	var endpointError *receiverTypes.CredentialEndpointError
	if errors.As(err, &endpointError) && endpointError.Interval > 0 {
		return time.Duration(endpointError.Interval) * time.Second
	}
	return fallback
}

func newOID4VCIFinalIssuancePendingError(intervalSeconds int) error {
	return fmt.Errorf("credential issuance is pending: %w", &receiverTypes.CredentialEndpointError{
		StatusCode: http.StatusAccepted,
		Code:       "issuance_pending",
		Interval:   intervalSeconds,
	})
}

func (w *Wallet) storeAndNotifyOID4VCIFinalCredentials(
	finalReceiver receiverTypes.OID4VCIFinalReceiver,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	credentialConfigurationID string,
	holderKeys []jose.JSONWebKey,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	credentialResponse *receiverTypes.CredentialResponse,
) (*OID4VCIFinalReceiveResult, error) {
	result := pendingOID4VCIFinalResult(issuerMetadata, credentialConfigurationID, token, credentialResponse)
	savedCredentials, storeErr := w.storeOID4VCIFinalCredentialResponseBatch(credentialResponse, issuerMetadata, credentialConfigurationID, holderKeys)
	if storeErr != nil {
		// §11: a credential that failed verification/storage is reported with
		// credential_failure (best effort); the original failure is returned.
		if notifyErr := notifyOID4VCIFinalCredential(finalReceiver, issuerMetadata, token, clientKey, result.NotificationID, "credential_failure"); notifyErr != nil {
			return nil, errors.Join(storeErr, fmt.Errorf("failed to send credential_failure notification: %w", notifyErr))
		}
		return nil, storeErr
	}
	result.SavedCredentials = savedCredentials
	// §11: credential_accepted MUST only be sent after the credential was
	// successfully stored.
	if result.NotificationID != "" && issuerMetadata.NotificationEndpoint != nil {
		if notifyErr := notifyOID4VCIFinalCredential(finalReceiver, issuerMetadata, token, clientKey, result.NotificationID, "credential_accepted"); notifyErr != nil {
			return nil, fmt.Errorf("failed to send credential_accepted notification: %w", notifyErr)
		}
	}
	return result, nil
}

// NotifyOID4VCIFinalCredentialDeleted sends the §11 credential_deleted
// notification for a credential the wallet removed from storage.
func (w *Wallet) NotifyOID4VCIFinalCredentialDeleted(req OID4VCIFinalNotificationRequest) error {
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
	finalReceiver, err := w.receiver.OID4VCIFinalReceiver(req.Type)
	if err != nil {
		return fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}
	return notifyOID4VCIFinalCredential(finalReceiver, req.IssuerMetadata, req.AccessToken, req.ClientKey, req.NotificationID, "credential_deleted")
}

func notifyOID4VCIFinalCredential(
	finalReceiver receiverTypes.OID4VCIFinalReceiver,
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
	return finalReceiver.SendCredentialNotificationWithDpopRetry(
		endpoint,
		token.Token,
		receiverTypes.NotificationRequest{NotificationID: notificationID, Event: event},
		oid4vciFinalDpopProofFactory(finalReceiver, clientKey, endpoint, token.Token),
	)
}

func oid4vciFinalCredentialRequestBodyFactory(
	receiver receiverTypes.OID4VCIFinalReceiver,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	holderKeys []jose.JSONWebKey,
	credentialIdentifier *string,
	credentialConfigurationID string,
	encryptionParams map[string]any,
	keyAttestation *oid4vciKeyAttestationPlan,
) receiverTypes.CredentialRequestBodyFactory {
	return func(cNonce string) ([]byte, string, error) {
		keyAttestationJWT := ""
		if keyAttestation != nil {
			request := KeyAttestationRequest{
				Keys:     holderKeys,
				Nonce:    cNonce,
				Audience: issuerMetadata.CredentialIssuer,
			}
			attestation, err := keyAttestation.provider.KeyAttestation(context.Background(), request)
			if err != nil {
				return nil, "", fmt.Errorf("failed to obtain key attestation: %w", err)
			}
			if err := validateKeyAttestation(attestation, request, keyAttestation.requireX5C, time.Now()); err != nil {
				return nil, "", err
			}
			keyAttestationJWT = attestation.JWT
		}
		proofs := make([]string, 0, len(holderKeys))
		for _, key := range holderKeys {
			proof, err := receiver.CreateCredentialRequestJWTProofWithKeyAttestation(key, issuerMetadata.CredentialIssuer, cNonce, keyAttestationJWT)
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
			payload["credential_configuration_id"] = credentialConfigurationID
		}
		if encryptionParams != nil {
			payload["credential_response_encryption"] = encryptionParams
		}
		body, contentType, err := receiver.EncodeCredentialRequest(payload, issuerMetadata)
		if err != nil {
			return nil, "", fmt.Errorf("failed to encode credential request: %w", err)
		}
		return body, contentType, nil
	}
}

func oid4vciFinalDpopProofFactory(receiver receiverTypes.OID4VCIFinalReceiver, clientKey jose.JSONWebKey, endpoint common.URIField, accessToken string) receiverTypes.DPoPProofFactory {
	return func(nonce string) (string, error) {
		return receiver.CreateDpopProof(clientKey, http.MethodPost, endpoint.String(), nonce, accessToken)
	}
}

func decodeOID4VCIFinalCredentialResponse(receiver receiverTypes.OID4VCIFinalReceiver, raw *receiverTypes.CredentialEndpointHTTPResponse, key *jose.JSONWebKey) (*receiverTypes.CredentialResponse, error) {
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
func oid4vciAuthorizationRequestParameters(requestedType, credentialConfigurationID string, config receiverTypes.CredentialConfiguration) (string, []map[string]any, error) {
	scope := strings.TrimSpace(config.Scope)
	authorizationDetails := []map[string]any{
		{
			"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
			"credential_configuration_id": credentialConfigurationID,
		},
	}
	switch strings.TrimSpace(requestedType) {
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

func credentialIdentifierForConfiguration(accessToken *receiverTypes.CredentialIssuanceAccessToken, issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string) *string {
	if accessToken == nil {
		return nil
	}
	var identifiers []string
	for _, detail := range accessToken.AuthorizationDetails {
		if detail.Type != receiverTypes.AuthorizationDetailTypeOpenIDCredential {
			continue
		}
		// §6.2: each authorization_details entry corresponds to the Credential
		// Configuration named by credential_configuration_id. When the issuer
		// echoes it, use the first credential_identifier of the matching entry.
		if detail.CredentialConfigurationID == credentialConfigurationID {
			for _, identifier := range detail.CredentialIdentifiers {
				if identifier != "" {
					selected := identifier
					return &selected
				}
			}
		}
		for _, identifier := range detail.CredentialIdentifiers {
			if identifier != "" {
				identifiers = append(identifiers, identifier)
			}
		}
	}
	if len(identifiers) == 0 {
		return nil
	}
	if issuerMetadata != nil {
		if config, ok := issuerMetadata.CredentialConfigurationSupported[credentialConfigurationID]; ok && config.CredentialIdentifier != "" {
			for _, identifier := range identifiers {
				if identifier == config.CredentialIdentifier {
					selected := identifier
					return &selected
				}
			}
		}
	}
	selected := identifiers[0]
	return &selected
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
	if req.CredentialOffer == nil {
		return fmt.Errorf("credential offer is required")
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
	if len(req.CredentialOffer.CredentialConfigurationIDs) == 0 {
		return fmt.Errorf("credential configuration IDs are empty")
	}
	if req.CredentialOffer.CredentialIssuer == nil {
		return fmt.Errorf("credential issuer is required")
	}
	return nil
}

func selectOID4VCIAuthorizationServer(issuerMetadata *receiverTypes.CredentialIssuerMetadata, grant *CredentialOfferGrant, issuerEndpoint common.URIField) (common.URIField, error) {
	if issuerMetadata == nil {
		return common.URIField{}, fmt.Errorf("issuer metadata is required")
	}
	hint := strings.TrimSpace(grant.AuthorizationServer)
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
	provider   KeyAttestationProvider
	requireX5C bool
}

// planOID4VCIKeyAttestation decides whether a key attestation is needed. It
// fails before any request is sent when the issuer requires one but the wallet
// has no provider, naming HAIP §4.5.1 under the HAIP profile.
func (w *Wallet) planOID4VCIKeyAttestation(metadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string, include bool) (*oid4vciKeyAttestationPlan, error) {
	required := issuerRequiresKeyAttestation(metadata, credentialConfigurationID)
	if required && w.keyAttestation == nil {
		if w.profile.IsHAIP() {
			return nil, fmt.Errorf("HAIP §4.5.1 requires wallets to support key attestations: the issuer requires a key attestation but no KeyAttestation provider is configured")
		}
		return nil, fmt.Errorf("the issuer requires a key attestation but no KeyAttestation provider is configured")
	}
	if w.keyAttestation == nil || (!required && !include) {
		return nil, nil
	}
	return &oid4vciKeyAttestationPlan{provider: w.keyAttestation, requireX5C: w.profile.IsHAIP()}, nil
}

// issuerRequiresKeyAttestation reports whether the selected credential
// configuration advertises proof_types_supported.jwt.key_attestations_required
// (OpenID4VCI 1.0 Appendix D). Presence of the object, even empty, is the
// signal.
func issuerRequiresKeyAttestation(metadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string) bool {
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

func (w *Wallet) createOID4VCIAttestationHeaders(receiver receiverTypes.OID4VCIFinalReceiver, req OID4VCIFinalReceiveRequest, authMetadata *receiverTypes.AuthorizationServerMetadata, authorizationServerIssuer string) (receiverTypes.OAuthClientAttestationHeaders, string, error) {
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
	// HAIP §4.4.1: verify the provider result before any request carrying the
	// attestation leaves the wallet; the attester signature is not verified
	// because the wallet does not hold the attester key.
	attestation, err := provider.ClientAttestation(context.Background(), attestationRequest)
	if err != nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", fmt.Errorf("failed to obtain client attestation: %w", err)
	}
	if err := validateClientAttestation(attestation, attestationRequest, w.profile.IsHAIP(), time.Now()); err != nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", err
	}

	attestationChallenge := ""
	if authMetadata.ChallengeEndpoint != nil {
		challenge, err := receiver.FetchClientAttestationChallenge(*authMetadata.ChallengeEndpoint)
		if err != nil {
			return receiverTypes.OAuthClientAttestationHeaders{}, "", fmt.Errorf("failed to fetch client attestation challenge: %w", err)
		}
		attestationChallenge = challenge.AttestationChallenge
	}

	clientAttestationPop, err := receiver.CreateClientAttestationPop(req.ClientKey, req.ClientID, authorizationServerIssuer, attestationChallenge, 5*time.Minute)
	if err != nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", err
	}
	return receiverTypes.OAuthClientAttestationHeaders{
		ClientAttestation:    attestation.JWT,
		ClientAttestationPop: clientAttestationPop,
	}, attestationChallenge, nil
}

// requestOID4VCIAuthorizationCode drives the §5.2 authorization endpoint with
// the pushed request_uri and validates the RFC 6749 §4.1.2 / RFC 9207
// authorization response. parExpiresAt is the §5.1.4 request_uri expiry
// measured from the PAR response time; the zero value disables the check.
// authorizationResponseIssuerPolicy is the RFC 9207 expectation for the
// authorization response: expected is the authorization server's issuer
// identifier; required is true when the server advertises
// authorization_response_iss_parameter_supported or the profile is HAIP (FAPI
// 2.0 §5.3.2.2 requires clients to check iss).
type authorizationResponseIssuerPolicy struct {
	expected string
	required bool
}

func requestOID4VCIAuthorizationCode(client *http.Client, endpoint *common.URIField, clientID string, requestURI string, expectedState string, registeredRedirectURI string, parExpiresAt time.Time, issuer authorizationResponseIssuerPolicy) (string, error) {
	if !parExpiresAt.IsZero() && !time.Now().Before(parExpiresAt) {
		return "", fmt.Errorf("pushed authorization request_uri expired before use")
	}

	authorizationURL := url.URL(*endpoint)
	query := authorizationURL.Query()
	query.Set("client_id", clientID)
	query.Set("request_uri", requestURI)
	authorizationURL.RawQuery = query.Encode()

	authClient := noRedirectHTTPClient(client)
	response, err := authClient.Get(authorizationURL.String())
	if err != nil {
		return "", fmt.Errorf("failed to request authorization endpoint: %w", err)
	}
	defer response.Body.Close()
	location := response.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("authorization endpoint did not redirect: %d", response.StatusCode)
	}
	redirectURL, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("failed to parse authorization redirect: %w", err)
	}
	if !redirectURL.IsAbs() {
		redirectURL = authorizationURL.ResolveReference(redirectURL)
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

func (w *Wallet) storeOID4VCIFinalCredentialResponse(response *receiverTypes.CredentialResponse, issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string, holderKey *jose.JSONWebKey) ([]*SavedCredential, error) {
	var holderKeys []jose.JSONWebKey
	if holderKey != nil {
		holderKeys = append(holderKeys, *holderKey)
	}
	return w.storeOID4VCIFinalCredentialResponseBatch(response, issuerMetadata, credentialConfigurationID, holderKeys)
}

// storeOID4VCIFinalCredentialResponseBatch verifies each returned credential
// against the holder key at the same index (§14.6 batch order) and stores
// nothing when any credential fails acceptance.
func (w *Wallet) storeOID4VCIFinalCredentialResponseBatch(response *receiverTypes.CredentialResponse, issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string, holderKeys []jose.JSONWebKey) ([]*SavedCredential, error) {
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
		parsedCredential, verification, err := w.verifyCredentialForAcceptance(raw, flavor, holderKey)
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
