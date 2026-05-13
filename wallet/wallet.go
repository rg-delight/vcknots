// Package wallet provides a verifiable credential wallet implementation.
//
// This package implements the OpenID for Verifiable Credentials specifications,
// enabling applications to receive credentials from issuers (OID4VCI) and present
// them to verifiers (OID4VP). It supports multiple credential formats including
// JWT-VC and SD-JWT-VC.
//
// Basic usage:
//
//	w, err := wallet.NewWallet()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	credential, err := w.ReceiveCredential(req)
//	if err != nil {
//		log.Fatal(err)
//	}
package wallet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/idprof"
	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/receiver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer"
	sdjwtvc "github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
	"github.com/trustknots/vcknots/wallet/verifier"
)

// Wallet implements high-level wallet operations for verifiable credentials.
//
// It coordinates multiple dispatcher components to execute complete workflows:
//   - ReceivingDispatcher: handles credential issuance protocols (e.g., OID4VCI)
//   - PresentationDispatcher: handles credential presentation protocols (e.g., OID4VP)
//   - SerializationDispatcher: handles credential serialization (JWT, SD-JWT)
//   - CredStoreDispatcher: manages credential storage
//   - IdentityProfileDispatcher: manages DIDs and identity profiles
//   - VerificationDispatcher: handles cryptographic signature verification
//
// Each workflow method (ReceiveCredential, PresentCredential) orchestrates
// multiple dispatchers to implement the complete protocol flow.
type Wallet struct {
	credStore  *credstore.CredStoreDispatcher
	idProf     *idprof.IdentityProfileDispatcher
	receiver   *receiver.ReceivingDispatcher
	serializer *serializer.SerializationDispatcher
	verifier   *verifier.VerificationDispatcher
	presenter  *presenter.PresentationDispatcher
}

// Config specifies the dispatcher components used by a Wallet.
//
// Each field represents an infrastructure component responsible for a specific
// aspect of wallet functionality. All fields are optional; if nil, a default
// implementation will be created automatically.
//
// This configuration is primarily used for dependency injection in testing
// or when custom plugin implementations are required.
type Config struct {
	CredStore  *credstore.CredStoreDispatcher
	IDProfiler *idprof.IdentityProfileDispatcher
	Receiver   *receiver.ReceivingDispatcher
	Serializer *serializer.SerializationDispatcher
	Verifier   *verifier.VerificationDispatcher
	Presenter  *presenter.PresentationDispatcher
}

// NewWallet creates a Wallet with default dispatcher configurations.
//
// This initializes all dispatcher components with their built-in plugin implementations:
//   - Credential storage using local file system
//   - OID4VCI for credential receiving
//   - OID4VP for credential presentation
//   - JWT and SD-JWT serialization support
//   - ES256 signature verification
//   - DID:key and DID:jwk identity profiles
//
// Returns an error if any dispatcher initialization fails.
func NewWallet() (*Wallet, error) {
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create credential store: %w", err)
	}

	receiver, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %w", err)
	}

	serializer, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create serializer: %w", err)
	}

	verifier, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	presenter, err := presenter.NewPresentationDispatcher(presenter.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create presenter: %w", err)
	}

	idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create identity profiler: %w", err)
	}

	config := Config{
		CredStore:  credStore,
		IDProfiler: idProf,
		Receiver:   receiver,
		Serializer: serializer,
		Verifier:   verifier,
		Presenter:  presenter,
	}

	return NewWalletWithConfig(config)
}

// NewWallet creates a Wallet with custom dispatcher configurations.
//
// This allows injection of custom dispatcher implementations or configurations.
// Any dispatcher field left nil in the config will be initialized with a default
// implementation automatically.
//
// This constructor is primarily used when:
//   - Testing with mock dispatchers
//   - Registering custom protocol plugins
//   - Using non-default storage backends
//
// For typical usage, prefer NewWallet instead.
func NewWalletWithConfig(config Config) (*Wallet, error) {
	if config.CredStore == nil {
		credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default credential store: %w", err)
		}
		config.CredStore = credStore
	}

	if config.IDProfiler == nil {
		idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default identity profiler: %w", err)
		}
		config.IDProfiler = idProf
	}

	if config.Receiver == nil {
		receiver, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default receiver: %w", err)
		}
		config.Receiver = receiver
	}

	if config.Serializer == nil {
		serializer, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default serializer: %w", err)
		}
		config.Serializer = serializer
	}

	if config.Verifier == nil {
		verifier, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default verifier: %w", err)
		}
		config.Verifier = verifier
	}

	if config.Presenter == nil {
		presenter, err := presenter.NewPresentationDispatcher(presenter.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default presenter: %w", err)
		}
		config.Presenter = presenter
	}

	return &Wallet{
		credStore:  config.CredStore,
		idProf:     config.IDProfiler,
		receiver:   config.Receiver,
		serializer: config.Serializer,
		verifier:   config.Verifier,
		presenter:  config.Presenter,
	}, nil
}

// SetReceiver sets the receiver dispatcher.
func (w *Wallet) SetReceiver(r *receiver.ReceivingDispatcher) {
	w.receiver = r
}

// GenerateDID generates a DID from given options.
func (w *Wallet) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error) {
	parts := strings.SplitN(options.TypeID, ":", 2)
	if len(parts) != 2 || parts[0] != "did" {
		return nil, fmt.Errorf("invalid DID type ID format: %s", options.TypeID)
	}
	method := parts[1]

	createOption := func(config *idprofTypes.CreateConfig) error {
		config.Set("method", method)
		config.Set("publicKey", &options.PublicKey)
		return nil
	}

	return w.idProf.Create("did", createOption)
}

// VerifyCredential verifies a credential with a public key.
func (w *Wallet) VerifyCredential(credential *credential.Credential, pubKey jose.JSONWebKey) bool {
	if credential.Proof == nil {
		return false
	}

	result, err := w.verifier.Verify(credential.Proof, &pubKey)
	return err != nil && result
}

// DIDCreateOptions holds options for DID creation.
type DIDCreateOptions struct {
	TypeID    string
	PublicKey jose.JSONWebKey
}

// ReceiveCredentialRequest holds parameters for receiving a credential.
type ReceiveCredentialRequest struct {
	CredentialOffer      *CredentialOffer
	Type                 receiverTypes.SupportedReceivingTypes
	Key                  IKeyEntry
	CachedIssuerMetadata *receiverTypes.CredentialIssuerMetadata
}

// CredentialOffer represents a credential offer from an issuer.
type CredentialOffer struct {
	CredentialIssuer           *url.URL                         `json:"credential_issuer"`
	CredentialConfigurationIDs []string                         `json:"credential_configuration_ids"`
	Grants                     map[string]*CredentialOfferGrant `json:"grants"`
}

// CredentialOfferGrant represents a grant in a credential offer.
type CredentialOfferGrant struct {
	PreAuthorizedCode string `json:"pre-authorized_code"`
	IssuerState       string `json:"issuer_state,omitempty"`
}

// OID4VCIFinalReceiveRequest holds the authorization-code Final/HAIP
// credential issuance inputs that are not discoverable from the credential
// offer or issuer metadata.
type OID4VCIFinalReceiveRequest struct {
	CredentialOffer                 *CredentialOffer
	Type                            receiverTypes.SupportedReceivingTypes
	ClientID                        string
	RedirectURI                     string
	HolderKey                       jose.JSONWebKey
	ClientKey                       jose.JSONWebKey
	AttesterKey                     jose.JSONWebKey
	AttesterIssuer                  string
	CredentialResponseEncryptionKey *jose.JSONWebKey
	HTTPClient                      *http.Client
}

type OID4VCIFinalReceiveResult struct {
	CredentialResponse *receiverTypes.CredentialResponse
	SavedCredentials   []*SavedCredential
	AccessToken        *receiverTypes.CredentialIssuanceAccessToken
}

func ParseCredentialOfferURL(rawURL string) (*CredentialOffer, error) {
	offerURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential offer URL: %w", err)
	}
	rawOffer := offerURL.Query().Get("credential_offer")
	if rawOffer == "" {
		return nil, fmt.Errorf("credential_offer query parameter is required")
	}

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
	offer := CredentialOffer{
		CredentialIssuer:           issuer,
		CredentialConfigurationIDs: raw.CredentialConfigurationIDs,
		Grants:                     raw.Grants,
	}
	return &offer, nil
}

// GetCredentialEntriesRequest holds parameters for querying credential entries.
type GetCredentialEntriesRequest struct {
	Offset int
	Limit  *int
	Filter func(*SavedCredential) bool
}

// SavedCredential represents a credential with its storage entry.
type SavedCredential struct {
	Credential *credential.Credential
	Entry      *types.CredentialEntry
}

// OID4VPFinalAuthorizationResponse represents the JSON payload that is
// encrypted into a direct_post.jwt response for OID4VP Final DCQL requests.
type OID4VPFinalAuthorizationResponse map[string]any

// IKeyEntry represents a key entry interface for signing operations.
type IKeyEntry interface {
	ID() string
	PublicKey() jose.JSONWebKey
	Sign(data []byte) ([]byte, error)
}

// convertEntryToSavedCredential converts a CredentialEntry to SavedCredential.
// Returns error if conversion fails (invalid flavor or deserialization error).
func (w *Wallet) convertEntryToSavedCredential(entry types.CredentialEntry) (*SavedCredential, error) {
	f, err := entry.SerializationFlavor()
	if err != nil {
		return nil, fmt.Errorf("invalid serialization flavor: %w", err)
	}

	cred, err := w.serializer.DeserializeCredential(f, entry.Raw)
	if err != nil {
		return nil, fmt.Errorf("deserialization failed: %w", err)
	}

	return &SavedCredential{
		Credential: cred,
		Entry:      &entry,
	}, nil
}

// generateJWTProof generates a JWT proof for credential requests.
// When clientID is nil, iss is omitted (anonymous pre-authorized flow).
// When clientID is provided, it must be non-empty.
func (w *Wallet) generateJWTProof(key IKeyEntry, did *idprofTypes.IdentityProfile, nonce *string, aud string, clientID *string) (string, error) {
	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "openid4vci-proof+jwt",
		"kid": did.ID,
	}

	payload := map[string]interface{}{
		"iat": time.Now().Unix(),
		"aud": aud,
	}

	if clientID != nil {
		if strings.TrimSpace(*clientID) == "" {
			return "", fmt.Errorf("clientID must be non-empty when provided")
		}
		payload["iss"] = *clientID
	}

	if nonce != nil && *nonce != "" {
		payload["nonce"] = *nonce
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	b64Header := base64.RawURLEncoding.EncodeToString(headerJSON)
	b64Payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := b64Header + "." + b64Payload
	signature, err := key.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	b64Signature := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + b64Signature, nil
}

// GetCredentialEntries retrieves credential entries with optional filtering.
func (w *Wallet) GetCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error) {
	if req.Filter != nil {
		result, err := w.credStore.GetCredentialEntries(0, nil, types.SupportedCredStoreTypes(0))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get credential entries: %w", err)
		}

		var filteredCredentials []*SavedCredential
		if result.Entries != nil {
			for _, entry := range *result.Entries {
				savedCred, err := w.convertEntryToSavedCredential(entry)
				if err != nil {
					continue // Skip invalid entries
				}

				if req.Filter(savedCred) {
					filteredCredentials = append(filteredCredentials, savedCred)
				}
			}
		}

		start := req.Offset
		if start > len(filteredCredentials) {
			start = len(filteredCredentials)
		}

		end := len(filteredCredentials)
		if req.Limit != nil && start+*req.Limit < end {
			end = start + *req.Limit
		}

		return filteredCredentials[start:end], len(filteredCredentials), nil
	}

	result, err := w.credStore.GetCredentialEntries(req.Offset, req.Limit, types.SupportedCredStoreTypes(0))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get credential entries: %w", err)
	}

	var savedCredentials []*SavedCredential
	if result.Entries != nil {
		for _, entry := range *result.Entries {
			savedCred, err := w.convertEntryToSavedCredential(entry)
			if err != nil {
				continue // Skip invalid entries
			}
			savedCredentials = append(savedCredentials, savedCred)
		}
	}

	totalCount := 0
	if result.TotalCount != nil {
		totalCount = *result.TotalCount
	}

	return savedCredentials, totalCount, nil
}

// GetCredentialEntry retrieves a single credential entry by ID.
func (w *Wallet) GetCredentialEntry(id string) (*SavedCredential, error) {
	entry, err := w.credStore.GetCredentialEntry(id, types.SupportedCredStoreTypes(0))
	if err != nil {
		return nil, fmt.Errorf("failed to get credential entry: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	savedCred, err := w.convertEntryToSavedCredential(*entry)
	if err != nil {
		return nil, fmt.Errorf("failed to convert credential: %w", err)
	}

	return savedCred, nil
}

// FetchCredentialIssuerMetadata fetches credential issuer metadata from the given endpoint.
func (w *Wallet) FetchCredentialIssuerMetadata(endpoint *url.URL, receivingType receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error) {
	uriField, err := common.ParseURIField(endpoint.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI field: %w", err)
	}

	return w.receiver.FetchIssuerMetadata(*uriField, receivingType)
}

// ReceiveCredential orchestrates the credential receiving flow.
func (w *Wallet) ReceiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error) {
	preAuthCode, err := w.validateCredentialOffer(req.CredentialOffer)
	if err != nil {
		return nil, err
	}

	issuerMetadata, authMetadata, err := w.fetchCredentialMetadata(req)
	if err != nil {
		return nil, err
	}

	accessToken, err := w.obtainAccessToken(req.Type, authMetadata, preAuthCode)
	if err != nil {
		return nil, err
	}

	credentialJWT, err := w.requestCredential(req, issuerMetadata, accessToken)
	if err != nil {
		return nil, err
	}

	return w.storeAndParseCredential(credentialJWT)
}

func (w *Wallet) ReceiveOID4VCIFinalCredential(req OID4VCIFinalReceiveRequest) (*OID4VCIFinalReceiveResult, error) {
	if req.Type != receiverTypes.Oid4vci {
		return nil, fmt.Errorf("unsupported OID4VCI Final receiving type: %v", req.Type)
	}
	if req.CredentialOffer == nil {
		return nil, fmt.Errorf("credential offer is required")
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if req.RedirectURI == "" {
		return nil, fmt.Errorf("redirect URI is required")
	}
	if req.HolderKey.Key == nil {
		return nil, fmt.Errorf("holder key is required")
	}
	if req.ClientKey.Key == nil {
		return nil, fmt.Errorf("client key is required")
	}
	if len(req.CredentialOffer.CredentialConfigurationIDs) == 0 {
		return nil, fmt.Errorf("credential configuration IDs are empty")
	}
	if req.CredentialOffer.CredentialIssuer == nil {
		return nil, fmt.Errorf("credential issuer is required")
	}
	authCodeGrant := req.CredentialOffer.Grants["authorization_code"]
	if authCodeGrant == nil {
		return nil, fmt.Errorf("authorization_code grant is not included in the offer")
	}

	finalReceiver, err := w.receiver.OID4VCIFinalReceiver(req.Type)
	if err != nil {
		return nil, fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}
	credentialConfigurationID := req.CredentialOffer.CredentialConfigurationIDs[0]
	issuerEndpoint, err := common.ParseURIField(req.CredentialOffer.CredentialIssuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential issuer endpoint: %w", err)
	}
	issuerMetadata, err := finalReceiver.FetchIssuerMetadata(*issuerEndpoint, req.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
	}

	authorizationServerEndpoint := *issuerEndpoint
	if len(issuerMetadata.AuthorizationServers) > 0 {
		authorizationServerEndpoint = issuerMetadata.AuthorizationServers[0]
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
	if issuerMetadata.NonceEndpoint == nil {
		return nil, fmt.Errorf("nonce endpoint is missing on credential issuer")
	}

	attestationHeaders, attestationChallenge, err := createOID4VCIAttestationHeaders(finalReceiver, req, authorizationServerMetadata)
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
	scope := credentialConfigurationID
	if config, ok := issuerMetadata.CredentialConfigurationSupported[credentialConfigurationID]; ok && config.Scope != "" {
		scope = config.Scope
	}
	parResponse, err := finalReceiver.PushAuthorizationRequest(*authorizationServerMetadata.PushedAuthorizationRequestEndpoint, receiverTypes.PushedAuthorizationRequest{
		ResponseType:        "code",
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               scope,
		State:               state,
		CodeChallenge:       base64.RawURLEncoding.EncodeToString(codeChallengeBytes[:]),
		CodeChallengeMethod: "S256",
		IssuerState:         authCodeGrant.IssuerState,
	}, attestationHeaders)
	if err != nil {
		return nil, fmt.Errorf("failed to push authorization request: %w", err)
	}

	code, err := requestOID4VCIAuthorizationCode(req.HTTPClient, authorizationServerMetadata.AuthorizationEndpoint, req.ClientID, parResponse.RequestURI, state)
	if err != nil {
		return nil, err
	}

	tokenAttestationHeaders := attestationHeaders
	if req.AttesterKey.Key != nil {
		tokenPop, err := finalReceiver.CreateClientAttestationPop(req.ClientKey, req.ClientID, authorizationServerMetadata.Issuer.String(), attestationChallenge, 5*time.Minute)
		if err != nil {
			return nil, err
		}
		tokenAttestationHeaders.ClientAttestationPop = tokenPop
	}
	token, err := finalReceiver.ExchangeAuthorizationCodeWithDpopRetry(
		*authorizationServerMetadata.TokenEndpoint,
		receiverTypes.AuthorizationCodeTokenRequest{
			Code:         code,
			RedirectURI:  req.RedirectURI,
			CodeVerifier: codeVerifier,
			ClientID:     req.ClientID,
		},
		tokenAttestationHeaders,
		func(nonce string) (string, error) {
			return finalReceiver.CreateDpopProof(req.ClientKey, http.MethodPost, authorizationServerMetadata.TokenEndpoint.String(), nonce, "")
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	nonce, err := finalReceiver.FetchNonce(*issuerMetadata.NonceEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credential nonce: %w", err)
	}
	proofJWT, err := finalReceiver.CreateCredentialRequestJWTProof(req.HolderKey, issuerMetadata.CredentialIssuer, nonce.CNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential request proof: %w", err)
	}

	credentialResponse, err := postOID4VCICredentialEndpoint(finalReceiver, issuerMetadata, req, *token, issuerMetadata.CredentialEndpoint, map[string]any{
		"credential_configuration_id": credentialConfigurationID,
		"proofs": map[string]any{
			"jwt": []string{proofJWT},
		},
	})
	if err != nil {
		return nil, err
	}
	if credentialResponse.TransactionID != "" {
		if issuerMetadata.DeferredCredentialEndpoint == nil {
			return nil, fmt.Errorf("deferred credential endpoint is missing on credential issuer")
		}
		credentialResponse, err = postOID4VCICredentialEndpoint(finalReceiver, issuerMetadata, req, *token, *issuerMetadata.DeferredCredentialEndpoint, map[string]any{
			"transaction_id": credentialResponse.TransactionID,
		})
		if err != nil {
			return nil, err
		}
	}
	if credentialResponse.NotificationID != "" && issuerMetadata.NotificationEndpoint != nil {
		err := finalReceiver.SendCredentialNotificationWithDpopRetry(
			*issuerMetadata.NotificationEndpoint,
			token.Token,
			receiverTypes.NotificationRequest{NotificationID: credentialResponse.NotificationID, Event: "credential_accepted"},
			func(nonce string) (string, error) {
				return finalReceiver.CreateDpopProof(req.ClientKey, http.MethodPost, issuerMetadata.NotificationEndpoint.String(), nonce, token.Token)
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to send credential notification: %w", err)
		}
	}

	savedCredentials, err := w.storeOID4VCIFinalCredentialResponse(credentialResponse, issuerMetadata, credentialConfigurationID)
	if err != nil {
		return nil, err
	}
	return &OID4VCIFinalReceiveResult{
		CredentialResponse: credentialResponse,
		SavedCredentials:   savedCredentials,
		AccessToken:        token,
	}, nil
}

// validateCredentialOffer validates the credential offer and extracts pre-authorization code.
func (w *Wallet) validateCredentialOffer(offer *CredentialOffer) (string, error) {
	if offer == nil {
		return "", fmt.Errorf("credential offer is required")
	}

	preAuthGrant := offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
	if preAuthGrant == nil {
		return "", fmt.Errorf("pre-authorization code is not included in the offer")
	}

	if len(offer.CredentialConfigurationIDs) == 0 {
		return "", fmt.Errorf("credential configuration IDs are empty")
	}

	preAuthCode := preAuthGrant.PreAuthorizedCode
	if preAuthCode == "" {
		return "", fmt.Errorf("pre-authorization code is not included in the offer")
	}

	return preAuthCode, nil
}

// fetchCredentialMetadata fetches issuer and authorization server metadata.
func (w *Wallet) fetchCredentialMetadata(req ReceiveCredentialRequest) (*receiverTypes.CredentialIssuerMetadata, *receiverTypes.AuthorizationServerMetadata, error) {
	var issuerMetadata *receiverTypes.CredentialIssuerMetadata
	var err error

	if req.CachedIssuerMetadata != nil {
		issuerMetadata = req.CachedIssuerMetadata
	} else {
		issuerMetadata, err = w.FetchCredentialIssuerMetadata(req.CredentialOffer.CredentialIssuer, req.Type)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
		}
	}

	if len(issuerMetadata.AuthorizationServers) == 0 {
		return nil, nil, fmt.Errorf("no authorization servers found in issuer metadata")
	}

	authMetadata, err := w.receiver.FetchAuthorizationServerMetadata(issuerMetadata.AuthorizationServers[0], req.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}

	if authMetadata == nil {
		return nil, nil, fmt.Errorf("authorization server metadata is nil")
	}

	if authMetadata.PreAuthorizedGrantAnonymousAccessSupported == nil || !*authMetadata.PreAuthorizedGrantAnonymousAccessSupported {
		return nil, nil, fmt.Errorf(
			"anonymous access support is missing on authorization server that the credential issuer relies on; PreAuthorizedGrantAnonymousAccessSupported: %v",
			authMetadata.PreAuthorizedGrantAnonymousAccessSupported,
		)
	}

	if authMetadata.TokenEndpoint == nil {
		return nil, nil, fmt.Errorf("token endpoint is missing on authorization server")
	}

	return issuerMetadata, authMetadata, nil
}

// obtainAccessToken obtains an access token using pre-authorization code.
func (w *Wallet) obtainAccessToken(receivingType receiverTypes.SupportedReceivingTypes, authMetadata *receiverTypes.AuthorizationServerMetadata, preAuthCode string) (*receiverTypes.CredentialIssuanceAccessToken, error) {
	accessToken, err := w.receiver.FetchAccessToken(receivingType, *authMetadata.TokenEndpoint, preAuthCode)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch access token: %w", err)
	}
	return accessToken, nil
}

// requestCredential requests the credential from the issuer with JWT proof.
func (w *Wallet) requestCredential(req ReceiveCredentialRequest, issuerMetadata *receiverTypes.CredentialIssuerMetadata, accessToken *receiverTypes.CredentialIssuanceAccessToken) (*string, error) {
	did, err := w.GenerateDID(DIDCreateOptions{
		TypeID:    "did:key",
		PublicKey: req.Key.PublicKey(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate DID: %w", err)
	}

	proof, err := w.generateJWTProof(req.Key, did, accessToken.CNonce, issuerMetadata.CredentialIssuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT proof: %w", err)
	}

	credentialJWT, err := w.receiver.ReceiveCredential(
		req.Type,
		issuerMetadata.CredentialEndpoint,
		"jwt_vc_json",
		*accessToken,
		&receiverTypes.CredentialDefinition{
			Type: append(req.CredentialOffer.CredentialConfigurationIDs, "VerifiableCredential"),
		},
		&proof,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to receive credential: %w", err)
	}

	return credentialJWT, nil
}

// storeAndParseCredential stores the credential and parses it for return.
func (w *Wallet) storeAndParseCredential(credentialJWT *string) (*SavedCredential, error) {
	credentialEntry := types.CredentialEntry{
		Id:         uuid.New().String(),
		ReceivedAt: time.Now(),
		Raw:        []byte(*credentialJWT),
		MimeType:   "application/vc+jwt",
	}

	if err := w.credStore.SaveCredentialEntry(credentialEntry, types.SupportedCredStoreTypes(0)); err != nil {
		return nil, fmt.Errorf("failed to save credential entry: %w", err)
	}

	f, err := credentialEntry.SerializationFlavor()
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	credential, err := w.serializer.DeserializeCredential(f, credentialEntry.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	return &SavedCredential{
		Credential: credential,
		Entry:      &credentialEntry,
	}, nil
}

func createOID4VCIAttestationHeaders(receiver receiverTypes.OID4VCIFinalReceiver, req OID4VCIFinalReceiveRequest, authMetadata *receiverTypes.AuthorizationServerMetadata) (receiverTypes.OAuthClientAttestationHeaders, string, error) {
	if req.AttesterKey.Key == nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", nil
	}
	attesterIssuer := req.AttesterIssuer
	if attesterIssuer == "" {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", fmt.Errorf("attester issuer is required when attester key is provided")
	}
	clientAttestation, err := receiver.CreateClientAttestation(req.ClientKey, req.AttesterKey, attesterIssuer, req.ClientID, 5*time.Minute)
	if err != nil {
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

	authIssuer := authMetadata.Issuer.String()
	if authIssuer == "" {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", fmt.Errorf("authorization server issuer is required for client attestation PoP")
	}
	clientAttestationPop, err := receiver.CreateClientAttestationPop(req.ClientKey, req.ClientID, authIssuer, attestationChallenge, 5*time.Minute)
	if err != nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", err
	}
	return receiverTypes.OAuthClientAttestationHeaders{
		ClientAttestation:    clientAttestation,
		ClientAttestationPop: clientAttestationPop,
	}, attestationChallenge, nil
}

func requestOID4VCIAuthorizationCode(client *http.Client, endpoint *common.URIField, clientID string, requestURI string, expectedState string) (string, error) {
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
	if state := redirectURL.Query().Get("state"); state != expectedState {
		return "", fmt.Errorf("authorization redirect state mismatch")
	}
	code := redirectURL.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("authorization redirect code is missing")
	}
	return code, nil
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

func postOID4VCICredentialEndpoint(receiver receiverTypes.OID4VCIFinalReceiver, issuerMetadata *receiverTypes.CredentialIssuerMetadata, req OID4VCIFinalReceiveRequest, accessToken receiverTypes.CredentialIssuanceAccessToken, endpoint common.URIField, payload map[string]any) (*receiverTypes.CredentialResponse, error) {
	addCredentialResponseEncryption(payload, issuerMetadata, req.CredentialResponseEncryptionKey)
	body, contentType, err := receiver.EncodeCredentialRequest(payload, issuerMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to encode credential request: %w", err)
	}
	rawResponse, err := receiver.PostCredentialEndpointWithDpopRetry(endpoint, accessToken.Token, body, contentType, func(nonce string) (string, error) {
		return receiver.CreateDpopProof(req.ClientKey, http.MethodPost, endpoint.String(), nonce, accessToken.Token)
	})
	if err != nil {
		return nil, err
	}

	var decryptionKey any
	if req.CredentialResponseEncryptionKey != nil {
		decryptionKey = req.CredentialResponseEncryptionKey.Key
	}
	response, err := receiver.DecodeCredentialResponse(rawResponse.Body, rawResponse.ContentType, decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode credential response: %w", err)
	}
	return response, nil
}

func addCredentialResponseEncryption(payload map[string]any, issuerMetadata *receiverTypes.CredentialIssuerMetadata, key *jose.JSONWebKey) {
	if issuerMetadata.CredentialResponseEncryption == nil || key == nil {
		return
	}
	publicKey := key.Public()
	if publicKey.Key == nil {
		return
	}
	enc := "A128GCM"
	if len(issuerMetadata.CredentialResponseEncryption.EncValuesSupported) > 0 && issuerMetadata.CredentialResponseEncryption.EncValuesSupported[0] != "" {
		enc = issuerMetadata.CredentialResponseEncryption.EncValuesSupported[0]
	}
	payload["credential_response_encryption"] = map[string]any{
		"jwk": publicKey,
		"enc": enc,
	}
}

func (w *Wallet) storeOID4VCIFinalCredentialResponse(response *receiverTypes.CredentialResponse, issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string) ([]*SavedCredential, error) {
	if response == nil {
		return nil, fmt.Errorf("credential response is nil")
	}
	mimeType := mimeTypeForCredentialConfiguration(issuerMetadata, credentialConfigurationID)
	values := []any{}
	if response.Credential != nil {
		values = append(values, response.Credential)
	}
	values = append(values, response.Credentials...)
	if len(values) == 0 {
		return nil, nil
	}

	saved := make([]*SavedCredential, 0, len(values))
	for _, value := range values {
		raw, err := rawCredentialBytes(value)
		if err != nil {
			return nil, err
		}
		entry := types.CredentialEntry{
			Id:         uuid.New().String(),
			ReceivedAt: time.Now(),
			Raw:        raw,
			MimeType:   mimeType,
		}
		if err := w.credStore.SaveCredentialEntry(entry, types.SupportedCredStoreTypes(0)); err != nil {
			return nil, fmt.Errorf("failed to save credential entry: %w", err)
		}
		savedCredential := &SavedCredential{Entry: &entry}
		if flavor, err := entry.SerializationFlavor(); err == nil {
			if parsed, err := w.serializer.DeserializeCredential(flavor, entry.Raw); err == nil {
				savedCredential.Credential = parsed
			}
		}
		saved = append(saved, savedCredential)
	}
	return saved, nil
}

func rawCredentialBytes(value any) ([]byte, error) {
	switch credentialValue := value.(type) {
	case string:
		return []byte(credentialValue), nil
	case []byte:
		return credentialValue, nil
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

func randomBase64URL(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// PresentCredential orchestrates the credential presentation flow.
func (w *Wallet) PresentCredential(uriString string, key IKeyEntry, options serializerTypes.SerializePresentationOptions) error {
	req, endpoint, err := w.parseAuthorizationRequest(uriString)
	if err != nil {
		return err
	}

	credentials, flavor, err := w.selectCredentialsForPresentation(req)
	if err != nil {
		return err
	}

	if options == nil {
		options, err = w.serializer.GetDefaultOption(*flavor)
		if err != nil {
			return err
		}
	}
	applyOID4VPRequestOptions(req, options)

	descriptorMap, err := w.buildDescriptorMap(credentials, flavor)
	if err != nil {
		return err
	}

	presentation, err := w.buildPresentation(credentials, flavor, descriptorMap, key, req)
	if err != nil {
		return err
	}

	return w.submitPresentation(presentation, flavor, endpoint, descriptorMap, req, key, options)
}

// BuildOID4VPFinalAuthorizationResponse builds an OID4VP Final DCQL
// authorization response from credentials already stored in the wallet. The
// returned value is ready to encrypt with Oid4vpPresenter.CreateEncryptedAuthorizationResponse
// and submit as the direct_post.jwt "response" form field.
func (w *Wallet) BuildOID4VPFinalAuthorizationResponse(uriString string, key IKeyEntry) (OID4VPFinalAuthorizationResponse, error) {
	req, _, err := w.parseAuthorizationRequest(uriString)
	if err != nil {
		return nil, err
	}
	if req.DCQLQuery == nil {
		return nil, fmt.Errorf("dcql_query is required for OID4VP Final authorization response")
	}

	credentials, selections, err := w.selectCredentialsForDCQL(req.DCQLQuery)
	if err != nil {
		return nil, err
	}

	vpToken := map[string][]string{}
	for _, selection := range selections {
		savedCredential := credentials[selection.CandidateID]
		flavor, err := savedCredential.Entry.SerializationFlavor()
		if err != nil {
			return nil, fmt.Errorf("failed to detect selected credential format: %w", err)
		}
		options, err := w.serializer.GetDefaultOption(flavor)
		if err != nil {
			return nil, err
		}
		if sdOpts, ok := options.(*sdjwtvc.SdJwtVcPresentationOptions); ok {
			sdOpts.SelectedClaims = selection.RequestedClaims
			sdOpts.RequireKeyBinding = true
			sdOpts.Audience = req.ClientID
			sdOpts.Nonce = req.Nonce
			sdOpts.TransactionData = req.TransactionData
			if req.TransactionDataHashesAlg != "" {
				sdOpts.TransactionDataHashesAlg = req.TransactionDataHashesAlg
			}
		}

		presentation, err := w.buildPresentation([]*SavedCredential{savedCredential}, &flavor, nil, key, req)
		if err != nil {
			return nil, err
		}
		serialized, _, err := w.serializer.SerializePresentation(flavor, presentation, key, options)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize selected credential %s: %w", selection.CandidateID, err)
		}
		vpToken[selection.QueryID] = append(vpToken[selection.QueryID], string(serialized))
	}

	response := OID4VPFinalAuthorizationResponse{
		"vp_token": vpToken,
	}
	if req.State != "" {
		response["state"] = req.State
	}
	return response, nil
}

// parseAuthorizationRequest parses the authorization request URI and determines the endpoint.
func (w *Wallet) parseAuthorizationRequest(uriString string) (*oid4vp.CredentialPresentationRequest, *url.URL, error) {
	req, err := w.presenter.ParseRequestURI(uriString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse request URI: %w", err)
	}

	if req.ResponseMode != oid4vp.OAuthAuthzReqResponseModeDirectPost && req.ResponseMode != oid4vp.OAuthAuthzReqResponseModeDirectPostJWT && req.RedirectURI == "" {
		return nil, nil, fmt.Errorf("redirect_uri is not specified")
	}

	var endpoint *url.URL
	if req.ResponseMode == oid4vp.OAuthAuthzReqResponseModeDirectPost || req.ResponseMode == oid4vp.OAuthAuthzReqResponseModeDirectPostJWT {
		if req.ResponseURI == "" {
			return nil, nil, fmt.Errorf("response_uri is not specified for response_mode=%s", req.ResponseMode)
		}
		endpoint, err = url.Parse(req.ResponseURI)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid response_uri: %w", err)
		}
	} else {
		endpoint, err = url.Parse(req.RedirectURI)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid redirect_uri: %w", err)
		}
	}

	if req.PresentationDefinition == nil {
		return nil, nil, fmt.Errorf("presentation definition is not specified")
	}

	return req, endpoint, nil
}

// selectCredentialsForPresentation selects credentials matching the presentation definition.
func (w *Wallet) selectCredentialsForPresentation(req *oid4vp.CredentialPresentationRequest) ([]*SavedCredential, *credential.SupportedSerializationFlavor, error) {
	entries, _, err := w.GetCredentialEntries(GetCredentialEntriesRequest{
		Offset: 0,
		Limit:  nil,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get credential entries: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("no credentials available for presentation")
	}

	// Use the first credential for testing
	selectedCredentials := entries[:1]

	// Validate that all selected credentials have the same serialization flavor
	serializationFlavor, err := w.validateSerializationFlavor(selectedCredentials)
	if err != nil {
		return nil, nil, err
	}

	return selectedCredentials, serializationFlavor, nil
}

func (w *Wallet) selectCredentialsForDCQL(query *oid4vp.DCQLQuery) (map[string]*SavedCredential, []oid4vp.DCQLCredentialSelection, error) {
	entries, _, err := w.GetCredentialEntries(GetCredentialEntriesRequest{
		Offset: 0,
		Limit:  nil,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get credential entries: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("no credentials available for presentation")
	}

	credentialsByID := map[string]*SavedCredential{}
	candidates := make([]oid4vp.DCQLCredentialCandidate, 0, len(entries))
	for _, entry := range entries {
		flavor, err := entry.Entry.SerializationFlavor()
		if err != nil {
			continue
		}
		_, vpFormat, err := flavor.OID4VPFormatIdentifier()
		if err != nil {
			continue
		}
		claimNames := []string{}
		if entry.Credential.Claims != nil {
			for name := range *entry.Credential.Claims {
				claimNames = append(claimNames, name)
			}
		}
		vct := ""
		if len(entry.Credential.Types) > 0 {
			vct = entry.Credential.Types[0]
		}
		credentialsByID[entry.Entry.Id] = entry
		candidates = append(candidates, oid4vp.DCQLCredentialCandidate{
			ID:     entry.Entry.Id,
			Format: vpFormat,
			VCT:    vct,
			Claims: claimNames,
		})
	}

	selections, err := oid4vp.ResolveSatisfiableDCQLCredentials(query, candidates)
	if err != nil {
		return nil, nil, err
	}
	if len(selections) == 0 {
		return nil, nil, fmt.Errorf("dcql_query cannot be satisfied by stored credentials")
	}
	return credentialsByID, selections, nil
}

// validateSerializationFlavor ensures all credentials have the same serialization flavor.
func (w *Wallet) validateSerializationFlavor(credentials []*SavedCredential) (*credential.SupportedSerializationFlavor, error) {
	var serializationFlavor *credential.SupportedSerializationFlavor

	for _, cred := range credentials {
		sf, err := cred.Entry.SerializationFlavor()
		if err != nil {
			return nil, fmt.Errorf("credential entry has no serialization flavor information")
		}

		if serializationFlavor == nil {
			serializationFlavor = &sf
		} else if *serializationFlavor != sf {
			return nil, fmt.Errorf("credentials have different serialization flavors")
		}
	}

	if serializationFlavor == nil {
		return nil, fmt.Errorf("failed to detect serialization flavor")
	}

	return serializationFlavor, nil
}

// buildDescriptorMap builds the presentation submission descriptor map.
func (w *Wallet) buildDescriptorMap(credentials []*SavedCredential, flavor *credential.SupportedSerializationFlavor) ([]presenterTypes.DescriptorMapItem, error) {
	vcFormat, vpFormat, err := flavor.OID4VPFormatIdentifier()
	if err != nil {
		return nil, fmt.Errorf("unsupported serialization format: %w", err)
	}

	var descriptorMap []presenterTypes.DescriptorMapItem
	for i := range credentials {
		descriptionItemID := uuid.New().String()
		descriptorPath := "$"
		if len(credentials) > 1 {
			descriptorPath = fmt.Sprintf("$[%d]", i)
		}
		// Temporary compatibility workaround:
		// the current verifier/request-object flow still requires
		// presentation_submission.descriptor_map, and dc+sd-jwt must point to the
		// combined vp_token itself with path "$" instead of JWT-VP style nested paths.
		// This format-specific branching does not belong in wallet core long term and
		// should be removed or moved once the verifier/request-object flow is
		// reorganized around DCQL.
		if vpFormat == "dc+sd-jwt" {
			descriptorMap = append(descriptorMap, presenterTypes.DescriptorMapItem{
				ID:     descriptionItemID,
				Format: vpFormat,
				Path:   descriptorPath,
			})
			continue
		}

		descriptorMap = append(descriptorMap, presenterTypes.DescriptorMapItem{
			ID:     descriptionItemID,
			Format: vpFormat,
			Path:   descriptorPath,
			PathNested: &presenterTypes.DescriptorMapItem{
				ID:     descriptionItemID,
				Format: vcFormat,
				Path:   fmt.Sprintf("$.verifiableCredential[%d]", i),
			},
		})
	}

	return descriptorMap, nil
}

// buildPresentation builds the credential presentation.
func (w *Wallet) buildPresentation(credentials []*SavedCredential, flavor *credential.SupportedSerializationFlavor, descriptorMap []presenterTypes.DescriptorMapItem, key IKeyEntry, req *oid4vp.CredentialPresentationRequest) (*credential.CredentialPresentation, error) {
	did, err := w.GenerateDID(DIDCreateOptions{
		TypeID:    "did:key",
		PublicKey: key.PublicKey(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate DID: %w", err)
	}

	var serializedCredentials [][]byte
	for _, entry := range credentials {
		serializedCredentials = append(serializedCredentials, entry.Entry.Raw)
	}

	presentation := &credential.CredentialPresentation{
		ID:          "urn:uuid:" + uuid.New().String(),
		Types:       []string{"VerifiablePresentation"},
		Credentials: serializedCredentials,
		Holder:      did.ID,
		Nonce:       &req.Nonce,
	}

	return presentation, nil
}

func applyOID4VPRequestOptions(req *oid4vp.CredentialPresentationRequest, options serializerTypes.SerializePresentationOptions) {
	if options == nil || req == nil || req.OAuthAuthzRequest == nil {
		return
	}
	options.SetAudience(req.ClientID)
	options.SetNonce(req.Nonce)
}

// submitPresentation serializes and submits the presentation to the verifier.
func (w *Wallet) submitPresentation(presentation *credential.CredentialPresentation, flavor *credential.SupportedSerializationFlavor, endpoint *url.URL, descriptorMap []presenterTypes.DescriptorMapItem, req *oid4vp.CredentialPresentationRequest, key IKeyEntry, options serializerTypes.SerializePresentationOptions) error {
	if len(req.TransactionData) > 0 {
		if sdOpts, ok := options.(*sdjwtvc.SdJwtVcPresentationOptions); ok && sdOpts != nil {
			transactionDataHashesAlg := req.TransactionDataHashesAlg
			if transactionDataHashesAlg == "" {
				// OID4VP transaction_data_hashes_alg default when omitted.
				transactionDataHashesAlg = "sha-256"
			}

			sdOpts.TransactionData = req.TransactionData
			sdOpts.TransactionDataHashesAlg = transactionDataHashesAlg
		}
	}

	bytes, _, err := w.serializer.SerializePresentation(
		*flavor,
		presentation,
		key,
		options,
	)
	if err != nil {
		return fmt.Errorf("failed to serialize presentation: %w", err)
	}

	presentationSubmission := presenterTypes.PresentationSubmission{
		ID:            uuid.New().String(),
		DefinitionID:  req.PresentationDefinition.ID,
		DescriptorMap: descriptorMap,
	}

	presentationRequest := &presenterTypes.PresentationRequest{
		State:          req.State,
		ClientMetadata: req.ClientMetadata,
	}

	if req.ClientMetadata != nil {
		presentationRequest.AuthorizationEncryptedRespAlg = req.ClientMetadata.AuthorizationEncryptedResponseAlg
		presentationRequest.AuthorizationEncryptedRespEnc = req.ClientMetadata.AuthorizationEncryptedResponseEnc
	}

	return w.presenter.Present(presenterTypes.Oid4vp, *endpoint, bytes, presentationSubmission, presentationRequest)
}
