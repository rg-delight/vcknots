package wallet

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// ReceiveCredentialRequest holds parameters for receiving a credential.
type ReceiveCredentialRequest struct {
	CredentialOffer      *CredentialOffer
	Type                 receiverTypes.SupportedReceivingTypes
	Key                  IKeyEntry
	RequestedFormat      credential.SupportedSerializationFlavor
	CachedIssuerMetadata *receiverTypes.CredentialIssuerMetadata
	TxCode               string `json:"tx_code,omitempty"`
}

// CredentialOffer represents a credential offer from an issuer.
type CredentialOffer struct {
	CredentialIssuer           *url.URL                         `json:"credential_issuer"`
	CredentialConfigurationIDs []string                         `json:"credential_configuration_ids"`
	Grants                     map[string]*CredentialOfferGrant `json:"grants"`
}

// CredentialOfferGrant represents a grant in a credential offer.
type CredentialOfferGrant struct {
	PreAuthorizedCode string           `json:"pre-authorized_code"`
	IssuerState       string           `json:"issuer_state,omitempty"`
	TxCode            *TransactionCode `json:"tx_code,omitempty"`
	// AuthorizationServer is the §4.1.1 authorization_server grant parameter:
	// the issuer-recommended authorization server identifier. It MUST be one of
	// the credential issuer metadata's authorization_servers.
	AuthorizationServer string `json:"authorization_server,omitempty"`
}

// TxCode is the upstream name for the transaction-code descriptor.
type TxCode = TransactionCode

// TransactionCode describes the transaction code expected by the issuer.
type TransactionCode struct {
	InputMode   string `json:"input_mode,omitempty"`
	Length      int    `json:"length,omitempty"`
	Description string `json:"description,omitempty"`
}

// OID4VCIFinalReceiveRequest holds the authorization-code Final/HAIP
// credential issuance inputs that are not discoverable from the credential
// offer or issuer metadata.
type OID4VCIFinalReceiveRequest struct {
	CredentialOffer *CredentialOffer
	// CredentialIssuer and CredentialConfigurationID drive a wallet-initiated
	// issuance (OpenID4VCI 1.0 §5: "The Wallet can also start the issuance
	// without a Credential Offer"): the wallet obtained the Credential Issuer
	// metadata itself and picked the Credential Configuration it wants. Both
	// are required when CredentialOffer is nil, and must be empty when a
	// Credential Offer is supplied.
	CredentialIssuer          *url.URL
	CredentialConfigurationID string
	Type                      receiverTypes.SupportedReceivingTypes
	ClientID                  string
	RedirectURI               string
	// AuthorizationRequestType selects how the selected Credential
	// Configuration is requested at the authorization endpoint. The empty
	// value uses scope when the configuration advertises one and
	// authorization_details otherwise. "scope" requires the configuration to
	// advertise a scope (error before PAR otherwise);
	// "authorization_details" sends an openid_credential entry with the
	// configuration id and no scope (OpenID4VCI 1.0 §5.1.1).
	//
	// Under HAIP only scope is allowed: HAIP §4.1 says "For Grant Type
	// `authorization_code`, the Issuer MUST include a scope value ... The
	// Wallet MUST use that value in the `scope` Authorization parameter" and
	// §4.2 that the Wallet "MUST use the `scope` parameter to communicate
	// Credential Type(s)". An explicit "authorization_details" fails, and so
	// does a Credential Configuration that advertises no scope.
	AuthorizationRequestType string
	HolderKey                jose.JSONWebKey
	// AdditionalHolderKeys requests §14.6 batch issuance. Each key yields one
	// proofs.jwt entry (HolderKey plus these, in order), and the returned
	// credentials are verified against the key at the same index. The total
	// number of proofs must not exceed the issuer's batch_size.
	AdditionalHolderKeys []jose.JSONWebKey
	ClientKey            jose.JSONWebKey
	// AttesterKey and AttesterIssuer are a deprecated fallback: when no
	// Config.ClientAttestation provider is configured they are wrapped into a
	// StaticClientAttester for this request. The wallet should never hold the
	// attester's private key; configure a remote ClientAttestationProvider.
	AttesterKey    jose.JSONWebKey
	AttesterIssuer string
	// IncludeKeyAttestation requests an OpenID4VCI 1.0 Appendix D key
	// attestation even when the issuer does not list
	// proof_types_supported.jwt.key_attestations_required. It is ignored when
	// no KeyAttestation provider is configured.
	IncludeKeyAttestation bool
	// ExternalKeyAttestation declares that the Appendix D key attestation is
	// minted outside this process, so no Config.KeyAttestation provider is
	// needed. The two-stage AuthorizeOID4VCIFinalToken /
	// RequestOID4VCIFinalCredential pair then stops before the Credential
	// Request with a *KeyAttestationRequiredError carrying the c_nonce and the
	// public holder keys to attest, and the caller repeats
	// RequestOID4VCIFinalCredential with KeyAttestation set. Without it a
	// wallet that has no provider refuses an issuer that requires a key
	// attestation before anything is sent.
	ExternalKeyAttestation bool
	// KeyAttestation is an Appendix D key attestation the caller obtained out
	// of process for this issuance, answering a *KeyAttestationRequiredError
	// or a *KeyAttestationNonceError. It takes precedence over a configured
	// Config.KeyAttestation provider, and its nonce claim must equal the
	// c_nonce of the OID4VCIFinalTokenGrant it is presented with.
	KeyAttestation *KeyAttestation
	// DeferredPollAttempts is the number of §9 deferred credential endpoint
	// polls. Zero means do not poll and return an IssuancePending result the
	// caller can resume with ResumeOID4VCIFinalDeferredCredential.
	DeferredPollAttempts int
	// MaxDeferredInterval caps the §9.2 deferred polling interval, including
	// one the issuer names in its issuance_pending response. Zero uses the
	// library's 60 second cap.
	MaxDeferredInterval             time.Duration
	CredentialResponseEncryptionKey *jose.JSONWebKey
	HTTPClient                      *http.Client
	// AllowSelfDrivenAuthorization lets ReceiveOID4VCIFinalCredential drive the
	// §5.2 authorization endpoint itself, by issuing a bare GET and reading the
	// Location header. Only an issuer that needs no user interaction answers
	// that way, so the default is false and a wallet with a user calls
	// BeginOID4VCIFinalAuthorization, opens the returned URL in the system
	// browser, and hands the redirect to ResumeOID4VCIFinalAuthorization.
	AllowSelfDrivenAuthorization bool
}
type OID4VCIFinalReceiveResult struct {
	CredentialResponse *receiverTypes.CredentialResponse
	SavedCredentials   []*SavedCredential
	AccessToken        *receiverTypes.CredentialIssuanceAccessToken
	// TransactionID and NotificationID expose the §9 deferred transaction and
	// §11 notification identifiers so callers can resume or notify later.
	TransactionID             string
	NotificationID            string
	IssuerMetadata            *receiverTypes.CredentialIssuerMetadata
	CredentialConfigurationID string
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
	return parseCredentialOfferJSON(rawOffer)
}
