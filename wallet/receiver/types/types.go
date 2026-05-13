// Package types provides types and structures related to receiving credentials
package types

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
)

// Sentinel errors for credential receiving operations
var (
	ErrInvalidMetadata           = errors.New("invalid credential issuer metadata")
	ErrUnsupportedProtocol       = errors.New("unsupported receiving protocol")
	ErrCredentialRequestFailed   = errors.New("credential request failed")
	ErrInvalidCredentialResponse = errors.New("invalid credential response")
	ErrAuthorizationFailed       = errors.New("authorization failed")
	ErrTokenRequestFailed        = errors.New("token request failed")
	ErrInvalidTokenResponse      = errors.New("invalid token response")
	ErrProofGenerationFailed     = errors.New("proof generation failed")
	ErrInvalidProofType          = errors.New("invalid or unsupported proof type")
	ErrNetworkFailed             = errors.New("network request failed")
	ErrTimeoutExpired            = errors.New("request timeout expired")
	ErrPluginNotFound            = errors.New("receiver plugin not found")
	ErrNilPlugin                 = errors.New("receiver plugin cannot be nil")
)

// ReceiverError represents an error during credential receiving operations
type ReceiverError struct {
	Protocol SupportedReceivingTypes `json:"protocol"`
	Endpoint string                  `json:"endpoint,omitempty"`
	Op       string                  `json:"operation"`
	Err      error                   `json:"error"`
}

func (e *ReceiverError) Error() string {
	if e.Endpoint != "" {
		return fmt.Sprintf("receiver %v operation %s at %s: %v", e.Protocol, e.Op, e.Endpoint, e.Err)
	}
	return fmt.Sprintf("receiver %v operation %s: %v", e.Protocol, e.Op, e.Err)
}

func (e *ReceiverError) Unwrap() error {
	return e.Err
}

// NewReceiverError creates a new ReceiverError
func NewReceiverError(protocol SupportedReceivingTypes, endpoint, op string, err error) *ReceiverError {
	return &ReceiverError{
		Protocol: protocol,
		Endpoint: endpoint,
		Op:       op,
		Err:      err,
	}
}

type SupportedReceivingTypes int

const (
	Oid4vci SupportedReceivingTypes = iota
	Mock                            // For mock receiver plugin that reads VC from txt files
)

type CredentialIssuerMetadata struct {
	CredentialIssuer                 string                             `json:"credential_issuer"`
	CredentialEndpoint               common.URIField                    `json:"credential_endpoint"`
	NonceEndpoint                    *common.URIField                   `json:"nonce_endpoint,omitempty"`
	DeferredCredentialEndpoint       *common.URIField                   `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint             *common.URIField                   `json:"notification_endpoint,omitempty"`
	CredentialRequestEncryption      *CredentialRequestEncryption       `json:"credential_request_encryption,omitempty"`
	CredentialResponseEncryption     *CredentialResponseEncryption      `json:"credential_response_encryption,omitempty"`
	AuthorizationServers             []common.URIField                  `json:"authorization_servers,omitempty"`
	Display                          []CredentialIssuerMetadataDisplay  `json:"display,omitempty"`
	CredentialConfigurationSupported map[string]CredentialConfiguration `json:"credential_configurations_supported,omitempty"`
}

type CredentialRequestEncryption struct {
	Jwks               jose.JSONWebKeySet `json:"jwks"`
	AlgValuesSupported []string           `json:"alg_values_supported,omitempty"`
	EncValuesSupported []string           `json:"enc_values_supported,omitempty"`
}

type CredentialResponseEncryption struct {
	AlgValuesSupported []string `json:"alg_values_supported,omitempty"`
	EncValuesSupported []string `json:"enc_values_supported,omitempty"`
	EncryptionRequired *bool    `json:"encryption_required,omitempty"`
}

type CredentialConfiguration struct {
	Display                              *[]CredentialConfigurationDisplay `json:"display,omitempty"`
	ProofTypesSupported                  *map[string]ProofType             `json:"proof_types_supported,omitempty"`
	Format                               string                            `json:"format"`
	Scope                                string                            `json:"scope,omitempty"`
	CredentialIdentifier                 string                            `json:"credential_identifier,omitempty"`
	CryptographicBindingMethodsSupported []string                          `json:"cryptographic_binding_methods_supported,omitempty"`
	CredentialDefinition                 *CredentialDefinition             `json:"credential_definition,omitempty"`
	CredentialSigningAlgValuesSupported  []any                             `json:"credential_signing_alg_values_supported,omitempty"`
}

type CredentialIssuerMetadataDisplay struct {
	Name   *string      `json:"name,omitempty"`
	Locale *string      `json:"locale,omitempty"`
	Logo   *DisplayLogo `json:"logo,omitempty"`
	MdbBio *string      `json:"mdb_bio,omitempty"`
}

type CredentialConfigurationDisplay struct {
	Name            string                                         `json:"name"`
	Locale          *string                                        `json:"locale,omitempty"`
	Logo            *DisplayLogo                                   `json:"logo,omitempty"`
	Description     *string                                        `json:"description,omitempty"`
	BackgroundColor *string                                        `json:"background_color,omitempty"`
	BackgroundImage *CredentialConfigurationDisplayBackgroundImage `json:"background_image,omitempty"`
	TextColor       *string                                        `json:"text_color,omitempty"`
}

type CredentialConfigurationDisplayBackgroundImage struct {
	Uri common.URIField `json:"uri"`
}

type DisplayLogo struct {
	Uri     common.URIField `json:"uri"`
	AltText *string         `json:"alt_text,omitempty"`
}

type ProofType struct {
	ProofSigningAlgValuesSupported []jose.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
}

type CredentialDefinition struct {
	Type              []string                               `json:"type"`
	CredentialSubject *CredentialDefinitionCredentialSubject `json:"credentialSubject,omitempty"`
}

type CredentialDefinitionCredentialSubject struct {
	Values    map[string]interface{}       `json:"values,omitempty"`
	Mandatory *bool                        `json:"mandatory,omitempty"`
	ValueType *string                      `json:"value_type,omitempty"`
	Display   *CredentialDefinitionDisplay `json:"display,omitempty"`
}

type CredentialDefinitionDisplay struct {
	Name   *string `json:"name,omitempty"`
	Locale *string `json:"locale,omitempty"`
}

type AuthorizationServerMetadata struct {
	PreAuthorizedGrantAnonymousAccessSupported         *bool                      `json:"pre-authorized_grant_anonymous_access_supported"`
	Issuer                                             common.URIField            `json:"issuer"`
	AuthorizationEndpoint                              *common.URIField           `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                                      *common.URIField           `json:"token_endpoint,omitempty"`
	PushedAuthorizationRequestEndpoint                 *common.URIField           `json:"pushed_authorization_request_endpoint,omitempty"`
	ChallengeEndpoint                                  *common.URIField           `json:"challenge_endpoint,omitempty"`
	DpopSigningAlgValuesSupported                      *[]jose.SignatureAlgorithm `json:"dpop_signing_alg_values_supported,omitempty"`
	JwksUri                                            *common.URIField           `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                               *common.URIField           `json:"registration_endpoint,omitempty"`
	ScopesSupported                                    *[]string                  `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                             []OAuthResponseType        `json:"response_types_supported"`
	ResponseModesSupported                             *[]OAuthResponseMode       `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                *[]OAuthGrantType          `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  *[]TokenEndpointAuthMethod `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         *[]jose.SignatureAlgorithm `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                               *common.URIField           `json:"service_documentation,omitempty"`
	UiLocalesSupported                                 *[]string                  `json:"ui_locales_supported,omitempty"`
	OpPolicyUri                                        *common.URIField           `json:"op_policy_uri,omitempty"`
	OpTosUri                                           *common.URIField           `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                 *common.URIField           `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported             *[]TokenEndpointAuthMethod `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    *[]jose.SignatureAlgorithm `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                              *common.URIField           `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          *[]TokenEndpointAuthMethod `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported *[]jose.SignatureAlgorithm `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported                      *[]PkceCodeChallengeMethod `json:"code_challenge_methods_supported,omitempty"`
}

type OAuthResponseType string

const (
	Code  OAuthResponseType = "code"
	Token OAuthResponseType = "token"
)

type OAuthResponseMode int

const (
	Query OAuthResponseMode = iota
	Fragment
)

type OAuthGrantType string

const (
	AuthorizationCode OAuthGrantType = "authorization_code"
	Password          OAuthGrantType = "password"
	ClientCredentials OAuthGrantType = "client_credentials"
	RefreshToken      OAuthGrantType = "refresh_token"
	JwtBearer         OAuthGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	Saml2Bearer       OAuthGrantType = "urn:ietf:params:oauth:grant-type:saml2-bearer"
)

type PkceCodeChallengeMethod string

const (
	Plain PkceCodeChallengeMethod = "plain"
	S256  PkceCodeChallengeMethod = "S256"
)

type TokenEndpointAuthMethod string

const (
	None                    TokenEndpointAuthMethod = "none"
	ClientSecretPost        TokenEndpointAuthMethod = "client_secret_post"
	ClientSecretBasic       TokenEndpointAuthMethod = "client_secret_basic"
	ClientSecretJwt         TokenEndpointAuthMethod = "client_secret_jwt"
	PrivateKeyJwt           TokenEndpointAuthMethod = "private_key_jwt"
	TlsClientAuth           TokenEndpointAuthMethod = "tls_client_auth"
	SelfSignedTlsClientAuth TokenEndpointAuthMethod = "self_signed_tls_client_auth"
)

// RFC 6749
type CredentialIssuanceAccessToken struct {
	Token           string  `json:"access_token"`
	TokenType       string  `json:"token_type"`
	ExpiresIn       int     `json:"expires_in,omitempty"`
	RefreshToken    *string `json:"refresh_token,omitempty"`
	CNonce          *string `json:"c_nonce,omitempty"`
	CNonceExpiresIn *int    `json:"c_nonce_expires_in,omitempty"`
}

type PushedAuthorizationRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	IssuerState         string
}

type PushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in,omitempty"`
}

type AuthorizationCodeTokenRequest struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
	ClientID     string
}

type ClientAttestationChallengeResponse struct {
	AttestationChallenge string `json:"attestation_challenge,omitempty"`
}

type OAuthClientAttestationHeaders struct {
	ClientAttestation    string
	ClientAttestationPop string
}

type NonceResponse struct {
	CNonce          string `json:"c_nonce"`
	CNonceExpiresIn *int   `json:"c_nonce_expires_in,omitempty"`
}

type CredentialRequest struct {
	CredentialConfigurationID    string                               `json:"credential_configuration_id,omitempty"`
	Proofs                       *CredentialProofs                    `json:"proofs,omitempty"`
	CredentialResponseEncryption *CredentialResponseEncryptionRequest `json:"credential_response_encryption,omitempty"`
}

type CredentialProofs struct {
	JWT []string `json:"jwt,omitempty"`
}

type CredentialResponseEncryptionRequest struct {
	Jwk jose.JSONWebKey `json:"jwk"`
	Enc string          `json:"enc"`
}

type CredentialResponse struct {
	Credential     any     `json:"credential,omitempty"`
	Credentials    []any   `json:"credentials,omitempty"`
	TransactionID  string  `json:"transaction_id,omitempty"`
	NotificationID string  `json:"notification_id,omitempty"`
	CNonce         *string `json:"c_nonce,omitempty"`
}

type DeferredCredentialRequest struct {
	TransactionID string `json:"transaction_id"`
}

type NotificationRequest struct {
	NotificationID string `json:"notification_id"`
	Event          string `json:"event"`
}

// Receiver defines the interface for credential receiving components
type Receiver interface {
	// FetchIssuerMetadata fetches OID4VCI Credential Issuer Metadata
	FetchIssuerMetadata(endpoint common.URIField, receivingType SupportedReceivingTypes) (*CredentialIssuerMetadata, error)

	// FetchAuthorizationServerMetadata fetches authorization server metadata
	FetchAuthorizationServerMetadata(endpoint common.URIField, receivingType SupportedReceivingTypes) (*AuthorizationServerMetadata, error)

	// FetchAccessToken fetches access token through OID4VCI
	FetchAccessToken(receivingType SupportedReceivingTypes, endpoint common.URIField, authzCode string) (*CredentialIssuanceAccessToken, error)

	// ReceiveCredential receives credential through OID4VCI
	ReceiveCredential(
		receivingType SupportedReceivingTypes,
		endpoint common.URIField,
		format string,
		accessToken CredentialIssuanceAccessToken,
		credentialDefinition *CredentialDefinition,
		jwtProof *string,
	) (*string, error)
}

type DPoPProofFactory func(nonce string) (string, error)

type OAuthClientAttestationHeadersFactory func() (OAuthClientAttestationHeaders, error)

type CredentialEndpointHTTPResponse struct {
	Body        []byte
	ContentType string
}

// OID4VCIFinalReceiver is an optional plugin capability for OpenID4VCI
// Final 1.0 / HAIP flows. It intentionally extends, rather than replaces,
// the legacy Receiver interface used by the existing Draft 13 flow.
type OID4VCIFinalReceiver interface {
	Receiver

	PushAuthorizationRequest(endpoint common.URIField, request PushedAuthorizationRequest, headers OAuthClientAttestationHeaders) (*PushedAuthorizationResponse, error)
	ExchangeAuthorizationCodeWithDpopRetry(endpoint common.URIField, request AuthorizationCodeTokenRequest, headers OAuthClientAttestationHeaders, proofFactory DPoPProofFactory) (*CredentialIssuanceAccessToken, error)
	ExchangeAuthorizationCodeWithDpopAndAttestationRetry(endpoint common.URIField, request AuthorizationCodeTokenRequest, headersFactory OAuthClientAttestationHeadersFactory, proofFactory DPoPProofFactory) (*CredentialIssuanceAccessToken, error)
	FetchClientAttestationChallenge(endpoint common.URIField) (*ClientAttestationChallengeResponse, error)
	FetchNonce(endpoint common.URIField) (*NonceResponse, error)
	PostCredentialEndpointWithDpopRetry(endpoint common.URIField, accessToken string, body []byte, contentType string, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, error)
	SendCredentialNotificationWithDpopRetry(endpoint common.URIField, accessToken string, notification NotificationRequest, proofFactory DPoPProofFactory) error
	EncodeCredentialRequest(request any, issuerMetadata *CredentialIssuerMetadata) ([]byte, string, error)
	DecodeCredentialResponse(body []byte, contentType string, decryptionKey any) (*CredentialResponse, error)
	CreateDpopProof(key jose.JSONWebKey, method string, rawURL string, nonce string, accessToken string) (string, error)
	CreateCredentialRequestJWTProof(key jose.JSONWebKey, audience string, nonce string) (string, error)
	CreateClientAttestation(clientKey jose.JSONWebKey, attesterKey jose.JSONWebKey, attesterIssuer string, clientID string, lifetime time.Duration) (string, error)
	CreateClientAttestationPop(clientKey jose.JSONWebKey, clientID string, authorizationServerIssuer string, attestationChallenge string, lifetime time.Duration) (string, error)
}
