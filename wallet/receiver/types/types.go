// Package types provides types and structures related to receiving credentials
package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
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
	ErrUseDPoPNonce              = errors.New("use DPoP nonce")
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

type DPoPNonceError struct {
	Nonce string
	Err   error
}

func NewDPoPNonceError(nonce string, err error) *DPoPNonceError {
	if err == nil {
		err = ErrUseDPoPNonce
	}
	return &DPoPNonceError{
		Nonce: strings.TrimSpace(nonce),
		Err:   err,
	}
}

func (e *DPoPNonceError) Error() string {
	message := fmt.Sprintf("%s (use_dpop_nonce)", e.Err)
	if e.Nonce == "" {
		return message
	}
	return fmt.Sprintf("%s, DPoP-Nonce: %q", message, e.Nonce)
}

func (e *DPoPNonceError) Unwrap() error {
	return e.Err
}

func (e *DPoPNonceError) Is(target error) bool {
	return target == ErrUseDPoPNonce
}

func DPoPNonceFromError(err error) (string, bool) {
	var nonceErr *DPoPNonceError
	if errors.As(err, &nonceErr) {
		return nonceErr.Nonce, true
	}
	return "", false
}

// CredentialEndpointError is an OpenID4VCI 1.0 §8.3.1.2 error response. The
// credential, deferred credential and notification endpoints return a JSON body
// with "error" and optional "error_description"/"interval" members on failure
// (§9.2 deferred credential error response, §11.3 notification error response);
// the DPoP-Nonce response header is also retained because a caller may still
// need it to build a corrected request. §9.2 defines "interval" as the number of
// seconds the wallet must wait before polling the deferred credential endpoint
// again when error is "issuance_pending".
type CredentialEndpointError struct {
	StatusCode  int
	Code        string // error
	Description string // error_description
	DPoPNonce   string // DPoP-Nonce header, if any
	Interval    int    // §9.2: seconds to wait when Code == "issuance_pending"
}

// Sentinel errors for the OpenID4VCI 1.0 §8.3.1.2 credential endpoint error
// codes. The sentinel's message is exactly the wire value so that Error's Is
// method can match it.
var (
	ErrInvalidNonce                = errors.New("invalid_nonce")
	ErrInvalidProof                = errors.New("invalid_proof")
	ErrIssuancePending             = errors.New("issuance_pending")
	ErrInvalidTransactionID        = errors.New("invalid_transaction_id")
	ErrUnknownCredentialIdentifier = errors.New("unknown_credential_identifier")
	ErrCredentialRequestDenied     = errors.New("credential_request_denied")
)

func (e *CredentialEndpointError) Error() string {
	if e == nil {
		return "credential endpoint error"
	}
	message := fmt.Sprintf("unexpected status code: %d", e.StatusCode)
	if e.Code != "" {
		message += fmt.Sprintf(", error: %s", e.Code)
	}
	if e.Description != "" {
		message += fmt.Sprintf(", error_description: %s", e.Description)
	}
	if e.Interval > 0 {
		message += fmt.Sprintf(", interval: %d", e.Interval)
	}
	return message
}

// Is lets callers use errors.Is(err, ErrInvalidNonce) to branch on the §8.3.1.2
// "error" code without inspecting the response body themselves.
func (e *CredentialEndpointError) Is(target error) bool {
	if e == nil {
		return false
	}
	switch target {
	case ErrInvalidNonce:
		return e.Code == "invalid_nonce"
	case ErrInvalidProof:
		return e.Code == "invalid_proof"
	case ErrIssuancePending:
		return e.Code == "issuance_pending"
	case ErrInvalidTransactionID:
		return e.Code == "invalid_transaction_id"
	case ErrUnknownCredentialIdentifier:
		return e.Code == "unknown_credential_identifier"
	case ErrCredentialRequestDenied:
		return e.Code == "credential_request_denied"
	default:
		return false
	}
}

type SupportedReceivingTypes int
type SignatureAlgorithm jose.SignatureAlgorithm

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
	BatchCredentialIssuance          *BatchCredentialIssuance           `json:"batch_credential_issuance,omitempty"`
	AuthorizationServers             []common.URIField                  `json:"authorization_servers,omitempty"`
	Display                          []CredentialIssuerMetadataDisplay  `json:"display,omitempty"`
	CredentialConfigurationSupported map[string]CredentialConfiguration `json:"credential_configurations_supported,omitempty"`
}

// BatchSize reports the issuer's §14.6 batch_size, defaulting to one when the
// metadata member is absent or advertises a non-positive value. A wallet must
// never request more credentials than the issuer declared.
func (m *CredentialIssuerMetadata) BatchSize() int {
	if m == nil || m.BatchCredentialIssuance == nil || m.BatchCredentialIssuance.BatchSize < 1 {
		return 1
	}
	return m.BatchCredentialIssuance.BatchSize
}

type CredentialRequestEncryption struct {
	Jwks               jose.JSONWebKeySet `json:"jwks"`
	AlgValuesSupported []string           `json:"alg_values_supported,omitempty"`
	EncValuesSupported []string           `json:"enc_values_supported,omitempty"`
	EncryptionRequired *bool              `json:"encryption_required,omitempty"`
}

// CredentialResponseEncryption mirrors the §12.2.4
// credential_response_encryption metadata member. zip_values_supported lists
// the compression algorithms the issuer accepts for encrypted responses (see
// §10 Encrypted Credential Requests and Responses).
type CredentialResponseEncryption struct {
	AlgValuesSupported []string `json:"alg_values_supported,omitempty"`
	EncValuesSupported []string `json:"enc_values_supported,omitempty"`
	ZipValuesSupported []string `json:"zip_values_supported,omitempty"`
	EncryptionRequired *bool    `json:"encryption_required,omitempty"`
}

// BatchCredentialIssuance carries the OpenID4VCI 1.0 §14.6
// batch_credential_issuance metadata member. batch_size is the maximum number of
// Credential Responses the wallet can request in one credential request.
type BatchCredentialIssuance struct {
	BatchSize int `json:"batch_size"`
}

type CredentialConfiguration struct {
	Display                              *[]CredentialConfigurationDisplay `json:"display,omitempty"`
	ProofTypesSupported                  *map[string]ProofType             `json:"proof_types_supported,omitempty"`
	Scope                                string                            `json:"scope,omitempty"`
	CredentialIdentifier                 string                            `json:"credential_identifier,omitempty"`
	CryptographicBindingMethodsSupported *[]string                         `json:"cryptographic_binding_methods_supported,omitempty"`
	Format                               string                            `json:"format"`
	CredentialDefinition                 *CredentialDefinition             `json:"credential_definition,omitempty"`
	CredentialSigningAlgValuesSupported  []SignatureAlgorithm              `json:"credential_signing_alg_values_supported,omitempty"`
}

var coseAlgToJWA = map[int64]jose.SignatureAlgorithm{
	-8:   jose.EdDSA,
	5:    jose.HS256,
	6:    jose.HS384,
	7:    jose.HS512,
	-257: jose.RS256,
	-258: jose.RS384,
	-259: jose.RS512,
	-7:   jose.ES256,
	-9:   jose.ES256, // ESP256 (fully-specified ECDSA using P-256 and SHA-256)
	-35:  jose.ES384,
	-36:  jose.ES512,
	-37:  jose.PS256,
	-38:  jose.PS384,
	-39:  jose.PS512,
}

func (c *SignatureAlgorithm) UnmarshalJSON(raw []byte) error {
	var coseID int64
	if err := json.Unmarshal(raw, &coseID); err == nil {
		// COSE algorithm identifier
		alg, ok := coseAlgToJWA[coseID]
		if !ok {
			return fmt.Errorf("unsupported COSE algorithm identifier %d", coseID)
		}
		*c = SignatureAlgorithm(alg)
		return nil
	}

	// JWA name
	var alg string
	if err := json.Unmarshal(raw, &alg); err != nil {
		return fmt.Errorf("invalid credential_signing_alg_values_supported entry: %w", err)
	}
	*c = SignatureAlgorithm(alg)
	return nil
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

// RFC 9396 (Rich Authorization Requests)
type CredentialIssuanceAuthorizationDetail struct {
	Type                  string   `json:"type,omitempty"`
	CredentialIdentifiers []string `json:"credential_identifiers,omitempty"`
}

const AuthorizationDetailTypeOpenIDCredential = "openid_credential"

// ClientAssertionTypeJWTBearer is the client_assertion_type value used for
// private_key_jwt (and client_secret_jwt) client authentication per RFC 7523.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

type CredentialIssuanceAccessToken struct {
	Token                string                                  `json:"access_token"`
	TokenType            string                                  `json:"token_type"`
	ExpiresIn            int                                     `json:"expires_in,omitempty"`
	RefreshToken         *string                                 `json:"refresh_token,omitempty"`
	CNonce               *string                                 `json:"c_nonce,omitempty"`
	CNonceExpiresIn      *int                                    `json:"c_nonce_expires_in,omitempty"`
	AuthorizationDetails []CredentialIssuanceAuthorizationDetail `json:"authorization_details,omitempty"`
}

type CredentialRequestOptions struct {
	DPoPProofJWT *string
}

type TokenRequestConfig struct {
	DPoPProof       string
	ClientID        string
	ClientAssertion string
}

type TokenRequestOption func(*TokenRequestConfig)

func NewTokenRequestConfig(opts ...TokenRequestOption) *TokenRequestConfig {
	cfg := &TokenRequestConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	return cfg
}

func WithDPoPProof(proof string) TokenRequestOption {
	return func(cfg *TokenRequestConfig) {
		cfg.DPoPProof = proof
	}
}

// WithClientAssertion sets the private_key_jwt client authentication parameters.
// When set, the token request includes client_id, client_assertion and
// client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer.
func WithClientAssertion(clientID, assertion string) TokenRequestOption {
	return func(cfg *TokenRequestConfig) {
		cfg.ClientID = clientID
		cfg.ClientAssertion = assertion
	}
}

// WithClientID sets the client_id sent with the token request without any
// client authentication. client_id is OPTIONAL for the pre-authorized code
// grant, so this identifies the client to an authorization server that expects
// to know who is asking without requiring the client to authenticate.
func WithClientID(clientID string) TokenRequestOption {
	return func(cfg *TokenRequestConfig) {
		cfg.ClientID = clientID
	}
}

// ResolveTokenEndpointURL returns the canonical token endpoint URL string.
// Metadata token_endpoint values are complete endpoint URLs, so this only
// normalizes trailing slashes and does not append "/token".
func ResolveTokenEndpointURL(endpoint common.URIField) string {
	endpointURL := url.URL(endpoint)
	endpointURL.Path = strings.TrimRight(endpointURL.Path, "/")
	return endpointURL.String()
}

// PreAuthorizedCodeTokenRequest holds the legacy pre-authorized token request parameters.
// Deprecated: FetchAccessToken now accepts authzCode, txCode and TokenRequestOption arguments.
type PreAuthorizedCodeTokenRequest struct {
	PreAuthorizedCode string `json:"pre-authorized_code"`
	TxCode            string `json:"tx_code,omitempty"`
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
	// Interval is the §9.1/§9.2 polling interval in seconds the issuer returns
	// alongside a deferred transaction_id. Zero when absent.
	Interval int `json:"interval,omitempty"`
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
	FetchAccessToken(receivingType SupportedReceivingTypes, endpoint common.URIField, authzCode string, txCode string, opts ...TokenRequestOption) (*CredentialIssuanceAccessToken, error)

	// FetchNonce fetches nonce from the issuer nonce endpoint
	FetchNonce(receivingType SupportedReceivingTypes, endpoint common.URIField) (*string, error)

	// ReceiveCredential receives credential through OID4VCI
	ReceiveCredential(
		receivingType SupportedReceivingTypes,
		endpoint common.URIField,
		credentialConfigurationID string,
		credentialIdentifier *string,
		accessToken CredentialIssuanceAccessToken,
		credentialDefinition *CredentialDefinition,
		jwtProof *string,
		options ...*CredentialRequestOptions,
	) (*string, error)
}

type DPoPProofFactory func(nonce string) (string, error)

// CredentialRequestBodyFactory builds the credential request body (already
// encoded, including any JWE wrapping) for a given c_nonce. OpenID4VCI 1.0
// §8.3.1 / §8.3.1.2 requires the wallet to embed the current c_nonce in the
// proof when the issuer supplied one; on "invalid_nonce" the wallet SHOULD
// rebuild the proof with a fresh c_nonce from the nonce endpoint.
type CredentialRequestBodyFactory func(cNonce string) (body []byte, contentType string, err error)

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
	FetchNonceResponse(endpoint common.URIField) (*NonceResponse, error)
	PostCredentialEndpointWithDpopRetry(endpoint common.URIField, accessToken string, body []byte, contentType string, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, error)
	PostCredentialEndpointWithNonceRetry(endpoint common.URIField, accessToken string, nonceEndpoint *common.URIField, initialCNonce string, build CredentialRequestBodyFactory, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, string, error)
	SendCredentialNotificationWithDpopRetry(endpoint common.URIField, accessToken string, notification NotificationRequest, proofFactory DPoPProofFactory) error
	EncodeCredentialRequest(request any, issuerMetadata *CredentialIssuerMetadata) ([]byte, string, error)
	DecodeCredentialResponse(body []byte, contentType string, decryptionKey any) (*CredentialResponse, error)
	CreateDpopProof(key jose.JSONWebKey, method string, rawURL string, nonce string, accessToken string) (string, error)
	CreateCredentialRequestJWTProof(key jose.JSONWebKey, audience string, nonce string) (string, error)
	CreateClientAttestation(clientKey jose.JSONWebKey, attesterKey jose.JSONWebKey, attesterIssuer string, clientID string, lifetime time.Duration) (string, error)
	CreateClientAttestationPop(clientKey jose.JSONWebKey, clientID string, authorizationServerIssuer string, attestationChallenge string, lifetime time.Duration) (string, error)
}
