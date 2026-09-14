// Package types provides types and structures related to receiving credentials
package types

import (
	"context"
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
	ErrNonceResponseInvalid      = errors.New("invalid nonce response")
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
	// SignedMetadata holds the OpenID4VCI 1.0 §12.2.3 signed Credential Issuer
	// Metadata. §12.2.3 requires the issuer to secure the metadata with a JWS
	// (alg MUST NOT be none or a MAC identifier, typ MUST be
	// openidvci-issuer-metadata+jwt) and to return it with media type
	// application/jwt; the wallet retains the compact serialization here.
	SignedMetadata string `json:"signed_metadata,omitempty"`
	// MetadataSignature records the outcome of verifying SignedMetadata so
	// callers can audit the signer. It is internal state and never serialized
	// (json:"-").
	MetadataSignature *MetadataVerification `json:"-"`
}

// MetadataVerification records the outcome of verifying the OpenID4VCI 1.0
// §12.2.3 signed Credential Issuer Metadata. §12.2.3 requires the wallet to
// establish trust in the signer of the metadata and reject it otherwise; when
// validating the signature the wallet obtains the keys via JOSE header
// parameters such as x5c, kid or trust_chain. The fields capture the signer
// identity the metadata was accepted under; they are never serialized.
type MetadataVerification struct {
	// LeafCertificateSHA256 is the SHA-256 fingerprint of the leaf X.509
	// certificate that signed the metadata.
	LeafCertificateSHA256 string
	// Subject is the subject distinguished name of the signing certificate.
	Subject string
	// IssuedAt is the JWS iat: the time the Credential Issuer Metadata was
	// issued, per §12.2.3.
	IssuedAt time.Time
	// ExpiresAt is the optional JWS exp, or nil when the signed metadata does
	// not expire, per §12.2.3.
	ExpiresAt *time.Time
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

// CredentialRequestEncryption mirrors the OpenID4VCI 1.0 §12.2.4
// credential_request_encryption metadata member, which is defined with exactly
// four members: jwks ("REQUIRED. A JSON Web Key Set ... that contains one or
// more public keys, to be used by the Wallet as an input to a key agreement for
// encryption of the Credential Request. Each JWK in the set MUST have a kid
// (Key ID) parameter that uniquely identifies the key"), enc_values_supported
// ("REQUIRED. A non-empty array containing a list of the JWE encryption
// algorithms (`enc` values) supported by the Credential Endpoint to decode the
// Credential Request from a JWT"), zip_values_supported (OPTIONAL) and
// encryption_required ("REQUIRED. Boolean value specifying whether the
// Credential Issuer requires the additional encryption on top of TLS for the
// Credential Requests").
//
// There is deliberately no alg_values_supported member: §12.2.4 defines that
// one on credential_response_encryption only, and §10 fixes the request's JWE
// alg from the chosen key instead — "The `alg` parameter MUST be present. The
// JWE `alg` algorithm used MUST be equal to the `alg` value of the chosen JWK."
//
// zip_values_supported is not modelled either, because §10 makes compression
// the Wallet's own option ("If a `zip` (Compression Algorithm) value is
// specified, then compression is performed before encryption ... If absent, no
// compression is performed") and this wallet never compresses a Credential
// Request, so the issuer's list would change nothing.
type CredentialRequestEncryption struct {
	// Jwks carries the issuer's request encryption keys.
	Jwks jose.JSONWebKeySet `json:"jwks"`
	// EncValuesSupported lists the JWE content encryption algorithms the
	// Credential Endpoint can decrypt.
	EncValuesSupported []string `json:"enc_values_supported,omitempty"`
	// EncryptionRequired is true when every Credential Request must be
	// encrypted on top of TLS.
	EncryptionRequired *bool `json:"encryption_required,omitempty"`
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
	Display             *[]CredentialConfigurationDisplay `json:"display,omitempty"`
	ProofTypesSupported *map[string]ProofType             `json:"proof_types_supported,omitempty"`
	Scope               string                            `json:"scope,omitempty"`
	// OpenID4VCI 1.0 Section 12.2.4 defines no credential_identifier member on
	// a Credential Configuration: credential_identifier values reach the wallet
	// only in the token response's authorization_details (Section 6.2). An
	// issuer that publishes the member anyway is ignored like any other unknown
	// metadata member.
	CryptographicBindingMethodsSupported *[]string             `json:"cryptographic_binding_methods_supported,omitempty"`
	Format                               string                `json:"format"`
	CredentialDefinition                 *CredentialDefinition `json:"credential_definition,omitempty"`
	CredentialSigningAlgValuesSupported  []SignatureAlgorithm  `json:"credential_signing_alg_values_supported,omitempty"`
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
	// KeyAttestationsRequired is the OpenID4VCI 1.0 Appendix D
	// proof_types_supported.jwt.key_attestations_required object. Its presence
	// (even when empty) tells the wallet a key attestation is required.
	KeyAttestationsRequired *KeyAttestationsRequired `json:"key_attestations_required,omitempty"`
}

// KeyAttestationsRequired carries the OpenID4VCI 1.0 Appendix D
// key_attestations_required constraints. Both members are optional.
type KeyAttestationsRequired struct {
	KeyStorage         []string `json:"key_storage,omitempty"`
	UserAuthentication []string `json:"user_authentication,omitempty"`
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
	PreAuthorizedGrantAnonymousAccessSupported *bool           `json:"pre-authorized_grant_anonymous_access_supported"`
	Issuer                                     common.URIField `json:"issuer"`
	// AuthorizationResponseIssParameterSupported advertises RFC 9207 support:
	// the authorization response then carries iss, which the wallet validates.
	AuthorizationResponseIssParameterSupported         *bool                      `json:"authorization_response_iss_parameter_supported,omitempty"`
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
	Type string `json:"type,omitempty"`
	// CredentialConfigurationID is the OpenID4VCI 1.0 §6.2 token response
	// member that ties the credential_identifiers to the Credential
	// Configuration requested with authorization_details.
	CredentialConfigurationID string   `json:"credential_configuration_id,omitempty"`
	CredentialIdentifiers     []string `json:"credential_identifiers,omitempty"`
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
	ResponseType string
	ClientID     string
	RedirectURI  string
	// Scope is the OAuth 2.0 scope parameter. OpenID4VCI 1.0 §5.1.2 uses it to
	// select the Credential Configuration; empty omits the parameter.
	Scope string
	// AuthorizationDetails is the RFC 9396 §2 authorization_details JSON array
	// parameter. OpenID4VCI 1.0 §5.1.1 uses entries of type
	// openid_credential with credential_configuration_id to request a
	// Credential Configuration. Empty omits the parameter.
	AuthorizationDetails []map[string]any
	State                string
	CodeChallenge        string
	CodeChallengeMethod  string
	IssuerState          string
	// ClientAssertion is the RFC 7523 §2.2 client_assertion sent for
	// private_key_jwt client authentication. RFC 9126 §2 requires the PAR
	// request to carry the client authentication of the token endpoint. An
	// empty value omits the parameter.
	ClientAssertion string
	// ClientAssertionType is the matching client_assertion_type. Empty omits
	// the parameter.
	ClientAssertionType string
}

type PushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in,omitempty"`
}

// ClientAssertionFactory produces a fresh client_assertion for a single HTTP
// attempt. RFC 7523 §3 requires every assertion to carry a unique jti, so a
// retry that re-sends the token request (for example after a DPoP nonce
// challenge) must not replay the previous assertion.
type ClientAssertionFactory func() (string, error)

type AuthorizationCodeTokenRequest struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
	ClientID     string
	// ClientAssertion is the RFC 7523 §2.2 client_assertion sent for
	// private_key_jwt client authentication. An empty value omits the
	// parameter.
	ClientAssertion string
	// ClientAssertionType is the matching client_assertion_type. Empty omits
	// the parameter.
	ClientAssertionType string
	// ClientAssertionFactory, when set, is called once per HTTP attempt to
	// obtain a fresh client_assertion; it takes precedence over
	// ClientAssertion. The retry wrappers use it so a DPoP nonce retry never
	// replays the same jti.
	ClientAssertionFactory ClientAssertionFactory
}

type ClientAttestationChallengeResponse struct {
	AttestationChallenge string `json:"attestation_challenge,omitempty"`
}

type OAuthClientAttestationHeaders struct {
	ClientAttestation    string
	ClientAttestationPop string
}

// NonceResponse is the OpenID4VCI 1.0 §7.2 Nonce Response.
type NonceResponse struct {
	// CNonce is the §7.2 c_nonce: "REQUIRED. String containing a challenge to
	// be used when creating a proof of possession of the key".
	CNonce string `json:"c_nonce"`
	// CNonceExpiresIn is the lifetime in seconds an issuer may advertise
	// alongside c_nonce.
	CNonceExpiresIn *int `json:"c_nonce_expires_in,omitempty"`
	// DPoPNonce is the RFC 9449 §8.2 DPoP-Nonce response header value, not a
	// body member, hence json:"-". §7.2 Nonce Response: "The Credential Issuer
	// MAY provide a DPoP nonce in an HTTP header as defined in Section 8.2 of
	// [@!RFC9449]. In this case, the Wallet uses the new nonce value in the
	// DPoP proof when presenting an access token at the Credential Endpoint."
	// It is empty when the Nonce Endpoint sent no such header.
	DPoPNonce string `json:"-"`
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

// ProofOptions carries the inputs of an OpenID4VCI 1.0 Section 8.2.1.1 "jwt"
// key proof. It lives here, next to the interface that takes it, so a signer
// outside this repository can implement OID4VCIFinalSigner without depending on
// the bundled oid4vci plugin.
type ProofOptions struct {
	// Audience is the Credential Issuer Identifier the proof is bound to.
	// Section 8.2.1.1 makes it "REQUIRED. ... the Credential Issuer Identifier".
	Audience string
	// Nonce is the c_nonce the issuer supplied, omitted when empty.
	Nonce string
	// KeyAttestation is the OpenID4VCI 1.0 Appendix D key attestation JWT,
	// carried in the key_attestation JOSE header parameter when non-empty.
	KeyAttestation string
	// SigningAlgValues is the proof_signing_alg_values_supported list of the
	// Credential Configuration being requested, that is
	// CredentialConfigurationSupported[id].ProofTypesSupported["jwt"]. An empty
	// list means the issuer published no constraint.
	SigningAlgValues []jose.SignatureAlgorithm
}

// OID4VCIFinalTransport is the OpenID4VCI 1.0 Final / HAIP transport a
// receiver plugin owns: the HTTP exchanges of Section 5 (Pushed Authorization
// Request and the Token Endpoint), Section 6.3 (the Client Attestation
// challenge), Section 7 (the Nonce Endpoint), Section 8 (the Credential
// Endpoint), Section 11 (the Notification Endpoint) and the Credential Request
// and Credential Response codec of Section 8.1 and Section 8.2. It
// intentionally extends, rather than replaces, the legacy Receiver interface
// used by the existing Draft 13 flow.
//
// It carries no signing primitive. Key proofs, DPoP proofs and Client
// Attestation PoPs are built by an OID4VCIFinalSigner, so a transport plugin
// can be implemented outside this repository without access to the wallet's
// private keys.
//
// # Context
//
// Every method that performs I/O takes a context.Context as its first
// parameter and MUST bind every HTTP request it makes — retries included — to
// it, so that cancelling the issuance stops a request that is already in
// flight. EncodeCredentialRequest and DecodeCredentialResponse take none: they
// are pure codecs (JSON plus JWE) that never reach the network.
//
// # The retry policy the method names encode
//
// The "…WithDpopAndAttestationRetry" and "…WithNonceRetryForToken" suffixes
// name a retry policy the implementation owns, not a convenience wrapper
// around a single request. A plugin that implements this interface implements
// that policy:
//
//   - RFC 9449 §8: an authorization server or resource server that answers
//     with "use_dpop_nonce" and a DPoP-Nonce header has rejected the proof
//     only because it lacks its nonce. The implementation retries once with a
//     proof built for that nonce. Every attempt calls the DPoPProofFactory and
//     the OAuthClientAttestationHeadersFactory again and rebuilds the request
//     body, because RFC 9449 §4.2 gives every DPoP proof a unique jti and
//     RFC 7523 §3 a unique jti to every client_assertion: nothing signed for a
//     previous attempt is ever replayed.
//   - OpenID4VCI 1.0 §8.3.1.2: an issuer that answers the Credential Endpoint
//     with "invalid_nonce" has rejected the key proof's c_nonce. The
//     implementation fetches a fresh c_nonce from the Nonce Endpoint, calls the
//     CredentialRequestBodyFactory again for it, and posts once more.
//
// At most one retry is performed for each of the two conditions, so a
// misbehaving server cannot hold the wallet in a loop.
type OID4VCIFinalTransport interface {
	Receiver

	// PushAuthorizationRequest sends the RFC 9126 Pushed Authorization Request
	// that OpenID4VCI 1.0 Section 5.1 and HAIP Section 4.3 use to move the
	// authorization request off the front channel.
	PushAuthorizationRequest(ctx context.Context, endpoint common.URIField, request PushedAuthorizationRequest, headers OAuthClientAttestationHeaders) (*PushedAuthorizationResponse, error)
	// ExchangeAuthorizationCodeWithDpopAndAttestationRetry exchanges the
	// authorization code at the Token Endpoint (Section 6.1). Both factories are
	// invoked once per HTTP attempt, so an RFC 9449 Section 8 "use_dpop_nonce"
	// retry re-signs the DPoP proof and rebuilds the Client Attestation headers
	// instead of replaying the first ones.
	ExchangeAuthorizationCodeWithDpopAndAttestationRetry(ctx context.Context, endpoint common.URIField, request AuthorizationCodeTokenRequest, headersFactory OAuthClientAttestationHeadersFactory, proofFactory DPoPProofFactory) (*CredentialIssuanceAccessToken, error)
	// FetchClientAttestationChallenge fetches a challenge from the
	// authorization server's challenge endpoint so the Client Attestation PoP
	// can be bound to it.
	FetchClientAttestationChallenge(ctx context.Context, endpoint common.URIField) (*ClientAttestationChallengeResponse, error)
	// FetchNonceResponse fetches the Section 7 Nonce Endpoint response,
	// including the optional c_nonce_expires_in member and the RFC 9449
	// Section 8.2 DPoP-Nonce response header. Section 7.2: "The Credential
	// Issuer MAY provide a DPoP nonce in an HTTP header as defined in Section
	// 8.2 of [@!RFC9449]. In this case, the Wallet uses the new nonce value in
	// the DPoP proof when presenting an access token at the Credential
	// Endpoint."
	FetchNonceResponse(ctx context.Context, endpoint common.URIField) (*NonceResponse, error)
	// PostCredentialEndpointWithNonceRetryForToken posts the Credential Request
	// and, on the Section 8.3.1.2 "invalid_nonce" error, rebuilds the body with
	// a fresh c_nonce from the Nonce Endpoint and posts it once more. It takes
	// the parsed token response rather than the bare access token so the
	// Authorization header carries the scheme the authorization server issued:
	// RFC 6750 Section 2.1 defines the Bearer scheme and RFC 9449 Section 7.1
	// the DPoP scheme. It returns the raw HTTP response and the c_nonce the
	// accepted request was built with.
	PostCredentialEndpointWithNonceRetryForToken(ctx context.Context, endpoint common.URIField, accessToken CredentialIssuanceAccessToken, nonceEndpoint *common.URIField, initialCNonce string, build CredentialRequestBodyFactory, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, string, error)
	// SendCredentialNotificationWithDpopRetryForToken sends the Section 11
	// notification, taking the parsed token response for the same reason as
	// PostCredentialEndpointWithNonceRetryForToken.
	SendCredentialNotificationWithDpopRetryForToken(ctx context.Context, endpoint common.URIField, accessToken CredentialIssuanceAccessToken, notification NotificationRequest, proofFactory DPoPProofFactory) error
	// EncodeCredentialRequest serialises a Credential Request, applying the
	// Section 8.1 Credential Request encryption when the issuer metadata
	// advertises credential_request_encryption. It returns the body and the
	// Content-Type to send it with. It is a pure codec and takes no context:
	// it performs no I/O.
	EncodeCredentialRequest(request any, issuerMetadata *CredentialIssuerMetadata) ([]byte, string, error)
	// DecodeCredentialResponse parses a Credential Response, decrypting the
	// Section 8.2 encrypted response with decryptionKey when the Content-Type
	// says the issuer encrypted it. It is a pure codec and takes no context:
	// it performs no I/O.
	DecodeCredentialResponse(body []byte, contentType string, decryptionKey any) (*CredentialResponse, error)
}

// OID4VCIFinalSigner builds the private-key operations of an OpenID4VCI 1.0
// Final / HAIP issuance: the RFC 9449 DPoP proof, the Section 8.2.1.1 "jwt" key
// proof and the attestation-based client authentication PoP of
// draft-ietf-oauth-attestation-based-client-auth Section 4.
//
// It is separated from OID4VCIFinalTransport so a wallet can keep its keys in a
// hardware module or a remote signing service while still using the bundled
// transport plugin. Wallet.Config selects the implementation; the receiver
// oid4vcisign package provides the software default.
//
// The Client Attestation itself is not built here: it is issued by the
// attester, not by the wallet, and reaches the wallet through a
// ClientAttestationProvider.
type OID4VCIFinalSigner interface {
	// CreateDpopProof builds the RFC 9449 Section 4.2 DPoP proof for one HTTP
	// request. An empty nonce omits the nonce claim and an empty accessToken
	// omits the ath claim.
	CreateDpopProof(key jose.JSONWebKey, method string, rawURL string, nonce string, accessToken string) (string, error)
	// CreateCredentialRequestJWTProofWithOptions builds the OpenID4VCI 1.0
	// Section 8.2.1.1 "jwt" key proof. It honours the Credential
	// Configuration's proof_signing_alg_values_supported, which Section 8.2.1.1
	// makes binding: "the `alg` JWT header of the key proof ... MUST match one
	// of the values listed in the `proof_signing_alg_values_supported` metadata
	// parameter".
	CreateCredentialRequestJWTProofWithOptions(key jose.JSONWebKey, opts ProofOptions) (string, error)
	// CreateClientAttestationPop builds the Client Attestation PoP JWT of
	// draft-ietf-oauth-attestation-based-client-auth Section 4, bound to the
	// authorization server and, when the server issued one, to its challenge.
	CreateClientAttestationPop(clientKey jose.JSONWebKey, clientID string, authorizationServerIssuer string, attestationChallenge string, lifetime time.Duration) (string, error)
}

// OID4VCIFinalReceiver is a plugin that is both an OID4VCIFinalTransport and an
// OID4VCIFinalSigner.
//
// Deprecated: implement OID4VCIFinalTransport instead and supply the signing
// primitives through Wallet Config.OID4VCISigner. This compound interface is
// kept so existing plugins and callers keep compiling.
type OID4VCIFinalReceiver interface {
	OID4VCIFinalTransport
	OID4VCIFinalSigner
}
