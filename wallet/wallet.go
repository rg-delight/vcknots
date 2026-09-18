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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	joseutil "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/idprof"
	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/oid4vcisign"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer"
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

	dpop       DPoPConfig
	clientAuth ClientAuthConfig

	// profile is the explicit Final/HAIP policy this wallet enforces. It is also
	// propagated to every registered protocol plugin so no lower-level API can
	// bypass the root policy.
	profile profile.Profile

	// clientAttestation and keyAttestation are the caller-selected attestation
	// providers. A nil clientAttestation falls back to a StaticClientAttester
	// built from a per-request AttesterKey for compatibility.
	clientAttestation ClientAttestationProvider
	keyAttestation    KeyAttestationProvider

	// attestationTrust authenticates what those providers return. The zero
	// value carries no trust material, which is enough for the bundled static
	// attesters (the wallet holds their key) and for an attester that ships its
	// certificate chain in x5c.
	attestationTrust AttestationTrustPolicy

	// oid4vciSigner is the caller-selected OpenID4VCI Final signer. A nil value
	// means "ask the receiver plugin, then fall back to oid4vcisign.Default",
	// which is resolved per issuance by oid4vciFinalSigner.
	oid4vciSigner receiverTypes.OID4VCIFinalSigner

	credentialAcceptance *CredentialAcceptancePolicy
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

	DPoP       DPoPConfig
	ClientAuth ClientAuthConfig

	// Profile selects the explicit Final/HAIP policy for the wallet. The zero
	// value normalizes to profile.Final. Caller-injected dispatchers must have
	// every protocol plugin carrying the same profile or NewWalletWithConfig
	// fails.
	Profile profile.Profile

	// SupportedTransactionDataTypes lists the transaction_data "type" values
	// the wallet can process. It is propagated to the default presenter plugin.
	SupportedTransactionDataTypes []string

	// CredentialAcceptance configures the minimum credential verification rules
	// applied before a received credential is stored.
	CredentialAcceptance *CredentialAcceptancePolicy

	// Storeless builds a wallet that holds no credential store at all. Nothing
	// it receives is persisted — the credentials it verified are returned in
	// OID4VCIFinalReceiveResult.SavedCredentials and it is the caller that
	// keeps them — and every presentation names its credentials by value
	// through PresentDCQLHolderSelection or Draft24CredentialSelection.Credential.
	//
	// It exists for a wallet whose durable state lives in another process: the
	// default store writes a credential database to the user's configuration
	// directory, so without this a component that only performs one protocol
	// exchange would leave a copy of every credential behind. CredStore must be
	// nil, and GetCredentialEntries, GetCredentialEntry and every presentation
	// that resolves a credential through the store report
	// ErrNoCredentialStore.
	Storeless bool

	// ClientAttestation supplies the OAuth 2.0 Client Attestation JWT for this
	// wallet instance. When nil, a per-request AttesterKey is wrapped into a
	// StaticClientAttester for compatibility.
	ClientAttestation ClientAttestationProvider

	// KeyAttestation supplies OpenID4VCI 1.0 Appendix D key attestations when
	// the issuer requires them or the caller opts in.
	KeyAttestation KeyAttestationProvider

	// AttestationTrust authenticates the attestation JWTs those providers
	// return, before any request carrying one leaves the wallet: which key
	// signed it and, when trust anchors are configured, whether its x5c chain
	// is trusted. Its RequireX5C is raised by the HAIP profile on its own, so a
	// deployment only sets this to configure trust anchors, a key resolver for
	// a provider that does not use x5c, or a revocation policy.
	//
	// A remote provider that returns an attestation without an x5c chain needs
	// a ResolveKey here: an attestation this wallet cannot authenticate is
	// refused rather than forwarded.
	AttestationTrust AttestationTrustPolicy

	// OID4VCISigner builds the private-key operations of an OpenID4VCI 1.0
	// Final / HAIP issuance: the RFC 9449 DPoP proof, the Section 8.2.1.1 "jwt"
	// key proof and the Client Attestation PoP. Configure it to keep the
	// wallet's keys in a hardware module or a remote signing service.
	//
	// When nil the receiver plugin is used if it implements
	// receiver/types.OID4VCIFinalSigner, as the bundled OpenID4VCI plugin does,
	// and oid4vcisign.Default otherwise.
	OID4VCISigner receiverTypes.OID4VCIFinalSigner
}

// DPoPConfig holds configuration for DPoP proof generation.
type DPoPConfig struct {
	Enabled bool
	Key     IKeyEntry
}

// ClientAuthConfig holds configuration for client authentication at the
// authorization server's token endpoint.
//
// Method selects the authentication method. An empty value defaults to None,
// so private_key_jwt is only used when explicitly configured.
//
// ClientID and Key are required to use PrivateKeyJwt. Key must be the private
// key whose corresponding public key is registered with the authorization
// server (as JWKS).
//
// AssertionAudience is the authorization server identifier placed in the
// client_assertion aud claim. When empty, the authorization server metadata
// issuer is used, falling back to the token endpoint URL when issuer is absent.
//
// SigningAlg selects the JWS algorithm used to sign the client_assertion. It
// corresponds to the token_endpoint_auth_signing_alg client metadata value
// defined by OpenID Connect Dynamic Client Registration 1.0, and must be one
// of ES256, ES384 or ES512. An empty value defaults to ES256.
type ClientAuthConfig struct {
	Method            receiverTypes.TokenEndpointAuthMethod
	ClientID          string
	Key               IKeyEntry
	AssertionAudience string
	SigningAlg        jose.SignatureAlgorithm
}

// signatureAlgorithm returns the configured client_assertion signing
// algorithm, defaulting to ES256 when unset.
func (c ClientAuthConfig) signatureAlgorithm() jose.SignatureAlgorithm {
	if c.SigningAlg == "" {
		return jose.ES256
	}
	return c.SigningAlg
}

// clientAuthenticationConfigured reports whether an OAuth2 client
// authentication mechanism is configured. An empty method defaults to none.
func clientAuthenticationConfigured(c ClientAuthConfig) bool {
	method := c.Method
	if method == "" {
		method = receiverTypes.None
	}
	return method != receiverTypes.None
}

// curveForSignatureAlgorithm returns the elliptic curve that alg requires.
// RFC 7518 section 3.4 pairs each ECDSA algorithm with exactly one curve, so
// the signing key must sit on the curve named here.
func curveForSignatureAlgorithm(alg jose.SignatureAlgorithm) (elliptic.Curve, error) {
	switch alg {
	case jose.ES256:
		return elliptic.P256(), nil
	case jose.ES384:
		return elliptic.P384(), nil
	case jose.ES512:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported client authentication signing algorithm: %q", alg)
	}
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
		DPoP:       DPoPConfig{},
		ClientAuth: ClientAuthConfig{},
	}

	return NewWalletWithConfig(config)
}

// NewWalletWithoutStore creates a Wallet that persists nothing: it is
// NewWalletWithConfig with Config.Storeless set, for a component that performs
// one OpenID4VCI or OpenID4VP exchange and hands the result to whatever owns
// the durable state. See Config.Storeless.
func NewWalletWithoutStore(config Config) (*Wallet, error) {
	config.Storeless = true
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
	if err := validateClientAuthConfig(config.ClientAuth); err != nil {
		return nil, err
	}

	normalizedProfile, err := config.Profile.Normalize()
	if err != nil {
		return nil, fmt.Errorf("invalid wallet profile: %w", err)
	}
	// A dispatcher supplied by the caller keeps ownership of its plugin
	// profiles; the root only verifies they match. Default dispatchers built
	// here are configured by the root before being verified.
	receiverInjected := config.Receiver != nil
	presenterInjected := config.Presenter != nil

	if config.Storeless && config.CredStore != nil {
		return nil, fmt.Errorf("a storeless wallet cannot be configured with a credential store")
	}
	if config.CredStore == nil && !config.Storeless {
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

	if !receiverInjected {
		propagateReceiverProfile(config.Receiver, normalizedProfile)
	}
	if err := validateReceiverPluginProfiles(config.Receiver, normalizedProfile); err != nil {
		return nil, err
	}
	if !presenterInjected {
		propagatePresenterProfile(config.Presenter, normalizedProfile)
		propagatePresenterTransactionDataTypes(config.Presenter, config.SupportedTransactionDataTypes)
	}
	if err := validatePresenterPluginProfiles(config.Presenter, normalizedProfile); err != nil {
		return nil, err
	}

	if config.DPoP.Enabled && config.DPoP.Key == nil {
		key, err := newInMemoryECKeyEntry()
		if err != nil {
			return nil, fmt.Errorf("failed to generate DPoP key: %w", err)
		}
		config.DPoP.Key = key
	}
	return &Wallet{
		credStore:  config.CredStore,
		idProf:     config.IDProfiler,
		receiver:   config.Receiver,
		serializer: config.Serializer,
		verifier:   config.Verifier,
		presenter:  config.Presenter,
		dpop:       config.DPoP,
		clientAuth: config.ClientAuth,

		profile: normalizedProfile,

		clientAttestation: config.ClientAttestation,
		keyAttestation:    config.KeyAttestation,
		attestationTrust:  config.AttestationTrust,
		oid4vciSigner:     config.OID4VCISigner,

		credentialAcceptance: config.CredentialAcceptance,
	}, nil
}

// oid4vciFinalSigner resolves the OpenID4VCI Final signing primitives for one
// issuance. Config.OID4VCISigner wins; otherwise the transport plugin itself is
// used when it also implements the signer, which keeps the bundled plugin's
// behaviour; otherwise the software default signs.
func (w *Wallet) oid4vciFinalSigner(transport receiverTypes.OID4VCIFinalTransport) receiverTypes.OID4VCIFinalSigner {
	if w.oid4vciSigner != nil {
		return w.oid4vciSigner
	}
	if signer, ok := transport.(receiverTypes.OID4VCIFinalSigner); ok {
		return signer
	}
	return oid4vcisign.Default{}
}

// oid4vciProfileValidator is the optional receiver capability the root uses to
// apply HAIP constraints to fetched issuer metadata before PAR. It is asserted
// at runtime instead of widening the exported Final receiver interface.
type oid4vciProfileValidator interface {
	ValidateIssuerMetadataForProfile(*receiverTypes.CredentialIssuerMetadata) error
	ValidateCredentialConfigurationForProfile(receiverTypes.CredentialConfiguration) error
}

// setProtocolProfile is implemented by the built-in protocol plugins so the root
// can propagate its profile to the default dispatchers it constructs itself.
type setProtocolProfile interface {
	SetProtocolProfile(profile.Profile)
}

// setSupportedTransactionDataTypes is implemented by presenter plugins that can
// accept the wallet's supported transaction_data types.
type setSupportedTransactionDataTypes interface {
	SetSupportedTransactionDataTypes([]string)
}

func propagateReceiverProfile(dispatcher *receiver.ReceivingDispatcher, value profile.Profile) {
	for _, plugin := range dispatcher.Plugins() {
		if setter, ok := plugin.(setProtocolProfile); ok {
			setter.SetProtocolProfile(value)
		}
	}
}
func propagatePresenterProfile(dispatcher *presenter.PresentationDispatcher, value profile.Profile) {
	for _, plugin := range dispatcher.Plugins() {
		if setter, ok := plugin.(setProtocolProfile); ok {
			setter.SetProtocolProfile(value)
		}
	}
}
func propagatePresenterTransactionDataTypes(dispatcher *presenter.PresentationDispatcher, values []string) {
	for _, plugin := range dispatcher.Plugins() {
		if setter, ok := plugin.(setSupportedTransactionDataTypes); ok {
			setter.SetSupportedTransactionDataTypes(values)
		}
	}
}

// validateReceiverPluginProfiles fails when a registered plugin that exposes a
// protocol profile disagrees with the wallet. Draft-only plugins that do not
// implement profile.Carrier are ignored.
func validateReceiverPluginProfiles(dispatcher *receiver.ReceivingDispatcher, value profile.Profile) error {
	for _, plugin := range dispatcher.Plugins() {
		carrier, ok := plugin.(profile.Carrier)
		if !ok {
			continue
		}
		if pluginProfile := carrier.ProtocolProfile(); pluginProfile != value {
			return fmt.Errorf("plugin profile %q does not match wallet profile %q", pluginProfile, value)
		}
	}
	return nil
}

// validatePresenterPluginProfiles fails when a registered presenter plugin does
// not carry the wallet profile.
func validatePresenterPluginProfiles(dispatcher *presenter.PresentationDispatcher, value profile.Profile) error {
	for _, plugin := range dispatcher.Plugins() {
		carrier, ok := plugin.(profile.Carrier)
		if !ok {
			continue
		}
		if pluginProfile := carrier.ProtocolProfile(); pluginProfile != value {
			return fmt.Errorf("plugin profile %q does not match wallet profile %q", pluginProfile, value)
		}
	}
	return nil
}
func validateClientAuthConfig(config ClientAuthConfig) error {
	method := config.Method
	if method == "" {
		method = receiverTypes.None
	}

	switch method {
	case receiverTypes.None:
		return nil
	case receiverTypes.PrivateKeyJwt:
		if strings.TrimSpace(config.ClientID) == "" {
			return fmt.Errorf("client ID is required for private_key_jwt client authentication")
		}
		if config.Key == nil {
			return fmt.Errorf("client authentication key is required for private_key_jwt client authentication")
		}
		if strings.TrimSpace(config.Key.PublicKey().KeyID) == "" {
			return fmt.Errorf("client authentication key kid is required for private_key_jwt client authentication")
		}
		alg := config.signatureAlgorithm()
		curve, err := curveForSignatureAlgorithm(alg)
		if err != nil {
			return err
		}
		if _, err := joseutil.NewJWKSigner(config.Key, alg); err != nil {
			return fmt.Errorf("client authentication key is not compatible with %s: %w", alg, err)
		}
		var publicKey *ecdsa.PublicKey

		switch k := config.Key.PublicKey().Key.(type) {
		case *ecdsa.PublicKey:
			publicKey = k
		case ecdsa.PublicKey:
			publicKey = &k
		}

		if publicKey == nil || publicKey.Curve == nil || publicKey.Params() == nil ||
			publicKey.Params().Name != curve.Params().Name {
			return fmt.Errorf("client authentication key is not compatible with %s", alg)
		}
		return nil
	default:
		return fmt.Errorf("unsupported client authentication method: %q", method)
	}
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

// DIDCreateOptions holds options for DID creation.
type DIDCreateOptions struct {
	TypeID    string
	PublicKey jose.JSONWebKey
}

func randomBase64URL(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
