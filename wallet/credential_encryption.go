package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// CredentialEncryptionRule is the Holder's own policy for one of the two
// OpenID4VCI 1.0 §8 credential encryptions.
type CredentialEncryptionRule int

const (
	// CredentialEncryptionFollowIssuer is the zero value and the specification
	// default: §8.1 and §8.2 drive both encryptions from the Credential Issuer
	// Metadata alone, so the wallet encrypts what the issuer advertises and
	// obeys an issuer that requires it.
	CredentialEncryptionFollowIssuer CredentialEncryptionRule = iota
	// CredentialEncryptionRequired refuses an issuance whose Credential Issuer
	// does not offer the encryption, with ErrCredentialEncryptionUnavailable.
	CredentialEncryptionRequired
	// CredentialEncryptionDisabled asks for no encryption. An issuer that makes
	// it mandatory is refused with ErrCredentialEncryptionDisallowed rather
	// than downgraded, because the Holder's policy and the issuer's cannot both
	// be satisfied.
	CredentialEncryptionDisabled
)

// CredentialEncryptionPolicy is the Holder's policy for the OpenID4VCI 1.0 §8.1
// Credential Request and §8.2 Credential Response encryption.
//
// The specification gives the Holder no say: both encryptions follow the
// Credential Issuer Metadata, so a wallet whose owner demands an encrypted
// exchange, or refuses one, has nothing to state it with. This policy is that
// statement, and it never downgrades silently — an issuance that cannot honour
// it is refused before any Credential Request is sent.
//
// The zero value is CredentialEncryptionFollowIssuer for both members, which is
// exactly the behaviour of a wallet that names no policy.
type CredentialEncryptionPolicy struct {
	// Request is the policy for §8.1 credential_request_encryption.
	Request CredentialEncryptionRule
	// Response is the policy for §8.2 credential_response_encryption. §8.2
	// requires the Credential Request to be encrypted whenever the response
	// encryption key travels in it, so requiring response encryption requires
	// request encryption too, and disabling request encryption disables the
	// response encryption that depends on it.
	Response CredentialEncryptionRule
}

// disablesEncryption reports whether either channel is disabled. Disabling
// either one disables the pair: the §8.2 response key can only be delivered
// inside an encrypted §8.1 request.
func (p CredentialEncryptionPolicy) disablesEncryption() bool {
	return p.Request == CredentialEncryptionDisabled || p.Response == CredentialEncryptionDisabled
}

// resolveCredentialResponseEncryptionKey applies the policy to the Credential
// Issuer Metadata this issuance resolved, and returns the ephemeral §8.2
// response encryption key the Credential Response is addressed to — nil when
// this issuance asks for none, because the issuer advertises no
// credential_response_encryption or the Holder disabled it.
//
// supplied is a key the caller generated itself; it is returned unchanged
// whenever the policy permits response encryption at all, so a wallet that
// keeps its own key material stays in control of it.
func (p CredentialEncryptionPolicy) resolveCredentialResponseEncryptionKey(
	metadata *receiverTypes.CredentialIssuerMetadata,
	supplied *jose.JSONWebKey,
) (*jose.JSONWebKey, error) {
	if err := p.validate(metadata); err != nil {
		return nil, err
	}
	if p.disablesEncryption() {
		return nil, nil
	}
	if metadata == nil || metadata.CredentialResponseEncryption == nil {
		return nil, nil
	}
	if supplied != nil {
		return supplied, nil
	}
	key, err := NewCredentialResponseEncryptionKey()
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// validate reports whether this issuance can honour the policy at all.
func (p CredentialEncryptionPolicy) validate(metadata *receiverTypes.CredentialIssuerMetadata) error {
	if metadata == nil {
		return nil
	}
	responseEncryption := metadata.CredentialResponseEncryption
	requestEncryption := metadata.CredentialRequestEncryption
	issuerRequiresResponseEncryption := responseEncryption != nil &&
		responseEncryption.EncryptionRequired != nil && *responseEncryption.EncryptionRequired
	if p.disablesEncryption() && issuerRequiresResponseEncryption {
		return fmt.Errorf("%w: the credential issuer requires credential response encryption",
			ErrCredentialEncryptionDisallowed)
	}
	if p.Request == CredentialEncryptionDisabled && requestEncryption != nil {
		// §8.1 leaves the wallet no way to opt out of an advertised
		// credential_request_encryption: the issuer publishes the key the
		// request is encrypted to, and a plaintext request is not the same
		// exchange. Refuse rather than send one shape while the policy asks
		// for another.
		return fmt.Errorf("%w: the credential issuer advertises credential request encryption",
			ErrCredentialEncryptionDisallowed)
	}
	if p.Request == CredentialEncryptionRequired && requestEncryption == nil {
		return fmt.Errorf("%w: the credential issuer advertises no credential_request_encryption",
			ErrCredentialEncryptionUnavailable)
	}
	if p.Response == CredentialEncryptionRequired && (responseEncryption == nil || requestEncryption == nil) {
		// §8.2: "Credential Request encryption MUST be used if the
		// `credential_response_encryption` parameter is included", so an
		// issuer offering only one of the two cannot serve an encrypted
		// response this wallet would accept.
		return fmt.Errorf("%w: the credential issuer advertises no encrypted credential response",
			ErrCredentialEncryptionUnavailable)
	}
	return nil
}

// NewCredentialResponseEncryptionKey generates the ephemeral P-256 key an
// OpenID4VCI 1.0 §8.2 encrypted Credential Response is addressed to. The key is
// for one issuance: it is published in the Credential Request's
// credential_response_encryption.jwk and used once to decrypt the answer.
func NewCredentialResponseEncryptionKey() (jose.JSONWebKey, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("failed to generate a credential response encryption key: %w", err)
	}
	return jose.JSONWebKey{Key: private, Algorithm: string(jose.ECDH_ES), Use: "enc"}, nil
}
