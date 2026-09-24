package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// CredentialEncryptionRule is the holder's rule for one of the two
// OpenID4VCI 1.0 credential encryptions.
type CredentialEncryptionRule int

const (
	// CredentialEncryptionFollowIssuer encrypts what the issuer metadata
	// advertises and obeys an issuer that requires it (Sections 8.1, 8.2).
	CredentialEncryptionFollowIssuer CredentialEncryptionRule = iota
	// CredentialEncryptionRequired refuses an issuer that does not offer the
	// encryption (ErrCredentialEncryptionUnavailable).
	CredentialEncryptionRequired
	// CredentialEncryptionDisabled asks for no encryption and refuses an
	// issuer that requires it (ErrCredentialEncryptionDisallowed).
	CredentialEncryptionDisabled
)

// CredentialEncryptionPolicy is the holder's policy for Credential Request
// (Section 8.1) and Credential Response (Section 8.2) encryption. An issuance
// that cannot honour it is refused at BeginIssuance or
// AuthorizePreAuthorizedIssuance; it is never downgraded. The response key
// travels only inside an encrypted request (Section 8.2), so requiring
// response encryption requires request encryption, and disabling either
// disables both.
type CredentialEncryptionPolicy struct {
	Request  CredentialEncryptionRule
	Response CredentialEncryptionRule
}

func (p CredentialEncryptionPolicy) disablesEncryption() bool {
	return p.Request == CredentialEncryptionDisabled || p.Response == CredentialEncryptionDisabled
}

// responseEncryptionKey returns a new ephemeral key the Credential Response is
// to be encrypted to, or nil when this issuance asks for no response
// encryption.
func (p CredentialEncryptionPolicy) responseEncryptionKey(md *receiverTypes.CredentialIssuerMetadata) (*jose.JSONWebKey, error) {
	if err := p.validate(md); err != nil {
		return nil, err
	}
	if p.disablesEncryption() || md == nil || md.CredentialResponseEncryption == nil || md.CredentialRequestEncryption == nil {
		return nil, nil
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a credential response encryption key: %w", err)
	}
	return &jose.JSONWebKey{Key: private, Algorithm: string(jose.ECDH_ES), Use: "enc"}, nil
}

// validate reports whether the issuer metadata can honour the policy.
func (p CredentialEncryptionPolicy) validate(md *receiverTypes.CredentialIssuerMetadata) error {
	if md == nil {
		return nil
	}
	responseEncryption := md.CredentialResponseEncryption
	requestEncryption := md.CredentialRequestEncryption
	issuerRequiresResponseEncryption := responseEncryption != nil &&
		responseEncryption.EncryptionRequired != nil && *responseEncryption.EncryptionRequired
	switch {
	case p.disablesEncryption() && issuerRequiresResponseEncryption:
		return fmt.Errorf("%w: the credential issuer requires credential response encryption", ErrCredentialEncryptionDisallowed)
	case issuerRequiresResponseEncryption && requestEncryption == nil:
		// Section 8.2: the request must be encrypted when it carries the
		// response key, so the issuer's own metadata leaves no valid request.
		return fmt.Errorf("%w: the credential issuer requires credential response encryption but advertises no credential_request_encryption", ErrCredentialEncryptionUnavailable)
	case p.Request == CredentialEncryptionDisabled && requestEncryption != nil:
		// Section 8.1 leaves no way to opt out of advertised request
		// encryption.
		return fmt.Errorf("%w: the credential issuer advertises credential request encryption", ErrCredentialEncryptionDisallowed)
	case p.Request == CredentialEncryptionRequired && requestEncryption == nil:
		return fmt.Errorf("%w: the credential issuer advertises no credential_request_encryption", ErrCredentialEncryptionUnavailable)
	case p.Response == CredentialEncryptionRequired && (responseEncryption == nil || requestEncryption == nil):
		return fmt.Errorf("%w: the credential issuer advertises no encrypted credential response", ErrCredentialEncryptionUnavailable)
	}
	return nil
}
