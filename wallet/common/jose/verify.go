package jose

import (
	"crypto/rsa"
	"fmt"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
)

// MinimumRSAModulusBits is the smallest RSA modulus a JWS signature is
// verified under. RFC 7518 Section 3.3 states for RSASSA-PKCS1-v1_5, and
// Section 3.5 repeats for RSASSA-PSS, that "A key of size 2048 bits or larger
// MUST be used with these algorithms".
const MinimumRSAModulusBits = 2048

// ErrVerificationKeyTooWeak reports a verification key the library refuses
// before any signature is checked under it: an RSA key whose modulus is
// shorter than MinimumRSAModulusBits (RFC 7518 Sections 3.3 and 3.5).
var ErrVerificationKeyTooWeak = common.NewCodedError("jose_verification_key_too_weak", "verification key is below the minimum strength")

// RequireVerificationKeyStrength refuses a key the JWS algorithms of RFC 7518
// forbid, with ErrVerificationKeyTooWeak. key may be a crypto public key
// (*rsa.PublicKey, rsa.PublicKey), an *rsa.PrivateKey, or a jose.JSONWebKey
// (value or pointer) holding one of them. A key of any other type is left to
// the JWS library, which refuses what it cannot use.
func RequireVerificationKeyStrength(key any) error {
	var modulusBits int
	switch typed := key.(type) {
	case jose.JSONWebKey:
		return RequireVerificationKeyStrength(typed.Key)
	case *jose.JSONWebKey:
		if typed == nil {
			return nil
		}
		return RequireVerificationKeyStrength(typed.Key)
	case *rsa.PublicKey:
		if typed == nil || typed.N == nil {
			return fmt.Errorf("%w: RSA public key has no modulus", ErrVerificationKeyTooWeak)
		}
		modulusBits = typed.N.BitLen()
	case rsa.PublicKey:
		return RequireVerificationKeyStrength(&typed)
	case *rsa.PrivateKey:
		if typed == nil {
			return nil
		}
		return RequireVerificationKeyStrength(&typed.PublicKey)
	default:
		return nil
	}
	if modulusBits < MinimumRSAModulusBits {
		return fmt.Errorf("%w: RSA modulus is %d bits, below the %d bit minimum of RFC 7518 Section 3.3",
			ErrVerificationKeyTooWeak, modulusBits, MinimumRSAModulusBits)
	}
	return nil
}

// VerifySignature verifies signed under key and returns the verified payload,
// after refusing a key RequireVerificationKeyStrength refuses. It is the one
// place the library verifies a JWS it parsed itself — a Status List Token, a
// signed Credential Issuer Metadata document, a Domain Linkage Credential — so
// that every such signature is held to the same key requirements. A weak key
// fails with ErrVerificationKeyTooWeak rather than with the JWS library's
// signature error, so a caller can tell the two apart.
func VerifySignature(signed *jose.JSONWebSignature, key any) ([]byte, error) {
	if err := RequireVerificationKeyStrength(key); err != nil {
		return nil, err
	}
	return signed.Verify(key)
}
