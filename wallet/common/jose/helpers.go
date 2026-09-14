package jose

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/serializer/types"
)

// acceptedSignatureAlgorithms is the canonical list of JWS signature
// algorithms this wallet accepts when parsing a credential or presentation.
// It holds the ECDSA family of RFC 7518 Section 3.4 (ES256, ES384, ES512), the
// RSASSA-PKCS1-v1_5 family of Section 3.3 (RS256, RS384, RS512), the
// RSASSA-PSS family of Section 3.5 (PS256, PS384, PS512) and EdDSA over Ed25519
// (RFC 8037).
//
// The MAC algorithms of RFC 7518 Section 3.2 and the unsigned "none" of RFC
// 7515 Section 3.6 are deliberately absent: neither authenticates an issuer to
// a wallet holding only public keys. Callers must not modify this slice; use
// AcceptedSignatureAlgorithms for a copy.
var acceptedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.EdDSA,
}

// AcceptedSignatureAlgorithms returns a copy of the canonical list of JWS
// signature algorithms a wallet may parse a credential or presentation with: the
// ECDSA family ES256/ES384/ES512 (RFC 7518 Section 3.4), the RSASSA-PKCS1-v1_5
// family RS256/RS384/RS512 (Section 3.3), the RSASSA-PSS family
// PS256/PS384/PS512 (Section 3.5) and EdDSA (RFC 8037).
//
// The MAC algorithms of RFC 7518 Section 3.2 and the unsigned "none" of RFC
// 7515 Section 3.6 are never included. The returned slice is a copy, so callers
// may modify it without affecting the canonical list or each other.
func AcceptedSignatureAlgorithms() []jose.SignatureAlgorithm {
	return slices.Clone(acceptedSignatureAlgorithms)
}

// ReconstructJWT reconstructs a complete JWT string from a CredentialProof
// The proof contains:
// - Payload: "header.payload" (signing input)
// - Signature: raw signature bytes
//
// This function base64url-encodes the signature and concatenates to create:
// "header.payload.signature"
func ReconstructJWT(proof *credential.CredentialProof) string {
	if proof == nil {
		return ""
	}

	// Payload already contains "header.payload"
	// Encode signature using URL-safe base64 without padding
	sigEncoded := base64.RawURLEncoding.EncodeToString(proof.Signature)

	// Concatenate to form complete JWT
	return string(proof.Payload) + "." + sigEncoded
}

// ParseAlgorithm converts an algorithm name string to the corresponding jose.SignatureAlgorithm.
// It returns the matching jose.SignatureAlgorithm for the digital signature
// algorithms this wallet verifies: the ECDSA family "ES256", "ES384" and
// "ES512" (RFC 7518 Section 3.4), the RSASSA families "RS256", "RS384",
// "RS512" (Section 3.3) and "PS256", "PS384", "PS512" (Section 3.5), and
// "EdDSA" (RFC 8037). The comparison is case sensitive, as the "alg" values of
// RFC 7515 Section 4.1.1 are.
//
// The accepted set is AcceptedSignatureAlgorithms, so the parser and the
// algorithm lists handed to go-jose can never disagree. The MAC algorithms of
// RFC 7518 Section 3.2 and the unsigned "none" of RFC 7515 Section 3.6 are
// deliberately absent: neither authenticates an issuer to a wallet holding only
// public keys. If algStr is not supported it returns an empty algorithm and an
// error wrapped with types.ErrUnsupportedAlgorithm.
func ParseAlgorithm(algStr string) (jose.SignatureAlgorithm, error) {
	alg := jose.SignatureAlgorithm(algStr)
	if slices.Contains(acceptedSignatureAlgorithms, alg) {
		return alg, nil
	}
	return "", fmt.Errorf("unsupported algorithm %s: %w", algStr, types.ErrUnsupportedAlgorithm)
}

// EqualPublicKey reports whether two JWKs represent the same public key
// EqualPublicKey reports whether two JSON Web Keys represent the same public key using RFC 7638 SHA-256 thumbprints.
// It computes each key's thumbprint with SHA-256 and returns true if the resulting thumbprints are identical.
// If computing a thumbprint for either key fails, it returns false and the wrapped error.
func EqualPublicKey(a, b jose.JSONWebKey) (bool, error) {
	tpA, err := a.Thumbprint(crypto.SHA256)
	if err != nil {
		return false, fmt.Errorf("failed to compute thumbprint: %w", err)
	}
	tpB, err := b.Thumbprint(crypto.SHA256)
	if err != nil {
		return false, fmt.Errorf("failed to compute thumbprint: %w", err)
	}
	return bytes.Equal(tpA, tpB), nil
}

// NewHashFromAlgorithm selects a hash.Hash implementation appropriate for the provided jose.SignatureAlgorithm.
// ES256, RS256 and PS256 use SHA-256; ES384, RS384 and PS384 use SHA-384; ES512, RS512, PS512 and EdDSA use SHA-512.
// If the algorithm is unrecognized, SHA-256 is used.
func NewHashFromAlgorithm(alg jose.SignatureAlgorithm) hash.Hash {
	switch alg {
	case jose.ES256, jose.RS256, jose.PS256:
		return sha256.New()
	case jose.ES384, jose.RS384, jose.PS384:
		return sha512.New384()
	case jose.ES512, jose.RS512, jose.PS512:
		return sha512.New()
	case jose.EdDSA:
		return sha512.New()
	default:
		return sha256.New()
	}
}
