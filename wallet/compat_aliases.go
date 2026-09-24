package wallet

// Temporary aliases for the credential acceptance and attestation API, which
// lives in wallet/acceptance and wallet/attestation. They keep the issuance
// code of this package compiling until it uses the sub-packages directly, and
// are removed then. New code uses the sub-packages.

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/attestation"
	"github.com/trustknots/vcknots/wallet/credential"
)

type (
	CredentialAcceptancePolicy = acceptance.Policy
	CredentialVerification     = acceptance.Verification
	IssuerX509TrustOptions     = acceptance.IssuerX509TrustOptions

	ClientAttestationProvider = attestation.ClientProvider
	ClientAttestationRequest  = attestation.ClientRequest
	ClientAttestation         = attestation.ClientAttestation
	KeyAttestationProvider    = attestation.KeyProvider
	KeyAttestationRequest     = attestation.KeyRequest
	KeyAttestation            = attestation.KeyAttestation
	StaticClientAttester      = attestation.StaticClientAttester
	StaticKeyAttester         = attestation.StaticKeyAttester
	AttestationTrustPolicy    = attestation.TrustPolicy
	AttestationJOSEHeader     = attestation.JOSEHeader
)

var (
	ErrCredentialParse                      = acceptance.ErrCredentialParse
	ErrCredentialTypInvalid                 = acceptance.ErrCredentialTypInvalid
	ErrCredentialAlgUnsupported             = acceptance.ErrCredentialAlgUnsupported
	ErrHolderBindingMissing                 = acceptance.ErrHolderBindingMissing
	ErrHolderBindingMismatch                = acceptance.ErrHolderBindingMismatch
	ErrHolderBindingConfirmationUnsupported = acceptance.ErrHolderBindingConfirmationUnsupported
	ErrIssuerKeyUnresolved                  = acceptance.ErrIssuerKeyUnresolved
	ErrIssuerSignatureInvalid               = acceptance.ErrIssuerSignatureInvalid
	ErrIssuerDNSBindingFailed               = acceptance.ErrIssuerDNSBindingFailed
	ErrCredentialExpired                    = acceptance.ErrCredentialExpired
	ErrCredentialNotYetValid                = acceptance.ErrCredentialNotYetValid
	ErrDisclosureIntegrity                  = acceptance.ErrDisclosureIntegrity
	ErrSDAlgUnsupported                     = acceptance.ErrSDAlgUnsupported
	ErrHAIPX5CRequired                      = acceptance.ErrHAIPX5CRequired
	ErrHAIPTrustAnchorInX5C                 = acceptance.ErrHAIPTrustAnchorInX5C

	ErrClientAttestationInvalid = attestation.ErrClientAttestationInvalid
	ErrKeyAttestationInvalid    = attestation.ErrKeyAttestationInvalid
)

// ValidateClientAttestation calls attestation.ValidateClientAttestation.
func ValidateClientAttestation(ctx context.Context, a *ClientAttestation, request ClientAttestationRequest, policy AttestationTrustPolicy) error {
	return attestation.ValidateClientAttestation(ctx, a, request, policy)
}

// ValidateKeyAttestation calls attestation.ValidateKeyAttestation.
func ValidateKeyAttestation(ctx context.Context, a *KeyAttestation, request KeyAttestationRequest, policy AttestationTrustPolicy) error {
	return attestation.ValidateKeyAttestation(ctx, a, request, policy)
}

// AttestationJOSEHeaderFromJWT decodes the protected header of a compact JWS
// without verifying it.
func AttestationJOSEHeaderFromJWT(token string) (AttestationJOSEHeader, error) {
	header, _, err := parseAttestationJWT(token)
	if err != nil {
		return AttestationJOSEHeader{}, err
	}
	return AttestationJOSEHeader(header), nil
}

const keyAttestationJWTType = "key-attestation+jwt"

type attestationJWTHeader struct {
	Type      string   `json:"typ"`
	Algorithm string   `json:"alg"`
	KeyID     string   `json:"kid"`
	X5C       []string `json:"x5c"`
}

type attestationJWTClaims struct {
	Iss          string            `json:"iss"`
	Aud          any               `json:"aud"`
	Nonce        string            `json:"nonce"`
	AttestedKeys []jose.JSONWebKey `json:"attested_keys"`
}

// parseAttestationJWT decodes a compact JWS header and claims without
// verifying them.
func parseAttestationJWT(token string) (attestationJWTHeader, attestationJWTClaims, error) {
	var header attestationJWTHeader
	var claims attestationJWTClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return header, claims, fmt.Errorf("expected a compact JWS with three parts")
	}
	for i, target := range []any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[i], "="))
		if err != nil {
			return header, claims, fmt.Errorf("invalid JWS segment encoding: %w", err)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return header, claims, fmt.Errorf("invalid JWS segment JSON: %w", err)
		}
	}
	return header, claims, nil
}

// publicHolderJWK is the public half of key with alg ES256 and use sig
// defaulted.
func publicHolderJWK(key jose.JSONWebKey) jose.JSONWebKey {
	public := key.Public()
	if public.Algorithm == "" {
		public.Algorithm = string(jose.ES256)
	}
	if public.Use == "" {
		public.Use = "sig"
	}
	return public
}

// jwkThumbprint is the base64url RFC 7638 SHA-256 thumbprint of key.
func jwkThumbprint(key jose.JSONWebKey) (string, error) {
	if key.Key == nil {
		return "", fmt.Errorf("missing key")
	}
	public := key.Public()
	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// requireJWKThumbprint fails unless want and got have the same thumbprint.
func requireJWKThumbprint(want jose.JSONWebKey, got jose.JSONWebKey) error {
	wantThumbprint, err := jwkThumbprint(want)
	if err != nil {
		return err
	}
	gotThumbprint, err := jwkThumbprint(got)
	if err != nil {
		return err
	}
	if wantThumbprint != gotThumbprint {
		return fmt.Errorf("thumbprint mismatch")
	}
	return nil
}

// issuerSignedJWT is the issuer-signed JWT of raw: for an SD-JWT VC, the part
// before the first "~".
func issuerSignedJWT(flavor credential.SupportedSerializationFlavor, raw []byte) string {
	if flavor == credential.SDJwtVC {
		if index := strings.IndexByte(string(raw), '~'); index >= 0 {
			return string(raw[:index])
		}
	}
	return string(raw)
}

// attestationPolicyFor is the trust policy one attestation is validated under:
// Config.AttestationTrust, with RequireX5C raised under HAIP (HAIP §4.4.1,
// §4.5.1), and, when no resolver is configured, the bundled static attester's
// own public key as the resolver for an attestation without x5c.
func (w *Wallet) attestationPolicyFor(provider any) AttestationTrustPolicy {
	policy := w.attestationTrust
	if w.profile.IsHAIP() {
		policy.RequireX5C = true
	}
	if policy.ResolveKey != nil {
		return policy
	}
	var key interface{ PublicKey() jose.JSONWebKey }
	switch attester := provider.(type) {
	case *StaticClientAttester:
		if attester != nil && attester.Key != nil {
			key = attester.Key
		}
	case *StaticKeyAttester:
		if attester != nil && attester.Key != nil {
			key = attester.Key
		}
	}
	if key != nil {
		public := key.PublicKey()
		policy.ResolveKey = func(AttestationJOSEHeader) (any, error) { return public.Key, nil }
	}
	return policy
}
