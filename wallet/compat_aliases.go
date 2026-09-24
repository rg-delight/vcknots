package wallet

// Temporary aliases for the credential acceptance and attestation API, which
// lives in wallet/acceptance and wallet/attestation. They keep the issuance
// code of this package compiling until it uses the sub-packages directly, and
// are removed then. New code uses the sub-packages.

import (
	"context"

	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/attestation"
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
	ErrHolderBindingMissing   = acceptance.ErrHolderBindingMissing
	ErrHolderBindingMismatch  = acceptance.ErrHolderBindingMismatch
	ErrIssuerSignatureInvalid = acceptance.ErrIssuerSignatureInvalid

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
