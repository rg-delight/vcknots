package wallet

import (
	"context"
	"fmt"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/profile"
)

// VerifyCredential reports whether the credential's proof verifies under
// pubKey. Only acceptance.DefaultSigningAlgorithms() are accepted, whatever
// plugins the verification dispatcher has registered.
func (w *Wallet) VerifyCredential(credential *credential.Credential, pubKey jose.JSONWebKey) bool {
	if credential == nil || credential.Proof == nil {
		return false
	}
	if !slices.Contains(acceptance.DefaultSigningAlgorithms(), credential.Proof.Algorithm) {
		return false
	}

	result, err := w.verifier.Verify(credential.Proof, &pubKey)
	return err == nil && result
}

// VerifyCredentialForAcceptance runs Config.CredentialAcceptance over raw,
// the check issuance runs before storing, and stores nothing. A nil policy
// fails with ErrCredentialAcceptancePolicyRequired; other failures wrap the
// acceptance package sentinels.
func (w *Wallet) VerifyCredentialForAcceptance(ctx context.Context, raw []byte, flavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey) (*credential.Credential, *acceptance.Verification, error) {
	parsed, verification, err := w.verifyCredentialForAcceptanceContext(ctx, raw, flavor, holderKey, true)
	return parsed, verification, classify(err)
}

// verifyCredentialForAcceptanceContext applies Config.CredentialAcceptance to
// raw under the Options of the wallet's 1.0 profile.
func (w *Wallet) verifyCredentialForAcceptanceContext(ctx context.Context, raw []byte, flavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey, requirePolicy bool) (*credential.Credential, *acceptance.Verification, error) {
	return w.verifyCredentialUnder(ctx, w.profile, raw, flavor, holderKey, requirePolicy)
}

// verifyCredentialUnder applies Config.CredentialAcceptance to raw under
// issuance profile p: the wallet's 1.0 profile for OpenID4VCI 1.0, and
// profile.Draft13 for a Draft 13 credential. With no policy it fails
// closed when requirePolicy is set, and otherwise runs only
// acceptance.Acceptor.Parse: ReceiveCredential stores without a policy.
func (w *Wallet) verifyCredentialUnder(ctx context.Context, p profile.Profile, raw []byte, flavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey, requirePolicy bool) (*credential.Credential, *acceptance.Verification, error) {
	if w.credentialAcceptance == nil && requirePolicy {
		return nil, nil, fmt.Errorf("issuer verification is not configured: %w", ErrCredentialAcceptancePolicyRequired)
	}
	acceptor, err := acceptance.NewAcceptor(p, w.serializer, w.verifier)
	if err != nil {
		return nil, nil, err
	}
	opts := acceptance.Options{Flavor: flavor, HolderKey: holderKey}
	if w.credentialAcceptance == nil {
		return acceptor.Parse(raw, opts)
	}
	return acceptor.Verify(ctx, raw, *w.credentialAcceptance, opts)
}
