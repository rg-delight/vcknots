package wallet

import (
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
)

// VerifyCredential reports whether the credential's proof verifies under
// pubKey. Only DefaultCredentialSigningAlgorithms() are accepted, whatever
// plugins the verification dispatcher has registered.
func (w *Wallet) VerifyCredential(credential *credential.Credential, pubKey jose.JSONWebKey) bool {
	if credential == nil || credential.Proof == nil {
		return false
	}
	if !slices.Contains(DefaultCredentialSigningAlgorithms(), credential.Proof.Algorithm) {
		return false
	}

	result, err := w.verifier.Verify(credential.Proof, &pubKey)
	return err == nil && result
}
