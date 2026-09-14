package wallet

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
)

// VerifyCredential verifies a credential with a public key.
func (w *Wallet) VerifyCredential(credential *credential.Credential, pubKey jose.JSONWebKey) bool {
	if credential.Proof == nil {
		return false
	}

	result, err := w.verifier.Verify(credential.Proof, &pubKey)
	return err == nil && result
}
