package wallet

import (
	"context"
	"fmt"
)

// ReceiveCredential runs a whole OpenID4VCI Draft 13 Pre-Authorized Code Flow
// in one call: it is Draft13().AuthorizePreAuthorizedIssuance followed by
// Draft13().RequestCredential with req.Key as the one holder key, so the wire
// is Draft 13's throughout. The metadata is read from the Draft 13 Section
// 11.2.2 location, and the key proof carries the c_nonce of the Token Response
// (Section 6.2); Draft 13 has no Nonce Endpoint, so none is called even when
// the metadata advertises one. The Credential Request is the Section 7.2
// shape: format (or credential_identifier) and one proof.
//
// The credential is stored once it passes req.Acceptance, or else
// Config.CredentialAcceptance; with neither policy, or without req.Key,
// nothing is requested at all (ErrCredentialAcceptancePolicyRequired,
// ErrDraft13HolderKeyMissing), so the pre-authorized code is not spent on a
// credential the wallet would refuse. A storeless wallet verifies the
// credential and returns it without storing it.
//
// ReceiveCredential returns ErrProfileForbidsDraft unless Config.Profiles
// enables profile.Draft13. An issuer that defers the credential
// (Section 7.3, transaction_id) gets ErrDraft13CredentialDeferred: polling
// and notifications need the staged Draft13() methods, and OpenID4VCI 1.0
// issuers need AuthorizePreAuthorizedIssuance and RequestCredential.
func (w *Wallet) ReceiveCredential(ctx context.Context, req ReceiveCredentialRequest) (*SavedCredential, error) {
	saved, err := w.receiveCredential(ctx, req)
	return saved, classifyKeepingMessage(err)
}

func (w *Wallet) receiveCredential(ctx context.Context, req ReceiveCredentialRequest) (*SavedCredential, error) {
	if err := w.requireDraft13(); err != nil {
		return nil, err
	}
	// Both are checked before the token request: the staged methods check
	// them only at RequestCredential, after the one-time code was redeemed.
	if _, err := w.acceptancePolicy(req.Acceptance); err != nil {
		return nil, err
	}
	if req.Key == nil {
		return nil, ErrDraft13HolderKeyMissing
	}
	draft13 := w.Draft13()
	grant, err := draft13.AuthorizePreAuthorizedIssuance(ctx, PreAuthorizedIssuanceRequest{
		CredentialOffer:           req.CredentialOffer,
		CredentialConfigurationID: req.CredentialConfigurationID,
		TxCode:                    req.TxCode,
	})
	if err != nil {
		return nil, err
	}
	result, err := draft13.RequestCredential(ctx, grant, CredentialRequest{
		HolderKeys: []IKeyEntry{req.Key},
		Acceptance: req.Acceptance,
	})
	if err != nil {
		return nil, err
	}
	if result.Deferred != nil {
		return nil, ErrDraft13CredentialDeferred
	}
	if len(result.Credentials) != 1 {
		return nil, fmt.Errorf("%w: %d credentials were returned", ErrDraft13CredentialResponseInvalid, len(result.Credentials))
	}
	return result.Credentials[0], nil
}
