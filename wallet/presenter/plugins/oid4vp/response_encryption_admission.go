package oid4vp

import "slices"

// validateResponseEncryptionMetadata refuses, while the request is parsed, a
// direct_post.jwt request whose Authorization Response this Wallet could not
// encrypt. It applies the selection the response will actually be encrypted
// with (selectResponseEncryptionForProfile), so a Verifier whose metadata
// cannot be answered is refused before the holder is asked to consent rather
// than after, when the response is built.
//
// The Draft24 wire contract is exempt from the HAIP rules, exactly as
// haipRequestObjectPolicy exempts it.
func (b *requestBuilder) validateResponseEncryptionMetadata() error {
	if b.req.ResponseMode != OAuthAuthzReqResponseModeDirectPostJWT {
		return nil
	}
	metadata := b.req.ClientMetadata
	if metadata == nil || len(metadata.Jwks.Keys) == 0 {
		return newAuthorizationRequestError(InvalidRequestError, "%w", ErrResponseEncryptionKeyMissing)
	}
	haip := b.haipRequestObjectPolicy()
	if _, err := selectResponseEncryptionForProfile(metadata, haip); err != nil {
		return newAuthorizationRequestError(InvalidRequestError, "%w", err)
	}
	if haip && (!slices.Contains(metadata.EncryptedResponseEncValuesSupported, "A128GCM") ||
		!slices.Contains(metadata.EncryptedResponseEncValuesSupported, "A256GCM")) {
		return newAuthorizationRequestError(InvalidRequestError, "%w", ErrResponseEncryptionEncMissing)
	}
	return nil
}
