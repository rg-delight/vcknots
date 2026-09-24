package oid4vp

import (
	"fmt"
)

// enforceHAIPProfile applies the HAIP 1.0 constraints that can only be checked
// once the Final Authorization Request parameters have been assembled. It is
// deliberately inert on the Draft24 path and for the Final profile.
func (b *requestBuilder) enforceHAIPProfile() error {
	// Record how this process observed the Request Object and whether the
	// caller's DeliveredByReference attestation was accepted. A caller
	// attestation lets an application that fetched the signed Request Object
	// through request_uri at admission time and re-submits the stored JWT with
	// request= satisfy HAIP §5.1 although this process cannot observe the
	// original delivery. It is scoped to the HAIP delivery check only; the
	// wallet_nonce echo stays bound to an actual request_uri POST.
	deliveryAttested := b.profile.IsHAIP() && b.requestSource == sourceValue &&
		b.requestObjectValidation != nil && b.requestObjectValidation.DeliveredByReference
	if b.req.RequestObjectVerification != nil {
		b.req.RequestObjectVerification.Delivery = b.requestSource.delivery()
		b.req.RequestObjectVerification.DeliveryAttested = deliveryAttested
	}
	if b.draft24 || !b.profile.IsHAIP() {
		return nil
	}
	// HAIP §5.2: "The Wallet MUST support the Response Mode dc_api.jwt" and
	// "The Wallet MUST support unsigned, signed, and multi-signed requests as
	// defined in Appendices A.3.1 and A.3.2". The request_uri encryption rule
	// of §5.1 is therefore relaxed for DC API modes.
	if b.requestSource.isDCAPI() {
		// HAIP §5.2: "The Verifier MUST use the Response Mode dc_api.jwt."
		// The unencrypted dc_api mode stays available to non-HAIP Final.
		if b.req.ResponseMode != OAuthAuthzReqResponseModeDCAPIJWT {
			return newAuthorizationRequestError(InvalidRequestError, "HAIP requires the response_mode dc_api.jwt for Digital Credentials API requests")
		}
		if b.requestSource == sourceDCAPIUnsigned {
			// An unsigned request has no Verifier client_id to authenticate.
			return nil
		}
		clientID, err := parseOID4VPClientID(b.req.ClientID)
		if err != nil {
			return err
		}
		if clientID.prefix != OID4VPClientIDPrefixX509Hash {
			// HAIP §5: "For signed requests, the Verifier MUST use, and the
			// Wallet MUST accept the Client Identifier Prefix x509_hash".
			return newAuthorizationRequestError(InvalidRequestError, "HAIP profile requires the x509_hash Client Identifier Prefix")
		}
		return nil
	}
	if b.requestSource != sourceReference && !deliveryAttested {
		// HAIP §5.1: "Signed Authorization Requests MUST be used by utilizing
		// JAR with the request_uri parameter".
		return fmt.Errorf("%w: %w",
			newAuthorizationRequestError(InvalidRequestError, "HAIP profile requires a signed Authorization Request delivered by request_uri"),
			ErrHAIPRequestURIRequired)
	}
	if b.req.ResponseMode != OAuthAuthzReqResponseModeDirectPostJWT {
		// HAIP §5.1: "Response encryption MUST be used by utilizing response
		// mode direct_post.jwt".
		return newAuthorizationRequestError(InvalidRequestError, "HAIP profile requires response_mode direct_post.jwt")
	}
	clientID, err := parseOID4VPClientID(b.req.ClientID)
	if err != nil {
		return err
	}
	if clientID.prefix != OID4VPClientIDPrefixX509Hash {
		// HAIP §5: "For signed requests, the Verifier MUST use, and the Wallet
		// MUST accept the Client Identifier Prefix x509_hash".
		return newAuthorizationRequestError(InvalidRequestError, "HAIP profile requires the x509_hash Client Identifier Prefix")
	}
	return nil
}
