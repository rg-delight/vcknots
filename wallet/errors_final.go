package wallet

import (
	"errors"

	oid4vp "github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
)

// Sentinel errors the OpenID4VCI Final and HAIP paths wrap with context. They
// exist so callers can branch on a condition with errors.Is instead of
// matching message text.
var (
	// ErrCredentialAcceptancePolicyRequired reports that a flow which must
	// authenticate the issuer before storing a credential ran without a
	// configured Config.CredentialAcceptance.
	ErrCredentialAcceptancePolicyRequired = errors.New("credential acceptance policy is required")
	// ErrUnknownCredentialConfiguration reports that the requested
	// credential_configuration_id is absent from the Credential Issuer's
	// credential_configurations_supported metadata.
	ErrUnknownCredentialConfiguration = errors.New("credential_configuration_id is not offered by the issuer")
	// ErrHTTPRedirectNotAllowed reports that an OpenID4VCI endpoint answered
	// with a redirect. Redirects are refused rather than followed, so that a
	// bound request body and its Authorization header never reach an origin
	// the response chose. It is an alias of the oid4vci plugin's sentinel:
	// the error travels up from there, so the two must be the same value for
	// errors.Is to hold at either import path.
	ErrHTTPRedirectNotAllowed = receiverOid4vci.ErrHTTPRedirectNotAllowed
	// ErrProofAlgorithmNotSupported reports that the wallet and the issuer
	// share no proof signing algorithm. It aliases the oid4vci plugin's
	// sentinel for the same reason as ErrHTTPRedirectNotAllowed.
	ErrProofAlgorithmNotSupported = receiverOid4vci.ErrProofAlgorithmNotSupported
	// ErrPreRegisteredClientUnknown reports that a pre-registered client_id
	// was presented which the wallet's client registry does not hold. It
	// aliases the oid4vp presenter plugin's sentinel, which raises it.
	ErrPreRegisteredClientUnknown = oid4vp.ErrPreRegisteredClientUnknown
)

// ErrHolderBindingConfirmationUnsupported reports that a credential's cnf
// claim names a confirmation method other than cnf.jwk, such as cnf.kid or
// cnf."x5t#S256". Only a confirmation carrying the key itself lets the wallet
// prove possession of it in a Key Binding JWT, so such a credential is
// rejected instead of stored with a binding the wallet cannot exercise.
var ErrHolderBindingConfirmationUnsupported = errors.New("credential cnf confirmation method is not supported; only cnf.jwk is accepted")
