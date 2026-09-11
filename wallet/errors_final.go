package wallet

import "errors"

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
	// the response chose.
	ErrHTTPRedirectNotAllowed = errors.New("OID4VCI endpoint redirected; redirects are not followed")
	// ErrProofAlgorithmNotSupported reports that the wallet and the issuer
	// share no proof signing algorithm.
	ErrProofAlgorithmNotSupported = errors.New("no proof signing algorithm shared with the issuer")
	// ErrPreRegisteredClientUnknown reports that a pre-registered client_id
	// was presented which the wallet's client registry does not hold.
	ErrPreRegisteredClientUnknown = errors.New("pre-registered client_id is not in the wallet registry")
)
