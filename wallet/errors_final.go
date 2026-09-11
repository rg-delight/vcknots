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

// Sentinel errors the credential acceptance path wraps at each failure site.
// They exist so an integrator can branch on the condition that stopped a
// credential from being stored — with errors.Is, which holds through every
// wrapping this package performs — instead of matching message text. Every one
// of them is reachable through VerifyCredentialForAcceptance and
// VerifyCredentialWithPolicy.
//
// Two acceptance failures keep the typed errors they already had rather than
// gaining a sentinel here: an untrusted, revoked or unknown-revocation issuer
// certificate chain arrives as a *x509.SigningChainError or *x509.CRLCheckError
// from wallet/common/x509, which carry the certificate and the reason.
var (
	// ErrCredentialParse reports that the credential is not a credential of
	// the requested serialization: it does not deserialize, its issuer JWT is
	// not three base64url parts, or one of its parts is not the JSON it must
	// be. Nothing about the issuer has been checked when it is returned.
	ErrCredentialParse = errors.New("credential could not be parsed")
	// ErrCredentialTypInvalid reports that the issuer JWT's typ header does
	// not name a media type the requested serialization allows. SD-JWT VC
	// (draft-ietf-oauth-sd-jwt-vc Section 3.1) allows dc+sd-jwt and the
	// earlier vc+sd-jwt.
	ErrCredentialTypInvalid = errors.New("credential typ header is not supported")
	// ErrCredentialAlgUnsupported reports that the issuer JWT's alg header is
	// missing, is the unsigned "none" of RFC 7515 Section 3.6, is absent from
	// the acceptance policy's SigningAlgorithms, or names an algorithm no
	// registered verifier plugin implements.
	ErrCredentialAlgUnsupported = errors.New("credential signing algorithm is not accepted")
	// ErrHolderBindingMissing reports that the policy requires holder binding
	// and the credential carries no cnf claim.
	ErrHolderBindingMissing = errors.New("credential does not contain a cnf holder binding")
	// ErrHolderBindingMismatch reports that the credential's cnf.jwk is not
	// the holder key the flow used, compared by RFC 7638 thumbprint.
	ErrHolderBindingMismatch = errors.New("credential is bound to a different holder key")
	// ErrIssuerKeyUnresolved reports that no issuer public key could be
	// obtained to verify the signature with: the policy configures neither
	// x5c trust nor a resolution hook, the hook failed, or it returned no key.
	// The credential's signature has not been checked when it is returned.
	ErrIssuerKeyUnresolved = errors.New("issuer key could not be resolved")
	// ErrIssuerSignatureInvalid reports that every candidate issuer key failed
	// to verify the credential's signature.
	ErrIssuerSignatureInvalid = errors.New("issuer signature could not be verified")
	// ErrIssuerDNSBindingFailed reports that RequireIssuerDNSBinding is set and
	// the leaf certificate carries no dNSName SAN equal to the host of an https
	// iss. This is ecosystem policy rather than an SD-JWT VC requirement.
	ErrIssuerDNSBindingFailed = errors.New("issuer certificate is not bound to the issuer host")
	// ErrCredentialExpired reports that the credential's exp claim is in the
	// past, measured against the policy clock and ClockSkew.
	ErrCredentialExpired = errors.New("credential has expired")
	// ErrCredentialNotYetValid reports that the credential's nbf claim is in
	// the future, measured the same way.
	ErrCredentialNotYetValid = errors.New("credential is not yet valid")
	// ErrDisclosureIntegrity reports that an SD-JWT disclosure is not covered
	// by exactly one digest of the issuer-signed payload, which would let a
	// disclosure be added or replayed without invalidating the signature.
	ErrDisclosureIntegrity = errors.New("SD-JWT disclosure integrity check failed")
	// ErrSDAlgUnsupported reports that the credential's _sd_alg is not a
	// string or names a hash outside AcceptedSDAlgorithms.
	ErrSDAlgUnsupported = errors.New("credential _sd_alg is not supported")
	// ErrHAIPX5CRequired reports that the wallet runs the HAIP profile and an
	// SD-JWT VC arrived without the x5c header HAIP Section 6.1.1 requires.
	ErrHAIPX5CRequired = errors.New("HAIP requires the issuer signing certificate in the x5c header")
	// ErrHAIPTrustAnchorInX5C reports that the credential's x5c chain contains
	// a configured trust anchor, which HAIP Section 6.1.1 forbids.
	ErrHAIPTrustAnchorInX5C = errors.New("HAIP forbids including the trust anchor certificate in the x5c header")
)
