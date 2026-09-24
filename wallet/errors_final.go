package wallet

import (
	"github.com/trustknots/vcknots/wallet/common"
	oid4vp "github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// Sentinel errors the OpenID4VCI Final and HAIP paths wrap with context. They
// exist so callers can branch on a condition with errors.Is instead of
// matching message text.
var (
	// ErrCredentialAcceptancePolicyRequired reports that a flow which must
	// authenticate the issuer before storing a credential ran without a
	// configured Config.CredentialAcceptance.
	ErrCredentialAcceptancePolicyRequired = common.NewCodedError("credential_acceptance_policy_required", "credential acceptance policy is required")
	// ErrUnknownCredentialConfiguration reports that the requested
	// credential_configuration_id is absent from the Credential Issuer's
	// credential_configurations_supported metadata.
	ErrUnknownCredentialConfiguration = common.NewCodedError("unknown_credential_configuration", "credential_configuration_id is not offered by the issuer")
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
	// ErrProofTypeUnsupported reports that the Credential Configuration lists
	// proof_types_supported without the jwt proof type, the only key proof
	// this wallet produces (OpenID4VCI 1.0 §12.2.4, Appendix F). It aliases the
	// receiver types sentinel of the same code.
	ErrProofTypeUnsupported = receiverTypes.ErrInvalidProofType
	// ErrDPoPRequired reports that a DPoP-bound access token is required, as
	// HAIP §4 does, and the token or the server exchange did not provide one.
	// It aliases the oid4vci plugin's sentinel.
	ErrDPoPRequired = receiverOid4vci.ErrDPoPRequired
	// ErrIssuerIdentifierMismatch reports that issuer metadata named a
	// credential_issuer other than the requested Credential Issuer Identifier
	// (VCI 1.0 §12.2.4). It aliases the oid4vci plugin's sentinel of that name.
	ErrIssuerIdentifierMismatch = receiverOid4vci.ErrIssuerIdentifierMismatch
	// ErrIssuerMetadataSignatureInvalid reports that a VCI 1.0 §12.2.3 signed
	// Credential Issuer Metadata document was not accepted. The conditions a
	// caller reports separately wrap it, so errors.Is holds for both the
	// specific cause and this umbrella. It aliases the oid4vci plugin's
	// sentinel, as the four below do.
	ErrIssuerMetadataSignatureInvalid = receiverOid4vci.ErrIssuerMetadataSignatureInvalid
	// ErrIssuerMetadataSubjectMismatch reports that the signed metadata's sub
	// claim names another Credential Issuer Identifier than the requested one.
	ErrIssuerMetadataSubjectMismatch = receiverOid4vci.ErrIssuerMetadataSubjectMismatch
	// ErrIssuerMetadataLeafDNSMismatch reports that the metadata signer's leaf
	// certificate carries no dNSName SAN equal to the DNS name it was required
	// to be bound to.
	ErrIssuerMetadataLeafDNSMismatch = receiverOid4vci.ErrIssuerMetadataLeafDNSMismatch
	// ErrIssuerMetadataExpired reports that the signed metadata's exp claim is
	// not in the future of the verification clock.
	ErrIssuerMetadataExpired = receiverOid4vci.ErrIssuerMetadataExpired
	// ErrIssuerMetadataSignatureRequired reports that signed metadata was
	// demanded and none was obtained: the issuer answered unsigned, or no trust
	// material was configured to authenticate a signer with.
	ErrIssuerMetadataSignatureRequired = receiverOid4vci.ErrIssuerMetadataSignatureRequired
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
var ErrHolderBindingConfirmationUnsupported = common.NewCodedError("credential_holder_binding_unsupported", "credential cnf confirmation method is not supported; only cnf.jwk is accepted")

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
	ErrCredentialParse = common.NewCodedError("credential_parse_failed", "credential could not be parsed")
	// ErrCredentialTypInvalid reports that the issuer JWT's typ header does
	// not name a media type the requested serialization allows. SD-JWT VC
	// (draft-ietf-oauth-sd-jwt-vc Section 3.1) allows dc+sd-jwt and the
	// earlier vc+sd-jwt.
	ErrCredentialTypInvalid = common.NewCodedError("credential_typ_invalid", "credential typ header is not supported")
	// ErrCredentialAlgUnsupported reports that the issuer JWT's alg header is
	// missing, is the unsigned "none" of RFC 7515 Section 3.6, is absent from
	// the acceptance policy's SigningAlgorithms, or names an algorithm no
	// registered verifier plugin implements.
	ErrCredentialAlgUnsupported = common.NewCodedError("credential_alg_unsupported", "credential signing algorithm is not accepted")
	// ErrHolderBindingMissing reports that the policy requires holder binding
	// and the wallet cannot establish one: the credential carries no cnf claim,
	// or it carries a cnf confirmation key while the acceptance call supplied
	// no holder key to compare it against.
	ErrHolderBindingMissing = common.NewCodedError("credential_holder_binding_missing", "credential does not contain a cnf holder binding")
	// ErrHolderBindingMismatch reports that the credential's cnf.jwk is not
	// the holder key the flow used, compared by RFC 7638 thumbprint.
	ErrHolderBindingMismatch = common.NewCodedError("credential_holder_binding_mismatch", "credential is bound to a different holder key")
	// ErrIssuerKeyUnresolved reports that no issuer public key could be
	// obtained to verify the signature with: the policy configures neither
	// x5c trust nor a resolution hook, the hook failed, or it returned no key.
	// The credential's signature has not been checked when it is returned.
	ErrIssuerKeyUnresolved = common.NewCodedError("issuer_key_unresolved", "issuer key could not be resolved")
	// ErrIssuerSignatureInvalid reports that every candidate issuer key failed
	// to verify the credential's signature.
	ErrIssuerSignatureInvalid = common.NewCodedError("issuer_signature_invalid", "issuer signature could not be verified")
	// ErrIssuerDNSBindingFailed reports that RequireIssuerDNSBinding is set and
	// the leaf certificate carries no dNSName SAN equal to the host of an https
	// iss. This is ecosystem policy rather than an SD-JWT VC requirement.
	ErrIssuerDNSBindingFailed = common.NewCodedError("issuer_dns_binding_failed", "issuer certificate is not bound to the issuer host")
	// ErrCredentialExpired reports that the credential's exp claim is in the
	// past, measured against the policy clock and ClockSkew.
	ErrCredentialExpired = common.NewCodedError("credential_expired", "credential has expired")
	// ErrCredentialNotYetValid reports that the credential's nbf claim is in
	// the future, measured the same way.
	ErrCredentialNotYetValid = common.NewCodedError("credential_not_yet_valid", "credential is not yet valid")
	// ErrDisclosureIntegrity reports that an SD-JWT disclosure is not covered
	// by exactly one digest of the issuer-signed payload, which would let a
	// disclosure be added or replayed without invalidating the signature.
	ErrDisclosureIntegrity = common.NewCodedError("disclosure_integrity_failed", "SD-JWT disclosure integrity check failed")
	// ErrSDAlgUnsupported reports that the credential's _sd_alg is not a
	// string or names a hash outside AcceptedSDAlgorithms.
	ErrSDAlgUnsupported = common.NewCodedError("sd_alg_unsupported", "credential _sd_alg is not supported")
	// ErrHAIPX5CRequired reports that the wallet runs the HAIP profile and an
	// SD-JWT VC arrived without the x5c header HAIP Section 6.1.1 requires.
	ErrHAIPX5CRequired = common.NewCodedError("haip_x5c_required", "HAIP requires the issuer signing certificate in the x5c header")
	// ErrHAIPTrustAnchorInX5C reports that the credential's x5c chain contains
	// a configured trust anchor, which HAIP Section 6.1.1 forbids.
	ErrHAIPTrustAnchorInX5C = common.NewCodedError("haip_trust_anchor_in_x5c", "HAIP forbids including the trust anchor certificate in the x5c header")
)

// Sentinel errors of the two-stage OpenID4VCI 1.0 Final issuance API, where
// AuthorizeOID4VCIFinalToken and RequestOID4VCIFinalCredential are separated by
// an interruption a caller may cross a process boundary at. Each one is
// reported through a typed error (*KeyAttestationRequiredError,
// *KeyAttestationNonceError) that also carries the OID4VCIFinalTokenGrant the
// caller resumes from, so errors.As recovers the state and errors.Is the
// condition.
var (
	// ErrKeyAttestationRequired reports that the issuance needs an OpenID4VCI
	// 1.0 Appendix D key attestation the wallet cannot mint itself: the
	// request set ExternalKeyAttestation and carried no KeyAttestation, and no
	// Config.KeyAttestation provider is configured. Nothing has been sent to
	// the Credential Endpoint when it is returned.
	ErrKeyAttestationRequired = common.NewCodedError("key_attestation_required", "credential request requires a key attestation the wallet cannot mint")
	// ErrKeyAttestationNonceStale reports that a caller-supplied key
	// attestation was minted for a different c_nonce than the one the
	// Credential Request must carry: either it never matched the grant, or
	// OpenID4VCI 1.0 §8.3.1.2 "invalid_nonce" made the Credential Issuer hand
	// out a fresh one. An attestation is single use; the caller signs a new
	// one for the c_nonce the accompanying grant now names.
	ErrKeyAttestationNonceStale = common.NewCodedError("key_attestation_nonce_stale", "key attestation nonce is stale")
	// ErrNonceEndpointRequired reports that the issuance needs a key
	// attestation bound to a c_nonce while the Credential Issuer advertises no
	// nonce_endpoint. HAIP requires one: "If the Issuer supports Credential
	// Configurations that require key binding, as indicated by the presence of
	// cryptographic_binding_methods_supported, the nonce_endpoint MUST be
	// present in the Credential Issuer Metadata."
	ErrNonceEndpointRequired = common.NewCodedError("nonce_endpoint_required", "key attestation requires a c_nonce but the issuer advertises no nonce_endpoint")
	// ErrPreAuthorizedGrantMissing reports that a Credential Offer handed to
	// ReceiveOID4VCIFinalPreAuthorizedCredential carries no
	// urn:ietf:params:oauth:grant-type:pre-authorized_code grant with a
	// pre-authorized_code (OpenID4VCI 1.0 §4.1.1).
	ErrPreAuthorizedGrantMissing = common.NewCodedError("pre_authorized_grant_missing", "credential offer carries no pre-authorized_code grant")
	// ErrTransactionCodeRequired reports that the Credential Offer's
	// pre-authorized_code grant carries a tx_code object while the request
	// supplies no Transaction Code. OpenID4VCI 1.0 §6.1: "This value MUST be
	// present if a tx_code object was present in the Credential Offer
	// (including if the object was empty)."
	ErrTransactionCodeRequired = common.NewCodedError("transaction_code_required", "credential offer requires a transaction code")
	// ErrTokenTypeUnsupported reports a Token Response whose token_type is
	// neither the Bearer scheme of RFC 6750 §2.1 nor the DPoP scheme of RFC
	// 9449 §7.1, so the wallet holds no way to present the access token.
	ErrTokenTypeUnsupported = common.NewCodedError("token_type_unsupported", "token response token_type is not supported")
	// ErrDPoPKeyMismatch reports that the key offered to
	// RequestOID4VCIFinalCredential is not the one the DPoP-bound access token
	// in the grant was issued to, compared by RFC 7638 thumbprint. RFC 9449 §5
	// binds the token to the proof key, so presenting it with another key
	// cannot succeed and is refused before the request is sent.
	ErrDPoPKeyMismatch = common.NewCodedError("dpop_key_mismatch", "token grant is bound to a different DPoP key")
)

// Sentinel errors DecodeOID4VCIFinalCredentialResponse wraps at each of its
// rejection sites, so a caller can classify a Credential Response failure with
// errors.Is instead of inspecting its own request options. They are separate
// from the acceptance sentinels above because they describe the transport and
// shape of the §8.2 Credential Response, before any credential is parsed.
var (
	// ErrCredentialResponsePlaintext, ErrCredentialResponseDecrypt and
	// ErrCredentialResponseShape are the receiver's Credential Response
	// decoding errors.
	ErrCredentialResponsePlaintext = receiverTypes.ErrCredentialResponsePlaintext
	ErrCredentialResponseDecrypt   = receiverTypes.ErrCredentialResponseDecrypt
	ErrCredentialResponseShape     = receiverTypes.ErrCredentialResponseShape
	// ErrCredentialResponseMultipleCredentials reports a §8.2 Credential
	// Response carrying more than one credential to an issuance that asked for
	// one. It is separate from ErrCredentialResponseShape because the response
	// is well formed: it simply answers a batch the caller did not request, and
	// a wallet reports that to its holder differently from a malformed body.
	ErrCredentialResponseMultipleCredentials = common.NewCodedError("credential_response_multiple_credentials", "credential response carries more than one credential")
	// ErrCredentialEncryptionUnavailable reports that the Holder's
	// CredentialEncryptionPolicy requires §8.1 request or §8.2 response
	// encryption and the Credential Issuer advertises none.
	ErrCredentialEncryptionUnavailable = common.NewCodedError("credential_encryption_unavailable", "the credential issuer does not offer the credential encryption this wallet requires")
	// ErrCredentialEncryptionDisallowed reports that the Holder's
	// CredentialEncryptionPolicy disables an encryption the Credential Issuer
	// makes mandatory. The two policies cannot both be satisfied, so the
	// issuance is refused rather than downgraded.
	ErrCredentialEncryptionDisallowed = common.NewCodedError("credential_encryption_disallowed", "the credential issuer requires a credential encryption this wallet disabled")
)

// Sentinel errors the RFC 6749 §4.1.2 / RFC 9207 §2.4 checks on the
// authorization response wrap. A wallet that drives the system browser itself
// gets the condition that made the callback unusable — so it can tell the
// holder whether the request expired, whether the redirect belongs to another
// request, or whether the authorization server answered a different issuer —
// instead of one opaque "authorization failed". Every one of them is reachable
// through AuthorizeOID4VCIFinalToken and ResumeOID4VCIFinalAuthorization.
//
// The error redirect itself is the one condition reported with a struct rather
// than a sentinel: it arrives as an *AuthorizationResponseError carrying the
// RFC 6749 §4.1.2.1 error code, its description and the echoed state.
var (
	// ErrAuthorizationRedirectInvalid reports that the redirect the caller
	// handed back is not a URL, or that it is relative and the authorization
	// request it answers is not a URL either, so no parameter of the
	// authorization response can be read.
	ErrAuthorizationRedirectInvalid = common.NewCodedError("authorization_redirect_invalid", "authorization redirect could not be read")
	// ErrAuthorizationRedirectURIMismatch reports that the redirect was not
	// delivered to the registered redirect_uri of this authorization request,
	// compared by scheme, host and path. A redirect to any other target is not
	// this request's response, whatever parameters it carries.
	ErrAuthorizationRedirectURIMismatch = common.NewCodedError("authorization_redirect_uri_mismatch", "authorization redirect does not match the registered redirect_uri")
	// ErrIssuanceStateInvalid reports that a resumed OID4VCIFinalAuthorization
	// or OID4VCIFinalTokenGrant is incomplete or does not belong to the request
	// it is presented with: another client_id, redirect_uri, Credential Issuer
	// or Credential Configuration, or an authorization server the issuer does
	// not delegate to.
	ErrIssuanceStateInvalid = common.NewCodedError("issuance_state_invalid", "resumed issuance state does not match the request")
	// ErrAuthorizationStateMismatch reports that the redirect does not echo the
	// RFC 6749 §4.1.1 state of the authorization request it is presented
	// against, which is what binds the response to the request.
	ErrAuthorizationStateMismatch = common.NewCodedError("authorization_state_mismatch", "authorization redirect state does not match the authorization request")
	// ErrAuthorizationIssMismatch reports that the redirect carries an RFC 9207
	// iss parameter that is not the issuer identifier of the authorization
	// server the request was sent to, or carries it more than once. §2.4: the
	// client "MUST compare" the value and reject a mismatch, which is what
	// stops a mix-up attack from replaying a code from another server.
	ErrAuthorizationIssMismatch = common.NewCodedError("authorization_iss_mismatch", "authorization redirect iss does not identify the authorization server")
	// ErrAuthorizationIssMissing reports that the redirect carries no iss
	// parameter while one is required: the authorization server advertises
	// authorization_response_iss_parameter_supported, or the wallet runs the
	// HAIP profile, whose FAPI 2.0 §5.3.2.2 base requires clients to check iss.
	ErrAuthorizationIssMissing = common.NewCodedError("authorization_iss_missing", "authorization redirect is missing the required iss parameter")
	// ErrAuthorizationCodeMissing reports a redirect that is neither an error
	// response nor carries the RFC 6749 §4.1.2 code parameter, so there is
	// nothing to exchange at the token endpoint.
	ErrAuthorizationCodeMissing = common.NewCodedError("authorization_code_missing", "authorization redirect carries no authorization code")
	// ErrAuthorizationRequestURIExpired reports that the RFC 9126 §2.2
	// request_uri of a Pushed Authorization Request is no longer usable at the
	// authorization endpoint, measured against OID4VCIFinalAuthorization.ExpiresAt.
	ErrAuthorizationRequestURIExpired = common.NewCodedError("authorization_request_uri_expired", "pushed authorization request_uri has expired")
)

// Sentinel errors the attestation validation of HAIP §4.4 wraps. The wallet
// authenticates every attestation an attester hands it before a request
// carrying it leaves the process, and there is no opt-out, so these are the two
// conditions that stop an otherwise well-formed issuance for a reason the
// issuer never sees. The reason stays in the chain: the error they wrap names
// the claim, signature or chain check that failed.
var (
	// ErrClientAttestationInvalid reports that the Appendix E Client
	// Attestation the provider returned is not usable as this wallet's client
	// credential: it is empty or malformed, its signature could not be
	// authenticated against the configured trust material, or its typ, sub,
	// cnf.jwk, aud or exp does not match the wallet instance and the
	// authorization server the request is for.
	ErrClientAttestationInvalid = common.NewCodedError("client_attestation_invalid", "client attestation is not valid for this wallet instance")
	// ErrKeyAttestationInvalid reports the same for an Appendix D key
	// attestation: empty, malformed, unauthenticated, or not attesting the
	// holder keys, the c_nonce, the audience or a future exp the Credential
	// Request needs.
	ErrKeyAttestationInvalid = common.NewCodedError("key_attestation_invalid", "key attestation is not valid for this credential request")
)

// Sentinel errors NotifyOID4VCIFinalCredential and NotifyOID4VCIDraft13Credential
// return before a Notification Request is sent (OpenID4VCI 1.0 §11.1, Draft 13
// §10.1). Each is a request the wallet itself got wrong, so repeating it cannot
// succeed.
var (
	// ErrNotificationIDMissing reports a request without the REQUIRED
	// notification_id.
	ErrNotificationIDMissing = common.NewCodedError("notification_id_missing", "notification_id is required")
	// ErrNotificationEventInvalid reports an event other than
	// credential_accepted, credential_failure or credential_deleted.
	ErrNotificationEventInvalid = common.NewCodedError("notification_event_invalid", "notification event is not credential_accepted, credential_failure or credential_deleted")
	// ErrNotificationEventDescriptionInvalid reports an event_description with
	// a character outside %x20-21 / %x23-5B / %x5D-7E.
	ErrNotificationEventDescriptionInvalid = common.NewCodedError("notification_event_description_invalid", "event_description contains a character the notification request does not allow")
	// ErrNotificationAccessTokenMissing reports a request without the access
	// token the Notification Endpoint requires.
	ErrNotificationAccessTokenMissing = common.NewCodedError("notification_access_token_missing", "access token is required for the notification request")
	// ErrNotificationEndpointMissing reports an issuer that advertises no
	// notification_endpoint, or a caller that named none.
	ErrNotificationEndpointMissing = common.NewCodedError("notification_endpoint_missing", "notification endpoint is missing on credential issuer")
	// ErrNotificationDPoPKeyMissing reports a DPoP-bound access token without
	// the client key it is bound to, so no RFC 9449 proof can be built.
	ErrNotificationDPoPKeyMissing = common.NewCodedError("notification_dpop_key_missing", "the access token is DPoP-bound but no client key was supplied")
)
