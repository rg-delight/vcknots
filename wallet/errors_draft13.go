package wallet

import "github.com/trustknots/vcknots/wallet/common"

// The conditions the OpenID4VCI Draft 13 issuance API names. Every one of them
// is a CodedError, so an integrator branches on the code rather than on Go
// error text, and carries the same code across a process or language boundary.
var (
	// ErrDraft13OfferMissing reports a request that carries no Credential
	// Offer. Draft 13 §4.1 makes the offer the document that names the
	// Credential Issuer, the configurations and the grant, so the flow has
	// nothing to start from without one.
	ErrDraft13OfferMissing = common.NewCodedError("draft13_offer_missing", "credential offer is required")
	// ErrDraft13AuthorizationCodeGrantMissing reports an offer that carries no
	// authorization_code grant, so it cannot start the Draft 13 §3.4
	// Authorization Code Flow.
	ErrDraft13AuthorizationCodeGrantMissing = common.NewCodedError("draft13_authorization_code_grant_missing", "authorization_code grant is not included in the offer")
	// ErrDraft13PreAuthorizedCodeGrantMissing reports an offer that carries no
	// usable pre-authorized_code grant.
	ErrDraft13PreAuthorizedCodeGrantMissing = common.NewCodedError("draft13_pre_authorized_code_grant_missing", "pre-authorized_code grant is not included in the offer")
	// ErrDraft13AuthorizationEndpointMissing reports an authorization server
	// that publishes no authorization_endpoint, so the holder cannot be sent
	// anywhere to authorize the issuance.
	ErrDraft13AuthorizationEndpointMissing = common.NewCodedError("draft13_authorization_endpoint_missing", "authorization endpoint is missing on authorization server")
	// ErrDraft13TokenEndpointMissing reports an authorization server that
	// publishes no token_endpoint.
	ErrDraft13TokenEndpointMissing = common.NewCodedError("draft13_token_endpoint_missing", "token endpoint is missing on authorization server")
	// ErrDraft13CredentialEndpointMissing reports a Credential Issuer that
	// publishes no credential_endpoint.
	ErrDraft13CredentialEndpointMissing = common.NewCodedError("draft13_credential_endpoint_missing", "credential endpoint is missing on credential issuer")
	// ErrDraft13DeferredEndpointMissing reports a Credential Issuer that
	// publishes no deferred_credential_endpoint, so a transaction_id it handed
	// out cannot be redeemed.
	ErrDraft13DeferredEndpointMissing = common.NewCodedError("draft13_deferred_endpoint_missing", "deferred credential endpoint is missing on credential issuer")
	// ErrDraft13NotificationEndpointMissing reports a Credential Issuer that
	// publishes no notification_endpoint.
	ErrDraft13NotificationEndpointMissing = common.NewCodedError("draft13_notification_endpoint_missing", "notification endpoint is missing on credential issuer")
	// ErrDraft13AuthorizationStateMissing reports a resume that was given no
	// authorization state, so the PKCE verifier and the metadata the
	// authorization request was built from are unavailable.
	ErrDraft13AuthorizationStateMissing = common.NewCodedError("draft13_authorization_state_missing", "authorization state is required to resume the authorization code flow")
	// ErrDraft13HolderKeyMissing reports a Credential Request that needs a key
	// proof but was given no holder key to sign it with.
	ErrDraft13HolderKeyMissing = common.NewCodedError("draft13_holder_key_missing", "holder key is required to build the credential request proof")
	// ErrDraft13CredentialConfigurationUnknown reports a configuration id that
	// the Credential Issuer metadata does not describe.
	ErrDraft13CredentialConfigurationUnknown = common.NewCodedError("draft13_credential_configuration_unknown", "credential configuration is not described by the credential issuer metadata")
	// ErrDraft13CredentialResponseInvalid reports a Credential Response this
	// wallet cannot read: no credential, or a shape Draft 13 §7.3 does not
	// define.
	ErrDraft13CredentialResponseInvalid = common.NewCodedError("draft13_credential_response_invalid", "credential response does not carry a usable credential")
	// ErrDraft13IssuancePending reports a Draft 13 §9 deferred transaction that
	// is still pending after the polls this call was allowed to make. The
	// result returned alongside it carries the transaction_id to resume with.
	ErrDraft13IssuancePending = common.NewCodedError("draft13_issuance_pending", "credential issuance is pending")
	// ErrDraft13ProofTransformFailed reports that a caller-supplied
	// ProofTransform refused the key proof it was given.
	ErrDraft13ProofTransformFailed = common.NewCodedError("draft13_proof_transform_failed", "proof transform failed")
)
