package wallet

import (
	"time"

	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// OID4VCIDraft13ReceiveRequest holds the OpenID4VCI Draft 13 issuance inputs
// that are not discoverable from the Credential Offer or the Credential Issuer
// metadata. The same request drives both grants: the Pre-Authorized Code Flow
// through ReceiveOID4VCIDraft13Credential, and the Authorization Code Flow
// through BeginOID4VCIDraft13Authorization and
// ResumeOID4VCIDraft13Authorization.
type OID4VCIDraft13ReceiveRequest struct {
	// CredentialOffer is the Draft 13 Section 4.1 Credential Offer. It is
	// required: this API does not start an issuance the holder never accepted.
	CredentialOffer *CredentialOffer
	Type            receiverTypes.SupportedReceivingTypes
	// Key signs the Section 7.2.1 key proof. It is required whenever the
	// Credential Configuration asks for a proof and PreSignedProof is empty.
	Key IKeyEntry
	// CachedIssuerMetadata skips the Credential Issuer metadata fetch. The
	// caller is responsible for it having been fetched from the offer's
	// credential_issuer.
	CachedIssuerMetadata *receiverTypes.CredentialIssuerMetadata
	// CredentialConfigurationID selects which of the offered configurations to
	// request. Empty uses the first one the offer lists.
	CredentialConfigurationID string
	// TxCode is the Section 4.1.1 tx_code the holder entered. Empty omits the
	// parameter.
	TxCode string
	// ClientID identifies this wallet at the authorization server. The
	// Authorization Code Flow requires it; the Pre-Authorized Code Flow sends
	// it only when it is set, because Section 6.1 makes it OPTIONAL there.
	ClientID string
	// RedirectURI is the registered redirect_uri of the Authorization Code
	// Flow. It is required by that grant and ignored by the other.
	RedirectURI string
	// AuthorizationRequestType selects how the Credential Configuration is
	// requested at the authorization endpoint: OID4VCIAuthorizationRequestTypeScope
	// or OID4VCIAuthorizationRequestTypeAuthorizationDetails. The empty value
	// uses scope when the configuration advertises one and
	// authorization_details otherwise.
	AuthorizationRequestType string
	// ProofTransform rewrites the key proof before and after it is signed. The
	// zero value produces the proof the library would build on its own.
	ProofTransform ProofTransform
	// PreSignedProof is a Section 7.2.1 key proof the caller built and signed
	// itself. When it is set the library signs nothing and sends this value, so
	// a wallet whose holder key lives outside this process can still issue. It
	// takes precedence over Key, and ProofTransform is not applied to it: a
	// proof the caller built is already the proof the caller wants.
	PreSignedProof string
	// DeferredPollAttempts is the number of Section 9 deferred credential polls
	// to make when the Credential Response defers the credential. Zero does not
	// poll and returns a pending result the caller resumes with
	// ResumeOID4VCIDraft13DeferredCredential.
	DeferredPollAttempts int
	// MaxDeferredInterval caps the deferred polling interval, including one the
	// issuer names. Zero uses the library's 60 second cap.
	MaxDeferredInterval time.Duration
	// StoreCredential verifies the received credential against the wallet's
	// acceptance policy and saves it in the credential store. It is off by
	// default because a caller that persists credentials itself — a wallet
	// whose store is a database in another process — would otherwise keep a
	// second copy it never reads.
	StoreCredential bool
}

// OID4VCIDraft13Authorization is the state a caller holds between the two
// halves of the Draft 13 Section 3.4 Authorization Code Flow:
// BeginOID4VCIDraft13Authorization produces it, the caller sends the holder to
// AuthorizationURL in a browser, and ResumeOID4VCIDraft13Authorization consumes
// it together with the redirect the browser came back with.
//
// Every member is JSON-serialisable so the state survives a process restart,
// which is what lets a wallet whose authorization leg runs in someone else's
// browser keep no session in memory. It carries the PKCE verifier, so a caller
// stores it the way it stores a secret.
type OID4VCIDraft13Authorization struct {
	// AuthorizationURL is the authorization request to open in the browser.
	AuthorizationURL string `json:"authorization_url"`
	// State is the RFC 6749 Section 4.1.1 state the redirect must echo. It is
	// not a secret: the redirect carries it back in the clear.
	State string `json:"state"`
	// CodeVerifier is the RFC 7636 PKCE verifier for the token request.
	CodeVerifier string `json:"code_verifier"`
	// RedirectURI is the redirect_uri the authorization request registered, and
	// the one the callback is checked against.
	RedirectURI string `json:"redirect_uri"`
	// ClientID is the client_id the authorization request named.
	ClientID string `json:"client_id"`
	// RequestURI is the RFC 9126 PAR request_uri, empty when the authorization
	// request parameters travelled inline.
	RequestURI string `json:"request_uri,omitempty"`
	// ExpiresAt is the RFC 9126 Section 2.2 request_uri expiry measured from
	// the PAR response; the zero value means the issuer stated no deadline.
	ExpiresAt                   time.Time                                  `json:"expires_at"`
	IssuerMetadata              *receiverTypes.CredentialIssuerMetadata    `json:"issuer_metadata"`
	AuthorizationServerMetadata *receiverTypes.AuthorizationServerMetadata `json:"authorization_server_metadata"`
	CredentialConfigurationID   string                                     `json:"credential_configuration_id"`
	// AuthorizationDetailsRequested records whether the authorization request
	// used authorization_details rather than scope, which decides how strictly
	// the Token Response is read (Section 6.2).
	AuthorizationDetailsRequested bool `json:"authorization_details_requested"`
}

// RequestURIExpired reports whether the RFC 9126 Section 2.2 request_uri
// lifetime has run out at now, so the authorization request can no longer be
// sent to the authorization endpoint. A zero ExpiresAt is never expired,
// because no deadline was stated and the wallet does not invent one.
//
// The lifetime bounds the use of the request_uri at the authorization endpoint
// and nothing after it: the authorization code arrives whenever the holder
// finishes authenticating, which may be later than the request_uri would have
// been accepted. Resuming therefore does not refuse a callback on this ground;
// a wallet that wants to bound how long a started issuance stays resumable owns
// that policy and applies it here.
func (a *OID4VCIDraft13Authorization) RequestURIExpired(now time.Time) bool {
	if a == nil || a.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(a.ExpiresAt)
}

// OID4VCIDraft13ReceiveResult is what a Draft 13 issuance produced.
type OID4VCIDraft13ReceiveResult struct {
	// RawCredential is the credential exactly as the issuer returned it, empty
	// when the issuance was deferred.
	RawCredential string
	// CredentialFormat is the Credential Configuration's format member, which
	// says how RawCredential is to be read.
	CredentialFormat string
	// SavedCredential is set when the request asked the wallet to verify and
	// store the credential.
	SavedCredential *SavedCredential
	// AccessToken is the Token Response, kept so a caller can drive the
	// Section 9 deferred endpoint and the Section 10 notification endpoint
	// later.
	AccessToken *receiverTypes.CredentialIssuanceAccessToken
	// TransactionID is the Section 7.3 transaction_id of a deferred issuance.
	TransactionID string
	// NotificationID is the Section 7.3 notification_id to report the
	// credential's fate with.
	NotificationID string
	// CNonce is the c_nonce the Credential Response carried, which Draft 13
	// lets the issuer refresh on every response.
	CNonce string
	// DeferredIntervalSeconds is the polling interval the issuer named for a
	// deferred transaction, zero when it named none.
	DeferredIntervalSeconds   int
	IssuerMetadata            *receiverTypes.CredentialIssuerMetadata
	CredentialConfigurationID string
}

// OID4VCIDraft13DeferredRequest resumes a Draft 13 Section 9 deferred
// credential transaction from the transaction_id and access token an earlier
// result reported.
type OID4VCIDraft13DeferredRequest struct {
	Type receiverTypes.SupportedReceivingTypes
	// IssuerMetadata, when set, is where the Deferred Credential Endpoint is
	// read from. A caller that kept only the endpoint names it in
	// DeferredCredentialEndpoint instead.
	IssuerMetadata             *receiverTypes.CredentialIssuerMetadata
	DeferredCredentialEndpoint string
	CredentialConfigurationID  string
	CredentialFormat           string
	TransactionID              string
	AccessToken                *receiverTypes.CredentialIssuanceAccessToken
	// DPoPKey signs the RFC 9449 proof when the access token is DPoP-bound. A
	// DPoP-bound token with no key here is refused rather than sent bare.
	DPoPKey IKeyEntry
	// PollAttempts is the number of polls to make. Zero or less makes one.
	PollAttempts int
	// Interval is the wait between polls, and MaxInterval caps it including one
	// the issuer names. Zero uses the library's defaults.
	Interval        time.Duration
	MaxInterval     time.Duration
	StoreCredential bool
	// Key is the holder key a stored credential is verified against.
	Key IKeyEntry
}

// OID4VCIDraft13NotificationRequest is the Draft 13 Section 10.1 Notification
// Request input.
type OID4VCIDraft13NotificationRequest struct {
	Type receiverTypes.SupportedReceivingTypes
	// IssuerMetadata, when set, is where the Notification Endpoint is read
	// from. A caller that kept only the endpoint names it in
	// NotificationEndpoint instead.
	IssuerMetadata       *receiverTypes.CredentialIssuerMetadata
	NotificationEndpoint string
	AccessToken          *receiverTypes.CredentialIssuanceAccessToken
	DPoPKey              IKeyEntry
	NotificationID       string
	// Event is the Section 10.1 event member: credential_accepted,
	// credential_failure or credential_deleted.
	Event string
	// EventDescription is the OPTIONAL human-readable event_description. It
	// reaches the issuer as written, so a caller keeps secrets out of it.
	EventDescription string
}
