package wallet

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// This file carries the OpenID4VCI 1.0 §11 Notification Endpoint as a call a
// wallet can make on its own schedule. The Final issuance itself sends
// credential_accepted and credential_failure unless the caller opted out with
// SkipNotification; a wallet that stores credentials in its own process, or
// that deletes one later, reports the outcome through NotifyOID4VCIFinalCredential
// once it knows it.

// OID4VCINotificationEvent is the §11.1 event member. Its values are case
// sensitive, and a Notification Request carries exactly one of the three.
type OID4VCINotificationEvent string

const (
	// OID4VCINotificationCredentialAccepted reports that the credentials were
	// stored in the wallet, with or without user action.
	OID4VCINotificationCredentialAccepted OID4VCINotificationEvent = "credential_accepted"
	// OID4VCINotificationCredentialFailure reports an unsuccessful issuance the
	// user did not cause. A batch in which one credential could not be stored
	// is a failure of the whole flow.
	OID4VCINotificationCredentialFailure OID4VCINotificationEvent = "credential_failure"
	// OID4VCINotificationCredentialDeleted reports an unsuccessful issuance
	// caused by a user action, such as the holder deleting the credential.
	OID4VCINotificationCredentialDeleted OID4VCINotificationEvent = "credential_deleted"
)

// OID4VCIFinalNotificationRequest is one OpenID4VCI 1.0 §11.1 Notification
// Request.
type OID4VCIFinalNotificationRequest struct {
	Type receiverTypes.SupportedReceivingTypes
	// IssuerMetadata, when set, is where the Notification Endpoint is read
	// from. A caller that kept only the endpoint the issuer advertised names it
	// in NotificationEndpoint instead.
	IssuerMetadata       *receiverTypes.CredentialIssuerMetadata
	NotificationEndpoint string
	// AccessToken is the §6.2 Token Response the credential was issued under.
	// §11 requires the wallet to present a token issued at the Token Endpoint,
	// and a DPoP-bound one is presented with a proof signed by ClientKey, as
	// the Credential Request was.
	AccessToken *receiverTypes.CredentialIssuanceAccessToken
	ClientKey   jose.JSONWebKey
	// NotificationID is the notification_id of the Credential Response or
	// Deferred Credential Response.
	NotificationID string
	Event          OID4VCINotificationEvent
	// EventDescription is the OPTIONAL event_description. It reaches the
	// issuer as written, so a caller keeps secrets out of it, and it is limited
	// to the ASCII set §11.1 allows.
	EventDescription string
}

// NotifyOID4VCIFinalCredential sends one §11 Notification Request. The request
// is validated before anything is sent: a notification_id, one of the three
// §11.1 events, an event_description inside the allowed character set, a
// Bearer or DPoP access token, and — for a DPoP-bound token — the client key
// it is bound to. The issuer's §11.3 refusal comes back as a
// *receiverTypes.CredentialEndpointError, and a redirect from the endpoint is
// refused like on every other OpenID4VCI endpoint.
func (w *Wallet) NotifyOID4VCIFinalCredential(ctx context.Context, req OID4VCIFinalNotificationRequest) error {
	if err := requireOID4VCIContext(ctx, "the notification request"); err != nil {
		return err
	}
	if req.Type != receiverTypes.Oid4vci {
		return fmt.Errorf("unsupported OID4VCI Final receiving type: %v", req.Type)
	}
	if err := validateOID4VCINotification(req.NotificationID, string(req.Event), req.EventDescription); err != nil {
		return err
	}
	if req.AccessToken == nil || strings.TrimSpace(req.AccessToken.Token) == "" {
		return ErrNotificationAccessTokenMissing
	}
	if err := requireOID4VCIFinalTokenType(req.AccessToken); err != nil {
		return err
	}
	if isDPoPAccessToken(req.AccessToken) && req.ClientKey.Key == nil {
		return fmt.Errorf("the access token is DPoP-bound but no client key was supplied: %w", ErrNotificationDPoPKeyMissing)
	}
	endpoint, err := oid4vciLifecycleEndpoint(req.IssuerMetadata, req.NotificationEndpoint, func(metadata *receiverTypes.CredentialIssuerMetadata) *common.URIField {
		return metadata.NotificationEndpoint
	}, ErrNotificationEndpointMissing)
	if err != nil {
		return err
	}
	finalReceiver, err := w.receiver.OID4VCIFinalTransport(req.Type)
	if err != nil {
		return fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}
	return sendOID4VCIFinalNotification(ctx, finalReceiver, w.oid4vciFinalSigner(finalReceiver), endpoint, req.AccessToken, req.ClientKey, receiverTypes.NotificationRequest{
		NotificationID:   req.NotificationID,
		Event:            string(req.Event),
		EventDescription: req.EventDescription,
	})
}

// NotifyOID4VCIFinalCredentialDeleted sends the §11 credential_deleted
// notification for a credential the wallet removed from storage. It is
// NotifyOID4VCIFinalCredentialDeletedContext with a background context.
func (w *Wallet) NotifyOID4VCIFinalCredentialDeleted(req OID4VCIFinalNotificationRequest) error {
	return w.NotifyOID4VCIFinalCredentialDeletedContext(context.Background(), req)
}

// NotifyOID4VCIFinalCredentialDeletedContext sends the §11 credential_deleted
// notification for a credential the wallet removed from storage. It is
// NotifyOID4VCIFinalCredential with the event fixed to credential_deleted.
func (w *Wallet) NotifyOID4VCIFinalCredentialDeletedContext(ctx context.Context, req OID4VCIFinalNotificationRequest) error {
	req.Event = OID4VCINotificationCredentialDeleted
	return w.NotifyOID4VCIFinalCredential(ctx, req)
}

// validateOID4VCINotification applies the Notification Request rules OpenID4VCI
// 1.0 §11.1 and Draft 13 §10.1 share: notification_id and event are REQUIRED,
// event is one of three case-sensitive values, and event_description stays
// inside %x20-21 / %x23-5B / %x5D-7E — printable ASCII without the double quote
// and the backslash.
func validateOID4VCINotification(notificationID, event, eventDescription string) error {
	if strings.TrimSpace(notificationID) == "" {
		return ErrNotificationIDMissing
	}
	switch OID4VCINotificationEvent(event) {
	case OID4VCINotificationCredentialAccepted, OID4VCINotificationCredentialFailure, OID4VCINotificationCredentialDeleted:
	default:
		return fmt.Errorf("notification event %q: %w", event, ErrNotificationEventInvalid)
	}
	for index := 0; index < len(eventDescription); index++ {
		if !notificationDescriptionByte(eventDescription[index]) {
			return fmt.Errorf("event_description byte 0x%02x at offset %d: %w", eventDescription[index], index, ErrNotificationEventDescriptionInvalid)
		}
	}
	return nil
}

func notificationDescriptionByte(value byte) bool {
	return value >= 0x20 && value <= 0x7e && value != '"' && value != '\\'
}

// notifyOID4VCIFinalCredential is the notification the Final issuance sends on
// its own, right after storing (or failing to store) what it received. It is
// best-effort: an issuer that did not ask for notifications — no
// notification_id or no Notification Endpoint — is simply not notified.
func notifyOID4VCIFinalCredential(
	ctx context.Context,
	finalReceiver receiverTypes.OID4VCIFinalTransport,
	signer receiverTypes.OID4VCIFinalSigner,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	notificationID string,
	event OID4VCINotificationEvent,
) error {
	if notificationID == "" || issuerMetadata == nil || issuerMetadata.NotificationEndpoint == nil || token == nil {
		return nil
	}
	return sendOID4VCIFinalNotification(ctx, finalReceiver, signer, *issuerMetadata.NotificationEndpoint, token, clientKey, receiverTypes.NotificationRequest{
		NotificationID: notificationID,
		Event:          string(event),
	})
}

func sendOID4VCIFinalNotification(
	ctx context.Context,
	finalReceiver receiverTypes.OID4VCIFinalTransport,
	signer receiverTypes.OID4VCIFinalSigner,
	endpoint common.URIField,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	notification receiverTypes.NotificationRequest,
) error {
	return finalReceiver.SendCredentialNotificationWithDpopRetryForToken(
		ctx,
		endpoint,
		*token,
		notification,
		oid4vciFinalDpopProofFactory(signer, clientKey, endpoint, token.Token),
	)
}
