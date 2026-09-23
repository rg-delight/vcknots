package wallet

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common/observe"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// MaxDeferredInterval is the single upper bound this library places on the
// §9.2 deferred credential polling interval a Credential Issuer chooses. The
// specification puts no upper bound on the interval member, so without a cap an
// issuer could pin a polling goroutine — or an application's own polling
// schedule — for an arbitrary time. It bounds both the wait between this
// library's own polls and the interval reported back to a caller that polls on
// its own schedule. OID4VCIFinalDeferredRequest.MaxInterval and
// OID4VCIFinalReceiveRequest.MaxDeferredInterval lower it per request.
const MaxDeferredInterval = 60 * time.Second

// defaultDeferredInterval is the wait between §9 deferred polls when neither
// the issuer nor the caller named one.
const defaultDeferredInterval = 5 * time.Second

// OID4VCIFinalNotificationRequest is the OpenID4VCI 1.0 §11 notification
// endpoint input for events the wallet sends after the initial credential
// response (credential_deleted).
type OID4VCIFinalNotificationRequest struct {
	Type           receiverTypes.SupportedReceivingTypes
	IssuerMetadata *receiverTypes.CredentialIssuerMetadata
	AccessToken    *receiverTypes.CredentialIssuanceAccessToken
	ClientKey      jose.JSONWebKey
	NotificationID string
}

// OID4VCIFinalDeferredRequest lets a restarted wallet resume a §9 deferred
// credential transaction from the transaction_id and access token returned by
// an IssuancePending result.
type OID4VCIFinalDeferredRequest struct {
	Type                            receiverTypes.SupportedReceivingTypes
	IssuerMetadata                  *receiverTypes.CredentialIssuerMetadata
	IssuerURL                       *url.URL
	CredentialConfigurationID       string
	AccessToken                     *receiverTypes.CredentialIssuanceAccessToken
	TransactionID                   string
	HolderKey                       jose.JSONWebKey
	AdditionalHolderKeys            []jose.JSONWebKey
	ClientKey                       jose.JSONWebKey
	CredentialResponseEncryptionKey *jose.JSONWebKey
	DeferredPollAttempts            int
	Interval                        time.Duration
	// MaxInterval caps the polling interval, including one the issuer names in
	// its §9.2 issuance_pending response. Zero uses MaxDeferredInterval.
	MaxInterval time.Duration
	// CredentialEncryption, SkipNotification and RequireSingleCredential
	// behave as the identically named members of OID4VCIFinalReceiveRequest.
	CredentialEncryption    CredentialEncryptionPolicy
	SkipNotification        bool
	RequireSingleCredential bool
}

func (w *Wallet) handleOID4VCIFinalDeferredResponse(
	ctx context.Context,
	flow *oid4vciFinalFlow,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	encryptionKey *jose.JSONWebKey,
	encryptionParams map[string]any,
	credentialResponse *receiverTypes.CredentialResponse,
	deferredPollAttempts int,
	maxInterval time.Duration,
) (*OID4VCIFinalReceiveResult, error) {
	if flow.issuerMetadata.DeferredCredentialEndpoint == nil {
		return nil, fmt.Errorf("deferred credential endpoint is missing on credential issuer")
	}
	// The interval an application polls on is bounded by the same
	// MaxDeferredInterval this library waits by, so a caller that owns the
	// schedule does not need a second cap of its own.
	credentialResponse.Interval = ClampDeferredIntervalSeconds(credentialResponse.Interval, maxInterval)
	if deferredPollAttempts <= 0 {
		// §9: do not report success with zero credentials. Hand the caller the
		// transaction_id and access token so it can resume after a restart.
		return pendingOID4VCIFinalResult(flow.issuerMetadata, flow.credentialConfigurationID, token, credentialResponse), newOID4VCIFinalIssuancePendingError(credentialResponse.Interval)
	}
	interval := clampDeferredInterval(time.Duration(credentialResponse.Interval)*time.Second, maxInterval)
	if interval <= 0 {
		interval = defaultDeferredInterval
	}
	return w.pollOID4VCIFinalDeferredCredential(ctx, flow, token, clientKey, encryptionKey, encryptionParams, credentialResponse.TransactionID, credentialResponse.NotificationID, deferredPollAttempts, interval, maxInterval)
}

func pendingOID4VCIFinalResult(issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string, token *receiverTypes.CredentialIssuanceAccessToken, response *receiverTypes.CredentialResponse) *OID4VCIFinalReceiveResult {
	transactionID := ""
	notificationID := ""
	if response != nil {
		transactionID = response.TransactionID
		notificationID = response.NotificationID
	}
	return &OID4VCIFinalReceiveResult{
		CredentialResponse:        response,
		AccessToken:               token,
		TransactionID:             transactionID,
		NotificationID:            notificationID,
		IssuerMetadata:            issuerMetadata,
		CredentialConfigurationID: credentialConfigurationID,
	}
}

func (w *Wallet) pollOID4VCIFinalDeferredCredential(
	ctx context.Context,
	flow *oid4vciFinalFlow,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	encryptionKey *jose.JSONWebKey,
	encryptionParams map[string]any,
	transactionID string,
	notificationID string,
	attempts int,
	interval time.Duration,
	maxInterval time.Duration,
) (*OID4VCIFinalReceiveResult, error) {
	issuerMetadata := flow.issuerMetadata
	endpoint := *issuerMetadata.DeferredCredentialEndpoint
	pending := &OID4VCIFinalReceiveResult{
		AccessToken:               token,
		TransactionID:             transactionID,
		NotificationID:            notificationID,
		IssuerMetadata:            issuerMetadata,
		CredentialConfigurationID: flow.credentialConfigurationID,
	}

	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 && interval > 0 {
			if err := waitForDeferredInterval(ctx, interval); err != nil {
				return nil, err
			}
		}
		if err := requireOID4VCIContext(ctx, "the deferred credential request"); err != nil {
			return nil, err
		}
		// §9.1: "Deferred Credential Request encryption MUST be used if the
		// `credential_response_encryption` parameter is included in the
		// Deferred Credential Request... If it is not included encryption will
		// not be performed." The wallet repeats the parameter it sent with the
		// Credential Request so the deferred response is encrypted to the same
		// key, and §8.1's "Credential Request encryption MUST be used if the
		// `credential_response_encryption` parameter is included, to prevent it
		// being substituted by an attacker" is honoured by routing the body
		// through EncodeCredentialRequest, which fails closed when the issuer
		// advertises no credential_request_encryption.
		request := map[string]any{"transaction_id": transactionID}
		if encryptionParams != nil {
			request["credential_response_encryption"] = encryptionParams
		}
		body, contentType, err := flow.receiver.EncodeCredentialRequest(request, issuerMetadata)
		if err != nil {
			return nil, fmt.Errorf("failed to encode deferred credential request: %w", err)
		}
		rawResponse, _, err := flow.receiver.PostCredentialEndpointWithNonceRetryForToken(
			observe.WithEndpoint(ctx, observe.EndpointDeferredCredential),
			endpoint,
			*token,
			nil,
			"",
			func(string) ([]byte, string, error) { return body, contentType, nil },
			oid4vciFinalDpopProofFactory(flow.signer, clientKey, endpoint, token.Token),
		)
		if err != nil {
			// §9.2: an issuance_pending error means poll again after the
			// interval the issuer advertised.
			if errors.Is(err, receiverTypes.ErrIssuancePending) {
				interval = deferredIntervalFromError(err, interval, maxInterval)
				continue
			}
			return nil, fmt.Errorf("failed to receive deferred credential: %w", err)
		}
		if encryptionParams != nil && !strings.Contains(strings.ToLower(rawResponse.ContentType), "application/jwt") {
			return nil, fmt.Errorf("credential response encryption was requested but the deferred credential endpoint returned %q", rawResponse.ContentType)
		}
		credentialResponse, err := decodeOID4VCIFinalCredentialResponse(flow.receiver, rawResponse, encryptionKey, flow.policy.requireSingleCredential)
		if err != nil {
			return nil, err
		}
		if credentialHasNoCredentials(credentialResponse) {
			if credentialResponse.Interval > 0 {
				interval = clampDeferredInterval(time.Duration(credentialResponse.Interval)*time.Second, maxInterval)
			}
			continue
		}
		result, err := w.storeAndNotifyOID4VCIFinalCredentials(ctx, flow, token, clientKey, credentialResponse)
		if err != nil {
			return nil, err
		}
		result.TransactionID = transactionID
		return result, nil
	}
	return pending, newOID4VCIFinalIssuancePendingError(int(interval / time.Second))
}

// waitForDeferredInterval sleeps for interval, or returns as soon as ctx is
// cancelled. A wallet polling a §9 deferred transaction must be able to give up
// while it waits, which time.Sleep does not allow.
func waitForDeferredInterval(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	select {
	case <-ctx.Done():
		timer.Stop()
		return fmt.Errorf("deferred credential polling cancelled: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

// clampDeferredInterval bounds a polling interval that the Credential Issuer
// chose. OpenID4VCI 1.0 §9.2 lets the issuer name the interval and sets no
// upper bound, so an issuer could otherwise pin a polling goroutine for an
// arbitrary time. maxInterval of zero or less uses MaxDeferredInterval.
func clampDeferredInterval(interval, maxInterval time.Duration) time.Duration {
	if maxInterval <= 0 {
		maxInterval = MaxDeferredInterval
	}
	if interval > maxInterval {
		return maxInterval
	}
	return interval
}

// ClampDeferredIntervalSeconds bounds a §9.1 / §9.2 polling interval an issuer
// named, in seconds, by the same rule this library applies to its own polling.
// A non-positive interval is returned unchanged, so "the issuer named none"
// stays distinguishable from a capped one. maxInterval of zero or less uses
// MaxDeferredInterval.
//
// It exists for an application that polls the Deferred Credential Endpoint on
// its own schedule: the interval it reports to its scheduler is capped by the
// library's value rather than by a second one it has to choose and document.
func ClampDeferredIntervalSeconds(seconds int, maxInterval time.Duration) int {
	if seconds <= 0 {
		return seconds
	}
	return int(clampDeferredInterval(time.Duration(seconds)*time.Second, maxInterval) / time.Second)
}

func credentialHasNoCredentials(response *receiverTypes.CredentialResponse) bool {
	if response == nil {
		return true
	}
	return response.Credential == nil && len(response.Credentials) == 0
}

func deferredIntervalFromError(err error, fallback time.Duration, maxInterval time.Duration) time.Duration {
	var endpointError *receiverTypes.CredentialEndpointError
	if errors.As(err, &endpointError) && endpointError.Interval > 0 {
		return clampDeferredInterval(time.Duration(endpointError.Interval)*time.Second, maxInterval)
	}
	return clampDeferredInterval(fallback, maxInterval)
}

func newOID4VCIFinalIssuancePendingError(intervalSeconds int) error {
	return fmt.Errorf("credential issuance is pending: %w", &receiverTypes.CredentialEndpointError{
		StatusCode: http.StatusAccepted,
		Code:       "issuance_pending",
		Interval:   intervalSeconds,
	})
}

func notifyOID4VCIFinalCredential(
	ctx context.Context,
	finalReceiver receiverTypes.OID4VCIFinalTransport,
	signer receiverTypes.OID4VCIFinalSigner,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	notificationID string,
	event string,
) error {
	if notificationID == "" || issuerMetadata == nil || issuerMetadata.NotificationEndpoint == nil || token == nil {
		return nil
	}
	endpoint := *issuerMetadata.NotificationEndpoint
	return finalReceiver.SendCredentialNotificationWithDpopRetryForToken(
		ctx,
		endpoint,
		*token,
		receiverTypes.NotificationRequest{NotificationID: notificationID, Event: event},
		oid4vciFinalDpopProofFactory(signer, clientKey, endpoint, token.Token),
	)
}
