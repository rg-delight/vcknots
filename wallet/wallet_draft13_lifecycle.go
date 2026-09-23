package wallet

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet/common"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// This file carries the two OpenID4VCI Draft 13 exchanges that follow a
// Credential Response: the Section 9 Deferred Credential Endpoint, which a
// wallet polls until the credential it was promised is ready, and the Section
// 10 Notification Endpoint, which it tells what became of a credential. Both
// can run long after the issuance that produced their inputs, so both are
// reachable from nothing but the transaction_id or notification_id and the
// access token a caller kept.

// draft13DeferredPoll is one deferred polling run: the endpoint, what to
// present to it, and how long to keep asking.
type draft13DeferredPoll struct {
	transport     OID4VCIDraft13Transport
	endpoint      common.URIField
	accessToken   receiverTypes.CredentialIssuanceAccessToken
	transactionID string
	proofFactory  receiverTypes.DPoPProofFactory
	attempts      int
	interval      time.Duration
	maxInterval   time.Duration
}

// pollDraft13Deferred asks the Deferred Credential Endpoint for the credential
// until it answers with one, refuses, or the attempts run out. Section 9.2 makes
// issuance_pending the only answer that means "ask again", and it may name the
// interval to wait; any other error is the issuer's final word on this
// transaction.
//
// When every attempt came back pending, the last endpoint error is returned
// wrapped in ErrDraft13IssuancePending, so a caller can both branch on the
// condition and read the interval the issuer last asked for.
func pollDraft13Deferred(ctx context.Context, poll draft13DeferredPoll) (*receiverOid4vci.Draft13CredentialResponse, error) {
	attempts := poll.attempts
	if attempts <= 0 {
		attempts = 1
	}
	interval := clampDeferredInterval(poll.interval, poll.maxInterval)
	if interval <= 0 {
		interval = defaultDeferredInterval
	}
	var pending *receiverOid4vci.Draft13CredentialEndpointError
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := waitForDeferredInterval(ctx, interval); err != nil {
				return nil, err
			}
		}
		if err := requireOID4VCIContext(ctx, "the deferred credential request"); err != nil {
			return nil, err
		}
		response, err := poll.transport.RequestOID4VCIDraft13DeferredCredential(ctx, poll.endpoint, poll.accessToken, poll.transactionID, poll.proofFactory)
		if err == nil {
			return response, nil
		}
		var endpointError *receiverOid4vci.Draft13CredentialEndpointError
		if !errors.As(err, &endpointError) || !errors.Is(endpointError, receiverOid4vci.ErrDraft13IssuancePending) {
			return nil, fmt.Errorf("deferred credential request failed: %w", err)
		}
		pending = endpointError
		if endpointError.Interval > 0 {
			interval = clampDeferredInterval(time.Duration(endpointError.Interval)*time.Second, poll.maxInterval)
		}
	}
	return nil, fmt.Errorf("%w: %w", ErrDraft13IssuancePending, pending)
}

// pollDraft13DeferredCredential continues an issuance whose Credential Response
// deferred the credential. With no polls allowed it returns the pending result
// as it is, for the caller to resume later with
// ResumeOID4VCIDraft13DeferredCredential; otherwise it polls, and a
// transaction that is still pending afterwards is returned together with
// ErrDraft13IssuancePending.
func (w *Wallet) pollDraft13DeferredCredential(
	ctx context.Context,
	flow *oid4vciDraft13Flow,
	req OID4VCIDraft13ReceiveRequest,
	result *OID4VCIDraft13ReceiveResult,
	proofFactory receiverTypes.DPoPProofFactory,
) (*OID4VCIDraft13ReceiveResult, error) {
	if req.DeferredPollAttempts <= 0 {
		return result, nil
	}
	endpoint := flow.issuerMetadata.DeferredCredentialEndpoint
	if endpoint == nil || endpoint.String() == "" {
		return nil, ErrDraft13DeferredEndpointMissing
	}
	deferredProofFactory := proofFactory
	if deferredProofFactory != nil {
		// A DPoP proof is bound to the URL it is sent to (RFC 9449 Section
		// 4.2 htu), so the credential endpoint's factory cannot be reused.
		deferredProofFactory = w.draft13DPoPProofFactory(w.dpop.Key, http.MethodPost, endpoint.String(), result.AccessToken.Token)
	}
	response, err := pollDraft13Deferred(ctx, draft13DeferredPoll{
		transport:     flow.transport,
		endpoint:      *endpoint,
		accessToken:   *result.AccessToken,
		transactionID: result.TransactionID,
		proofFactory:  deferredProofFactory,
		attempts:      req.DeferredPollAttempts,
		interval:      time.Duration(result.DeferredIntervalSeconds) * time.Second,
		maxInterval:   req.MaxDeferredInterval,
	})
	if err != nil {
		if errors.Is(err, ErrDraft13IssuancePending) {
			return result, err
		}
		return nil, err
	}
	if response.Credential == "" {
		return nil, ErrDraft13CredentialResponseInvalid
	}
	issued := *result
	issued.RawCredential = response.Credential
	issued.TransactionID = ""
	issued.DeferredIntervalSeconds = 0
	if response.NotificationID != "" {
		issued.NotificationID = response.NotificationID
	}
	if err := w.storeDraft13Credential(ctx, req.StoreCredential, req.Key, flow.credentialConfiguration.Format, &issued); err != nil {
		return nil, err
	}
	return &issued, nil
}

// ResumeOID4VCIDraft13DeferredCredential redeems a Draft 13 Section 9 deferred
// transaction that an earlier issuance left pending. It needs only what that
// issuance reported — the transaction_id and the access token — and the
// Deferred Credential Endpoint, so a wallet that persisted those can resume from
// another process or after a restart.
//
// A transaction that is still pending after the allowed polls is reported as
// ErrDraft13IssuancePending, wrapping the issuer's Section 9.2 error so the
// interval it named stays readable. Any other issuer refusal is returned as the
// *receiverOid4vci.Draft13CredentialEndpointError it arrived as.
func (w *Wallet) ResumeOID4VCIDraft13DeferredCredential(ctx context.Context, req OID4VCIDraft13DeferredRequest) (*OID4VCIDraft13ReceiveResult, error) {
	if err := requireOID4VCIContext(ctx, "the deferred credential request"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.TransactionID) == "" {
		return nil, fmt.Errorf("transaction ID is required")
	}
	if req.AccessToken == nil || strings.TrimSpace(req.AccessToken.Token) == "" {
		return nil, fmt.Errorf("access token is required")
	}
	endpoint, err := draft13LifecycleEndpoint(req.IssuerMetadata, req.DeferredCredentialEndpoint, func(metadata *receiverTypes.CredentialIssuerMetadata) *common.URIField {
		return metadata.DeferredCredentialEndpoint
	}, ErrDraft13DeferredEndpointMissing)
	if err != nil {
		return nil, err
	}
	transport, err := w.draft13Transport(req.Type)
	if err != nil {
		return nil, err
	}
	response, err := pollDraft13Deferred(ctx, draft13DeferredPoll{
		transport:     transport,
		endpoint:      endpoint,
		accessToken:   *req.AccessToken,
		transactionID: req.TransactionID,
		proofFactory:  w.draft13LifecycleProofFactory(req.AccessToken, req.DPoPKey, endpoint),
		attempts:      req.PollAttempts,
		interval:      req.Interval,
		maxInterval:   req.MaxInterval,
	})
	if err != nil {
		return nil, err
	}
	if response.Credential == "" {
		// Section 9.1: a Deferred Credential Response carries the credential.
		// "Still pending" is the Section 9.2 error, never a success body.
		return nil, ErrDraft13CredentialResponseInvalid
	}
	result := &OID4VCIDraft13ReceiveResult{
		RawCredential:             response.Credential,
		CredentialFormat:          req.CredentialFormat,
		AccessToken:               req.AccessToken,
		NotificationID:            response.NotificationID,
		CNonce:                    response.CNonce,
		IssuerMetadata:            req.IssuerMetadata,
		CredentialConfigurationID: req.CredentialConfigurationID,
	}
	if err := w.storeDraft13Credential(ctx, req.StoreCredential, req.Key, req.CredentialFormat, result); err != nil {
		return nil, err
	}
	return result, nil
}

// NotifyOID4VCIDraft13Credential sends the Draft 13 Section 10.1 Notification
// Request that tells the Credential Issuer what became of a credential it
// issued. The issuer's Section 10.2 refusal is returned as the
// *receiverOid4vci.Draft13CredentialEndpointError it arrived as.
func (w *Wallet) NotifyOID4VCIDraft13Credential(ctx context.Context, req OID4VCIDraft13NotificationRequest) error {
	if err := requireOID4VCIContext(ctx, "the notification request"); err != nil {
		return err
	}
	if strings.TrimSpace(req.NotificationID) == "" {
		return fmt.Errorf("notification ID is required")
	}
	if req.AccessToken == nil || strings.TrimSpace(req.AccessToken.Token) == "" {
		return fmt.Errorf("access token is required")
	}
	switch req.Event {
	case "credential_accepted", "credential_failure", "credential_deleted":
	default:
		return fmt.Errorf("notification event %q is not one Section 10.1 defines", req.Event)
	}
	endpoint, err := draft13LifecycleEndpoint(req.IssuerMetadata, req.NotificationEndpoint, func(metadata *receiverTypes.CredentialIssuerMetadata) *common.URIField {
		return metadata.NotificationEndpoint
	}, ErrDraft13NotificationEndpointMissing)
	if err != nil {
		return err
	}
	transport, err := w.draft13Transport(req.Type)
	if err != nil {
		return err
	}
	return transport.SendOID4VCIDraft13Notification(ctx, endpoint, *req.AccessToken, receiverOid4vci.Draft13NotificationRequest{
		NotificationID:   req.NotificationID,
		Event:            req.Event,
		EventDescription: req.EventDescription,
	}, w.draft13LifecycleProofFactory(req.AccessToken, req.DPoPKey, endpoint))
}

// draft13LifecycleEndpoint resolves the endpoint a lifecycle request goes to.
// The issuer metadata is authoritative when the caller has it; a caller that
// kept only the endpoint names it directly.
func draft13LifecycleEndpoint(
	metadata *receiverTypes.CredentialIssuerMetadata,
	named string,
	advertised func(*receiverTypes.CredentialIssuerMetadata) *common.URIField,
	missing error,
) (common.URIField, error) {
	if metadata != nil {
		endpoint := advertised(metadata)
		if endpoint == nil || endpoint.String() == "" {
			return common.URIField{}, missing
		}
		return *endpoint, nil
	}
	if strings.TrimSpace(named) == "" {
		return common.URIField{}, missing
	}
	endpoint, err := common.ParseURIField(named)
	if err != nil {
		return common.URIField{}, fmt.Errorf("invalid endpoint %q: %w", named, err)
	}
	return *endpoint, nil
}

// draft13LifecycleProofFactory builds the RFC 9449 proof factory for a
// lifecycle request. A Bearer token needs none. A DPoP-bound token is presented
// with the caller's key, or the wallet's configured DPoP key; with neither, no
// factory is built and the transport refuses the request rather than sending
// the token bare.
func (w *Wallet) draft13LifecycleProofFactory(accessToken *receiverTypes.CredentialIssuanceAccessToken, key IKeyEntry, endpoint common.URIField) receiverTypes.DPoPProofFactory {
	if accessToken == nil || !strings.EqualFold(accessToken.TokenType, "DPoP") {
		return nil
	}
	if key == nil {
		key = w.dpop.Key
	}
	return w.draft13DPoPProofFactory(key, http.MethodPost, endpoint.String(), accessToken.Token)
}
