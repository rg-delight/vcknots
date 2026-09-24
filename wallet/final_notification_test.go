package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// finalNotificationRequest is a §11.1 request against the fixture issuer's
// Notification Endpoint, presenting a DPoP-bound token with the fixture client
// key the way an authorization code issuance holds it.
func (f *finalIssuanceFixture) finalNotificationRequest(event OID4VCINotificationEvent) OID4VCIFinalNotificationRequest {
	return OID4VCIFinalNotificationRequest{
		Type:                 receiverTypes.Oid4vci,
		NotificationEndpoint: f.server.URL + "/notification",
		AccessToken:          &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "DPoP"},
		ClientKey:            f.clientKey,
		NotificationID:       "notification-1",
		Event:                event,
	}
}

func TestNotifyOID4VCIFinalCredentialSendsEachEventWithADPoPProof(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	for _, event := range []OID4VCINotificationEvent{
		OID4VCINotificationCredentialAccepted,
		OID4VCINotificationCredentialFailure,
		OID4VCINotificationCredentialDeleted,
	} {
		req := fixture.finalNotificationRequest(event)
		if event == OID4VCINotificationCredentialFailure {
			req.EventDescription = "Could not store the Credential. Out of storage."
		}
		require.NoError(t, fixture.wallet.NotifyOID4VCIFinalCredential(context.Background(), req))
	}

	require.Equal(t, []map[string]any{
		{"notification_id": "notification-1", "event": "credential_accepted"},
		{"notification_id": "notification-1", "event": "credential_failure", "event_description": "Could not store the Credential. Out of storage."},
		{"notification_id": "notification-1", "event": "credential_deleted"},
	}, fixture.notificationBodies)
	accessTokenHash := sha256.Sum256([]byte("access-1"))
	for _, headers := range fixture.notificationHeaders {
		require.Equal(t, "application/json", headers.Get("Content-Type"))
		require.Equal(t, "DPoP access-1", headers.Get("Authorization"))
		proof := headers.Get("DPoP")
		require.NotEmpty(t, proof)
		require.Equal(t, "POST", extractPayloadField(t, proof, "htm"))
		require.Equal(t, fixture.server.URL+"/notification", extractPayloadField(t, proof, "htu"))
		require.Equal(t, base64.RawURLEncoding.EncodeToString(accessTokenHash[:]), extractPayloadField(t, proof, "ath"))
	}
}

func TestNotifyOID4VCIFinalCredentialPresentsABearerTokenWithoutAProof(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.finalNotificationRequest(OID4VCINotificationCredentialAccepted)
	req.AccessToken = &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "bearer"}
	req.ClientKey = jose.JSONWebKey{}

	require.NoError(t, fixture.wallet.NotifyOID4VCIFinalCredential(context.Background(), req))
	require.Len(t, fixture.notificationHeaders, 1)
	require.Equal(t, "Bearer access-1", fixture.notificationHeaders[0].Get("Authorization"))
	require.Empty(t, fixture.notificationHeaders[0].Get("DPoP"))
}

// The endpoint comes from the issuer metadata when the caller has it, which is
// how the issuance itself reaches it.
func TestNotifyOID4VCIFinalCredentialReadsTheEndpointFromIssuerMetadata(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) { f.includeNotification = true })
	req := fixture.finalNotificationRequest(OID4VCINotificationCredentialDeleted)
	req.NotificationEndpoint = "https://ignored.example/notification"
	req.IssuerMetadata = fixture.issuerMetadata(t)

	require.NoError(t, fixture.wallet.NotifyOID4VCIFinalCredential(context.Background(), req))
	require.Equal(t, []string{"credential_deleted"}, fixture.notificationEvents)

	req.IssuerMetadata.NotificationEndpoint = nil
	require.ErrorIs(t, fixture.wallet.NotifyOID4VCIFinalCredential(context.Background(), req), ErrNotificationEndpointMissing)
}

// Every rule of §11.1 is checked before a request leaves the wallet, and each
// refusal is a coded error a caller can branch on.
func TestNotifyOID4VCIFinalCredentialRefusesAnInvalidRequestBeforeSending(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	for name, tc := range map[string]struct {
		mutate func(*OID4VCIFinalNotificationRequest)
		want   error
	}{
		"missing notification_id": {func(r *OID4VCIFinalNotificationRequest) { r.NotificationID = " " }, ErrNotificationIDMissing},
		"unknown event":           {func(r *OID4VCIFinalNotificationRequest) { r.Event = "credential_lost" }, ErrNotificationEventInvalid},
		"event in another case":   {func(r *OID4VCIFinalNotificationRequest) { r.Event = "Credential_Accepted" }, ErrNotificationEventInvalid},
		"double quote":            {func(r *OID4VCIFinalNotificationRequest) { r.EventDescription = `say "no"` }, ErrNotificationEventDescriptionInvalid},
		"backslash":               {func(r *OID4VCIFinalNotificationRequest) { r.EventDescription = `a\b` }, ErrNotificationEventDescriptionInvalid},
		"non-ASCII":               {func(r *OID4VCIFinalNotificationRequest) { r.EventDescription = "保存失敗" }, ErrNotificationEventDescriptionInvalid},
		"control character":       {func(r *OID4VCIFinalNotificationRequest) { r.EventDescription = "line\nbreak" }, ErrNotificationEventDescriptionInvalid},
		"missing access token":    {func(r *OID4VCIFinalNotificationRequest) { r.AccessToken = nil }, ErrNotificationAccessTokenMissing},
		"empty access token":      {func(r *OID4VCIFinalNotificationRequest) { r.AccessToken.Token = "" }, ErrNotificationAccessTokenMissing},
		"unsupported token_type":  {func(r *OID4VCIFinalNotificationRequest) { r.AccessToken.TokenType = "MAC" }, ErrTokenTypeUnsupported},
		"DPoP token without key":  {func(r *OID4VCIFinalNotificationRequest) { r.ClientKey = jose.JSONWebKey{} }, ErrNotificationDPoPKeyMissing},
		"no endpoint":             {func(r *OID4VCIFinalNotificationRequest) { r.NotificationEndpoint = "" }, ErrNotificationEndpointMissing},
	} {
		t.Run(name, func(t *testing.T) {
			req := fixture.finalNotificationRequest(OID4VCINotificationCredentialAccepted)
			req.AccessToken = &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "DPoP"}
			tc.mutate(&req)
			require.ErrorIs(t, fixture.wallet.NotifyOID4VCIFinalCredential(context.Background(), req), tc.want)
		})
	}
	require.Empty(t, fixture.notificationBodies, "no invalid request reached the issuer")
}

func TestNotifyOID4VCIFinalCredentialReportsTheIssuerRefusal(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.notificationHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_notification_id"})
		}
	})
	err := fixture.wallet.NotifyOID4VCIFinalCredential(context.Background(), fixture.finalNotificationRequest(OID4VCINotificationCredentialAccepted))

	var endpointError *receiverTypes.CredentialEndpointError
	require.ErrorAs(t, err, &endpointError)
	require.Equal(t, http.StatusBadRequest, endpointError.StatusCode)
	require.Equal(t, "invalid_notification_id", endpointError.Code)
}

// RFC 9449 §8: a DPoP-Nonce challenge is answered once with a fresh proof.
func TestNotifyOID4VCIFinalCredentialAnswersTheDPoPNonceChallenge(t *testing.T) {
	calls := 0
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.notificationHandler = func(w http.ResponseWriter, _ *http.Request) {
			calls++
			if calls == 1 {
				w.Header().Set("DPoP-Nonce", "notification-nonce-1")
				mockserver.JSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "use_dpop_nonce"})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	})
	require.NoError(t, fixture.wallet.NotifyOID4VCIFinalCredential(context.Background(), fixture.finalNotificationRequest(OID4VCINotificationCredentialAccepted)))
	require.Len(t, fixture.notificationHeaders, 2)
	require.NotContains(t, decodeDPoPProofClaims(t, fixture.notificationHeaders[0].Get("DPoP")), "nonce")
	require.Equal(t, "notification-nonce-1", extractPayloadField(t, fixture.notificationHeaders[1].Get("DPoP"), "nonce"))
}

// No OpenID4VCI endpoint redirects; following one would replay the access
// token and its proof to an origin the response chose.
func decodeDPoPProofClaims(t *testing.T, proof string) map[string]any {
	t.Helper()
	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

func TestNotifyOID4VCIFinalCredentialRefusesARedirect(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.notificationHandler = func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/notification-elsewhere", http.StatusTemporaryRedirect)
		}
	})
	err := fixture.wallet.NotifyOID4VCIFinalCredential(context.Background(), fixture.finalNotificationRequest(OID4VCINotificationCredentialAccepted))
	require.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	require.Len(t, fixture.notificationBodies, 1)
}

func TestNotifyOID4VCIFinalCredentialLabelsTheRequestForAnObserver(t *testing.T) {
	recorder := observe.NewRecorder(8)
	fixture := newFinalIssuanceFixture(t, observeFixtureTransport(recorder))
	require.NoError(t, fixture.wallet.NotifyOID4VCIFinalCredential(context.Background(), fixture.finalNotificationRequest(OID4VCINotificationCredentialAccepted)))

	require.Equal(t, []observe.Endpoint{observe.EndpointNotification}, requireFixtureEndpointLabels(t, recorder.Exchanges()))
}

func TestNotifyOID4VCIFinalCredentialDeletedFixesTheEvent(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.finalNotificationRequest(OID4VCINotificationCredentialAccepted)
	require.NoError(t, fixture.wallet.NotifyOID4VCIFinalCredentialDeleted(req))
	require.Equal(t, []string{"credential_deleted"}, fixture.notificationEvents)
}

// §11 notifications are best effort: a credential_accepted the issuer refuses
// does not undo the credential the wallet already stored.
func TestReceiveOID4VCIFinalCredentialKeepsTheStoredCredentialWhenNotificationFails(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeNotification = true
		f.notificationHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		}
	})
	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	require.Equal(t, []string{"credential_accepted"}, fixture.notificationEvents)

	require.NotNil(t, result.NotificationError)
	require.Equal(t, OID4VCINotificationCredentialAccepted, result.NotificationError.Event)
	var endpointError *receiverTypes.CredentialEndpointError
	require.ErrorAs(t, result.NotificationError, &endpointError)

	entries, _, err := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

// A failed credential_failure notification is reported next to the storage
// failure it was about, which stays the error the caller branches on.
func TestReceiveOID4VCIFinalCredentialReportsAFailedFailureNotification(t *testing.T) {
	otherKey := newPrivateJWKForFinalVCITest(t, "other-holder-key")
	badCredential := buildTestSDJWTVC(t, otherKey, map[string]string{"given_name": "Taro"})
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeNotification = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials":     []any{map[string]any{"credential": badCredential}},
				"notification_id": "notification-1",
			})
		}
		f.notificationHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		}
	})
	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.Nil(t, result)
	require.ErrorContains(t, err, "not part of the request")
	var notificationError *OID4VCINotificationError
	require.ErrorAs(t, err, &notificationError)
	require.Equal(t, OID4VCINotificationCredentialFailure, notificationError.Event)
}
