package wallet

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// TestIssuanceErrorsAreCoded runs known failure paths of every exported
// issuance method and requires each error to carry a code other than
// unclassified.
func TestIssuanceErrorsAreCoded(t *testing.T) {
	ctx := context.Background()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	token := &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "Bearer"}

	cases := map[string]func(t *testing.T) error{
		"ResolveCredentialOffer without an offer": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.ResolveCredentialOffer(ctx, "openid-credential-offer://")
			return err
		},
		"ResolveCredentialOffer with a missing offer document": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.ResolveCredentialOffer(ctx, "openid-credential-offer://?credential_offer_uri="+f.server.URL+"/missing")
			return err
		},
		"BeginIssuance canceled": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.BeginIssuance(canceled, f.issuanceRequest())
			return err
		},
		"BeginIssuance against an unreachable issuer": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			f.server.Close()
			_, err := f.wallet.BeginIssuance(ctx, f.issuanceRequest())
			return err
		},
		"BeginIssuance with a foreign authorization server issuer": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) { f.asIssuerOverride = "https://other.example" })
			_, err := f.wallet.BeginIssuance(ctx, f.issuanceRequest())
			return err
		},
		"AuthorizeIssuance with a nil state": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.AuthorizeIssuance(ctx, nil, "")
			return err
		},
		"AuthorizeIssuance with a foreign redirect": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			authorization, err := f.wallet.BeginIssuance(ctx, f.issuanceRequest())
			require.NoError(t, err)
			_, err = f.wallet.AuthorizeIssuance(ctx, authorization, "https://attacker.example/cb?code=x")
			return err
		},
		"AuthorizeIssuance when the token endpoint refuses": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
				f.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
					mockserver.JSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
				}
			})
			_, err := f.authorize(f.issuanceRequest())
			return err
		},
		"AuthorizePreAuthorizedIssuance without the grant": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.AuthorizePreAuthorizedIssuance(ctx, PreAuthorizedIssuanceRequest{CredentialOffer: f.offer()})
			return err
		},
		"RequestCredential without holder keys": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			grant, err := f.authorize(f.issuanceRequest())
			require.NoError(t, err)
			_, err = f.wallet.RequestCredential(ctx, grant, CredentialRequest{})
			return err
		},
		"RequestCredential when the credential endpoint refuses": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
				f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
					mockserver.JSONResponse(w, http.StatusBadRequest, map[string]any{"error": "credential_request_denied"})
				}
			})
			_, err := f.receive(f.issuanceRequest())
			return err
		},
		"RequestCredential with a Draft 13 grant": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.RequestCredential(ctx, &IssuanceGrant{Version: IssuanceVersionDraft13}, f.credentialRequest())
			return err
		},
		"RequestDeferredCredential with an incomplete state": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.RequestDeferredCredential(ctx, &DeferredIssuance{Version: IssuanceVersionFinal})
			return err
		},
		"RequestDeferredCredential against an issuer without a deferred endpoint": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			_, err := f.wallet.RequestDeferredCredential(ctx, &DeferredIssuance{
				Version: IssuanceVersionFinal, CredentialIssuer: f.server.URL, CredentialConfigurationID: "pid",
				TransactionID: "tx-1", AccessToken: token,
			})
			return err
		},
		"NotifyIssuer with an invalid event": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			return f.wallet.NotifyIssuer(ctx, &IssuanceNotification{
				Version: IssuanceVersionFinal, CredentialIssuer: f.server.URL, NotificationID: "n-1", AccessToken: token,
			}, NotificationEvent("credential_lost"), "")
		},
		"NotifyIssuer against an issuer without a notification endpoint": func(t *testing.T) error {
			f := newFinalIssuanceFixture(t)
			return f.wallet.NotifyIssuer(ctx, &IssuanceNotification{
				Version: IssuanceVersionFinal, CredentialIssuer: f.server.URL, NotificationID: "n-1", AccessToken: token,
			}, NotificationCredentialAccepted, "")
		},
		"Draft13 under HAIP": func(t *testing.T) error {
			f := newHAIPIssuanceFixture(t)
			_, err := f.wallet.Draft13().AuthorizePreAuthorizedIssuance(ctx, PreAuthorizedIssuanceRequest{CredentialOffer: f.offer()})
			return err
		},
		"Draft13 without an offer": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.Draft13().BeginIssuance(ctx, IssuanceRequest{})
			return err
		},
		"ReceiveCredential without an offer": func(t *testing.T) error {
			_, err := newFinalIssuanceFixture(t).wallet.ReceiveCredential(ReceiveCredentialRequest{Type: receiverTypes.Oid4vci})
			return err
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			err := run(t)
			require.Error(t, err)
			code, ok := ErrorCode(err)
			require.True(t, ok, "error has no code: %v", err)
			require.NotEqual(t, "unclassified", code, "error: %v", err)
		})
	}
}
