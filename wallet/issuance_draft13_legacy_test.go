package wallet

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// ReceiveCredential is Draft13().AuthorizePreAuthorizedIssuance followed by
// Draft13().RequestCredential; these tests pin what the one call adds and
// that its wire is Draft 13's. The staged Draft 13 behavior itself is tested
// in issuance_draft13_test.go.

// receiveCredentialRequest is the one-call request for the fixture's
// pre-authorized offer.
func (f *draft13Fixture) receiveCredentialRequest() ReceiveCredentialRequest {
	return ReceiveCredentialRequest{CredentialOffer: f.preAuthorizedOffer(), TxCode: "4321", Key: f.key}
}

// Draft 13 Section 6.2 and 7.2: the c_nonce of the key proof comes from the
// Token Response (or a Credential Error Response); Draft 13 has no Nonce
// Endpoint, so an advertised nonce_endpoint is never called. The Credential
// Request is the Section 7.2 shape: format plus one proof object, never the
// 1.0 credential_configuration_id and proofs.
func TestReceiveCredentialSpeaksDraft13AndNeverCallsANonceEndpoint(t *testing.T) {
	var nonceCalls atomic.Int32
	nonceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nonceCalls.Add(1)
		draft13WriteJSON(w, http.StatusOK, map[string]any{"c_nonce": "nonce-from-endpoint"})
	}))
	t.Cleanup(nonceServer.Close)
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.issuerMetadataExtra = func(string) map[string]any { return map[string]any{"nonce_endpoint": nonceServer.URL + "/nonce"} }
	})

	saved, err := fixture.wallet.ReceiveCredential(t.Context(), fixture.receiveCredentialRequest())
	require.NoError(t, err)
	require.Equal(t, fixture.credential, string(saved.Entry.Raw))
	require.True(t, saved.Verification.HolderBound)
	require.Equal(t, 1, draft13StoredCount(t, fixture.wallet))
	require.Zero(t, nonceCalls.Load(), "Draft 13 has no nonce endpoint to call")

	tokens := fixture.tokens()
	require.Len(t, tokens, 1)
	require.Equal(t, string(receiverTypes.PreAuthorizedCode), tokens[0].Get("grant_type"))
	require.Equal(t, "pre-code-1", tokens[0].Get("pre-authorized_code"))
	require.Equal(t, "4321", tokens[0].Get("tx_code"))

	requests := fixture.credentials()
	require.Len(t, requests, 1)
	request := requests[0]
	require.Equal(t, "vc+sd-jwt", request["format"])
	require.NotContains(t, request, "credential_configuration_id")
	require.NotContains(t, request, "proofs")
	_, _, claims := draft13ProofParts(t, request)
	require.Equal(t, "nonce-1", claims["nonce"], "the key proof carries the Token Response c_nonce")
}

// Draft 13 Section 6.1: tx_code is sent only when the holder entered one.
func TestReceiveCredentialOmitsAnEmptyTxCode(t *testing.T) {
	fixture := newDraft13Fixture(t)
	request := fixture.receiveCredentialRequest()
	request.CredentialOffer = fixture.offer(map[string]*CredentialOfferGrant{
		string(receiverTypes.PreAuthorizedCode): {PreAuthorizedCode: "pre-code-1"},
	})
	request.TxCode = ""
	_, err := fixture.wallet.ReceiveCredential(t.Context(), request)
	require.NoError(t, err)
	tokens := fixture.tokens()
	require.Len(t, tokens, 1)
	require.False(t, tokens[0].Has("tx_code"))
}

// A deferred credential cannot be polled for without the state the staged
// methods return, so ReceiveCredential reports it instead of dropping the
// transaction silently.
func TestReceiveCredentialReportsADeferredCredential(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.credentialResponse = func(int, map[string]any) (int, any) {
			return http.StatusAccepted, map[string]any{"transaction_id": "transaction-1"}
		}
	})
	saved, err := fixture.wallet.ReceiveCredential(t.Context(), fixture.receiveCredentialRequest())
	require.Nil(t, saved)
	draft13RequireCoded(t, err, ErrDraft13CredentialDeferred)
	require.Zero(t, draft13StoredCount(t, fixture.wallet))
}

// The pre-authorized code is used once (Draft 13 Section 4.1.1), so what
// would make RequestCredential refuse is checked before the token request.
func TestReceiveCredentialRefusesBeforeRedeemingTheCode(t *testing.T) {
	for name, test := range map[string]struct {
		configure func(*Config)
		change    func(*ReceiveCredentialRequest)
		want      error
	}{
		"no acceptance policy": {
			configure: func(c *Config) { c.CredentialAcceptance = nil },
			want:      ErrCredentialAcceptancePolicyRequired,
		},
		"no holder key": {
			change: func(r *ReceiveCredentialRequest) { r.Key = nil },
			want:   ErrDraft13HolderKeyMissing,
		},
		"a configuration the offer does not list": {
			change: func(r *ReceiveCredentialRequest) { r.CredentialConfigurationID = "other" },
			want:   ErrDraft13CredentialConfigurationUnknown,
		},
		"no pre-authorized_code grant": {
			change: func(r *ReceiveCredentialRequest) { r.CredentialOffer.Grants = map[string]*CredentialOfferGrant{} },
			want:   ErrDraft13PreAuthorizedCodeGrantMissing,
		},
		"no offer": {
			change: func(r *ReceiveCredentialRequest) { r.CredentialOffer = nil },
			want:   ErrDraft13OfferMissing,
		},
	} {
		t.Run(name, func(t *testing.T) {
			var configure []func(*Config)
			if test.configure != nil {
				configure = append(configure, test.configure)
			}
			fixture := newDraft13Fixture(t, configure...)
			request := fixture.receiveCredentialRequest()
			if test.change != nil {
				test.change(&request)
			}
			_, err := fixture.wallet.ReceiveCredential(t.Context(), request)
			draft13RequireCoded(t, err, test.want)
			require.Empty(t, fixture.tokens(), "no token request was sent")
		})
	}
}

// Review of 2026-09-25 (finding 8): the Draft 13 one-call flow reads the
// Credential Issuer Metadata from the Draft 13 Section 11.2.2 location only;
// for an identifier with a path it differs from the 1.0 Section 12.2.2 one.
func TestReceiveCredentialReadsTheDraft13MetadataLocation(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	issuer, err := url.Parse(server.URL + "/tenant")
	require.NoError(t, err)

	_, err = createTestControllerAllowingHTTP(t).ReceiveCredential(t.Context(), ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer: issuer, CredentialConfigurationIDs: []string{"c"},
			Grants: map[string]*CredentialOfferGrant{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {PreAuthorizedCode: "code"}},
		},
		Key: newMockKeyEntry(), Acceptance: mockIssuerAcceptance(),
	})
	require.Error(t, err)
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"/tenant/.well-known/openid-credential-issuer"}, paths)
}

// newReceiveCredentialTestServer is a plain-http Draft 13 issuer of one
// jwt_vc_json credential whose subject is holder's did:key, signed by the
// mockserver issuer key, for tests that need a stored credential.
func newReceiveCredentialTestServer(t *testing.T, holder IKeyEntry) *url.URL {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	jwtBuilder := mockserver.MustNewJWTBuilder(mockserver.MustGenerateKeyPair("issuer-key-id"))
	credentialJWT, err := jwtBuilder.CreateSignedCredentialJWT(server.URL, map[string]any{
		"sub": didKeyOf(t, holder.PublicKey()),
		"vc": map[string]any{
			"@context":     []string{"https://www.w3.org/2018/credentials/v1"},
			"id":           "http://example.com/credential/1",
			"type":         []string{"VerifiableCredential"},
			"issuer":       server.URL,
			"issuanceDate": "2023-01-01T00:00:00Z",
			"credentialSubject": map[string]any{
				"id":   "http://example.com/subject",
				"name": "John Doe",
			},
		},
	})
	require.NoError(t, err)

	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{
			"credential_issuer":     server.URL,
			"credential_endpoint":   server.URL + "/credential",
			"authorization_servers": []string{server.URL},
			"credential_configurations_supported": map[string]any{
				"test-config": map[string]any{
					"format":                "jwt_vc_json",
					"credential_definition": map[string]any{"type": []string{"VerifiableCredential"}},
				},
			},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{
			"issuer":         server.URL,
			"token_endpoint": server.URL + "/token",
			"pre-authorized_grant_anonymous_access_supported": true,
			"response_types_supported":                        []string{"code"},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"c_nonce":      "test-nonce",
		})
	})
	mux.HandleFunc("/credential", func(w http.ResponseWriter, _ *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential": credentialJWT})
	})

	issuer, err := url.Parse(server.URL)
	require.NoError(t, err)
	return issuer
}
