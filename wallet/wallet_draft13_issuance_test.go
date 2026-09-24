package wallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/receiver"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// draft13Fixture is a Draft 13 Credential Issuer and Authorization Server on
// one httptest server. Each endpoint records what it received and answers
// with a handler the test may replace, so a test states only the exchange it
// is about.
type draft13Fixture struct {
	server *httptest.Server
	wallet *Wallet
	key    IKeyEntry

	mu                    sync.Mutex
	configuration         map[string]any
	authorizationServers  bool
	asIssuerOverride      string
	tokenForms            []url.Values
	credentialRequests    []map[string]any
	deferredRequests      []map[string]any
	notificationRequests  []map[string]any
	tokenResponse         func(form url.Values) (int, any)
	credentialResponse    func(call int, request map[string]any) (int, any)
	deferredResponse      func(call int) (int, any)
	notificationResponse  func() (int, any)
	credentialCallCounter int
	deferredCallCounter   int
}

func newDraft13Fixture(t *testing.T) *draft13Fixture {
	t.Helper()
	fixture := &draft13Fixture{
		configuration: map[string]any{
			"format": "vc+sd-jwt",
			"vct":    "https://credentials.example/degree",
			"scope":  "degree",
			"cryptographic_binding_methods_supported": []string{"did:key"},
			"proof_types_supported": map[string]any{
				"jwt": map[string]any{"proof_signing_alg_values_supported": []string{"ES256"}},
			},
		},
		tokenResponse: func(url.Values) (int, any) {
			return http.StatusOK, map[string]any{"access_token": "access-1", "token_type": "Bearer", "c_nonce": "nonce-1"}
		},
		credentialResponse: func(int, map[string]any) (int, any) {
			return http.StatusOK, map[string]any{"credential": "issued-credential", "notification_id": "notification-1", "c_nonce": "nonce-2"}
		},
		deferredResponse: func(int) (int, any) {
			return http.StatusOK, map[string]any{"credential": "deferred-credential", "notification_id": "notification-2"}
		},
		notificationResponse: func() (int, any) { return http.StatusNoContent, nil },
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		base := fixture.server.URL
		metadata := map[string]any{
			"credential_issuer":            base,
			"credential_endpoint":          base + "/credential",
			"deferred_credential_endpoint": base + "/deferred",
			"notification_endpoint":        base + "/notification",
			"credential_configurations_supported": map[string]any{
				"degree": fixture.configuration,
			},
		}
		if fixture.authorizationServers {
			metadata["authorization_servers"] = []string{base}
		}
		writeDraft13FixtureJSON(w, http.StatusOK, metadata)
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		base := fixture.server.URL
		issuer := base
		fixture.mu.Lock()
		if fixture.asIssuerOverride != "" {
			issuer = fixture.asIssuerOverride
		}
		fixture.mu.Unlock()
		writeDraft13FixtureJSON(w, http.StatusOK, map[string]any{
			"issuer":                   issuer,
			"authorization_endpoint":   base + "/authorize",
			"token_endpoint":           base + "/token",
			"response_types_supported": []string{"code"},
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		fixture.mu.Lock()
		fixture.tokenForms = append(fixture.tokenForms, r.PostForm)
		respond := fixture.tokenResponse
		fixture.mu.Unlock()
		status, body := respond(r.PostForm)
		writeDraft13FixtureJSON(w, status, body)
	})
	mux.HandleFunc("POST /credential", func(w http.ResponseWriter, r *http.Request) {
		request := decodeDraft13FixtureBody(t, r)
		fixture.mu.Lock()
		fixture.credentialRequests = append(fixture.credentialRequests, request)
		fixture.credentialCallCounter++
		call := fixture.credentialCallCounter
		respond := fixture.credentialResponse
		fixture.mu.Unlock()
		status, body := respond(call, request)
		writeDraft13FixtureJSON(w, status, body)
	})
	mux.HandleFunc("POST /deferred", func(w http.ResponseWriter, r *http.Request) {
		request := decodeDraft13FixtureBody(t, r)
		fixture.mu.Lock()
		fixture.deferredRequests = append(fixture.deferredRequests, request)
		fixture.deferredCallCounter++
		call := fixture.deferredCallCounter
		respond := fixture.deferredResponse
		fixture.mu.Unlock()
		status, body := respond(call)
		writeDraft13FixtureJSON(w, status, body)
	})
	mux.HandleFunc("POST /notification", func(w http.ResponseWriter, r *http.Request) {
		request := decodeDraft13FixtureBody(t, r)
		fixture.mu.Lock()
		fixture.notificationRequests = append(fixture.notificationRequests, request)
		respond := fixture.notificationResponse
		fixture.mu.Unlock()
		status, body := respond()
		writeDraft13FixtureJSON(w, status, body)
	})
	fixture.server = httptest.NewServer(mux)
	t.Cleanup(fixture.server.Close)

	plugin := receiverTypes.Receiver(&receiverOid4vci.Oid4vciReceiver{HTTPClient: fixture.server.Client(), AllowHTTP: true})
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
	require.NoError(t, err)
	fixture.wallet, err = NewWalletWithConfig(Config{Receiver: receiving, CredStore: newProfileCredStore(t)})
	require.NoError(t, err)
	fixture.key, err = newInMemoryECKeyEntry()
	require.NoError(t, err)
	return fixture
}

func writeDraft13FixtureJSON(w http.ResponseWriter, status int, body any) {
	if body == nil {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func decodeDraft13FixtureBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	decoded["_authorization"] = r.Header.Get("Authorization")
	return decoded
}

func (f *draft13Fixture) offer(t *testing.T, grants map[string]*CredentialOfferGrant) *CredentialOffer {
	t.Helper()
	issuer, err := url.Parse(f.server.URL)
	require.NoError(t, err)
	return &CredentialOffer{CredentialIssuer: issuer, CredentialConfigurationIDs: []string{"degree"}, Grants: grants}
}

func (f *draft13Fixture) preAuthorizedRequest(t *testing.T) OID4VCIDraft13ReceiveRequest {
	t.Helper()
	return OID4VCIDraft13ReceiveRequest{
		CredentialOffer: f.offer(t, map[string]*CredentialOfferGrant{
			preAuthorizedCodeGrantType: {PreAuthorizedCode: "pre-code-1"},
		}),
		Type: receiverTypes.Oid4vci,
		Key:  f.key,
	}
}

// draft13ProofParts decodes the header and claims of the one key proof a
// recorded Credential Request carried.
func draft13ProofParts(t *testing.T, request map[string]any) (string, map[string]any, map[string]any) {
	t.Helper()
	proof, ok := request["proof"].(map[string]any)
	require.True(t, ok, "credential request carries a proof object")
	require.Equal(t, "jwt", proof["proof_type"])
	compact, ok := proof["jwt"].(string)
	require.True(t, ok)
	segments := strings.Split(compact, ".")
	require.Len(t, segments, 3)
	decode := func(segment string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(segment)
		require.NoError(t, err)
		var decoded map[string]any
		require.NoError(t, json.Unmarshal(raw, &decoded))
		return decoded
	}
	return compact, decode(segments[0]), decode(segments[1])
}

func TestReceiveOID4VCIDraft13CredentialPreAuthorizedCode(t *testing.T) {
	fixture := newDraft13Fixture(t)
	req := fixture.preAuthorizedRequest(t)
	req.TxCode = "4321"

	result, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "issued-credential", result.RawCredential)
	require.Equal(t, "vc+sd-jwt", result.CredentialFormat)
	require.Equal(t, "notification-1", result.NotificationID)
	require.Equal(t, "nonce-2", result.CNonce)
	require.Equal(t, "access-1", result.AccessToken.Token)
	require.Nil(t, result.SavedCredential, "nothing is stored unless the caller asks")

	// Section 6.1: the anonymous grant sends no client_id.
	require.Len(t, fixture.tokenForms, 1)
	form := fixture.tokenForms[0]
	require.Equal(t, preAuthorizedCodeGrantType, form.Get("grant_type"))
	require.Equal(t, "pre-code-1", form.Get("pre-authorized_code"))
	require.Equal(t, "4321", form.Get("tx_code"))
	require.False(t, form.Has("client_id"))

	// Section 7.2: the SD-JWT VC is named by format and vct, with one proof.
	require.Len(t, fixture.credentialRequests, 1)
	request := fixture.credentialRequests[0]
	require.Equal(t, "Bearer access-1", request["_authorization"])
	require.Equal(t, "vc+sd-jwt", request["format"])
	require.Equal(t, "https://credentials.example/degree", request["vct"])
	require.NotContains(t, request, "credential_identifier")
	require.NotContains(t, request, "proofs")

	_, header, claims := draft13ProofParts(t, request)
	require.Equal(t, "openid4vci-proof+jwt", header["typ"])
	require.Equal(t, "ES256", header["alg"])
	require.NotContains(t, header, "jwk")
	kid, _ := header["kid"].(string)
	did, identifier, found := strings.Cut(kid, "#")
	require.True(t, found, "a kid-bound proof names a DID URL, not a bare DID")
	require.Equal(t, "did:key:"+identifier, did)
	require.Equal(t, fixture.server.URL, claims["aud"])
	require.Equal(t, "nonce-1", claims["nonce"])
	require.NotContains(t, claims, "iss", "the anonymous flow has no client_id to put in iss")
}

func TestReceiveOID4VCIDraft13CredentialNamesJWTVCByTypeOnly(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.configuration = map[string]any{
		"format": "jwt_vc_json",
		"credential_definition": map[string]any{
			"type":              []string{"VerifiableCredential", "UniversityDegree"},
			"credentialSubject": map[string]any{"degree": map[string]any{"mandatory": true}},
		},
		"cryptographic_binding_methods_supported": []string{"did:key"},
	}
	_, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), fixture.preAuthorizedRequest(t))
	require.NoError(t, err)
	request := fixture.credentialRequests[0]
	require.Equal(t, "jwt_vc_json", request["format"])
	require.Equal(t, map[string]any{"type": []any{"VerifiableCredential", "UniversityDegree"}}, request["credential_definition"])
}

func TestReceiveOID4VCIDraft13CredentialRetriesInvalidProofOnceWithTheFreshNonce(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.credentialResponse = func(call int, _ map[string]any) (int, any) {
		if call == 1 {
			return http.StatusBadRequest, map[string]any{"error": "invalid_proof", "c_nonce": "fresh-nonce"}
		}
		return http.StatusOK, map[string]any{"credential": "issued-credential"}
	}

	result, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), fixture.preAuthorizedRequest(t))
	require.NoError(t, err)
	require.Equal(t, "issued-credential", result.RawCredential)
	require.Len(t, fixture.credentialRequests, 2)
	_, _, retried := draft13ProofParts(t, fixture.credentialRequests[1])
	require.Equal(t, "fresh-nonce", retried["nonce"])
}

func TestReceiveOID4VCIDraft13CredentialReportsASecondInvalidProof(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.credentialResponse = func(call int, _ map[string]any) (int, any) {
		return http.StatusBadRequest, map[string]any{"error": "invalid_proof", "c_nonce": "fresh-nonce-" + string(rune('0'+call))}
	}

	_, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), fixture.preAuthorizedRequest(t))
	require.ErrorIs(t, err, receiverOid4vci.ErrDraft13InvalidProof)
	require.Len(t, fixture.credentialRequests, 2, "invalid_proof is retried exactly once")
}

func TestDraft13ProofTransformRewritesTheProofBeforeAndAfterSigning(t *testing.T) {
	fixture := newDraft13Fixture(t)
	req := fixture.preAuthorizedRequest(t)
	var seenNonce any
	req.ProofTransform = ProofTransform{
		Content: func(content ProofJWTContent) (ProofJWTContent, error) {
			seenNonce = content.Claims["nonce"]
			content.Header["kid"] = "did:key:elsewhere#elsewhere"
			content.Claims["nonce"] = "replayed"
			return content, nil
		},
		Serialized: func(compact string) (string, error) {
			return compact + "-tampered", nil
		},
	}

	_, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "nonce-1", seenNonce, "the transform sees the proof the library built")

	compact, header, claims := draft13ProofParts(t, map[string]any{"proof": map[string]any{
		"proof_type": "jwt",
		"jwt":        strings.TrimSuffix(fixture.credentialRequests[0]["proof"].(map[string]any)["jwt"].(string), "-tampered"),
	}})
	require.True(t, strings.HasSuffix(fixture.credentialRequests[0]["proof"].(map[string]any)["jwt"].(string), "-tampered"))
	require.Equal(t, "did:key:elsewhere#elsewhere", header["kid"])
	require.Equal(t, "replayed", claims["nonce"])

	// The content rewrite happened before signing: the signature still
	// verifies over what the proof now says.
	signed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	publicKey := fixture.key.PublicKey()
	_, err = signed.Verify(publicKey.Public())
	require.NoError(t, err)
}

func TestDraft13ZeroProofTransformIsTheUntouchedProof(t *testing.T) {
	fixture := newDraft13Fixture(t)
	nonce := "nonce-1"
	build := func(transform ProofTransform) (map[string]any, map[string]any) {
		compact, err := fixture.wallet.generateJWTProofWithTransform(fixture.key, "did:key:zExample#zExample", &nonce, "https://issuer.example", nil, credentialRequestProofBindingMethodKID, transform)
		require.NoError(t, err)
		_, header, claims := draft13ProofParts(t, map[string]any{"proof": map[string]any{"proof_type": "jwt", "jwt": compact}})
		delete(claims, "iat")
		return header, claims
	}
	identity := ProofTransform{
		Content:    func(content ProofJWTContent) (ProofJWTContent, error) { return content, nil },
		Serialized: func(compact string) (string, error) { return compact, nil },
	}
	zeroHeader, zeroClaims := build(ProofTransform{})
	identityHeader, identityClaims := build(identity)
	require.Equal(t, zeroHeader, identityHeader)
	require.Equal(t, zeroClaims, identityClaims)
	require.Equal(t, map[string]any{"typ": "openid4vci-proof+jwt", "alg": "ES256", "kid": "did:key:zExample#zExample"}, zeroHeader)
}

func TestDraft13ProofTransformFailureSendsNothing(t *testing.T) {
	fixture := newDraft13Fixture(t)
	req := fixture.preAuthorizedRequest(t)
	req.ProofTransform = ProofTransform{Content: func(ProofJWTContent) (ProofJWTContent, error) {
		return ProofJWTContent{}, errors.New("refused")
	}}

	_, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), req)
	require.ErrorIs(t, err, ErrDraft13ProofTransformFailed)
	require.Empty(t, fixture.credentialRequests)
}

func TestReceiveOID4VCIDraft13CredentialSendsAPreSignedProofVerbatim(t *testing.T) {
	fixture := newDraft13Fixture(t)
	req := fixture.preAuthorizedRequest(t)
	req.Key = nil
	req.PreSignedProof = "caller.signed.proof"

	_, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), req)
	require.NoError(t, err)
	proof := fixture.credentialRequests[0]["proof"].(map[string]any)
	require.Equal(t, "caller.signed.proof", proof["jwt"])
}

func TestReceiveOID4VCIDraft13CredentialRequiresAHolderKey(t *testing.T) {
	fixture := newDraft13Fixture(t)
	req := fixture.preAuthorizedRequest(t)
	req.Key = nil

	_, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), req)
	require.ErrorIs(t, err, ErrDraft13HolderKeyMissing)
}

func TestReceiveOID4VCIDraft13CredentialRefusesCachedMetadataOfAnotherIssuer(t *testing.T) {
	fixture := newDraft13Fixture(t)
	req := fixture.preAuthorizedRequest(t)
	req.CachedIssuerMetadata = &receiverTypes.CredentialIssuerMetadata{CredentialIssuer: "https://other-issuer.example"}

	_, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), req)
	require.ErrorIs(t, err, ErrIssuerIdentifierMismatch)
	require.Empty(t, fixture.tokenForms)
}

// RFC 8414 §3.3: the authorization server metadata's issuer MUST be identical
// to the identifier it was fetched for, on the Draft 13 path as on the Final
// one, so another server's metadata cannot redirect the token request.
func TestReceiveOID4VCIDraft13CredentialRefusesForeignAuthorizationServerIssuer(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.asIssuerOverride = "https://other-as.example"
	req := fixture.preAuthorizedRequest(t)

	_, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), req)
	require.ErrorContains(t, err, "does not match the selected authorization server")
	require.Empty(t, fixture.tokenForms)
}

func TestReceiveOID4VCIDraft13CredentialReadsAnObjectCredentialAsJSON(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.credentialResponse = func(int, map[string]any) (int, any) {
		return http.StatusOK, map[string]any{"credential": map[string]any{"type": []string{"VerifiableCredential"}}}
	}

	result, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), fixture.preAuthorizedRequest(t))
	require.NoError(t, err)
	require.JSONEq(t, `{"type":["VerifiableCredential"]}`, result.RawCredential)
}

func TestReceiveOID4VCIDraft13CredentialReturnsTheDeferredTransaction(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.credentialResponse = func(int, map[string]any) (int, any) {
		return http.StatusAccepted, map[string]any{"transaction_id": "transaction-1", "interval": 7}
	}

	result, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), fixture.preAuthorizedRequest(t))
	require.NoError(t, err)
	require.Empty(t, result.RawCredential)
	require.Equal(t, "transaction-1", result.TransactionID)
	require.Equal(t, 7, result.DeferredIntervalSeconds)
	require.Empty(t, fixture.deferredRequests, "no poll unless the caller allows one")
}

func TestReceiveOID4VCIDraft13CredentialPollsTheDeferredTransactionWhenAllowed(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.credentialResponse = func(int, map[string]any) (int, any) {
		return http.StatusAccepted, map[string]any{"transaction_id": "transaction-1"}
	}
	req := fixture.preAuthorizedRequest(t)
	req.DeferredPollAttempts = 1

	result, err := fixture.wallet.ReceiveOID4VCIDraft13Credential(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "deferred-credential", result.RawCredential)
	require.Equal(t, "notification-2", result.NotificationID)
	require.Empty(t, result.TransactionID)
	require.Equal(t, "transaction-1", fixture.deferredRequests[0]["transaction_id"])
}

func (f *draft13Fixture) deferredRequest() OID4VCIDraft13DeferredRequest {
	return OID4VCIDraft13DeferredRequest{
		Type:                       receiverTypes.Oid4vci,
		DeferredCredentialEndpoint: f.server.URL + "/deferred",
		CredentialConfigurationID:  "degree",
		CredentialFormat:           "vc+sd-jwt",
		TransactionID:              "transaction-1",
		AccessToken:                &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "Bearer"},
		MaxInterval:                1,
	}
}

func TestResumeOID4VCIDraft13DeferredCredentialWaitsOutIssuancePending(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.deferredResponse = func(call int) (int, any) {
		if call == 1 {
			return http.StatusBadRequest, map[string]any{"error": "issuance_pending", "interval": 30}
		}
		return http.StatusOK, map[string]any{"credential": "deferred-credential", "notification_id": "notification-2"}
	}
	req := fixture.deferredRequest()
	req.PollAttempts = 2

	result, err := fixture.wallet.ResumeOID4VCIDraft13DeferredCredential(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "deferred-credential", result.RawCredential)
	require.Equal(t, "notification-2", result.NotificationID)
	require.Len(t, fixture.deferredRequests, 2)
	require.Equal(t, "Bearer access-1", fixture.deferredRequests[0]["_authorization"])
}

func TestResumeOID4VCIDraft13DeferredCredentialReportsStillPendingWithTheInterval(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.deferredResponse = func(int) (int, any) {
		return http.StatusBadRequest, map[string]any{"error": "issuance_pending", "interval": 30}
	}

	_, err := fixture.wallet.ResumeOID4VCIDraft13DeferredCredential(context.Background(), fixture.deferredRequest())
	require.ErrorIs(t, err, ErrDraft13IssuancePending)
	var endpointError *receiverOid4vci.Draft13CredentialEndpointError
	require.ErrorAs(t, err, &endpointError)
	require.Equal(t, 30, endpointError.Interval)
	require.Equal(t, []string{"draft13_issuance_pending", "draft13_credential_issuance_pending"}, ErrorCodes(err))
}

func TestResumeOID4VCIDraft13DeferredCredentialReportsATerminalRefusal(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.deferredResponse = func(int) (int, any) {
		return http.StatusBadRequest, map[string]any{"error": "invalid_transaction_id"}
	}
	req := fixture.deferredRequest()
	req.PollAttempts = 3

	_, err := fixture.wallet.ResumeOID4VCIDraft13DeferredCredential(context.Background(), req)
	require.NotErrorIs(t, err, ErrDraft13IssuancePending)
	var endpointError *receiverOid4vci.Draft13CredentialEndpointError
	require.ErrorAs(t, err, &endpointError)
	require.Equal(t, "invalid_transaction_id", endpointError.Code)
	require.Len(t, fixture.deferredRequests, 1, "a terminal answer is not polled again")
}

func TestResumeOID4VCIDraft13DeferredCredentialRefusesADPoPTokenWithoutAKey(t *testing.T) {
	fixture := newDraft13Fixture(t)
	req := fixture.deferredRequest()
	req.AccessToken = &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "DPoP"}

	_, err := fixture.wallet.ResumeOID4VCIDraft13DeferredCredential(context.Background(), req)
	require.ErrorIs(t, err, receiverOid4vci.ErrDPoPRequired)
	require.Empty(t, fixture.deferredRequests)
}

func TestNotifyOID4VCIDraft13Credential(t *testing.T) {
	fixture := newDraft13Fixture(t)
	req := OID4VCIDraft13NotificationRequest{
		Type:                 receiverTypes.Oid4vci,
		NotificationEndpoint: fixture.server.URL + "/notification",
		AccessToken:          &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "Bearer"},
		NotificationID:       "notification-1",
		Event:                "credential_accepted",
		EventDescription:     "stored",
	}

	require.NoError(t, fixture.wallet.NotifyOID4VCIDraft13Credential(context.Background(), req))
	require.Equal(t, []map[string]any{{
		"_authorization":    "Bearer access-1",
		"notification_id":   "notification-1",
		"event":             "credential_accepted",
		"event_description": "stored",
	}}, fixture.notificationRequests)

	fixture.notificationResponse = func() (int, any) {
		return http.StatusBadRequest, map[string]any{"error": "invalid_notification_id"}
	}
	err := fixture.wallet.NotifyOID4VCIDraft13Credential(context.Background(), req)
	var endpointError *receiverOid4vci.Draft13CredentialEndpointError
	require.ErrorAs(t, err, &endpointError)
	require.Equal(t, "invalid_notification_id", endpointError.Code)

	req.Event = "credential_lost"
	require.ErrorIs(t, fixture.wallet.NotifyOID4VCIDraft13Credential(context.Background(), req), ErrNotificationEventInvalid)
	req.Event = "credential_accepted"
	req.EventDescription = `quote " refused`
	require.ErrorIs(t, fixture.wallet.NotifyOID4VCIDraft13Credential(context.Background(), req), ErrNotificationEventDescriptionInvalid)
	require.Len(t, fixture.notificationRequests, 2)
}

func (f *draft13Fixture) authorizationCodeRequest(t *testing.T) OID4VCIDraft13ReceiveRequest {
	t.Helper()
	return OID4VCIDraft13ReceiveRequest{
		CredentialOffer: f.offer(t, map[string]*CredentialOfferGrant{
			"authorization_code": {IssuerState: "issuer-state-1"},
		}),
		Type:        receiverTypes.Oid4vci,
		Key:         f.key,
		ClientID:    "https://wallet.example/credential-offer/callback",
		RedirectURI: "https://wallet.example/credential-offer/callback",
	}
}

func TestDraft13AuthorizationCodeFlowSurvivesJSONRoundTrip(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.authorizationServers = true
	req := fixture.authorizationCodeRequest(t)

	authorization, err := fixture.wallet.BeginOID4VCIDraft13Authorization(context.Background(), req)
	require.NoError(t, err)
	require.Empty(t, fixture.tokenForms, "beginning the flow sends nothing to the token endpoint")

	authorizationURL, err := url.Parse(authorization.AuthorizationURL)
	require.NoError(t, err)
	require.Equal(t, fixture.server.URL+"/authorize", authorizationURL.Scheme+"://"+authorizationURL.Host+authorizationURL.Path)
	query := authorizationURL.Query()
	require.Equal(t, "code", query.Get("response_type"))
	require.Equal(t, req.ClientID, query.Get("client_id"))
	require.Equal(t, req.RedirectURI, query.Get("redirect_uri"))
	require.Equal(t, authorization.State, query.Get("state"))
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.NotEmpty(t, query.Get("code_challenge"))
	require.Equal(t, "degree", query.Get("scope"))
	require.Equal(t, "issuer-state-1", query.Get("issuer_state"))
	require.Equal(t, fixture.server.URL, query.Get("resource"))

	var restored OID4VCIDraft13Authorization
	requireJSONRoundTrip(t, authorization, &restored)
	redirect := req.RedirectURI + "?code=code-1&state=" + url.QueryEscape(restored.State) + "&iss=" + url.QueryEscape(fixture.server.URL)
	result, err := fixture.wallet.ResumeOID4VCIDraft13Authorization(context.Background(), req, &restored, redirect)
	require.NoError(t, err)
	require.Equal(t, "issued-credential", result.RawCredential)

	form := fixture.tokenForms[0]
	require.Equal(t, "authorization_code", form.Get("grant_type"))
	require.Equal(t, "code-1", form.Get("code"))
	require.Equal(t, req.RedirectURI, form.Get("redirect_uri"))
	require.Equal(t, req.ClientID, form.Get("client_id"))
	require.Equal(t, restored.CodeVerifier, form.Get("code_verifier"))

	_, _, claims := draft13ProofParts(t, fixture.credentialRequests[0])
	require.Equal(t, req.ClientID, claims["iss"], "a registered client names itself in the proof")
}

func TestResumeOID4VCIDraft13AuthorizationRefusesAForeignState(t *testing.T) {
	fixture := newDraft13Fixture(t)
	req := fixture.authorizationCodeRequest(t)
	authorization, err := fixture.wallet.BeginOID4VCIDraft13Authorization(context.Background(), req)
	require.NoError(t, err)

	_, err = fixture.wallet.ResumeOID4VCIDraft13Authorization(context.Background(), req, authorization, req.RedirectURI+"?code=code-1&state=someone-else")
	require.Error(t, err)
	require.Contains(t, ErrorCodes(err), "authorization_state_mismatch")
	require.Empty(t, fixture.tokenForms)
}

// The Draft 13 authorization state carries identifiers, not endpoints: one
// that names another issuer or an authorization server the issuer does not
// delegate to is refused before the code is redeemed.
func TestResumeOID4VCIDraft13AuthorizationRefusesTamperedState(t *testing.T) {
	for name, tamper := range map[string]func(*OID4VCIDraft13Authorization){
		"foreign credential issuer":        func(a *OID4VCIDraft13Authorization) { a.CredentialIssuer = "https://attacker.example" },
		"undelegated authorization server": func(a *OID4VCIDraft13Authorization) { a.AuthorizationServer = "https://attacker.example" },
		"missing code_verifier":            func(a *OID4VCIDraft13Authorization) { a.CodeVerifier = "" },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDraft13Fixture(t)
			req := fixture.authorizationCodeRequest(t)
			authorization, err := fixture.wallet.BeginOID4VCIDraft13Authorization(context.Background(), req)
			require.NoError(t, err)
			var restored OID4VCIDraft13Authorization
			requireJSONRoundTrip(t, authorization, &restored)
			tamper(&restored)

			redirect := req.RedirectURI + "?code=code-1&state=" + url.QueryEscape(restored.State)
			_, err = fixture.wallet.ResumeOID4VCIDraft13Authorization(context.Background(), req, &restored, redirect)
			require.ErrorIs(t, err, ErrIssuanceStateInvalid)
			require.Empty(t, fixture.tokenForms)
		})
	}
}

func TestResumeOID4VCIDraft13AuthorizationRequiresAuthorizationDetailsItAskedFor(t *testing.T) {
	fixture := newDraft13Fixture(t)
	req := fixture.authorizationCodeRequest(t)
	req.AuthorizationRequestType = OID4VCIAuthorizationRequestTypeAuthorizationDetails
	authorization, err := fixture.wallet.BeginOID4VCIDraft13Authorization(context.Background(), req)
	require.NoError(t, err)
	require.True(t, authorization.AuthorizationDetailsRequested)

	redirect := req.RedirectURI + "?code=code-1&state=" + url.QueryEscape(authorization.State)
	_, err = fixture.wallet.ResumeOID4VCIDraft13Authorization(context.Background(), req, authorization, redirect)
	require.ErrorIs(t, err, ErrAuthorizationDetailsMissing)
	require.Empty(t, fixture.credentialRequests)
}

func TestBeginOID4VCIDraft13AuthorizationRequiresTheGrant(t *testing.T) {
	fixture := newDraft13Fixture(t)
	_, err := fixture.wallet.BeginOID4VCIDraft13Authorization(context.Background(), fixture.preAuthorizedRequest(t))
	require.ErrorIs(t, err, ErrDraft13AuthorizationCodeGrantMissing)
}

// TestObserveLabelsEveryDraft13IssuanceRequest drives a Draft 13 issuance, its
// deferred poll and its notification through an observed client: each request
// carries the role it was sent for.
func TestObserveLabelsEveryDraft13IssuanceRequest(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.credentialResponse = func(int, map[string]any) (int, any) {
		return http.StatusAccepted, map[string]any{"transaction_id": "transaction-1"}
	}
	recorder := observe.NewRecorder(32)
	plugin := receiverTypes.Receiver(&receiverOid4vci.Oid4vciReceiver{HTTPClient: observedClient(fixture.server.Client(), recorder), AllowHTTP: true})
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
	require.NoError(t, err)
	wallet, err := NewWalletWithConfig(Config{Receiver: receiving, CredStore: newProfileCredStore(t)})
	require.NoError(t, err)

	req := fixture.preAuthorizedRequest(t)
	req.DeferredPollAttempts = 1
	result, err := wallet.ReceiveOID4VCIDraft13Credential(context.Background(), req)
	require.NoError(t, err)
	require.NoError(t, wallet.NotifyOID4VCIDraft13Credential(context.Background(), OID4VCIDraft13NotificationRequest{
		Type:                 receiverTypes.Oid4vci,
		NotificationEndpoint: fixture.server.URL + "/notification",
		AccessToken:          result.AccessToken,
		NotificationID:       result.NotificationID,
		Event:                "credential_accepted",
	}))

	labels := make([]observe.Endpoint, 0)
	for _, exchange := range recorder.Exchanges() {
		labels = append(labels, exchange.Endpoint)
	}
	require.Equal(t, []observe.Endpoint{
		observe.EndpointIssuerMetadata,
		observe.EndpointAuthorizationServerMetadata,
		observe.EndpointToken,
		observe.EndpointCredential,
		observe.EndpointDeferredCredential,
		observe.EndpointNotification,
	}, labels)
}
