package wallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func encryptFinalCredentialResponse(t *testing.T, key jose.JSONWebKey, payload any) string {
	t.Helper()
	plaintext, err := json.Marshal(payload)
	require.NoError(t, err)
	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.ECDH_ES, Key: key.Public().Key, KeyID: key.KeyID},
		(&jose.EncrypterOptions{}).WithContentType("json"),
	)
	require.NoError(t, err)
	encrypted, err := encrypter.Encrypt(plaintext)
	require.NoError(t, err)
	serialized, err := encrypted.CompactSerialize()
	require.NoError(t, err)
	return serialized
}

func writeEncryptedFinalCredentialResponse(t *testing.T, w http.ResponseWriter, key jose.JSONWebKey, payload any) {
	t.Helper()
	serialized := encryptFinalCredentialResponse(t, key, payload)
	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(serialized))
}

type finalIssuanceFixture struct {
	t      *testing.T
	server *httptest.Server
	wallet *Wallet

	holderKey     jose.JSONWebKey
	additionalKey jose.JSONWebKey
	clientKey     jose.JSONWebKey
	attesterKey   jose.JSONWebKey
	encryptionKey jose.JSONWebKey

	issuedCredential string

	credentialIssuerOverride string
	authorizationServers     []string
	asIssuerOverride         string
	includeNonceEndpoint     bool
	includeDeferredEndpoint  bool
	includeNotification      bool
	responseEncryption       bool
	encryptionRequired       bool
	omitScope                bool
	keyAttestationsRequired  bool
	batchSize                int
	parExpiresIn             int
	authMethodsSupported     []receiverTypes.TokenEndpointAuthMethod
	authSigningAlgsSupported []jose.SignatureAlgorithm
	authorizeLocation        func(f *finalIssuanceFixture, state string) string
	tokenResponse            map[string]any
	tokenHandler             http.HandlerFunc
	credentialHandler        http.HandlerFunc
	deferredHandler          http.HandlerFunc

	parCalls           int
	authorizeCalls     int
	tokenCalls         int
	nonceCalls         int
	credentialCalls    int
	deferredCalls      int
	notificationEvents []string
	pushedState        string
	lastCredentialBody map[string]any
	parForm            url.Values
	parHeaders         http.Header
	tokenForms         []url.Values
}

func newFinalIssuanceFixture(t *testing.T, opts ...func(*finalIssuanceFixture)) *finalIssuanceFixture {
	t.Helper()
	httpAllowed := env.IsHTTPAllowed()
	t.Cleanup(func() { env.SetHTTPAllowed(httpAllowed) })
	env.SetHTTPAllowed(true)

	f := &finalIssuanceFixture{
		t:                    t,
		holderKey:            newPrivateJWKForFinalVCITest(t, "holder-key-1"),
		additionalKey:        newPrivateJWKForFinalVCITest(t, "holder-key-2"),
		clientKey:            newPrivateJWKForFinalVCITest(t, "client-key-1"),
		attesterKey:          newPrivateJWKForFinalVCITest(t, "attester-key-1"),
		includeNonceEndpoint: true,
		parExpiresIn:         60,
	}
	f.encryptionKey = newPrivateJWKForFinalVCITest(t, "credential-response-enc-key-1")
	f.encryptionKey.Algorithm = "ECDH-ES"
	f.encryptionKey.Use = "enc"

	for _, opt := range opts {
		opt(f)
	}
	f.issuedCredential = buildTestSDJWTVC(t, f.holderKey, map[string]string{"given_name": "Taro"})
	f.server = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	f.wallet = createTestControllerWithDefaults(t)
	return f
}

func (f *finalIssuanceFixture) credentialIssuer(base string) string {
	if f.credentialIssuerOverride != "" {
		return f.credentialIssuerOverride
	}
	return base
}

func (f *finalIssuanceFixture) resolveAuthorizationServers(base string) []string {
	if f.authorizationServers != nil {
		return f.authorizationServers
	}
	return []string{base}
}

func (f *finalIssuanceFixture) authorizationServerIssuer(base string) string {
	if f.asIssuerOverride != "" {
		return f.asIssuerOverride
	}
	return base
}

func (f *finalIssuanceFixture) tokenResponseValue() map[string]any {
	if f.tokenResponse != nil {
		return f.tokenResponse
	}
	return map[string]any{"access_token": "access-1", "token_type": "DPoP", "expires_in": 3600}
}

func (f *finalIssuanceFixture) authorizeRedirect(base string) string {
	if f.authorizeLocation != nil {
		return f.authorizeLocation(f, f.pushedState)
	}
	return "openid-credential-offer://callback?code=code-1&state=" + url.QueryEscape(f.pushedState)
}

func (f *finalIssuanceFixture) writeDefaultCredentialResponse(w http.ResponseWriter, payload any) {
	if f.responseEncryption {
		writeEncryptedFinalCredentialResponse(f.t, w, f.encryptionKey, payload)
		return
	}
	mockserver.JSONResponse(w, http.StatusOK, payload)
}

func (f *finalIssuanceFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	base := f.server.URL
	switch r.URL.Path {
	case "/.well-known/openid-credential-issuer":
		credentialConfiguration := map[string]any{"format": "dc+sd-jwt"}
		if !f.omitScope {
			credentialConfiguration["scope"] = "pid-scope"
		}
		if f.keyAttestationsRequired {
			credentialConfiguration["proof_types_supported"] = map[string]any{
				"jwt": map[string]any{
					"proof_signing_alg_values_supported": []string{"ES256"},
					"key_attestations_required":          map[string]any{"key_storage": []string{"iso_18045_high"}},
				},
			}
		}
		metadata := map[string]any{
			"credential_issuer":     f.credentialIssuer(base),
			"credential_endpoint":   base + "/credential",
			"authorization_servers": f.resolveAuthorizationServers(base),
			"credential_configurations_supported": map[string]any{
				"pid": credentialConfiguration,
			},
		}
		if f.includeNonceEndpoint {
			metadata["nonce_endpoint"] = base + "/nonce"
		}
		if f.includeDeferredEndpoint {
			metadata["deferred_credential_endpoint"] = base + "/deferred"
		}
		if f.includeNotification {
			metadata["notification_endpoint"] = base + "/notification"
		}
		if f.batchSize > 0 {
			metadata["batch_credential_issuance"] = map[string]any{"batch_size": f.batchSize}
		}
		if f.responseEncryption {
			metadata["credential_response_encryption"] = map[string]any{
				"enc_values_supported": []string{"A128GCM"},
				"encryption_required":  f.encryptionRequired,
			}
		}
		mockserver.JSONResponse(w, http.StatusOK, metadata)
	case "/.well-known/oauth-authorization-server":
		metadata := map[string]any{
			"issuer":                                f.authorizationServerIssuer(base),
			"authorization_endpoint":                base + "/authorize",
			"pushed_authorization_request_endpoint": base + "/par",
			"token_endpoint":                        base + "/token",
			"pre-authorized_grant_anonymous_access_supported": true,
			"response_types_supported":                        []string{"code"},
		}
		if f.authMethodsSupported != nil {
			metadata["token_endpoint_auth_methods_supported"] = f.authMethodsSupported
		}
		if f.authSigningAlgsSupported != nil {
			metadata["token_endpoint_auth_signing_alg_values_supported"] = f.authSigningAlgsSupported
		}
		mockserver.JSONResponse(w, http.StatusOK, metadata)
	case "/par":
		f.parCalls++
		_ = r.ParseForm()
		f.parForm = r.Form
		f.parHeaders = r.Header.Clone()
		f.pushedState = r.Form.Get("state")
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{"request_uri": "urn:request:1", "expires_in": f.parExpiresIn})
	case "/authorize":
		f.authorizeCalls++
		w.Header().Set("Location", f.authorizeRedirect(base))
		w.WriteHeader(http.StatusFound)
	case "/token":
		f.tokenCalls++
		_ = r.ParseForm()
		f.tokenForms = append(f.tokenForms, r.Form)
		if f.tokenHandler != nil {
			f.tokenHandler(w, r)
			return
		}
		mockserver.JSONResponse(w, http.StatusOK, f.tokenResponseValue())
	case "/nonce":
		f.nonceCalls++
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "credential-nonce-1"})
	case "/credential":
		f.credentialCalls++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.lastCredentialBody = body
		if f.credentialHandler != nil {
			f.credentialHandler(w, r)
			return
		}
		payload := map[string]any{"credential": f.issuedCredential}
		if f.includeNotification {
			payload["notification_id"] = "notification-1"
		}
		f.writeDefaultCredentialResponse(w, payload)
	case "/deferred":
		f.deferredCalls++
		if f.deferredHandler != nil {
			f.deferredHandler(w, r)
			return
		}
		payload := map[string]any{"credential": f.issuedCredential}
		if f.includeNotification {
			payload["notification_id"] = "notification-1"
		}
		f.writeDefaultCredentialResponse(w, payload)
	case "/notification":
		var body receiverTypes.NotificationRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.notificationEvents = append(f.notificationEvents, body.Event)
		w.WriteHeader(http.StatusNoContent)
	case "/offer":
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{
			"credential_issuer":            base,
			"credential_configuration_ids": []string{"pid"},
			"grants": map[string]any{
				"authorization_code": map[string]any{"issuer_state": "issuer-state-1"},
			},
		})
	case "/bigoffer":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"credential_issuer":"` + base + `","padding":"` + strings.Repeat("a", 64<<10) + `"}`))
	default:
		http.NotFound(w, r)
	}
}

func (f *finalIssuanceFixture) request() OID4VCIFinalReceiveRequest {
	issuerURL, err := url.Parse(f.server.URL)
	require.NoError(f.t, err)
	return OID4VCIFinalReceiveRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{"pid"},
			Grants: map[string]*CredentialOfferGrant{
				"authorization_code": {IssuerState: "issuer-state-1"},
			},
		},
		Type:        receiverTypes.Oid4vci,
		ClientID:    "client-1",
		RedirectURI: "openid-credential-offer://callback",
		HolderKey:   f.holderKey,
		ClientKey:   f.clientKey,
	}
}

func (f *finalIssuanceFixture) proofJWTs(t *testing.T) []string {
	t.Helper()
	proofs, ok := f.lastCredentialBody["proofs"].(map[string]any)
	require.True(t, ok, "request did not include proofs: %#v", f.lastCredentialBody)
	jwtRaw, ok := proofs["jwt"].([]any)
	require.True(t, ok)
	jwts := make([]string, 0, len(jwtRaw))
	for _, entry := range jwtRaw {
		value, ok := entry.(string)
		require.True(t, ok)
		jwts = append(jwts, value)
	}
	return jwts
}

func finalProofClaims(t *testing.T, proof string) map[string]any {
	t.Helper()
	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

func finalProofHeader(t *testing.T, proof string) map[string]any {
	t.Helper()
	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3)
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(header, &claims))
	return claims
}

// fixedKeyAttestationProvider returns a prebuilt key attestation regardless of
// the request, so tests can model a misbehaving remote provider.
type fixedKeyAttestationProvider struct {
	attestation *KeyAttestation
}

func (p fixedKeyAttestationProvider) KeyAttestation(context.Context, KeyAttestationRequest) (*KeyAttestation, error) {
	return p.attestation, nil
}

func TestResolveCredentialOffer_ByReference(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)

	offerURI := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(fixture.server.URL+"/offer")
	offer, err := fixture.wallet.ResolveCredentialOffer(offerURI)
	require.NoError(t, err)
	require.Equal(t, fixture.server.URL, offer.CredentialIssuer.String())
	require.Equal(t, []string{"pid"}, offer.CredentialConfigurationIDs)
}

func TestResolveCredentialOffer_RejectsBothParameters(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	offerURI := "openid-credential-offer://?credential_offer=" +
		url.QueryEscape(`{"credential_issuer":"`+fixture.server.URL+`","credential_configuration_ids":["pid"]}`) +
		"&credential_offer_uri=" + url.QueryEscape(fixture.server.URL+"/offer")
	_, err := fixture.wallet.ResolveCredentialOffer(offerURI)
	require.ErrorContains(t, err, "both")
}

func TestResolveCredentialOffer_ByReferenceEnforcesSizeLimit(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	offerURI := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(fixture.server.URL+"/bigoffer")
	_, err := fixture.wallet.ResolveCredentialOffer(offerURI)
	require.ErrorContains(t, err, "exceeds")
}

func TestReceiveOID4VCIFinalCredential_IssuerIdentifierMismatch(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.credentialIssuerOverride = "https://other.example"
	})
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.ErrorContains(t, err, "does not match the credential offer credential_issuer")
	require.Equal(t, 0, fixture.parCalls)
	require.Equal(t, 0, fixture.credentialCalls)
}

func TestReceiveOID4VCIFinalCredential_AuthorizationServerHintNotListed(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.request()
	req.CredentialOffer.Grants["authorization_code"].AuthorizationServer = "https://evil.example"
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorContains(t, err, "not listed")
	require.Equal(t, 0, fixture.parCalls)
}

func TestReceiveOID4VCIFinalCredential_AuthorizationServerMetadataIssuerMismatch(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.asIssuerOverride = "https://other.example"
	})
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.ErrorContains(t, err, "does not match the selected authorization server")
	require.Equal(t, 0, fixture.parCalls)
}

func TestReceiveOID4VCIFinalCredential_RedirectOriginMismatch(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.authorizeLocation = func(f *finalIssuanceFixture, state string) string {
			return "https://attacker.example/callback?code=code-1&state=" + url.QueryEscape(state)
		}
	})
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.ErrorContains(t, err, "registered redirect_uri")
	require.Equal(t, 1, fixture.authorizeCalls)
}

func TestReceiveOID4VCIFinalCredential_ErrorRedirectSurfaced(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.authorizeLocation = func(f *finalIssuanceFixture, state string) string {
			return "openid-credential-offer://callback?error=access_denied&error_description=denied&state=" + url.QueryEscape(state)
		}
	})
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.Error(t, err)
	var responseErr *AuthorizationResponseError
	require.True(t, errors.As(err, &responseErr))
	require.Equal(t, "access_denied", responseErr.Code)
	require.Equal(t, "denied", responseErr.Description)
}

func TestRequestOID4VCIAuthorizationCode_ExpiredRequestURI(t *testing.T) {
	endpoint, err := common.ParseURIField("https://as.example/authorize")
	require.NoError(t, err)
	_, err = requestOID4VCIAuthorizationCode(nil, endpoint, "client-1", "urn:request:1", "state-1", "https://wallet.example/callback", time.Now().Add(-time.Second), authorizationResponseIssuerPolicy{})
	require.ErrorContains(t, err, "expired")
}

func TestReceiveOID4VCIFinalCredential_NoNonceEndpointProofOmitsNonce(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeNonceEndpoint = false
	})
	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	require.Equal(t, 0, fixture.nonceCalls)
	claims := finalProofClaims(t, fixture.proofJWTs(t)[0])
	_, hasNonce := claims["nonce"]
	require.False(t, hasNonce)
}

func TestReceiveOID4VCIFinalCredential_UsesCredentialIdentifier(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.tokenResponse = map[string]any{
			"access_token": "access-1",
			"token_type":   "DPoP",
			"authorization_details": []map[string]any{
				{"type": receiverTypes.AuthorizationDetailTypeOpenIDCredential, "credential_identifiers": []string{"id-1"}},
			},
		}
	})
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Equal(t, "id-1", fixture.lastCredentialBody["credential_identifier"])
	_, hasConfigurationID := fixture.lastCredentialBody["credential_configuration_id"]
	require.False(t, hasConfigurationID)
}

func decodeAuthorizationDetails(t *testing.T, raw string) []map[string]any {
	t.Helper()
	require.NotEmpty(t, raw)
	var details []map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &details))
	return details
}

// OpenID4VCI 1.0 §5.1.2 / §12.2.4: the default requests the scope the
// Credential Configuration advertises.
func TestReceiveOID4VCIFinalCredential_DefaultUsesScopeWhenAdvertised(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Equal(t, "pid-scope", fixture.parForm.Get("scope"))
	require.Empty(t, fixture.parForm.Get("authorization_details"))
}

// OpenID4VCI 1.0 §12.2.4: "If scope is absent, the only way to request the
// Credential is using authorization_details".
func TestReceiveOID4VCIFinalCredential_DefaultUsesAuthorizationDetailsWithoutScope(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.omitScope = true
	})
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Empty(t, fixture.parForm.Get("scope"))
	details := decodeAuthorizationDetails(t, fixture.parForm.Get("authorization_details"))
	require.Len(t, details, 1)
	require.Equal(t, receiverTypes.AuthorizationDetailTypeOpenIDCredential, details[0]["type"])
	require.Equal(t, "pid", details[0]["credential_configuration_id"])
}

// OpenID4VCI 1.0 §5.1.1: explicit authorization_details sends an
// openid_credential entry with credential_configuration_id and no scope.
func TestReceiveOID4VCIFinalCredential_ExplicitAuthorizationDetails(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.request()
	req.AuthorizationRequestType = OID4VCIAuthorizationRequestTypeAuthorizationDetails
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)
	require.Empty(t, fixture.parForm.Get("scope"))
	details := decodeAuthorizationDetails(t, fixture.parForm.Get("authorization_details"))
	require.Len(t, details, 1)
	require.Equal(t, receiverTypes.AuthorizationDetailTypeOpenIDCredential, details[0]["type"])
	require.Equal(t, "pid", details[0]["credential_configuration_id"])
}

// OpenID4VCI 1.0 §5.1.2: explicit scope requires an advertised scope; the
// failure happens before PAR.
func TestReceiveOID4VCIFinalCredential_ExplicitScopeWithoutAdvertisedScopeFailsBeforePAR(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.omitScope = true
	})
	req := fixture.request()
	req.AuthorizationRequestType = OID4VCIAuthorizationRequestTypeScope
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorContains(t, err, "scope")
	require.Equal(t, 0, fixture.parCalls)
}

// OpenID4VCI 1.0 §6.2: the token response entry names the Credential
// Configuration; the wallet uses the first credential_identifier of the entry
// that matches the requested configuration.
func TestReceiveOID4VCIFinalCredential_RARPathMapsCredentialIdentifierByConfiguration(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.tokenResponse = map[string]any{
			"access_token": "access-1",
			"token_type":   "DPoP",
			"authorization_details": []map[string]any{
				{
					"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
					"credential_configuration_id": "pid",
					"credential_identifiers":      []string{"id-1"},
				},
			},
		}
	})
	req := fixture.request()
	req.AuthorizationRequestType = OID4VCIAuthorizationRequestTypeAuthorizationDetails
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)
	require.Equal(t, "id-1", fixture.lastCredentialBody["credential_identifier"])
	_, hasConfigurationID := fixture.lastCredentialBody["credential_configuration_id"]
	require.False(t, hasConfigurationID)
}

func TestReceiveOID4VCIFinalCredential_InvalidNonceRetriedOnce(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			if f.credentialCalls == 1 {
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_nonce"})
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential": f.issuedCredential})
		}
	})
	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	require.Equal(t, 2, fixture.credentialCalls)
	require.Equal(t, 2, fixture.nonceCalls)
}

func TestReceiveOID4VCIFinalCredential_EncryptionRequiredWithoutKey(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.responseEncryption = true
		f.encryptionRequired = true
	})
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.ErrorContains(t, err, "encryption")
	require.Equal(t, 0, fixture.credentialCalls)
}

func TestReceiveOID4VCIFinalCredential_RequestedEncryptionPlaintextResponseFailsClosed(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.responseEncryption = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential": f.issuedCredential})
		}
	})
	req := fixture.request()
	req.CredentialResponseEncryptionKey = &fixture.encryptionKey
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorContains(t, err, "encryption was requested")
}

func TestReceiveOID4VCIFinalCredential_BatchWithTwoKeys(t *testing.T) {
	secondCredential := ""
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.batchSize = 3
		secondCredential = buildTestSDJWTVC(t, f.additionalKey, map[string]string{"given_name": "Hanako"})
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials": []string{f.issuedCredential, secondCredential},
			})
		}
	})
	req := fixture.request()
	req.AdditionalHolderKeys = []jose.JSONWebKey{fixture.additionalKey}

	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)
	require.Len(t, fixture.proofJWTs(t), 2)
	require.Len(t, result.SavedCredentials, 2)
	require.Equal(t, []byte(fixture.issuedCredential), result.SavedCredentials[0].Entry.Raw)
	require.Equal(t, []byte(secondCredential), result.SavedCredentials[1].Entry.Raw)
}

func TestReceiveOID4VCIFinalCredential_BatchExceedsBatchSize(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.batchSize = 1
	})
	req := fixture.request()
	req.AdditionalHolderKeys = []jose.JSONWebKey{fixture.additionalKey}
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorContains(t, err, "batch_size")
	require.Equal(t, 0, fixture.credentialCalls)
}

func TestReceiveOID4VCIFinalCredential_KeyAttestationRequiredWithProvider(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
	})
	keyAttesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	fixture.wallet.keyAttestation = &StaticKeyAttester{Key: keyAttesterKey, Issuer: "https://key-attester.example"}

	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)

	proofs := fixture.proofJWTs(t)
	require.Len(t, proofs, 1)
	header := finalProofHeader(t, proofs[0])
	keyAttestationJWT, ok := header["key_attestation"].(string)
	require.True(t, ok, "proof header is missing key_attestation: %#v", header)

	attestationHeader, claims, err := parseAttestationJWT(keyAttestationJWT)
	require.NoError(t, err)
	require.Equal(t, keyAttestationJWTType, attestationHeader.Type)
	require.Equal(t, "credential-nonce-1", claims.Nonce)
	require.Len(t, claims.AttestedKeys, 1)
	require.NoError(t, requireJWKThumbprint(fixture.holderKey, claims.AttestedKeys[0]))
}

func TestReceiveOID4VCIFinalCredential_KeyAttestationRequiredWithoutProvider(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
	})
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.ErrorContains(t, err, "KeyAttestation")
	require.Equal(t, 0, fixture.parCalls)
}

func TestReceiveOID4VCIFinalCredential_KeyAttestationProviderMissingHolderKey(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
	})
	otherKey := newPrivateJWKForFinalVCITest(t, "other-holder-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	attestation, err := (&StaticKeyAttester{Key: attesterKey, Issuer: "https://key-attester.example"}).KeyAttestation(
		context.Background(),
		KeyAttestationRequest{Keys: []jose.JSONWebKey{otherKey}, Nonce: "credential-nonce-1"},
	)
	require.NoError(t, err)
	fixture.wallet.keyAttestation = fixedKeyAttestationProvider{attestation: attestation}

	_, err = fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.ErrorContains(t, err, "does not attest the holder key")
}

func TestReceiveOID4VCIFinalCredential_IncludeKeyAttestationWhenNotRequired(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	keyAttesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	fixture.wallet.keyAttestation = &StaticKeyAttester{Key: keyAttesterKey, Issuer: "https://key-attester.example"}

	req := fixture.request()
	req.IncludeKeyAttestation = true
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)

	header := finalProofHeader(t, fixture.proofJWTs(t)[0])
	require.Contains(t, header, "key_attestation")
}

func TestReceiveOID4VCIFinalCredential_DeferredPollIntervalThenSuccess(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"transaction_id": "tx-1"})
		}
		f.deferredHandler = func(w http.ResponseWriter, r *http.Request) {
			if f.deferredCalls == 1 {
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]any{"error": "issuance_pending", "interval": 1})
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential": f.issuedCredential})
		}
	})
	req := fixture.request()
	req.DeferredPollAttempts = 2

	start := time.Now()
	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)
	require.GreaterOrEqual(t, time.Since(start), time.Second)
	require.Equal(t, 2, fixture.deferredCalls)
	require.Len(t, result.SavedCredentials, 1)
	require.Equal(t, "tx-1", result.TransactionID)
}

func TestReceiveOID4VCIFinalCredential_DeferredPendingThenResume(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"transaction_id": "tx-1"})
		}
	})
	req := fixture.request()
	req.DeferredPollAttempts = 0

	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.Error(t, err)
	require.True(t, errors.Is(err, receiverTypes.ErrIssuancePending))
	require.NotNil(t, result)
	require.Equal(t, "tx-1", result.TransactionID)
	require.NotNil(t, result.AccessToken)
	require.Empty(t, result.SavedCredentials)
	require.Equal(t, 0, fixture.deferredCalls)

	resumed, err := fixture.wallet.ResumeOID4VCIFinalDeferredCredential(OID4VCIFinalDeferredRequest{
		Type:                      receiverTypes.Oid4vci,
		IssuerMetadata:            result.IssuerMetadata,
		CredentialConfigurationID: result.CredentialConfigurationID,
		AccessToken:               result.AccessToken,
		TransactionID:             result.TransactionID,
		HolderKey:                 fixture.holderKey,
		ClientKey:                 fixture.clientKey,
		DeferredPollAttempts:      1,
	})
	require.NoError(t, err)
	require.Len(t, resumed.SavedCredentials, 1)
	require.Equal(t, "tx-1", resumed.TransactionID)
}

func TestReceiveOID4VCIFinalCredential_NotificationFailureOnInvalidCredential(t *testing.T) {
	otherKey := newPrivateJWKForFinalVCITest(t, "other-holder-key")
	badCredential := buildTestSDJWTVC(t, otherKey, map[string]string{"given_name": "Taro"})
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeNotification = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credential":      badCredential,
				"notification_id": "notification-1",
			})
		}
	})
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.Error(t, err)
	require.Equal(t, []string{"credential_failure"}, fixture.notificationEvents)
}

func TestReceiveOID4VCIFinalCredential_NotificationAcceptedAfterStoreAndDeleted(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeNotification = true
	})
	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Equal(t, "notification-1", result.NotificationID)
	require.Equal(t, []string{"credential_accepted"}, fixture.notificationEvents)

	err = fixture.wallet.NotifyOID4VCIFinalCredentialDeleted(OID4VCIFinalNotificationRequest{
		Type:           receiverTypes.Oid4vci,
		IssuerMetadata: result.IssuerMetadata,
		AccessToken:    result.AccessToken,
		ClientKey:      fixture.clientKey,
		NotificationID: result.NotificationID,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"credential_accepted", "credential_deleted"}, fixture.notificationEvents)
}

// RFC 9207 §2.4: a present iss must identify the authorization server; when
// the server advertises support the parameter is required.
func TestRequestOID4VCIAuthorizationCodeValidatesIssuer(t *testing.T) {
	newServer := func(location string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", location)
			w.WriteHeader(http.StatusFound)
		}))
	}
	call := func(server *httptest.Server, policy authorizationResponseIssuerPolicy) (string, error) {
		endpoint, err := common.ParseURIField(server.URL + "/authorize")
		require.NoError(t, err)
		return requestOID4VCIAuthorizationCode(server.Client(), endpoint, "client-1", "urn:request:1", "state-1", "https://wallet.example/callback", time.Time{}, policy)
	}
	matching := newServer("https://wallet.example/callback?code=c1&state=state-1&iss=https%3A%2F%2Fas.example")
	defer matching.Close()
	code, err := call(matching, authorizationResponseIssuerPolicy{expected: "https://as.example", required: true})
	require.NoError(t, err)
	require.Equal(t, "c1", code)

	mismatch := newServer("https://wallet.example/callback?code=c1&state=state-1&iss=https%3A%2F%2Fattacker.example")
	defer mismatch.Close()
	_, err = call(mismatch, authorizationResponseIssuerPolicy{expected: "https://as.example"})
	require.ErrorContains(t, err, "iss does not identify")

	missing := newServer("https://wallet.example/callback?code=c1&state=state-1")
	defer missing.Close()
	_, err = call(missing, authorizationResponseIssuerPolicy{expected: "https://as.example", required: true})
	require.ErrorContains(t, err, "missing the iss parameter")
	code, err = call(missing, authorizationResponseIssuerPolicy{expected: "https://as.example"})
	require.NoError(t, err)
	require.Equal(t, "c1", code)
}

// OpenID4VCI 1.0 §8.3: each "credentials" entry is an object whose
// "credential" member carries the issued credential.
func TestRawCredentialBytesUnwrapsFinalCredentialsEnvelope(t *testing.T) {
	raw, err := rawCredentialBytes(map[string]any{"credential": "eyJ.abc.def~"})
	require.NoError(t, err)
	require.Equal(t, "eyJ.abc.def~", string(raw))

	raw, err = rawCredentialBytes(map[string]any{"credential": map[string]any{"kind": "object"}})
	require.NoError(t, err)
	require.JSONEq(t, `{"kind":"object"}`, string(raw))

	raw, err = rawCredentialBytes(map[string]any{"credential": "x", "other": 1})
	require.NoError(t, err)
	require.JSONEq(t, `{"credential":"x","other":1}`, string(raw))
}

// OpenID4VCI 1.0 §8.3 does not fix the order of the credentials array; the
// official batch module returns them reversed. Each credential is matched to
// the holder key its cnf names.
func TestReceiveOID4VCIFinalCredential_BatchCredentialsMayArriveOutOfOrder(t *testing.T) {
	var secondCredential string
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.batchSize = 3
		secondCredential = buildTestSDJWTVC(t, f.additionalKey, map[string]string{"given_name": "Hanako"})
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials": []map[string]any{{"credential": secondCredential}, {"credential": f.issuedCredential}},
			})
		}
	})
	req := fixture.request()
	req.AdditionalHolderKeys = []jose.JSONWebKey{fixture.additionalKey}

	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 2)
	require.Equal(t, []byte(secondCredential), result.SavedCredentials[0].Entry.Raw)
	require.Equal(t, []byte(fixture.issuedCredential), result.SavedCredentials[1].Entry.Raw)
	require.True(t, result.SavedCredentials[0].Verification.HolderBound)
	require.True(t, result.SavedCredentials[1].Verification.HolderBound)

	// A credential bound to a key that was not part of the request is rejected
	// and nothing is stored.
	stranger := newPrivateJWKForFinalVCITest(t, "stranger")
	strangerCredential := buildTestSDJWTVC(t, stranger, map[string]string{"given_name": "X"})
	fixture2 := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.batchSize = 3
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials": []map[string]any{{"credential": f.issuedCredential}, {"credential": strangerCredential}},
			})
		}
	})
	req2 := fixture2.request()
	req2.AdditionalHolderKeys = []jose.JSONWebKey{fixture2.additionalKey}
	_, err = fixture2.wallet.ReceiveOID4VCIFinalCredential(req2)
	require.ErrorContains(t, err, "not part of the request")
}

// verifyFinalClientAssertion parses a private_key_jwt client_assertion and
// checks its signature, issuer, subject and audience.
func verifyFinalClientAssertion(t *testing.T, assertion string, publicKey jose.JSONWebKey, expectedAudience, expectedClientID string) map[string]any {
	t.Helper()
	signature, err := jose.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	payload, err := signature.Verify(publicKey)
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Equal(t, expectedClientID, claims["iss"])
	require.Equal(t, expectedClientID, claims["sub"])
	require.Equal(t, expectedAudience, claims["aud"])
	exp, ok := claims["exp"].(float64)
	require.True(t, ok)
	require.Greater(t, int64(exp), time.Now().Unix())
	return claims
}

func TestReceiveOID4VCIFinalCredential_PrivateKeyJwtClientAssertion(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.authMethodsSupported = []receiverTypes.TokenEndpointAuthMethod{receiverTypes.PrivateKeyJwt}
		f.authSigningAlgsSupported = []jose.SignatureAlgorithm{jose.ES256}
	})
	keyEntry, publicJWK := newClientAuthKeyEntry(t, "client-key-1")
	fixture.wallet.clientAuth = ClientAuthConfig{
		Method:   receiverTypes.PrivateKeyJwt,
		ClientID: "client-1",
		Key:      keyEntry,
	}

	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)

	parForm := fixture.parForm
	require.Equal(t, receiverTypes.ClientAssertionTypeJWTBearer, parForm.Get("client_assertion_type"))
	require.NotEmpty(t, parForm.Get("client_assertion"))
	parClaims := verifyFinalClientAssertion(t, parForm.Get("client_assertion"), publicJWK, fixture.server.URL, "client-1")

	require.Len(t, fixture.tokenForms, 1)
	tokenForm := fixture.tokenForms[0]
	require.Equal(t, receiverTypes.ClientAssertionTypeJWTBearer, tokenForm.Get("client_assertion_type"))
	require.NotEmpty(t, tokenForm.Get("client_assertion"))
	tokenClaims := verifyFinalClientAssertion(t, tokenForm.Get("client_assertion"), publicJWK, fixture.server.URL, "client-1")

	require.NotEqual(t, parClaims["jti"], tokenClaims["jti"])
}

func TestReceiveOID4VCIFinalCredential_PrivateKeyJwtNotAdvertisedFailsBeforePAR(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.authMethodsSupported = []receiverTypes.TokenEndpointAuthMethod{receiverTypes.ClientSecretBasic}
		f.authSigningAlgsSupported = []jose.SignatureAlgorithm{jose.ES256}
	})
	keyEntry, _ := newClientAuthKeyEntry(t, "client-key-1")
	fixture.wallet.clientAuth = ClientAuthConfig{
		Method:   receiverTypes.PrivateKeyJwt,
		ClientID: "client-1",
		Key:      keyEntry,
	}

	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.ErrorContains(t, err, "private_key_jwt")
	require.Equal(t, 0, fixture.parCalls)
}

func TestReceiveOID4VCIFinalCredential_PrivateKeyJwtTokenRetryRefreshesAssertion(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.authMethodsSupported = []receiverTypes.TokenEndpointAuthMethod{receiverTypes.PrivateKeyJwt}
		f.authSigningAlgsSupported = []jose.SignatureAlgorithm{jose.ES256}
		f.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
			if f.tokenCalls == 1 {
				w.Header().Set("DPoP-Nonce", "nonce-1")
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "use_dpop_nonce"})
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"access_token": "access-1", "token_type": "DPoP", "expires_in": 3600})
		}
	})
	keyEntry, publicJWK := newClientAuthKeyEntry(t, "client-key-1")
	fixture.wallet.clientAuth = ClientAuthConfig{
		Method:   receiverTypes.PrivateKeyJwt,
		ClientID: "client-1",
		Key:      keyEntry,
	}

	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Equal(t, 2, fixture.tokenCalls)
	require.Len(t, fixture.tokenForms, 2)

	first := fixture.tokenForms[0].Get("client_assertion")
	second := fixture.tokenForms[1].Get("client_assertion")
	require.NotEmpty(t, first)
	require.NotEmpty(t, second)
	firstClaims := verifyFinalClientAssertion(t, first, publicJWK, fixture.server.URL, "client-1")
	secondClaims := verifyFinalClientAssertion(t, second, publicJWK, fixture.server.URL, "client-1")
	require.NotEqual(t, first, second)
	require.NotEqual(t, firstClaims["jti"], secondClaims["jti"])
}

func TestReceiveOID4VCIFinalCredential_NoClientAuthSendsNoAssertion(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)

	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Empty(t, fixture.parForm.Get("client_assertion"))
	require.Empty(t, fixture.parForm.Get("client_assertion_type"))
	require.Len(t, fixture.tokenForms, 1)
	require.Empty(t, fixture.tokenForms[0].Get("client_assertion"))
	require.Empty(t, fixture.tokenForms[0].Get("client_assertion_type"))
}

// OpenID4VCI 1.0 §5.1.1: with authorization_servers advertised, each
// authorization detail carries locations = [credential_issuer].
func TestReceiveOID4VCIFinalCredential_RARCarriesLocationsWhenAuthorizationServersAdvertised(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.request()
	req.AuthorizationRequestType = OID4VCIAuthorizationRequestTypeAuthorizationDetails
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)
	form := fixture.parForm
	require.NotNil(t, form)
	var details []map[string]any
	require.NoError(t, json.Unmarshal([]byte(form.Get("authorization_details")), &details))
	require.Len(t, details, 1)
	// The fixture always advertises authorization_servers, so locations must
	// name the credential issuer identifier.
	require.Equal(t, []any{fixture.credentialIssuer(fixture.server.URL)}, details[0]["locations"])
}

// Attestation-based client authentication takes precedence over a configured
// private_key_jwt ClientAuth: no client_assertion is sent and the authorization
// server does not have to advertise private_key_jwt.
func TestReceiveOID4VCIFinalCredential_AttestationSupersedesPrivateKeyJwt(t *testing.T) {
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-1")
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.authMethodsSupported = []receiverTypes.TokenEndpointAuthMethod{receiverTypes.ClientSecretBasic}
	})
	keyEntry, _ := newClientAuthKeyEntry(t, "client-key-1")
	fixture.wallet.clientAuth = ClientAuthConfig{Method: receiverTypes.PrivateKeyJwt, ClientID: "client-1", Key: keyEntry}
	fixture.wallet.clientAttestation = &StaticClientAttester{Key: attesterKey, Issuer: "https://attester.example"}
	req := fixture.request()
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)
	require.Empty(t, fixture.parForm.Get("client_assertion"))
	require.NotEmpty(t, fixture.parHeaders.Get("OAuth-Client-Attestation"))
}
