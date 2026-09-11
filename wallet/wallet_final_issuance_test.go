package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/oid4vcisign"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
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
	// issuerKey signs every credential the fixture issues; the fixture wallet's
	// CredentialAcceptance policy resolves it, which the Final path requires.
	issuerKey *ecdsa.PrivateKey
	// requestEncryptionKey backs credential_request_encryption when
	// requestEncryption is set (OpenID4VCI Final §8.1).
	requestEncryptionKey jose.JSONWebKey

	issuedCredential string

	credentialIssuerOverride string
	authorizationServers     []string
	asIssuerOverride         string
	includeNonceEndpoint     bool
	includeDeferredEndpoint  bool
	includeNotification      bool
	responseEncryption       bool
	encryptionRequired       bool
	requestEncryption        bool
	omitPAREndpoint          bool
	issParameterSupported    bool
	// walletProfile selects the wallet and receiver plugin profile. HAIP also
	// forces a TLS server, because HAIP §4 requires TLS for the issuer and
	// authorization server endpoints.
	walletProfile            profile.Profile
	clientAuthKey            IKeyEntry
	omitScope                bool
	keyAttestationsRequired  bool
	batchSize                int
	parExpiresIn             int
	authMethodsSupported     []receiverTypes.TokenEndpointAuthMethod
	authSigningAlgsSupported []jose.SignatureAlgorithm
	authorizeLocation        func(f *finalIssuanceFixture, state string) string
	// oid4vciSigner is the Config.OID4VCISigner the fixture wallet is built
	// with; nil leaves the receiver plugin signing.
	oid4vciSigner receiverTypes.OID4VCIFinalSigner
	// wrapReceiverPlugin decorates the bundled receiver plugin before it is
	// registered, so a test can register a narrower plugin than the bundled one.
	wrapReceiverPlugin func(receiverTypes.Receiver) receiverTypes.Receiver
	tokenResponse      map[string]any
	tokenHandler       http.HandlerFunc
	credentialHandler  http.HandlerFunc
	deferredHandler    http.HandlerFunc

	issuerMetadataCalls int
	parCalls            int
	authorizeCalls      int
	tokenCalls          int
	nonceCalls          int
	credentialCalls     int
	deferredCalls       int
	notificationEvents  []string
	pushedState         string
	lastCredentialBody  map[string]any
	lastDeferredBody    map[string]any
	authorizeQuery      url.Values
	parForm             url.Values
	parHeaders          http.Header
	tokenHeaders        http.Header
	tokenForms          []url.Values
}

func newFinalIssuanceFixture(t *testing.T, opts ...func(*finalIssuanceFixture)) *finalIssuanceFixture {
	t.Helper()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	f := &finalIssuanceFixture{
		t:                    t,
		holderKey:            newPrivateJWKForFinalVCITest(t, "holder-key-1"),
		additionalKey:        newPrivateJWKForFinalVCITest(t, "holder-key-2"),
		clientKey:            newPrivateJWKForFinalVCITest(t, "client-key-1"),
		attesterKey:          newPrivateJWKForFinalVCITest(t, "attester-key-1"),
		issuerKey:            issuerKey,
		includeNonceEndpoint: true,
		parExpiresIn:         60,
	}
	f.encryptionKey = newPrivateJWKForFinalVCITest(t, "credential-response-enc-key-1")
	f.encryptionKey.Algorithm = "ECDH-ES"
	f.encryptionKey.Use = "enc"
	f.requestEncryptionKey = newPrivateJWKForFinalVCITest(t, "credential-request-enc-key-1")
	f.requestEncryptionKey.Algorithm = "ECDH-ES"
	f.requestEncryptionKey.Use = "enc"

	for _, opt := range opts {
		opt(f)
	}
	f.issuedCredential = f.issueCredential(f.holderKey, map[string]string{"given_name": "Taro"})
	if f.walletProfile.IsHAIP() {
		f.server = httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	} else {
		f.server = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	}
	t.Cleanup(f.server.Close)
	// A1: the OpenID4VCI Final issuance path stores nothing without a
	// Config.CredentialAcceptance, so the fixture wallet authenticates the
	// issuer key it signs with.
	acceptance := acceptIssuerKeyPolicy(f.issuerKey)
	// The fixture always registers its own receiver plugin so the plain-HTTP
	// escape is the receiver's explicit AllowHTTP flag, not a process-wide
	// environment setting. HAIP serves over TLS and pins the flag off.
	plugin := receiverTypes.Receiver(&oid4vci.Oid4vciReceiver{
		HTTPClient: f.server.Client(),
		AllowHTTP:  !f.walletProfile.IsHAIP(),
		Profile:    f.walletProfile,
	})
	if f.wrapReceiverPlugin != nil {
		plugin = f.wrapReceiverPlugin(plugin)
	}
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
	require.NoError(t, err)
	config := Config{
		Profile:              f.walletProfile,
		CredStore:            newProfileCredStore(t),
		Receiver:             receiving,
		CredentialAcceptance: acceptance,
		OID4VCISigner:        f.oid4vciSigner,
	}
	if f.clientAuthKey != nil {
		// HAIP §4.4.1: "Wallets MUST use ... an OAuth2 Client authentication
		// mechanism at OAuth2 Endpoints that support client authentication".
		config.ClientAuth = ClientAuthConfig{Method: receiverTypes.PrivateKeyJwt, ClientID: "client-1", Key: f.clientAuthKey}
	}
	f.wallet, err = NewWalletWithConfig(config)
	require.NoError(t, err)
	return f
}

// newHAIPIssuanceFixture is newFinalIssuanceFixture with the HAIP profile: a TLS
// issuer (HAIP §4 requires TLS), a HAIP-profiled receiver plugin,
// private_key_jwt client authentication (HAIP §4.4.1) and the RFC 9207 iss
// parameter HAIP requires in the authorization response.
func newHAIPIssuanceFixture(t *testing.T, opts ...func(*finalIssuanceFixture)) *finalIssuanceFixture {
	t.Helper()
	clientAuthKey, _ := newClientAuthKeyEntry(t, "client-auth-key-1")
	haip := append([]func(*finalIssuanceFixture){func(f *finalIssuanceFixture) {
		f.walletProfile = profile.HAIP
		f.clientAuthKey = clientAuthKey
		f.issParameterSupported = true
		f.authMethodsSupported = []receiverTypes.TokenEndpointAuthMethod{receiverTypes.PrivateKeyJwt}
		f.authSigningAlgsSupported = []jose.SignatureAlgorithm{jose.ES256}
	}}, opts...)
	return newFinalIssuanceFixture(t, haip...)
}

// issuerMetadata fetches the fixture issuer's §12.2.2 metadata the way the
// wallet does, so a test can hand it to a deferred resume request.
func (f *finalIssuanceFixture) issuerMetadata(t *testing.T) *receiverTypes.CredentialIssuerMetadata {
	t.Helper()
	endpoint, err := common.ParseURIField(f.server.URL)
	require.NoError(t, err)
	metadata, err := f.wallet.receiver.FetchIssuerMetadata(*endpoint, receiverTypes.Oid4vci)
	require.NoError(t, err)
	return metadata
}

// issueCredential signs an SD-JWT VC with the fixture's issuer key, so the
// fixture wallet's acceptance policy accepts it.
func (f *finalIssuanceFixture) issueCredential(holderKey jose.JSONWebKey, claims map[string]string) string {
	return buildTestSDJWTVCWithIssuerKey(f.t, f.issuerKey, holderKey, claims)
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
	location := "openid-credential-offer://callback?code=code-1&state=" + url.QueryEscape(f.pushedState)
	if f.issParameterSupported {
		// RFC 9207 §2: the authorization server that advertises the parameter
		// returns it in the authorization response.
		location += "&iss=" + url.QueryEscape(f.authorizationServerIssuer(base))
	}
	return location
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
		f.issuerMetadataCalls++
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
		if f.requestEncryption {
			metadata["credential_request_encryption"] = map[string]any{
				"jwks":                 map[string]any{"keys": []any{f.requestEncryptionKey.Public()}},
				"alg_values_supported": []string{"ECDH-ES"},
				"enc_values_supported": []string{"A128GCM"},
				"encryption_required":  true,
			}
		}
		mockserver.JSONResponse(w, http.StatusOK, metadata)
	case "/.well-known/oauth-authorization-server":
		metadata := map[string]any{
			"issuer":                 f.authorizationServerIssuer(base),
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"pre-authorized_grant_anonymous_access_supported": true,
			"response_types_supported":                        []string{"code"},
		}
		if !f.omitPAREndpoint {
			metadata["pushed_authorization_request_endpoint"] = base + "/par"
		}
		if f.issParameterSupported {
			metadata["authorization_response_iss_parameter_supported"] = true
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
		f.authorizeQuery = r.URL.Query()
		if f.pushedState == "" {
			f.pushedState = r.URL.Query().Get("state")
		}
		w.Header().Set("Location", f.authorizeRedirect(base))
		w.WriteHeader(http.StatusFound)
	case "/token":
		f.tokenCalls++
		_ = r.ParseForm()
		f.tokenForms = append(f.tokenForms, r.Form)
		f.tokenHeaders = r.Header.Clone()
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
		f.lastCredentialBody = decodeEncryptedCredentialRequest(f.t, r, f.requestEncryptionKey)
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
		f.lastDeferredBody = decodeEncryptedCredentialRequest(f.t, r, f.requestEncryptionKey)
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
		// The fixture issuer answers the authorization endpoint with the code
		// redirect and needs no browser (C2).
		AllowSelfDrivenAuthorization: true,
	}
}

// walletInitiatedRequest starts the flow from issuer metadata alone, with no
// Credential Offer (OpenID4VCI 1.0 §5).
func (f *finalIssuanceFixture) walletInitiatedRequest() OID4VCIFinalReceiveRequest {
	issuerURL, err := url.Parse(f.server.URL)
	require.NoError(f.t, err)
	return OID4VCIFinalReceiveRequest{
		CredentialIssuer:             issuerURL,
		CredentialConfigurationID:    "pid",
		Type:                         receiverTypes.Oid4vci,
		ClientID:                     "client-1",
		RedirectURI:                  "openid-credential-offer://callback",
		HolderKey:                    f.holderKey,
		ClientKey:                    f.clientKey,
		AllowSelfDrivenAuthorization: true,
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

// OpenID4VCI 1.0 §12.2.2 requires the credential issuer to be identified by an
// https URL. A Final wallet that has not enabled the plain-HTTP escape refuses
// a plain-http issuer at metadata discovery, before any authorization request
// leaves the wallet.
func TestReceiveOID4VCIFinalCredentialRefusesPlainHTTPIssuerWithoutAllowance(t *testing.T) {
	t.Setenv(env.HTTP_ALLOWED.String(), "")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{})
	}))
	defer server.Close()
	issuerURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	plugin := receiverTypes.Receiver(&oid4vci.Oid4vciReceiver{
		HTTPClient: server.Client(),
		AllowHTTP:  false,
	})
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
	require.NoError(t, err)
	wallet, err := NewWalletWithConfig(Config{
		CredStore:            newProfileCredStore(t),
		Receiver:             receiving,
		CredentialAcceptance: acceptIssuerKeyPolicy(issuerKey),
	})
	require.NoError(t, err)

	_, err = wallet.ReceiveOID4VCIFinalCredential(OID4VCIFinalReceiveRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{"pid"},
			Grants: map[string]*CredentialOfferGrant{
				"authorization_code": {IssuerState: "issuer-state-1"},
			},
		},
		Type:                         receiverTypes.Oid4vci,
		ClientID:                     "client-1",
		RedirectURI:                  "openid-credential-offer://callback",
		HolderKey:                    newPrivateJWKForFinalVCITest(t, "holder-key-1"),
		ClientKey:                    newPrivateJWKForFinalVCITest(t, "client-key-1"),
		AllowSelfDrivenAuthorization: true,
	})
	require.ErrorContains(t, err, "https required")
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

// §5.1.4: the pushed request_uri expires, and the wallet does not send an
// authorization request that carries an expired one.
func TestRequestOID4VCIAuthorizationCode_ExpiredRequestURI(t *testing.T) {
	_, err := followOID4VCIAuthorizationEndpoint(nil, &OID4VCIFinalAuthorization{
		AuthorizationURL: "https://as.example/authorize?client_id=client-1&request_uri=urn%3Arequest%3A1",
		State:            "state-1",
		RequestURI:       "urn:request:1",
		ExpiresAt:        time.Now().Add(-time.Second),
	})
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

// OpenID4VCI 1.0 §6.2: each authorization_details entry of the token response
// names its own credential_configuration_id and carries the
// credential_identifiers usable for that configuration, so the wallet picks the
// identifier out of the entry that matches what it asked for.
func TestCredentialIdentifierUsesMatchingConfigurationEntry(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.tokenResponse = map[string]any{
			"access_token": "access-1",
			"token_type":   "DPoP",
			"authorization_details": []map[string]any{
				{
					"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
					"credential_configuration_id": "other",
					"credential_identifiers":      []string{"id-other"},
				},
				{
					"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
					"credential_configuration_id": "pid",
					"credential_identifiers":      []string{"id-1"},
				},
			},
		}
	})
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Equal(t, "id-1", fixture.lastCredentialBody["credential_identifier"])
	_, hasConfigurationID := fixture.lastCredentialBody["credential_configuration_id"]
	require.False(t, hasConfigurationID)
}

// An identifier that belongs to another Credential Configuration is not a
// usable substitute: §6.2 scopes credential_identifiers to their own entry.
func TestCredentialIdentifierRejectsForeignConfigurationEntry(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.tokenResponse = map[string]any{
			"access_token": "access-1",
			"token_type":   "DPoP",
			"authorization_details": []map[string]any{
				{
					"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
					"credential_configuration_id": "other",
					"credential_identifiers":      []string{"id-other"},
				},
			},
		}
	})
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.ErrorContains(t, err, `authorization_details contains no entry for credential_configuration_id "pid"`)
	require.Equal(t, 0, fixture.credentialCalls)
}

// §8.1: without authorization_details the Credential Request names the
// Credential Configuration instead of an identifier.
func TestCredentialIdentifierNilWhenNoAuthorizationDetails(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Equal(t, "pid", fixture.lastCredentialBody["credential_configuration_id"])
	_, hasIdentifier := fixture.lastCredentialBody["credential_identifier"]
	require.False(t, hasIdentifier)
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
		secondCredential = f.issueCredential(f.additionalKey, map[string]string{"given_name": "Hanako"})
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
		authorizationURL := server.URL + "/authorize?client_id=client-1&request_uri=urn%3Arequest%3A1"
		location, err := followOID4VCIAuthorizationEndpoint(server.Client(), &OID4VCIFinalAuthorization{
			AuthorizationURL: authorizationURL,
			State:            "state-1",
			RequestURI:       "urn:request:1",
		})
		if err != nil {
			return "", err
		}
		return validateOID4VCIAuthorizationRedirect(location, authorizationURL, "state-1", "https://wallet.example/callback", policy)
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
		secondCredential = f.issueCredential(f.additionalKey, map[string]string{"given_name": "Hanako"})
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

// OpenID4VCI 1.0 §5: "The Wallet can also start the issuance without a
// Credential Offer." The wallet names the Credential Configuration itself, so
// PAR carries no issuer_state and requests that configuration's scope.
func TestReceiveOID4VCIFinalCredential_WalletInitiatedUsesRequestedConfiguration(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.walletInitiatedRequest())
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	require.Empty(t, fixture.parForm.Get("issuer_state"))
	require.Equal(t, "pid-scope", fixture.parForm.Get("scope"))
	require.Empty(t, fixture.parForm.Get("authorization_details"))
}

// With authorization_details the wallet sends the Credential Configuration id
// it selected from the issuer metadata (OpenID4VCI 1.0 §5.1.1).
func TestReceiveOID4VCIFinalCredential_WalletInitiatedSendsConfigurationID(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.walletInitiatedRequest()
	req.AuthorizationRequestType = OID4VCIAuthorizationRequestTypeAuthorizationDetails
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)
	require.Empty(t, fixture.parForm.Get("issuer_state"))
	details := decodeAuthorizationDetails(t, fixture.parForm.Get("authorization_details"))
	require.Len(t, details, 1)
	require.Equal(t, "pid", details[0]["credential_configuration_id"])
}

func TestReceiveOID4VCIFinalCredential_WalletInitiatedRequiresIssuerAndConfiguration(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)

	req := fixture.walletInitiatedRequest()
	req.CredentialIssuer = nil
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorContains(t, err, "credential issuer is required")
	require.Equal(t, 0, fixture.issuerMetadataCalls)

	req = fixture.walletInitiatedRequest()
	req.CredentialConfigurationID = ""
	_, err = fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorContains(t, err, "credential configuration ID is required")
	require.Equal(t, 0, fixture.issuerMetadataCalls)
}

func TestReceiveOID4VCIFinalCredential_OfferAndWalletInitiatedFieldsAreExclusive(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	issuerURL, err := url.Parse(fixture.server.URL)
	require.NoError(t, err)

	req := fixture.request()
	req.CredentialIssuer = issuerURL
	_, err = fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorContains(t, err, "must be empty when a credential offer is provided")

	req = fixture.request()
	req.CredentialConfigurationID = "pid"
	_, err = fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorContains(t, err, "must be empty when a credential offer is provided")
	require.Equal(t, 0, fixture.issuerMetadataCalls)
}

// HAIP §4.4.1 applies unchanged to wallet-initiated issuance: client
// authentication is required before any issuer request.
func TestReceiveOID4VCIFinalCredential_WalletInitiatedHAIPRequiresClientAuthentication(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	fixture.wallet.profile = profile.HAIP
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.walletInitiatedRequest())
	require.ErrorContains(t, err, "HAIP requires an OAuth2 client authentication mechanism")
	require.Equal(t, 0, fixture.issuerMetadataCalls)
}

// ---------------------------------------------------------------------------
// A1: the Final and HAIP issuance paths require Config.CredentialAcceptance.
// ---------------------------------------------------------------------------

// The Final issuance path knows which issuer it is talking to, so it can and
// must authenticate the credential it receives. A wallet configured without an
// acceptance policy fails rather than storing an unauthenticated credential.
func TestReceiveOID4VCIFinalCredentialFailsWithoutAcceptancePolicy(t *testing.T) {
	// This test builds a wallet through NewWallet, whose default receiver takes
	// its plain-HTTP allowance from the environment, so scope that allowance to
	// this test only.
	t.Setenv(env.HTTP_ALLOWED.String(), "true")
	fixture := newFinalIssuanceFixture(t)
	fixture.wallet = createTestControllerWithDefaults(t)

	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.ErrorIs(t, err, ErrCredentialAcceptancePolicyRequired)
	require.Nil(t, result)
	entries, _, listErr := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, listErr)
	require.Empty(t, entries)
}

func TestResumeOID4VCIFinalDeferredCredentialFailsWithoutAcceptancePolicy(t *testing.T) {
	// Scope the plain-HTTP allowance to this test: the replacement wallet is
	// built through NewWallet, whose default receiver reads it from the
	// environment.
	t.Setenv(env.HTTP_ALLOWED.String(), "true")
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
	})
	fixture.wallet = createTestControllerWithDefaults(t)
	issuerMetadata := fixture.issuerMetadata(t)

	_, err := fixture.wallet.ResumeOID4VCIFinalDeferredCredential(OID4VCIFinalDeferredRequest{
		Type:                      receiverTypes.Oid4vci,
		IssuerMetadata:            issuerMetadata,
		CredentialConfigurationID: "pid",
		AccessToken:               &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "DPoP"},
		TransactionID:             "tx-1",
		HolderKey:                 fixture.holderKey,
		ClientKey:                 fixture.clientKey,
		DeferredPollAttempts:      1,
	})
	require.ErrorIs(t, err, ErrCredentialAcceptancePolicyRequired)
	entries, _, listErr := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, listErr)
	require.Empty(t, entries)
}

// ---------------------------------------------------------------------------
// A3: an unknown credential_configuration_id fails before the authorization
// request is sent.
// ---------------------------------------------------------------------------

// §12.2.4: credential_configurations_supported names every Credential
// Configuration the issuer offers, so one that is absent cannot be requested.
func TestReceiveOID4VCIFinalCredentialRejectsUnknownConfigurationID(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.walletInitiatedRequest()
	req.CredentialConfigurationID = "not-offered"

	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorIs(t, err, ErrUnknownCredentialConfiguration)
	require.Equal(t, 0, fixture.parCalls)
	require.Equal(t, 0, fixture.authorizeCalls)
	require.Equal(t, 0, fixture.credentialCalls)
}

func TestReceiveOID4VCIFinalCredentialAcceptsOfferedConfigurationID(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.walletInitiatedRequest())
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	require.Equal(t, 1, fixture.parCalls)
}

// ---------------------------------------------------------------------------
// B5(a): PAR is a HAIP requirement, not an OpenID4VCI one.
// ---------------------------------------------------------------------------

// HAIP §4 lists "Pushed Authorization Requests (PAR): Only required when using
// the Authorization Endpoint", so a Final issuer without a
// pushed_authorization_request_endpoint gets the authorization request
// parameters inline.
func TestReceiveOID4VCIFinalCredentialWithoutPAR(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.omitPAREndpoint = true
	})
	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	require.Equal(t, 0, fixture.parCalls)
	require.Equal(t, 1, fixture.authorizeCalls)
	require.Equal(t, "code", fixture.authorizeQuery.Get("response_type"))
	require.Equal(t, "client-1", fixture.authorizeQuery.Get("client_id"))
	require.Equal(t, "openid-credential-offer://callback", fixture.authorizeQuery.Get("redirect_uri"))
	require.Equal(t, "pid-scope", fixture.authorizeQuery.Get("scope"))
	require.Equal(t, "S256", fixture.authorizeQuery.Get("code_challenge_method"))
	require.NotEmpty(t, fixture.authorizeQuery.Get("code_challenge"))
	require.Equal(t, "issuer-state-1", fixture.authorizeQuery.Get("issuer_state"))
	require.Empty(t, fixture.authorizeQuery.Get("request_uri"))
}

func TestReceiveOID4VCIFinalCredentialHAIPRequiresPAR(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.omitPAREndpoint = true
	})
	_, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), fixture.request())
	require.ErrorContains(t, err, "HAIP requires a pushed authorization request endpoint")
	require.Equal(t, 0, fixture.authorizeCalls)
}

// ---------------------------------------------------------------------------
// B6(a): the deferred request carries credential_response_encryption.
// ---------------------------------------------------------------------------

// §9.1: "Deferred Credential Request encryption MUST be used if the
// credential_response_encryption parameter is included in the Deferred
// Credential Request ... If it is not included encryption will not be
// performed", and §8.1 requires the request itself to be encrypted whenever it
// carries that parameter.
func TestDeferredCredentialRequestCarriesResponseEncryption(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.responseEncryption = true
		f.encryptionRequired = true
		f.requestEncryption = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			writeEncryptedFinalCredentialResponse(f.t, w, f.encryptionKey, map[string]any{"transaction_id": "tx-1"})
		}
	})
	req := fixture.request()
	req.DeferredPollAttempts = 1
	req.CredentialResponseEncryptionKey = &fixture.encryptionKey

	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	require.Equal(t, "tx-1", fixture.lastDeferredBody["transaction_id"])
	encryption, ok := fixture.lastDeferredBody["credential_response_encryption"].(map[string]any)
	require.True(t, ok, "deferred request is missing credential_response_encryption: %#v", fixture.lastDeferredBody)
	require.NotNil(t, encryption["jwk"])
	require.Equal(t, "A128GCM", encryption["enc"])
}

func TestDeferredCredentialRequestOmitsEncryptionWhenNotRequested(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"transaction_id": "tx-1"})
		}
	})
	req := fixture.request()
	req.DeferredPollAttempts = 1

	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	require.Equal(t, "tx-1", fixture.lastDeferredBody["transaction_id"])
	_, hasEncryption := fixture.lastDeferredBody["credential_response_encryption"]
	require.False(t, hasEncryption)
}

// ---------------------------------------------------------------------------
// B10: HAIP communicates the Credential Type with scope.
// ---------------------------------------------------------------------------

// HAIP §4.1: "For Grant Type authorization_code, the Issuer MUST include a
// scope value ... The Wallet MUST use that value in the scope Authorization
// parameter"; §4.2: the Wallet "MUST use the scope parameter to communicate
// Credential Type(s)".
func TestHAIPAuthorizationRequestUsesScope(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t)
	_, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), fixture.request())
	require.NoError(t, err)
	require.Equal(t, "pid-scope", fixture.parForm.Get("scope"))
	require.Empty(t, fixture.parForm.Get("authorization_details"))
}

func TestHAIPAuthorizationRequestRejectsAuthorizationDetails(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t)
	req := fixture.request()
	req.AuthorizationRequestType = OID4VCIAuthorizationRequestTypeAuthorizationDetails
	_, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), req)
	require.ErrorContains(t, err, "HAIP requires the scope authorization request type")
	require.Equal(t, 0, fixture.parCalls)
}

// A Credential Configuration without a scope cannot be requested under HAIP.
// The receiver plugin's own HAIP metadata validation rejects such a
// configuration before this point, so the rule is asserted on the function that
// builds the authorization request parameters.
func TestHAIPAuthorizationRequestRejectsScopelessConfiguration(t *testing.T) {
	_, _, err := oid4vciAuthorizationRequestParameters("", "pid", receiverTypes.CredentialConfiguration{Format: "dc+sd-jwt"}, true)
	require.ErrorContains(t, err, `HAIP requires the credential configuration "pid" to advertise a scope`)

	_, _, err = oid4vciAuthorizationRequestParameters(OID4VCIAuthorizationRequestTypeScope, "pid", receiverTypes.CredentialConfiguration{Format: "dc+sd-jwt"}, true)
	require.ErrorContains(t, err, `HAIP requires the credential configuration "pid" to advertise a scope`)

	// Final keeps the §12.2.4 fallback to authorization_details.
	scope, details, err := oid4vciAuthorizationRequestParameters("", "pid", receiverTypes.CredentialConfiguration{Format: "dc+sd-jwt"}, false)
	require.NoError(t, err)
	require.Empty(t, scope)
	require.Len(t, details, 1)
}

// Final outside HAIP keeps both request types, as §5.1.1 allows.
func TestFinalAuthorizationRequestStillAllowsAuthorizationDetails(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.request()
	req.AuthorizationRequestType = OID4VCIAuthorizationRequestTypeAuthorizationDetails
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)
	require.Empty(t, fixture.parForm.Get("scope"))
	details := decodeAuthorizationDetails(t, fixture.parForm.Get("authorization_details"))
	require.Len(t, details, 1)
	require.Equal(t, "pid", details[0]["credential_configuration_id"])
}

// ---------------------------------------------------------------------------
// C1: contexts, cancellable polling and a capped issuer interval.
// ---------------------------------------------------------------------------

func TestReceiveOID4VCIFinalCredentialContextCancellation(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := fixture.wallet.ReceiveOID4VCIFinalCredentialContext(ctx, fixture.request())
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 0, fixture.credentialCalls)
}

// §9.2 puts no upper bound on the interval the issuer names, so the wallet
// caps it; without the cap a hostile issuer could hold the polling goroutine
// for an hour.
func TestDeferredPollingCapsIssuerInterval(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"transaction_id": "tx-1", "interval": 3600})
		}
		f.deferredHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]any{"error": "issuance_pending", "interval": 3600})
		}
	})
	req := fixture.request()
	req.DeferredPollAttempts = 2
	// MaxDeferredInterval keeps the test quick; without it the library's own
	// 60 second cap applies.
	req.MaxDeferredInterval = 10 * time.Millisecond

	start := time.Now()
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorIs(t, err, receiverTypes.ErrIssuancePending)
	require.Less(t, time.Since(start), 5*time.Second)
	require.Equal(t, 2, fixture.deferredCalls)
}

// Cancelling the context stops the wait between deferred polls.
func TestDeferredPollingStopsOnContextCancellation(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"transaction_id": "tx-1", "interval": 3600})
		}
		f.deferredHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]any{"error": "issuance_pending", "interval": 3600})
		}
	})
	req := fixture.request()
	req.DeferredPollAttempts = 5

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := fixture.wallet.ReceiveOID4VCIFinalCredentialContext(ctx, req)
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(start), 30*time.Second)
}

func TestReceiveOID4VCIFinalCredentialWithoutContextStillWorks(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
}

// ---------------------------------------------------------------------------
// C2: the authorization code flow splits around a browser.
// ---------------------------------------------------------------------------

func TestBeginOID4VCIFinalAuthorizationReturnsResumableState(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	authorization, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), fixture.request())
	require.NoError(t, err)
	require.Equal(t, 1, fixture.parCalls)
	require.Equal(t, 0, fixture.authorizeCalls)

	authorizationURL, err := url.Parse(authorization.AuthorizationURL)
	require.NoError(t, err)
	require.Equal(t, "client-1", authorizationURL.Query().Get("client_id"))
	require.Equal(t, "urn:request:1", authorizationURL.Query().Get("request_uri"))
	require.Equal(t, "urn:request:1", authorization.RequestURI)
	require.Equal(t, fixture.pushedState, authorization.State)
	require.NotEmpty(t, authorization.CodeVerifier)
	require.Equal(t, "pid", authorization.CredentialConfigurationID)

	// The state must survive a process restart, so the round trip is completed
	// by resuming from the decoded value rather than from the original.
	encoded, err := json.Marshal(authorization)
	require.NoError(t, err)
	var restored OID4VCIFinalAuthorization
	require.NoError(t, json.Unmarshal(encoded, &restored))
	require.Equal(t, authorization.State, restored.State)
	require.Equal(t, authorization.CodeVerifier, restored.CodeVerifier)
	require.Equal(t, authorization.AuthorizationURL, restored.AuthorizationURL)
	require.NotNil(t, restored.IssuerMetadata)
	require.NotNil(t, restored.AuthorizationServerMetadata)

	redirect := "openid-credential-offer://callback?code=code-1&state=" + url.QueryEscape(restored.State)
	result, err := fixture.wallet.ResumeOID4VCIFinalAuthorization(context.Background(), fixture.request(), &restored, redirect)
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
}

func TestResumeOID4VCIFinalAuthorizationIssuesCredential(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.request()
	authorization, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), req)
	require.NoError(t, err)

	redirect := "openid-credential-offer://callback?code=code-1&state=" + url.QueryEscape(authorization.State)
	result, err := fixture.wallet.ResumeOID4VCIFinalAuthorization(context.Background(), req, authorization, redirect)
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	// The wallet never drove the authorization endpoint itself.
	require.Equal(t, 0, fixture.authorizeCalls)
}

func TestResumeOID4VCIFinalAuthorizationRejectsStateMismatch(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.request()
	authorization, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), req)
	require.NoError(t, err)

	_, err = fixture.wallet.ResumeOID4VCIFinalAuthorization(context.Background(), req, authorization,
		"openid-credential-offer://callback?code=code-1&state=someone-elses-state")
	require.ErrorContains(t, err, "state mismatch")
	require.Equal(t, 0, fixture.tokenCalls)
}

// RFC 9207 §2.4: when the authorization server advertises
// authorization_response_iss_parameter_supported the iss parameter MUST be
// present, so a mix-up attack cannot omit it.
func TestResumeOID4VCIFinalAuthorizationRejectsMissingIssuerParameter(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.issParameterSupported = true
	})
	req := fixture.request()
	authorization, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), req)
	require.NoError(t, err)

	_, err = fixture.wallet.ResumeOID4VCIFinalAuthorization(context.Background(), req, authorization,
		"openid-credential-offer://callback?code=code-1&state="+url.QueryEscape(authorization.State))
	require.ErrorContains(t, err, "missing the iss parameter")
	require.Equal(t, 0, fixture.tokenCalls)
}

func TestResumeOID4VCIFinalAuthorizationReturnsAuthorizationError(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.request()
	authorization, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), req)
	require.NoError(t, err)

	_, err = fixture.wallet.ResumeOID4VCIFinalAuthorization(context.Background(), req, authorization,
		"openid-credential-offer://callback?error=access_denied&error_description=user%20said%20no")
	var authorizationError *AuthorizationResponseError
	require.ErrorAs(t, err, &authorizationError)
	require.Equal(t, "access_denied", authorizationError.Code)
	require.Equal(t, "user said no", authorizationError.Description)
	require.Equal(t, 0, fixture.tokenCalls)
}

// A real wallet needs a system browser at the authorization endpoint, so
// driving it from the library is opt-in.
func TestReceiveOID4VCIFinalCredentialRefusesSelfDrivenAuthorizationByDefault(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.request()
	req.AllowSelfDrivenAuthorization = false

	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorContains(t, err, "the authorization code flow requires a browser")
	require.Equal(t, 0, fixture.parCalls)
	require.Equal(t, 0, fixture.authorizeCalls)
}

// fakeFinalSigner is a caller-supplied receiverTypes.OID4VCIFinalSigner. It
// keeps the software key proof and PoP by embedding the default signer, and
// replaces only the DPoP proof with a value a test can recognise on the wire.
type fakeFinalSigner struct {
	oid4vcisign.Default

	dpopProof  string
	dpopCalls  int
	proofCalls int
}

func (s *fakeFinalSigner) CreateDpopProof(jose.JSONWebKey, string, string, string, string) (string, error) {
	s.dpopCalls++
	return s.dpopProof, nil
}

func (s *fakeFinalSigner) CreateCredentialRequestJWTProofWithOptions(key jose.JSONWebKey, opts receiverTypes.ProofOptions) (string, error) {
	s.proofCalls++
	return s.Default.CreateCredentialRequestJWTProofWithOptions(key, opts)
}

// transportOnlyOID4VCIPlugin is a receiver plugin that implements the Final
// transport contract and nothing else. Embedding the interface rather than the
// bundled receiver keeps the signing primitives from being promoted, which is
// what a plugin written outside this module looks like.
type transportOnlyOID4VCIPlugin struct {
	receiverTypes.OID4VCIFinalTransport
}

// TestWalletAcceptsCustomFinalSigner drives a whole Final issuance with
// Config.OID4VCISigner set, so the wallet's private-key operations come from the
// caller: the DPoP proof the fake signs is the one the issuer's token endpoint
// receives.
func TestWalletAcceptsCustomFinalSigner(t *testing.T) {
	signer := &fakeFinalSigner{dpopProof: "fake-dpop-proof"}
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.oid4vciSigner = signer
	})

	result, err := fixture.wallet.ReceiveOID4VCIFinalCredentialContext(t.Context(), fixture.request())
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)

	require.Equal(t, "fake-dpop-proof", fixture.tokenHeaders.Get("DPoP"))
	require.Positive(t, signer.dpopCalls)
	require.Positive(t, signer.proofCalls)
	// The key proof still comes from the configured signer, so the issuer sees a
	// proof bound to the holder key.
	claims := finalProofClaims(t, fixture.proofJWTs(t)[0])
	require.Equal(t, fixture.credentialIssuer(fixture.server.URL), claims["aud"])
}

// TestWalletAcceptsTransportOnlyPlugin registers a receiver plugin thatonly speaks
// HTTP and lets the wallet fall back to the bundled software signer, which is
// the point of splitting OID4VCIFinalReceiver into a transport and a signer.
func TestWalletAcceptsTransportOnlyPlugin(t *testing.T) {
	var registered receiverTypes.Receiver
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.wrapReceiverPlugin = func(plugin receiverTypes.Receiver) receiverTypes.Receiver {
			transport, ok := plugin.(receiverTypes.OID4VCIFinalTransport)
			require.True(t, ok)
			registered = &transportOnlyOID4VCIPlugin{OID4VCIFinalTransport: transport}
			return registered
		}
	})

	_, isSigner := registered.(receiverTypes.OID4VCIFinalSigner)
	require.False(t, isSigner, "the registered plugin must not implement the signer")

	result, err := fixture.wallet.ReceiveOID4VCIFinalCredentialContext(t.Context(), fixture.request())
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	// The fallback signer produced a real DPoP proof and a real key proof.
	require.NotEmpty(t, fixture.tokenHeaders.Get("DPoP"))
	claims := finalProofClaims(t, fixture.proofJWTs(t)[0])
	require.Equal(t, fixture.credentialIssuer(fixture.server.URL), claims["aud"])
}
