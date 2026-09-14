package wallet

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// freshWallet builds a second Wallet against the same fixture issuer, with its
// own credential store and no memory of the earlier stages. Decoding the state
// into it is what proves an OID4VCIFinalAuthorization or an
// OID4VCIFinalTokenGrant carries everything the next stage needs.
func (f *finalIssuanceFixture) freshWallet(t *testing.T, trust AttestationTrustPolicy) *Wallet {
	t.Helper()
	plugin := receiverTypes.Receiver(&oid4vci.Oid4vciReceiver{
		HTTPClient: f.server.Client(),
		AllowHTTP:  !f.walletProfile.IsHAIP(),
		Profile:    f.walletProfile,
	})
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
	require.NoError(t, err)
	config := Config{
		Profile:              f.walletProfile,
		CredStore:            newProfileCredStore(t),
		Receiver:             receiving,
		CredentialAcceptance: acceptIssuerKeyPolicy(f.issuerKey),
		AttestationTrust:     trust,
	}
	if f.clientAuthKey != nil {
		config.ClientAuth = ClientAuthConfig{Method: receiverTypes.PrivateKeyJwt, ClientID: "client-1", Key: f.clientAuthKey}
	}
	wallet, err := NewWalletWithConfig(config)
	require.NoError(t, err)
	return wallet
}

// requireJSONRoundTrip marshals value and decodes it into target, so a test
// reads the state back exactly as a caller that persisted it would.
func requireJSONRoundTrip(t *testing.T, value any, target any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, target))
}

// staticKeyAttestationFor signs an Appendix D key attestation the way an
// out-of-process attester would: over the public holder keys the library asked
// for, with the c_nonce and audience it named.
func staticKeyAttestationFor(t *testing.T, attesterKey jose.JSONWebKey, keys []jose.JSONWebKey, nonce, audience string) *KeyAttestation {
	t.Helper()
	attestation, err := (&StaticKeyAttester{Key: attesterKey, Issuer: "https://key-attester.example"}).KeyAttestation(
		context.Background(),
		KeyAttestationRequest{Keys: keys, Nonce: nonce, Audience: audience},
	)
	require.NoError(t, err)
	return attestation
}

// attesterTrust is the trust policy a wallet needs to authenticate an
// attestation minted outside it: the attester's own public key, because a
// static attester ships no x5c chain.
func attesterTrust(attesterKey jose.JSONWebKey) AttestationTrustPolicy {
	return AttestationTrustPolicy{ResolveKey: func(AttestationJOSEHeader) (any, error) {
		return attesterKey.Public().Key, nil
	}}
}

// TestOID4VCIFinalTwoStageAuthorizationSurvivesJSONRoundTrip walks the three
// interruption points of a Final authorization code issuance — the browser, the
// token grant, and the credential request — with a different Wallet instance on
// each side of every boundary, so the only thing carried across is JSON.
func TestOID4VCIFinalTwoStageAuthorizationSurvivesJSONRoundTrip(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.request()

	authorization, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), req)
	require.NoError(t, err)
	var restoredAuthorization OID4VCIFinalAuthorization
	requireJSONRoundTrip(t, authorization, &restoredAuthorization)

	tokenWallet := fixture.freshWallet(t, AttestationTrustPolicy{})
	redirect := "openid-credential-offer://callback?code=code-1&state=" + url.QueryEscape(restoredAuthorization.State)
	grant, err := tokenWallet.AuthorizeOID4VCIFinalToken(context.Background(), req, &restoredAuthorization, redirect)
	require.NoError(t, err)
	// The token stage stops before the credential request, having taken the
	// c_nonce the proof will need.
	require.Equal(t, 1, fixture.tokenCalls)
	require.Equal(t, 1, fixture.nonceCalls)
	require.Equal(t, 0, fixture.credentialCalls)
	require.Equal(t, "credential-nonce-1", grant.CNonce)
	require.Nil(t, grant.KeyAttestation)

	var restoredGrant OID4VCIFinalTokenGrant
	requireJSONRoundTrip(t, grant, &restoredGrant)
	require.NotNil(t, restoredGrant.AccessToken)
	require.Equal(t, "pid", restoredGrant.CredentialConfigurationID)
	require.NotNil(t, restoredGrant.IssuerMetadata)
	require.NotNil(t, restoredGrant.AuthorizationServerMetadata)
	// The fixture issues a DPoP-bound token, so the grant records the key it is
	// bound to (RFC 9449 §5).
	require.NotEmpty(t, restoredGrant.DPoPKeyThumbprint)

	credentialWallet := fixture.freshWallet(t, AttestationTrustPolicy{})
	result, err := credentialWallet.RequestOID4VCIFinalCredential(context.Background(), req, &restoredGrant)
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	require.Equal(t, 1, fixture.credentialCalls)
	require.Equal(t, 1, fixture.nonceCalls)
}

// A DPoP-bound access token may only be presented with the key it was issued
// to, so the credential stage refuses another one before sending anything.
func TestRequestOID4VCIFinalCredentialRejectsForeignDPoPKey(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.request()
	authorization, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), req)
	require.NoError(t, err)
	redirect := "openid-credential-offer://callback?code=code-1&state=" + url.QueryEscape(authorization.State)
	grant, err := fixture.wallet.AuthorizeOID4VCIFinalToken(context.Background(), req, authorization, redirect)
	require.NoError(t, err)

	foreign := req
	foreign.ClientKey = newPrivateJWKForFinalVCITest(t, "someone-elses-client-key")
	_, err = fixture.wallet.RequestOID4VCIFinalCredential(context.Background(), foreign, grant)
	require.ErrorIs(t, err, ErrDPoPKeyMismatch)
	require.Equal(t, 0, fixture.credentialCalls)
}

// TestAuthorizeOID4VCIFinalTokenCarriesTheKeyAttestationRequest pins the shape
// of the interruption: the grant names the keys, the c_nonce and the audience
// an Appendix D attestation must be signed over.
func TestAuthorizeOID4VCIFinalTokenCarriesTheKeyAttestationRequest(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
	})
	req := fixture.request()
	req.ExternalKeyAttestation = true

	authorization, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), req)
	require.NoError(t, err)
	redirect := "openid-credential-offer://callback?code=code-1&state=" + url.QueryEscape(authorization.State)
	grant, err := fixture.wallet.AuthorizeOID4VCIFinalToken(context.Background(), req, authorization, redirect)
	require.NoError(t, err)

	require.NotNil(t, grant.KeyAttestation)
	require.Equal(t, grant.CNonce, grant.KeyAttestation.Nonce)
	require.Equal(t, "credential-nonce-1", grant.KeyAttestation.Nonce)
	require.Equal(t, fixture.server.URL, grant.KeyAttestation.Audience)
	require.Len(t, grant.KeyAttestation.Keys, 1)
	require.NoError(t, requireJWKThumbprint(fixture.holderKey, grant.KeyAttestation.Keys[0]))
	// Only the public half travels: a private key in the grant would be handed
	// to whatever process signs the attestation.
	require.True(t, grant.KeyAttestation.Keys[0].IsPublic())
}

// TestRequestOID4VCIFinalCredentialRequiresThenAcceptsAKeyAttestation is the
// whole point of the split: a wallet with no in-process attester stops, is
// handed what to sign, and completes the issuance with the signature.
func TestRequestOID4VCIFinalCredentialRequiresThenAcceptsAKeyAttestation(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
	})
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	req := fixture.request()
	req.ExternalKeyAttestation = true

	authorization, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), req)
	require.NoError(t, err)
	redirect := "openid-credential-offer://callback?code=code-1&state=" + url.QueryEscape(authorization.State)
	grant, err := fixture.wallet.AuthorizeOID4VCIFinalToken(context.Background(), req, authorization, redirect)
	require.NoError(t, err)

	credentialWallet := fixture.freshWallet(t, attesterTrust(attesterKey))
	_, err = credentialWallet.RequestOID4VCIFinalCredential(context.Background(), req, grant)
	var required *KeyAttestationRequiredError
	require.ErrorAs(t, err, &required)
	require.ErrorIs(t, err, ErrKeyAttestationRequired)
	require.True(t, required.IssuerRequired)
	require.Equal(t, "credential-nonce-1", required.CNonce)
	require.Equal(t, fixture.server.URL, required.Audience)
	require.Len(t, required.HolderKeys, 1)
	// Nothing was sent: the issuance stops before the credential request.
	require.Equal(t, 0, fixture.credentialCalls)

	signed := req
	signed.KeyAttestation = staticKeyAttestationFor(t, attesterKey, required.HolderKeys, required.CNonce, required.Audience)
	result, err := credentialWallet.RequestOID4VCIFinalCredential(context.Background(), signed, required.Grant)
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	require.Equal(t, 1, fixture.credentialCalls)

	header := finalProofHeader(t, fixture.proofJWTs(t)[0])
	attestationJWT, ok := header["key_attestation"].(string)
	require.True(t, ok, "proof header is missing key_attestation: %#v", header)
	require.Equal(t, signed.KeyAttestation.JWT, attestationJWT)
}

// An attestation minted for another c_nonce never reaches the wire: Appendix F
// makes echoing the issuer's c_nonce mandatory once it provided one.
func TestRequestOID4VCIFinalCredentialRejectsForeignNonceAttestation(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
	})
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	req := fixture.request()
	req.ExternalKeyAttestation = true

	authorization, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), req)
	require.NoError(t, err)
	redirect := "openid-credential-offer://callback?code=code-1&state=" + url.QueryEscape(authorization.State)
	grant, err := fixture.wallet.AuthorizeOID4VCIFinalToken(context.Background(), req, authorization, redirect)
	require.NoError(t, err)

	stale := req
	stale.KeyAttestation = staticKeyAttestationFor(t, attesterKey, grant.KeyAttestation.Keys, "some-other-nonce", grant.KeyAttestation.Audience)
	credentialWallet := fixture.freshWallet(t, attesterTrust(attesterKey))
	_, err = credentialWallet.RequestOID4VCIFinalCredential(context.Background(), stale, grant)
	var nonceError *KeyAttestationNonceError
	require.ErrorAs(t, err, &nonceError)
	require.ErrorIs(t, err, ErrKeyAttestationNonceStale)
	require.Equal(t, "credential-nonce-1", nonceError.Grant.CNonce)
	require.Equal(t, 0, fixture.credentialCalls)
}

// TestRequestOID4VCIFinalCredentialReSignsAfterInvalidNonce is the second call
// the in-process provider would have absorbed silently: §8.3.1.2
// "invalid_nonce" invalidates the attestation, and the caller gets the fresh
// c_nonce back in the grant instead of a dead end.
func TestRequestOID4VCIFinalCredentialReSignsAfterInvalidNonce(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
		f.nonceHandler = func(w http.ResponseWriter, r *http.Request) {
			if f.nonceCalls == 1 {
				mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "credential-nonce-1"})
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "credential-nonce-2"})
		}
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			if f.credentialCalls == 1 {
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_nonce"})
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential": f.issuedCredential})
		}
	})
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	req := fixture.request()
	req.ExternalKeyAttestation = true

	authorization, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), req)
	require.NoError(t, err)
	redirect := "openid-credential-offer://callback?code=code-1&state=" + url.QueryEscape(authorization.State)
	grant, err := fixture.wallet.AuthorizeOID4VCIFinalToken(context.Background(), req, authorization, redirect)
	require.NoError(t, err)
	require.Equal(t, "credential-nonce-1", grant.CNonce)

	credentialWallet := fixture.freshWallet(t, attesterTrust(attesterKey))
	first := req
	first.KeyAttestation = staticKeyAttestationFor(t, attesterKey, grant.KeyAttestation.Keys, grant.CNonce, grant.KeyAttestation.Audience)
	_, err = credentialWallet.RequestOID4VCIFinalCredential(context.Background(), first, grant)
	var nonceError *KeyAttestationNonceError
	require.ErrorAs(t, err, &nonceError)
	require.Equal(t, "credential-nonce-2", nonceError.Grant.CNonce)
	require.Equal(t, "credential-nonce-2", nonceError.Grant.KeyAttestation.Nonce)
	require.Equal(t, 1, fixture.credentialCalls)
	require.Equal(t, 2, fixture.nonceCalls)

	second := req
	second.KeyAttestation = staticKeyAttestationFor(t, attesterKey,
		nonceError.Grant.KeyAttestation.Keys, nonceError.Grant.CNonce, nonceError.Grant.KeyAttestation.Audience)
	result, err := credentialWallet.RequestOID4VCIFinalCredential(context.Background(), second, nonceError.Grant)
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	require.Equal(t, 2, fixture.credentialCalls)

	claims := finalProofClaims(t, fixture.proofJWTs(t)[0])
	require.Equal(t, "credential-nonce-2", claims["nonce"])
}

// HAIP leaves no room for an attestation without a c_nonce: "If the Issuer
// supports Credential Configurations that require key binding ... the
// nonce_endpoint MUST be present in the Credential Issuer Metadata."
func TestAuthorizeOID4VCIFinalTokenRequiresNonceEndpointUnderHAIP(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeNonceEndpoint = false
		f.keyAttestationsRequired = true
	})
	req := fixture.request()
	req.ExternalKeyAttestation = true

	authorization, err := fixture.wallet.BeginOID4VCIFinalAuthorization(context.Background(), req)
	require.NoError(t, err)
	redirect := "openid-credential-offer://callback?code=code-1&state=" + url.QueryEscape(authorization.State) +
		"&iss=" + url.QueryEscape(fixture.server.URL)
	_, err = fixture.wallet.AuthorizeOID4VCIFinalToken(context.Background(), req, authorization, redirect)
	require.ErrorIs(t, err, ErrNonceEndpointRequired)
	require.Equal(t, 0, fixture.credentialCalls)
}

// preAuthorizedOffer builds a §4.1.1 Credential Offer for the fixture issuer
// that carries only the Pre-Authorized Code grant.
func (f *finalIssuanceFixture) preAuthorizedOffer(t *testing.T, txCode *TransactionCode) *CredentialOffer {
	t.Helper()
	issuerURL, err := url.Parse(f.server.URL)
	require.NoError(t, err)
	return &CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{"pid"},
		Grants: map[string]*CredentialOfferGrant{
			preAuthorizedCodeGrantType: {PreAuthorizedCode: "pre-auth-code-1", TxCode: txCode},
		},
	}
}

func (f *finalIssuanceFixture) preAuthorizedRequest(t *testing.T, txCode *TransactionCode) OID4VCIFinalPreAuthorizedReceiveRequest {
	t.Helper()
	return OID4VCIFinalPreAuthorizedReceiveRequest{
		CredentialOffer: f.preAuthorizedOffer(t, txCode),
		Type:            receiverTypes.Oid4vci,
		HolderKey:       f.holderKey,
	}
}

// bearerTokenResponse makes the fixture's token endpoint answer with the plain
// Bearer token OpenID4VCI 1.0 §6.1 permits outside HAIP.
func bearerTokenResponse(f *finalIssuanceFixture) {
	f.tokenResponse = map[string]any{"access_token": "access-1", "token_type": "Bearer", "expires_in": 3600}
}

// A Final wallet with no client key is the anonymous Pre-Authorized Code
// client of §6.1: no client_id is sent and the Bearer token it gets back is
// presented as one.
func TestReceiveOID4VCIFinalPreAuthorizedCredentialAcceptsAnonymousBearer(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, bearerTokenResponse)
	result, err := fixture.wallet.ReceiveOID4VCIFinalPreAuthorizedCredential(context.Background(), fixture.preAuthorizedRequest(t, nil))
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)

	require.Len(t, fixture.tokenForms, 1)
	form := fixture.tokenForms[0]
	require.Equal(t, preAuthorizedCodeGrantType, form.Get("grant_type"))
	require.Equal(t, "pre-auth-code-1", form.Get("pre-authorized_code"))
	require.Empty(t, form.Get("client_id"))
	require.Empty(t, form.Get("tx_code"))
	require.Empty(t, fixture.tokenHeaders.Get("DPoP"))
	// The credential request presents the token with the scheme the token
	// response named (RFC 6750 §2.1).
	require.Equal(t, 1, fixture.credentialCalls)
	require.Equal(t, "pid", fixture.lastCredentialBody["credential_configuration_id"])
}

// With a client key the same Final issuer may bind the token to it, and the
// wallet presents it with the RFC 9449 §7.1 DPoP scheme.
func TestReceiveOID4VCIFinalPreAuthorizedCredentialAcceptsDPoP(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.preAuthorizedRequest(t, nil)
	req.ClientID = "client-1"
	req.ClientKey = fixture.clientKey

	result, err := fixture.wallet.ReceiveOID4VCIFinalPreAuthorizedCredential(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
	require.Equal(t, "client-1", fixture.tokenForms[0].Get("client_id"))
	require.NotEmpty(t, fixture.tokenHeaders.Get("DPoP"))
}

// §6.1: "tx_code ... MUST be present if a tx_code object was present in the
// Credential Offer (including if the object was empty)."
func TestReceiveOID4VCIFinalPreAuthorizedCredentialSendsTransactionCode(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, bearerTokenResponse)
	req := fixture.preAuthorizedRequest(t, &TransactionCode{InputMode: "numeric", Length: 6})
	req.TxCode = "493536"

	_, err := fixture.wallet.ReceiveOID4VCIFinalPreAuthorizedCredential(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "493536", fixture.tokenForms[0].Get("tx_code"))
}

// A missing Transaction Code is caught before the single-use pre-authorized
// code is spent.
func TestReceiveOID4VCIFinalPreAuthorizedCredentialRequiresTransactionCode(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, bearerTokenResponse)
	req := fixture.preAuthorizedRequest(t, &TransactionCode{})

	_, err := fixture.wallet.ReceiveOID4VCIFinalPreAuthorizedCredential(context.Background(), req)
	require.ErrorIs(t, err, ErrTransactionCodeRequired)
	require.Equal(t, 0, fixture.tokenCalls)
	require.Equal(t, 0, fixture.issuerMetadataCalls)
}

// An offer without the Pre-Authorized Code grant is refused before any request.
func TestReceiveOID4VCIFinalPreAuthorizedCredentialRequiresTheGrant(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.preAuthorizedRequest(t, nil)
	req.CredentialOffer.Grants = map[string]*CredentialOfferGrant{
		"authorization_code": {IssuerState: "issuer-state-1"},
	}

	_, err := fixture.wallet.ReceiveOID4VCIFinalPreAuthorizedCredential(context.Background(), req)
	require.ErrorIs(t, err, ErrPreAuthorizedGrantMissing)
	require.Equal(t, 0, fixture.issuerMetadataCalls)
}

// HAIP §4: "Sender-constrained access token: MUST support DPoP". A Bearer
// token_type cannot bind the token to the wallet key, so it is refused.
func TestReceiveOID4VCIFinalPreAuthorizedCredentialRejectsBearerUnderHAIP(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t, bearerTokenResponse)
	req := fixture.preAuthorizedRequest(t, nil)
	req.ClientID = "client-1"
	req.ClientKey = fixture.clientKey

	_, err := fixture.wallet.ReceiveOID4VCIFinalPreAuthorizedCredential(context.Background(), req)
	require.ErrorContains(t, err, "HAIP requires a DPoP-bound access token")
	require.Equal(t, 1, fixture.tokenCalls)
	require.Equal(t, 0, fixture.credentialCalls)
}

// The same HAIP issuer answering with a DPoP-bound token is accepted, the
// request carries the proof, and the client authenticates itself (HAIP §4.4.1).
// The assertions stop at the grant because the fixture issues an SD-JWT VC
// without the x5c header HAIP §6.1.1 requires of a stored credential, which is
// a credential acceptance concern rather than a Pre-Authorized Code one.
func TestReceiveOID4VCIFinalPreAuthorizedCredentialAcceptsDPoPUnderHAIP(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t)
	req := fixture.preAuthorizedRequest(t, nil)
	req.ClientID = "client-1"
	req.ClientKey = fixture.clientKey

	grant, err := fixture.wallet.AuthorizeOID4VCIFinalPreAuthorizedToken(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "DPoP", grant.AccessToken.TokenType)
	require.NotEmpty(t, grant.DPoPKeyThumbprint)
	require.Equal(t, "credential-nonce-1", grant.CNonce)
	require.NotEmpty(t, fixture.tokenHeaders.Get("DPoP"))
	require.Equal(t, preAuthorizedCodeGrantType, fixture.tokenForms[0].Get("grant_type"))
	require.NotEmpty(t, fixture.tokenForms[0].Get("client_assertion"))
	require.Equal(t, receiverTypes.ClientAssertionTypeJWTBearer, fixture.tokenForms[0].Get("client_assertion_type"))
}

// HAIP has no anonymous clients: §4.4.1 requires an OAuth2 client
// authentication mechanism at endpoints that support one.
func TestReceiveOID4VCIFinalPreAuthorizedCredentialRejectsAnonymousUnderHAIP(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t)
	_, err := fixture.wallet.ReceiveOID4VCIFinalPreAuthorizedCredential(context.Background(), fixture.preAuthorizedRequest(t, nil))
	require.ErrorContains(t, err, "client_id")
	require.Equal(t, 0, fixture.tokenCalls)
}

// The Pre-Authorized Code path stops at the same interruption as the
// authorization code path, so a key attestation minted elsewhere completes it.
func TestReceiveOID4VCIFinalPreAuthorizedCredentialCrossesTheKeyAttestationBoundary(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, bearerTokenResponse, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
	})
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	req := fixture.preAuthorizedRequest(t, nil)
	req.ExternalKeyAttestation = true

	grant, err := fixture.wallet.AuthorizeOID4VCIFinalPreAuthorizedToken(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, grant.KeyAttestation)
	require.Equal(t, "credential-nonce-1", grant.KeyAttestation.Nonce)
	require.Equal(t, 0, fixture.credentialCalls)

	var restoredGrant OID4VCIFinalTokenGrant
	requireJSONRoundTrip(t, grant, &restoredGrant)

	credentialWallet := fixture.freshWallet(t, attesterTrust(attesterKey))
	credentialRequest := OID4VCIFinalReceiveRequest{
		Type:                   receiverTypes.Oid4vci,
		HolderKey:              fixture.holderKey,
		ExternalKeyAttestation: true,
	}
	_, err = credentialWallet.RequestOID4VCIFinalCredential(context.Background(), credentialRequest, &restoredGrant)
	var required *KeyAttestationRequiredError
	require.ErrorAs(t, err, &required)

	credentialRequest.KeyAttestation = staticKeyAttestationFor(t, attesterKey, required.HolderKeys, required.CNonce, required.Audience)
	result, err := credentialWallet.RequestOID4VCIFinalCredential(context.Background(), credentialRequest, required.Grant)
	require.NoError(t, err)
	require.Len(t, result.SavedCredentials, 1)
}

// The library must keep telling a caller that never opted into an external
// attester that it has no way to produce one, before anything is sent.
func TestReceiveOID4VCIFinalPreAuthorizedCredentialRefusesMissingKeyAttestationProvider(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, bearerTokenResponse, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
	})
	_, err := fixture.wallet.ReceiveOID4VCIFinalPreAuthorizedCredential(context.Background(), fixture.preAuthorizedRequest(t, nil))
	require.ErrorContains(t, err, "KeyAttestation")
	require.Equal(t, 0, fixture.tokenCalls)
}

// An unknown token_type is neither presentable nor assumed to be Bearer.
func TestReceiveOID4VCIFinalPreAuthorizedCredentialRejectsUnknownTokenType(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.tokenResponse = map[string]any{"access_token": "access-1", "token_type": "Mac", "expires_in": 3600}
	})
	req := fixture.preAuthorizedRequest(t, nil)
	req.ClientKey = fixture.clientKey

	_, err := fixture.wallet.ReceiveOID4VCIFinalPreAuthorizedCredential(context.Background(), req)
	require.ErrorIs(t, err, ErrTokenTypeUnsupported)
	require.Equal(t, 0, fixture.credentialCalls)
}

// An anonymous wallet holds no key for a DPoP proof, so a DPoP-bound token is
// refused rather than downgraded to Bearer use.
func TestReceiveOID4VCIFinalPreAuthorizedCredentialRejectsDPoPWithoutClientKey(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	_, err := fixture.wallet.ReceiveOID4VCIFinalPreAuthorizedCredential(context.Background(), fixture.preAuthorizedRequest(t, nil))
	require.True(t, errors.Is(err, oid4vci.ErrDPoPRequired), "expected ErrDPoPRequired, got %v", err)
	require.Equal(t, 0, fixture.credentialCalls)
}
