package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

func presentationURI(baseURL, query string) string {
	return "openid4vp://present?" + url.Values{
		"client_id": {"redirect_uri:" + baseURL + "/response"}, "response_uri": {baseURL + "/response"}, "response_type": {"vp_token"},
		"response_mode": {"direct_post"}, "nonce": {"presentation-nonce"}, "state": {"state-to-preserve"}, "dcql_query": {query},
	}.Encode()
}

func disclosedNames(t *testing.T, wire string) []string {
	t.Helper()
	names := []string{}
	parts := strings.Split(wire, "~")
	for _, encoded := range parts[1 : len(parts)-1] {
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		require.NoError(t, err)
		var disclosure []any
		require.NoError(t, json.Unmarshal(raw, &disclosure))
		require.Len(t, disclosure, 3)
		names = append(names, disclosure[1].(string))
	}
	return names
}

func TestWallet_PublicDCQLPresentation(t *testing.T) {
	for _, api := range []string{"present", "build-final"} {
		for _, tc := range []struct {
			name, query string
			want        map[string][]string
			wantError   bool
		}{
			{name: "no claims discloses none", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]}}]}`, want: map[string][]string{"pid": {}}},
			{name: "only requested claim", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`, want: map[string][]string{"pid": {"given_name"}}},
			{name: "mandatory claim needs no disclosure", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["nationality"]},{"path":["given_name"]}]}]}`, want: map[string][]string{"pid": {"given_name"}}},
			{name: "all credential queries answered", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},{"id":"address","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:address"]},"claims":[{"path":["street_address"]}]}]}`, want: map[string][]string{"pid": {"given_name"}, "address": {"street_address"}}},
			{name: "required missing credential sends nothing", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]}},{"id":"missing","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:missing"]}}]}`, wantError: true},
			{name: "required missing claim sends nothing", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]},{"path":["unavailable"]}]}]}`, wantError: true},
			{name: "optional missing query omitted", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]}},{"id":"missing","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:missing"]}}],"credential_sets":[{"options":[["pid"]]},{"options":[["missing"]],"required":false}]}`, want: map[string][]string{"pid": {}}},
			{name: "claim sets disclose only first matching choice", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"id":"given","path":["given_name"]},{"id":"family","path":["family_name"]}],"claim_sets":[["given"],["family"]]}]}`, want: map[string][]string{"pid": {"given_name"}}},
			{name: "claim sets use available alternative", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"id":"missing","path":["not_available"]},{"id":"given","path":["given_name"]}],"claim_sets":[["missing"],["given"]]}]}`, want: map[string][]string{"pid": {"given_name"}}},
			{name: "credential sets select fallback", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},{"id":"missing","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:missing"]}}],"credential_sets":[{"options":[["pid","missing"],["pid"]]}]}`, want: map[string][]string{"pid": {"given_name"}}},
			{name: "same credential has different disclosure per query", query: `{"credentials":[{"id":"given","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},{"id":"family","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["family_name"]}]}]}`, want: map[string][]string{"given": {"given_name"}, "family": {"family_name"}}},
			{name: "claim value matches", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"],"values":["Taro"]}]}]}`, want: map[string][]string{"pid": {"given_name"}}},
			{name: "claim value mismatch sends nothing", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"],"values":["Hanako"]}]}]}`, wantError: true},
		} {
			t.Run(api+"/"+tc.name, func(t *testing.T) {
				fixture := newSDJWTPresentationFixture(t)
				holder := fixture.key.PublicKey()
				fixture.receive("urn:test:identity", &holder, map[string]any{"nationality": "JP"}, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
				// A newer, different credential must not replace the matching identity.
				fixture.receive("urn:test:address", &holder, nil, map[string]string{"street_address": "1 Example St", "postal_code": "100-0000"})
				uri := presentationURI(fixture.baseURL, tc.query)
				var tokens map[string][]string
				var err error
				if api == "present" {
					var redirect string
					redirect, err = fixture.wallet.PresentCredential(uri, fixture.key, nil)
					if err == nil {
						require.Equal(t, fixture.baseURL+"/done", redirect)
						select {
						case form := <-fixture.posted:
							require.Equal(t, "state-to-preserve", form.Get("state"))
							require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
						default:
							t.Fatal("no response received")
						}
					}
				} else {
					var response OID4VPFinalAuthorizationResponse
					response, err = fixture.wallet.BuildOID4VPFinalAuthorizationResponse(uri, fixture.key)
					if err == nil {
						tokens = response["vp_token"].(map[string][]string)
						require.Equal(t, "state-to-preserve", response["state"])
					}
				}
				if tc.wantError {
					require.Error(t, err)
					select {
					case <-fixture.posted:
						t.Fatal("unsatisfied request disclosed credentials")
					default:
					}
					return
				}
				require.NoError(t, err)
				require.Len(t, tokens, len(tc.want))
				for id, names := range tc.want {
					require.Len(t, tokens[id], 1)
					require.ElementsMatch(t, names, disclosedNames(t, tokens[id][0]))
					wire := tokens[id][0]
					separator := strings.LastIndex(wire, "~")
					signed, err := jwt.ParseSigned(wire[separator+1:], []jose.SignatureAlgorithm{jose.ES256})
					require.NoError(t, err)
					var claims map[string]any
					require.NoError(t, signed.Claims(holder.Key, &claims))
					require.Equal(t, "kb+jwt", signed.Headers[0].ExtraHeaders[jose.HeaderType])
					require.Equal(t, "redirect_uri:"+fixture.baseURL+"/response", claims["aud"])
					require.Equal(t, "presentation-nonce", claims["nonce"])
					digest := sha256.Sum256([]byte(wire[:separator+1]))
					require.Equal(t, base64.RawURLEncoding.EncodeToString(digest[:]), claims["sd_hash"])
				}
			})
		}
	}
}

func TestWallet_DCQLRespectsCallerDisclosureChoice(t *testing.T) {
	for _, tc := range []struct {
		name      string
		options   *sdjwtvc.SdJwtVcPresentationOptions
		wantError bool
	}{
		{name: "caller cannot add unrequested claims", options: &sdjwtvc.SdJwtVcPresentationOptions{SelectedClaims: []string{"given_name", "family_name"}}},
		{name: "caller cannot be forced to disclose denied claim", options: &sdjwtvc.SdJwtVcPresentationOptions{SelectedClaims: []string{"family_name"}}, wantError: true},
		{name: "explicit empty selection denies all", options: &sdjwtvc.SdJwtVcPresentationOptions{LimitDisclosureToSelectedClaims: true}, wantError: true},
		{name: "typed nil defaults safely"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSDJWTPresentationFixture(t)
			holder := fixture.key.PublicKey()
			fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
			uri := presentationURI(fixture.baseURL, `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`)
			var options serializerTypes.SerializePresentationOptions = tc.options
			var before sdjwtvc.SdJwtVcPresentationOptions
			if tc.options != nil {
				before = *tc.options
			}
			_, err := fixture.wallet.PresentCredential(uri, fixture.key, options)
			if tc.options != nil {
				require.Equal(t, before, *tc.options)
			}
			if tc.wantError {
				require.Error(t, err)
				select {
				case <-fixture.posted:
					t.Fatal("caller denial was ignored")
				default:
				}
				return
			}
			require.NoError(t, err)
			var tokens map[string][]string
			require.NoError(t, json.Unmarshal([]byte((<-fixture.posted).Get("vp_token")), &tokens))
			require.Equal(t, []string{"given_name"}, disclosedNames(t, tokens["pid"][0]))
		})
	}
}

func TestWallet_DCQLDoesNotSubmitWhenLaterCredentialCannotBind(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	otherHolder := newMockKeyEntry().PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	fixture.receive("urn:test:address", &otherHolder, nil, map[string]string{"street_address": "1 Example St"})
	uri := presentationURI(fixture.baseURL, `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},{"id":"address","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:address"]},"claims":[{"path":["street_address"]}]}]}`)
	_, err := fixture.wallet.PresentCredential(uri, fixture.key, nil)
	require.ErrorContains(t, err, "signing key does not match")
	select {
	case <-fixture.posted:
		t.Fatal("partially serialized response was submitted")
	default:
	}
}

func TestWallet_DCQLIntegerValuesSurviveReceiveAndPresentation(t *testing.T) {
	for _, selective := range []bool{false, true} {
		for _, requested := range []string{"9007199254740993", "9007199254740992"} {
			t.Run(fmt.Sprintf("selective=%t/request=%s", selective, requested), func(t *testing.T) {
				fixture := newSDJWTPresentationFixture(t)
				holder := fixture.key.PublicKey()
				claims := map[string]any{"account_number": int64(9007199254740993)}
				if selective {
					fixture.receiveValues("urn:test:identity", &holder, nil, claims)
				} else {
					fixture.receiveValues("urn:test:identity", &holder, claims, nil)
				}
				query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["account_number"],"values":[` + requested + `]}]}]}`
				_, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
				if requested != "9007199254740993" {
					require.Error(t, err)
					select {
					case <-fixture.posted:
						t.Fatal("different integer value was submitted")
					default:
					}
					return
				}
				require.NoError(t, err)
				select {
				case <-fixture.posted:
				default:
					t.Fatal("exact integer value was not submitted")
				}
			})
		}
	}
}

func TestWallet_DCQLUnboundCredentialIsSkipped(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", nil, nil, map[string]string{"given_name": "Unbound"})

	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`
	_, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
	var authzErr *oid4vp.AuthorizationRequestError
	require.ErrorAs(t, err, &authzErr)
	require.Equal(t, oid4vp.AccessDeniedError, authzErr.Code)

	// A bound credential for the same query must be selected instead.
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Bound"})
	redirect, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)
	select {
	case form := <-fixture.posted:
		var tokens map[string][]string
		require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
		require.Len(t, tokens["pid"], 1)
	default:
		t.Fatal("no presentation submitted")
	}
}

func TestWallet_DCQLMultiplePresentsEveryMatch(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Hanako"})

	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"multiple":true}]}`
	redirect, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)
	select {
	case form := <-fixture.posted:
		var tokens map[string][]string
		require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
		require.Len(t, tokens["pid"], 2)
	default:
		t.Fatal("no presentation submitted")
	}
}

func TestWallet_DCQLNestedClaimDisclosureMinimality(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	encodeDisclosure := func(name, value string) (string, string) {
		raw, err := json.Marshal([]any{"salt-" + name, name, value})
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		digest := sha256.Sum256([]byte(encoded))
		return encoded, base64.RawURLEncoding.EncodeToString(digest[:])
	}
	postal, postalHash := encodeDisclosure("postal_code", "12345")
	city, cityHash := encodeDisclosure("city", "Milliways")

	payload := map[string]any{
		"iss": "https://issuer.example", "vct": "urn:test:identity",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		"cnf":     map[string]any{"jwk": holder},
		"address": map[string]any{"_sd": []any{postalHash, cityHash}},
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: issuerKey}, (&jose.SignerOptions{}).WithType("dc+sd-jwt"))
	require.NoError(t, err)
	signed, err := jwt.Signed(signer).Claims(payload).Serialize()
	require.NoError(t, err)
	wire := signed + "~" + postal + "~" + city + "~"
	require.NoError(t, fixture.wallet.credStore.SaveCredentialEntry(credstoreTypes.CredentialEntry{
		Id: uuid.NewString(), ReceivedAt: time.Now(), Raw: []byte(wire), MimeType: string(credential.SDJwtVC),
	}, credstoreTypes.SupportedCredStoreTypes(0)))

	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["address","postal_code"]}]}]}`
	redirect, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)
	select {
	case form := <-fixture.posted:
		var tokens map[string][]string
		require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
		require.Len(t, tokens["pid"], 1)
		require.Equal(t, []string{"postal_code"}, disclosedNames(t, tokens["pid"][0]))
	default:
		t.Fatal("no presentation submitted")
	}
}

func TestWallet_DCQLUnsatisfiableIsAccessDenied(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:missing"]}}]}`
	_, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
	var authzErr *oid4vp.AuthorizationRequestError
	require.ErrorAs(t, err, &authzErr)
	require.Equal(t, oid4vp.AccessDeniedError, authzErr.Code)
}

func TestWallet_ConfigPropagatesTransactionDataTypes(t *testing.T) {
	controller, err := NewWalletWithConfig(Config{SupportedTransactionDataTypes: []string{"example"}})
	require.NoError(t, err)
	var finalPresenter *oid4vp.Oid4vpPresenter
	for _, plugin := range controller.presenter.Plugins() {
		if candidate, ok := plugin.(*oid4vp.Oid4vpPresenter); ok {
			finalPresenter = candidate
		}
	}
	require.NotNil(t, finalPresenter)
	require.Equal(t, []string{"example"}, finalPresenter.SupportedTransactionDataTypes)
}

func TestWallet_SubmitHandlesTransactionData(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})

	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	metadata := &oid4vp.VerifierMetadata{
		Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &recipient.PublicKey, KeyID: "enc", Use: "enc", Algorithm: string(jose.ECDH_ES),
		}}},
		EncryptedResponseEncValuesSupported: []string{"A256GCM"},
	}
	transactionData := base64.RawURLEncoding.EncodeToString([]byte(`{"type":"example","credential_ids":["pid"]}`))
	req := &oid4vp.CredentialPresentationRequest{
		OAuthAuthzRequest: &oid4vp.OAuthAuthzRequest{
			ResponseType: "vp_token", ClientID: "redirect_uri:" + fixture.baseURL + "/response",
			Nonce: "n", State: "s", ResponseMode: oid4vp.OAuthAuthzReqResponseModeDirectPostJWT,
			RedirectURI: fixture.baseURL + "/response",
		},
		DcqlQuery: &oid4vp.DcqlQuery{Credentials: []oid4vp.CredentialQuery{{
			ID: "pid", Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{"urn:test:identity"}},
			Claims: []oid4vp.DCQLClaimQuery{{Path: []any{"given_name"}}},
		}}},
		ClientMetadata:           metadata,
		TransactionData:          []string{transactionData},
		TransactionDataHashesAlg: "sha-384",
		ResponseURI:              fixture.baseURL + "/response",
	}
	endpoint, err := url.Parse(fixture.baseURL + "/response")
	require.NoError(t, err)
	_, err = fixture.wallet.SubmitOID4VPFinalAuthorizationRequest(req, *endpoint, fixture.key)
	require.NoError(t, err)

	select {
	case form := <-fixture.posted:
		jwe, err := jose.ParseEncrypted(form.Get("response"), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
		require.NoError(t, err)
		plaintext, err := jwe.Decrypt(recipient)
		require.NoError(t, err)
		var payload struct {
			VPToken map[string][]string `json:"vp_token"`
		}
		require.NoError(t, json.Unmarshal(plaintext, &payload))
		wire := payload.VPToken["pid"][0]
		kbJWT := wire[strings.LastIndex(wire, "~")+1:]
		parts := strings.Split(kbJWT, ".")
		require.Len(t, parts, 3)
		claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)
		var claims map[string]any
		require.NoError(t, json.Unmarshal(claimsBytes, &claims))
		require.Equal(t, "sha-384", claims["transaction_data_hashes_alg"])
		hashes, ok := claims["transaction_data_hashes"].([]any)
		require.True(t, ok)
		require.Len(t, hashes, 1)
		expected := sha512.Sum384([]byte(transactionData))
		require.Equal(t, base64.RawURLEncoding.EncodeToString(expected[:]), hashes[0])
	default:
		t.Fatal("no encrypted response submitted")
	}
}
