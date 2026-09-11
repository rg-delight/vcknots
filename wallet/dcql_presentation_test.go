package wallet

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
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
