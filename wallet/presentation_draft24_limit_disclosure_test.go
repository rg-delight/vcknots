package wallet

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
)

// limitedDefinition asks for the identity credential with limit_disclosure
// "required" and one listed field.
const limitedDefinition = `{"id":"limited","input_descriptors":[{"id":"identity","format":{"vc+sd-jwt":{}},` +
	`"constraints":{"limit_disclosure":"required","fields":[{"path":["$.given_name"]}]}}]}`

func limitedDisclosureURI(baseURL, definition string) string {
	return "openid4vp://present?" + url.Values{
		"client_id":               {"redirect_uri:" + baseURL + "/response"},
		"response_uri":            {baseURL + "/response"},
		"response_type":           {"vp_token"},
		"response_mode":           {"direct_post"},
		"nonce":                   {"presentation-nonce"},
		"presentation_definition": {definition},
	}.Encode()
}

// DIF Presentation Exchange 2.0, Input Descriptor Object, limit_disclosure
// "required": "the Conformant Consumer MUST limit submitted fields to those
// listed in the fields array". The library's own choice left DisclosedClaims
// nil, which disclosed every claim of an SD-JWT VC (CX-VP A01); it now
// discloses the listed fields only, and refuses a caller disclosure beyond
// them before anything is sent.
func TestWallet_Draft24LimitDisclosureRequired(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
	request := parseDraft24(t, fixture.wallet, limitedDisclosureURI(fixture.baseURL, limitedDefinition))

	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, selections)
	require.NoError(t, err)
	form := <-fixture.posted
	require.Equal(t, []string{"given_name"}, disclosedNames(t, form.Get("vp_token")))

	id := draft24SelectionCredentialIDs(t, fixture)["urn:test:identity"]
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
		{CredentialID: id, QueryIDs: []string{"identity"}, DisclosedClaims: []string{"given_name", "family_name"}},
	})
	require.ErrorIs(t, err, ErrLimitDisclosureUnsatisfiable)
	select {
	case <-fixture.posted:
		t.Fatal("a presentation beyond the listed fields was sent")
	default:
	}

	// A descriptor without limit_disclosure keeps the caller's choice.
	unlimited := `{"id":"open","input_descriptors":[{"id":"identity","format":{"vc+sd-jwt":{}},"constraints":{"fields":[{"path":["$.given_name"]}]}}]}`
	request = parseDraft24(t, fixture.wallet, limitedDisclosureURI(fixture.baseURL, unlimited))
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
		{CredentialID: id, QueryIDs: []string{"identity"}, DisclosedClaims: []string{"given_name", "family_name"}},
	})
	require.NoError(t, err)
	form = <-fixture.posted
	require.ElementsMatch(t, []string{"given_name", "family_name"}, disclosedNames(t, form.Get("vp_token")))
}

// A JWT or Data Integrity W3C VC is presented whole, so it cannot limit
// disclosure; Presentation Exchange lets the Wallet "return nothing".
func TestWallet_Draft24LimitDisclosureRequiredRefusesAWholeCredential(t *testing.T) {
	controller, key := receiveCredentialForPresentationTest(t)
	entries, _, err := controller.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	definition := `{"id":"limited","input_descriptors":[{"id":"d1","constraints":{"limit_disclosure":"required","fields":[{"path":["$.credentialSubject.name"]}]}}]}`
	req := &oid4vp.CredentialPresentationRequest{
		OAuthAuthzRequest:         &oid4vp.OAuthAuthzRequest{ResponseType: "vp_token", ClientID: "redirect_uri:https://verifier.example/response", Nonce: "n"},
		PresentationDefinition:    &oid4vp.PresentationDefinition{ID: "limited"},
		RawPresentationDefinition: json.RawMessage(definition),
	}
	selections := []CredentialSelection{{CredentialID: entries[0].Entry.Id, QueryIDs: []string{"d1"}}}
	credentials, err := controller.resolveSelections(selections, key)
	require.NoError(t, err)
	_, err = draft24DisclosureLimits(req.RawPresentationDefinition, selections, credentials)
	require.ErrorIs(t, err, ErrLimitDisclosureUnsatisfiable)
}

func TestJSONPathLeafName(t *testing.T) {
	for path, want := range map[string]string{
		"$.given_name":                       "given_name",
		"$.address.street_address":           "street_address",
		"$['given_name']":                    "given_name",
		`$["address"]["locality"]`:           "locality",
		"$.nationalities[0]":                 "nationalities",
		"$.nationalities[*]":                 "nationalities",
		"$..birthdate":                       "birthdate",
		"$.vc.credentialSubject.family_name": "family_name",
		"$.credentialSubject.degree.type":    "type",
	} {
		name, ok := jsonPathLeafName(path)
		require.True(t, ok, path)
		require.Equal(t, want, name, path)
	}
	names, ok := jsonPathMemberNames("$.address['locality'][0]")
	require.True(t, ok)
	require.Equal(t, []string{"address", "locality"}, names)
	for _, path := range []string{"", "given_name", "$", "$.*", "$[?(@.age > 18)]", "$.a[", "$.a[b]"} {
		_, ok := jsonPathLeafName(path)
		require.False(t, ok, path)
	}
}

// A nested selectively disclosable claim is reachable only through its
// parent's disclosure (RFC 9901, recursive disclosures), so a required
// $.address.city discloses address and city - and nothing else.
func TestWallet_Draft24LimitDisclosureRequiredKeepsTheParentOfANestedClaim(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	given, givenHash := sdDisclosure(t, "salt-given", "given_name", "Taro")
	postal, postalHash := sdDisclosure(t, "salt-postal", "postal_code", "12345")
	city, cityHash := sdDisclosure(t, "salt-city", "city", "Milliways")
	address, addressHash := sdDisclosure(t, "salt-address", "address", map[string]any{"_sd": []any{postalHash, cityHash}})
	storeSDJWT(t, fixture, map[string]any{"_sd": []any{givenHash, addressHash}}, given, address, postal, city)
	definition := `{"id":"limited","input_descriptors":[{"id":"identity","format":{"vc+sd-jwt":{}},` +
		`"constraints":{"limit_disclosure":"required","fields":[{"path":["$.address.city"]}]}}]}`
	request := parseDraft24(t, fixture.wallet, limitedDisclosureURI(fixture.baseURL, definition))
	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, selections)
	require.NoError(t, err)
	form := <-fixture.posted
	require.ElementsMatch(t, []string{"address", "city"}, disclosedNames(t, form.Get("vp_token")))
}
