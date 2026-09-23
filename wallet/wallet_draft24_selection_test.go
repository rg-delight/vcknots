package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

// draft24PresentationDefinition answers two input descriptors so the caller's
// per-descriptor choice is observable in descriptor_map.
const draft24PresentationDefinition = `{"id":"definition-1","input_descriptors":[{"id":"identity"},{"id":"address"}]}`

func draft24PresentationURI(baseURL, responseMode, clientMetadata string) string {
	params := url.Values{
		"client_id":               {"redirect_uri:" + baseURL + "/response"},
		"response_uri":            {baseURL + "/response"},
		"response_type":           {"vp_token"},
		"response_mode":           {responseMode},
		"nonce":                   {"presentation-nonce"},
		"state":                   {"state-to-preserve"},
		"presentation_definition": {draft24PresentationDefinition},
	}
	if clientMetadata != "" {
		params.Set("client_metadata", clientMetadata)
	}
	return "openid4vp://present?" + params.Encode()
}

func draft24SelectionCredentialIDs(t *testing.T, fixture sdjwtPresentationFixture) map[string]string {
	t.Helper()
	entries, _, err := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{Offset: 0, Limit: nil})
	require.NoError(t, err)
	byVCT := map[string]string{}
	for _, entry := range entries {
		require.NotEmpty(t, entry.Credential.Types)
		byVCT[entry.Credential.Types[0]] = entry.Entry.Id
	}
	return byVCT
}

// The Holder's per-input-descriptor choice must reach descriptor_map, and each
// selected credential must carry its own disclosure selection: the previous
// single-credential PresentDraft24Credential could express neither.
func TestWallet_PresentDraft24SelectionUsesCallerChoice(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
	fixture.receive("urn:test:address", &holder, nil, map[string]string{"street_address": "1 Example St", "postal_code": "100-0000"})
	ids := draft24SelectionCredentialIDs(t, fixture)

	request, err := fixture.wallet.presenter.ParseDraft24RequestURI(draft24PresentationURI(fixture.baseURL, "direct_post", ""))
	require.NoError(t, err)
	endpoint, err := url.Parse(fixture.baseURL + "/response")
	require.NoError(t, err)

	redirect, err := fixture.wallet.PresentDraft24Selection(request, *endpoint, fixture.key, []Draft24CredentialSelection{
		{
			CredentialID:       ids["urn:test:identity"],
			InputDescriptorIDs: []string{"identity"},
			Options:            &sdjwtvc.SdJwtVcPresentationOptions{SelectedClaims: []string{"given_name"}, LimitDisclosureToSelectedClaims: true, RequireKeyBinding: true},
		},
		{
			CredentialID:       ids["urn:test:address"],
			InputDescriptorIDs: []string{"address"},
			Options:            &sdjwtvc.SdJwtVcPresentationOptions{SelectedClaims: []string{"postal_code"}, LimitDisclosureToSelectedClaims: true, RequireKeyBinding: true},
		},
	}, nil)
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)

	form := <-fixture.posted
	require.Equal(t, "state-to-preserve", form.Get("state"))
	var tokens []string
	require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
	require.Len(t, tokens, 2)
	require.Equal(t, []string{"given_name"}, disclosedNames(t, tokens[0]))
	require.Equal(t, []string{"postal_code"}, disclosedNames(t, tokens[1]))

	var submission presenterTypes.PresentationSubmission
	require.NoError(t, json.Unmarshal([]byte(form.Get("presentation_submission")), &submission))
	require.Equal(t, "definition-1", submission.DefinitionID)
	require.Len(t, submission.DescriptorMap, 2)
	require.Equal(t, "identity", submission.DescriptorMap[0].ID)
	require.Equal(t, "dc+sd-jwt", submission.DescriptorMap[0].Format)
	require.Equal(t, "$[0]", submission.DescriptorMap[0].Path)
	require.Equal(t, "address", submission.DescriptorMap[1].ID)
	require.Equal(t, "$[1]", submission.DescriptorMap[1].Path)
}

// A single selection keeps the vp_token a bare presentation at path "$", which
// is what every existing Draft24 verifier of this fork reads.
func TestWallet_PresentDraft24SelectionSingleCredentialKeepsRootPath(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	ids := draft24SelectionCredentialIDs(t, fixture)

	request, err := fixture.wallet.presenter.ParseDraft24RequestURI(draft24PresentationURI(fixture.baseURL, "direct_post", ""))
	require.NoError(t, err)
	endpoint, err := url.Parse(fixture.baseURL + "/response")
	require.NoError(t, err)

	var options serializerTypes.SerializePresentationOptions = &sdjwtvc.SdJwtVcPresentationOptions{SelectedClaims: []string{"given_name"}, LimitDisclosureToSelectedClaims: true, RequireKeyBinding: true}
	_, err = fixture.wallet.PresentDraft24Selection(request, *endpoint, fixture.key, []Draft24CredentialSelection{
		{CredentialID: ids["urn:test:identity"], InputDescriptorIDs: []string{"identity"}},
	}, options)
	require.NoError(t, err)

	form := <-fixture.posted
	require.NotContains(t, form.Get("vp_token"), "[")
	require.Equal(t, []string{"given_name"}, disclosedNames(t, form.Get("vp_token")))
	var submission presenterTypes.PresentationSubmission
	require.NoError(t, json.Unmarshal([]byte(form.Get("presentation_submission")), &submission))
	require.Len(t, submission.DescriptorMap, 1)
	require.Equal(t, "$", submission.DescriptorMap[0].Path)
}

// response_mode=direct_post.jwt must encrypt, send the JWE alone, and carry
// presentation_submission as a JSON object rather than the legacy
// double-encoded string (OID4VP 1.0 Section 8.3).
func TestWallet_PresentDraft24SelectionEncryptsDirectPostJWT(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	ids := draft24SelectionCredentialIDs(t, fixture)

	verifierKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &verifierKey.PublicKey, KeyID: "recipient", Use: "enc", Algorithm: "ECDH-ES"}}})
	require.NoError(t, err)
	clientMetadata := `{"jwks":` + string(jwks) + `,"encrypted_response_enc_values_supported":["A256GCM"],"authorization_encrypted_response_alg":"ECDH-ES","authorization_encrypted_response_enc":"A256GCM"}`

	request, err := fixture.wallet.presenter.ParseDraft24RequestURI(draft24PresentationURI(fixture.baseURL, "direct_post.jwt", clientMetadata))
	require.NoError(t, err)
	endpoint, err := url.Parse(fixture.baseURL + "/response")
	require.NoError(t, err)

	_, err = fixture.wallet.PresentDraft24Selection(request, *endpoint, fixture.key, []Draft24CredentialSelection{
		{CredentialID: ids["urn:test:identity"], InputDescriptorIDs: []string{"identity"}},
	}, &sdjwtvc.SdJwtVcPresentationOptions{SelectedClaims: []string{"given_name"}, LimitDisclosureToSelectedClaims: true, RequireKeyBinding: true})
	require.NoError(t, err)

	form := <-fixture.posted
	require.Len(t, form, 1)
	require.NotEmpty(t, form.Get("response"))
	jwe, err := jose.ParseEncrypted(form.Get("response"), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	require.NoError(t, err)
	plaintext, err := jwe.Decrypt(verifierKey)
	require.NoError(t, err)
	payload := map[string]any{}
	require.NoError(t, json.Unmarshal(plaintext, &payload))
	require.Equal(t, "state-to-preserve", payload["state"])
	require.IsType(t, "", payload["vp_token"])
	submission, ok := payload["presentation_submission"].(map[string]any)
	require.True(t, ok, "presentation_submission must be a JSON object, got %#v", payload["presentation_submission"])
	require.Equal(t, "definition-1", submission["definition_id"])
}

// An unknown credential id must not be silently skipped: the descriptor_map
// would then describe credentials the wallet never sent.
func TestWallet_PresentDraft24SelectionRejectsUnknownCredential(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})

	request, err := fixture.wallet.presenter.ParseDraft24RequestURI(draft24PresentationURI(fixture.baseURL, "direct_post", ""))
	require.NoError(t, err)
	endpoint, err := url.Parse(fixture.baseURL + "/response")
	require.NoError(t, err)

	_, err = fixture.wallet.PresentDraft24Selection(request, *endpoint, fixture.key, []Draft24CredentialSelection{
		{CredentialID: "not-stored", InputDescriptorIDs: []string{"identity"}},
	}, nil)
	require.ErrorContains(t, err, "not stored in this wallet")
	select {
	case <-fixture.posted:
		t.Fatal("an unresolvable selection disclosed credentials")
	default:
	}
}

// A Presentation Exchange vp_token cannot express "no credential"; only the
// DCQL response object can, so an empty selection is refused before any POST.
func TestWallet_PresentDraft24SelectionRejectsEmptySelection(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	request := &oid4vp.CredentialPresentationRequest{PresentationDefinition: &oid4vp.PresentationDefinition{ID: "definition-1"}}
	endpoint, err := url.Parse(fixture.baseURL + "/response")
	require.NoError(t, err)
	_, err = fixture.wallet.PresentDraft24Selection(request, *endpoint, fixture.key, nil, nil)
	require.ErrorContains(t, err, "at least one credential selection is required")
}

// buildDraft24DescriptorMap decides two things the vp_token shape depends on:
// an SD-JWT VC Presentation holds one credential, so several of them are a JSON
// array the path indexes, while a JWT Verifiable Presentation holds them all and
// stays a single token at "$" whose path_nested distinguishes them.
func TestBuildDraft24DescriptorMapPathsFollowTheVPTokenShape(t *testing.T) {
	wallet := &Wallet{}
	credentials := []*SavedCredential{{}, {}}
	for _, tc := range []struct {
		name       string
		flavor     credential.SupportedSerializationFlavor
		paths      []string
		nested     []string
		vpFormat   string
		descriptor [][]string
		wantIDs    []string
	}{
		{
			name:       "sd-jwt vc indexes the vp_token array",
			flavor:     credential.SDJwtVC,
			paths:      []string{"$[0]", "$[0]", "$[1]"},
			vpFormat:   "dc+sd-jwt",
			descriptor: [][]string{{"identity", "identity-backup"}, {"address"}},
			wantIDs:    []string{"identity", "identity-backup", "address"},
		},
		{
			name:       "jwt vc indexes inside one presentation",
			flavor:     credential.JwtVc,
			paths:      []string{"$", "$", "$"},
			nested:     []string{"$.vp.verifiableCredential[0]", "$.vp.verifiableCredential[0]", "$.vp.verifiableCredential[1]"},
			vpFormat:   "jwt_vp_json",
			descriptor: [][]string{{"identity", "identity-backup"}, {"address"}},
			wantIDs:    []string{"identity", "identity-backup", "address"},
		},
		{
			name:       "ldp vp indexes the presentation itself",
			flavor:     credential.LdpVc,
			paths:      []string{"$", "$", "$"},
			nested:     []string{"$.verifiableCredential[0]", "$.verifiableCredential[0]", "$.verifiableCredential[1]"},
			vpFormat:   "ldp_vp",
			descriptor: [][]string{{"identity", "identity-backup"}, {"address"}},
			wantIDs:    []string{"identity", "identity-backup", "address"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flavor := tc.flavor
			descriptorMap, err := wallet.buildDraft24DescriptorMap(credentials, &flavor, tc.descriptor)
			require.NoError(t, err)
			require.Len(t, descriptorMap, len(tc.wantIDs))
			for index, item := range descriptorMap {
				require.Equal(t, tc.wantIDs[index], item.ID)
				require.Equal(t, tc.vpFormat, item.Format)
				require.Equal(t, tc.paths[index], item.Path)
				if len(tc.nested) == 0 {
					require.Nil(t, item.PathNested)
					continue
				}
				require.NotNil(t, item.PathNested)
				require.Equal(t, tc.nested[index], item.PathNested.Path)
				require.Equal(t, tc.wantIDs[index], item.PathNested.ID)
			}
		})
	}
}

// An entry without caller descriptor ids keeps the legacy invented id, so the
// single-credential PresentDraft24Credential flow is unchanged.
func TestBuildDraft24DescriptorMapInventsIDWhenCallerNamesNone(t *testing.T) {
	wallet := &Wallet{}
	flavor := credential.SDJwtVC
	descriptorMap, err := wallet.buildDraft24DescriptorMap([]*SavedCredential{{}}, &flavor, nil)
	require.NoError(t, err)
	require.Len(t, descriptorMap, 1)
	require.NotEmpty(t, descriptorMap[0].ID)
	require.Equal(t, "$", descriptorMap[0].Path)
}
