package wallet

import (
	"encoding/json"
	"maps"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
)

// fixtureCredStore is any real credential store, used only to prove that a
// storeless wallet refuses one.
func fixtureCredStore(t *testing.T) *credstore.CredStoreDispatcher {
	t.Helper()
	storage, err := local.NewLocalCredentialStorage(t.TempDir() + "/credentials.db")
	require.NoError(t, err)
	store, err := credstore.NewCredStoreDispatcher(credstore.WithPlugin(local.Local, storage))
	require.NoError(t, err)
	return store
}

// storelessPresentationWallet is the wallet under test in this file: it holds no
// credential store at all and presents only what the caller names by value.
func storelessPresentationWallet(t *testing.T, fixture sdjwtPresentationFixture) *Wallet {
	t.Helper()
	wallet, err := NewWalletWithoutStore(Config{Presenter: fixture.wallet.presenter})
	require.NoError(t, err)
	require.Nil(t, wallet.credStore)
	return wallet
}

// heldCredential lifts one credential out of the fixture's store so the
// storeless wallet can be handed it by value, the way an application that keeps
// its own credentials would.
func heldCredential(t *testing.T, fixture sdjwtPresentationFixture, vct string) credstoreTypes.CredentialEntry {
	t.Helper()
	entries, _, err := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{Offset: 0, Limit: nil})
	require.NoError(t, err)
	for _, entry := range entries {
		if len(entry.Credential.Types) > 0 && entry.Credential.Types[0] == vct {
			return *entry.Entry
		}
	}
	t.Fatalf("no stored credential with vct %q", vct)
	return credstoreTypes.CredentialEntry{}
}

// heldCredentialWithClaim is heldCredential for a wallet holding several
// credentials of one vct, told apart by one claim value.
func heldCredentialWithClaim(t *testing.T, fixture sdjwtPresentationFixture, name, value string) credstoreTypes.CredentialEntry {
	t.Helper()
	entries, _, err := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{Offset: 0, Limit: nil})
	require.NoError(t, err)
	for _, entry := range entries {
		if entry.Credential.Claims != nil && (*entry.Credential.Claims)[name] == value {
			return *entry.Entry
		}
	}
	t.Fatalf("no stored credential with %s %q", name, value)
	return credstoreTypes.CredentialEntry{}
}

// postedVPToken returns the vp_token the fixture's Verifier received.
func postedVPToken(t *testing.T, fixture sdjwtPresentationFixture) map[string][]string {
	t.Helper()
	select {
	case form := <-fixture.posted:
		var tokens map[string][]string
		require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
		return tokens
	default:
		t.Fatal("no presentation submitted")
		return nil
	}
}

// A Holder answers a consent screen in disclosure names. The kept names choose
// one claim set of the query (OID4VP 1.0 Section 6.4.1), and only that set is
// disclosed.
func TestWallet_PresentDCQLHolderSelectionDisclosesTheHoldersClaims(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
	credential := heldCredential(t, fixture, "urn:test:identity")
	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},` +
		`"claims":[{"id":"given","path":["given_name"]},{"id":"family","path":["family_name"]}],"claim_sets":[["given","family"],["given"]]}]}`
	req, endpoint := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, query))

	redirect, err := storelessPresentationWallet(t, fixture).PresentDCQLHolderSelection(
		req, endpoint, fixture.key,
		[]DCQLHolderSelection{{QueryIDs: []string{"pid"}, Credential: credential, DisclosedClaims: []string{"given_name"}}},
		nil,
	)
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)
	tokens := postedVPToken(t, fixture)
	require.Len(t, tokens["pid"], 1)
	require.Equal(t, []string{"given_name"}, disclosedNames(t, tokens["pid"][0]))
}

// Section 6.4.1: "If the Wallet cannot deliver all claims requested by the
// Verifier according to these rules, it MUST NOT return the respective
// Credential." Withholding part of the only claim set is refusing the query.
func TestWallet_PresentDCQLHolderSelectionRefusesAPartialClaimSet(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},` +
		`"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]}`
	req, endpoint := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, query))

	_, err := storelessPresentationWallet(t, fixture).PresentDCQLHolderSelection(
		req, endpoint, fixture.key,
		[]DCQLHolderSelection{{QueryIDs: []string{"pid"}, Credential: heldCredential(t, fixture, "urn:test:identity"), DisclosedClaims: []string{"given_name"}}},
		nil,
	)
	require.ErrorIs(t, err, oid4vp.ErrDCQLSelectionUnsatisfied)
	select {
	case <-fixture.posted:
		t.Fatal("a partial claim set was disclosed")
	default:
	}
}

// The response carries exactly the Holder's (query, credential) choices: a
// credential chosen for one query is not also sent for an optional query it
// happens to satisfy.
func TestWallet_PresentDCQLHolderSelectionSendsOnlyTheChosenQueries(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
	query := `{"credentials":[` +
		`{"id":"given","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},` +
		`{"id":"family","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["family_name"]}]}],` +
		`"credential_sets":[{"options":[["given"]]},{"required":false,"options":[["family"]]}]}`
	req, endpoint := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, query))

	_, err := storelessPresentationWallet(t, fixture).PresentDCQLHolderSelection(
		req, endpoint, fixture.key,
		[]DCQLHolderSelection{{QueryIDs: []string{"given"}, Credential: heldCredential(t, fixture, "urn:test:identity")}},
		nil,
	)
	require.NoError(t, err)
	tokens := postedVPToken(t, fixture)
	require.Equal(t, []string{"given"}, slices.Collect(maps.Keys(tokens)))
	require.Equal(t, []string{"given_name"}, disclosedNames(t, tokens["given"][0]))
}

// With multiple false a query takes one credential, and which one is the
// Holder's choice: when two chosen credentials both satisfy a query, the one
// the Holder named for it is presented, not the first that matches.
func TestWallet_PresentDCQLHolderSelectionPresentsTheChosenCandidate(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Hanako"})
	query := `{"credentials":[` +
		`{"id":"first","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},` +
		`{"id":"second","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`
	req, endpoint := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, query))

	_, err := storelessPresentationWallet(t, fixture).PresentDCQLHolderSelection(
		req, endpoint, fixture.key,
		[]DCQLHolderSelection{
			{QueryIDs: []string{"second"}, Credential: heldCredentialWithClaim(t, fixture, "given_name", "Taro")},
			{QueryIDs: []string{"first"}, Credential: heldCredentialWithClaim(t, fixture, "given_name", "Hanako")},
		},
		nil,
	)
	require.NoError(t, err)
	tokens := postedVPToken(t, fixture)
	require.Len(t, tokens["first"], 1)
	require.Len(t, tokens["second"], 1)
	require.Contains(t, tokens["first"][0], disclosureFor(t, fixture, "Hanako"))
	require.Contains(t, tokens["second"][0], disclosureFor(t, fixture, "Taro"))
}

// A nil DisclosedClaims is the Holder agreeing to the claim set the query asked
// for, which is what a consent screen with nothing to deselect means.
func TestWallet_PresentDCQLHolderSelectionDisclosesTheWholeClaimSetByDefault(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
	credential := heldCredential(t, fixture, "urn:test:identity")
	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},` +
		`"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]}`
	req, endpoint := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, query))

	_, err := storelessPresentationWallet(t, fixture).PresentDCQLHolderSelection(
		req, endpoint, fixture.key,
		[]DCQLHolderSelection{{QueryIDs: []string{"pid"}, Credential: credential}},
		nil,
	)
	require.NoError(t, err)

	select {
	case form := <-fixture.posted:
		var tokens map[string][]string
		require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
		require.ElementsMatch(t, []string{"given_name", "family_name"}, disclosedNames(t, tokens["pid"][0]))
	default:
		t.Fatal("no presentation submitted")
	}
}

// The satisfiability gate belongs to the library: a choice the request cannot
// accept must fail before anything is serialized.
func TestWallet_PresentDCQLHolderSelectionRejectsUnsatisfyingChoices(t *testing.T) {
	twoQueries := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},` +
		`{"id":"address","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:address"]},"claims":[{"path":["street_address"]}]}]}`
	oneQuery := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`
	for _, testCase := range []struct {
		name       string
		query      string
		selections func(identity, address credstoreTypes.CredentialEntry) []DCQLHolderSelection
	}{
		{
			name:  "credential the credential query does not accept",
			query: oneQuery,
			selections: func(_, address credstoreTypes.CredentialEntry) []DCQLHolderSelection {
				return []DCQLHolderSelection{{QueryIDs: []string{"pid"}, Credential: address}}
			},
		},
		{
			name:  "required credential query left unanswered",
			query: twoQueries,
			selections: func(identity, _ credstoreTypes.CredentialEntry) []DCQLHolderSelection {
				return []DCQLHolderSelection{{QueryIDs: []string{"pid"}, Credential: identity}}
			},
		},
		{
			name:  "nothing answered at all",
			query: oneQuery,
			selections: func(_, _ credstoreTypes.CredentialEntry) []DCQLHolderSelection {
				return nil
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newSDJWTPresentationFixture(t)
			holder := fixture.key.PublicKey()
			fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
			fixture.receive("urn:test:address", &holder, nil, map[string]string{"street_address": "1 Example St"})
			req, endpoint := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, testCase.query))

			_, err := storelessPresentationWallet(t, fixture).PresentDCQLHolderSelection(
				req, endpoint, fixture.key,
				testCase.selections(heldCredential(t, fixture, "urn:test:identity"), heldCredential(t, fixture, "urn:test:address")),
				nil,
			)
			require.Error(t, err)
			select {
			case <-fixture.posted:
				t.Fatal("a rejected selection still disclosed credentials")
			default:
			}
		})
	}
}

// OID4VP 1.0 Section 6.4.2 lets the Holder decline a credential_set whose
// `required` is false, and Section 8.1 carries that as the empty vp_token
// object. CredentialSetQuery.IsRequired is what makes the default true.
func TestWallet_PresentDCQLHolderSelectionSendsTheEmptyVPToken(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}],` +
		`"credential_sets":[{"options":[["pid"]],"required":false}]}`
	req, endpoint := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, query))

	redirect, err := storelessPresentationWallet(t, fixture).PresentDCQLHolderSelection(req, endpoint, fixture.key, nil, nil)
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)

	select {
	case form := <-fixture.posted:
		require.Equal(t, "{}", form.Get("vp_token"))
	default:
		t.Fatal("no presentation submitted")
	}
}

// A credential that names no credential query cannot be placed in the vp_token,
// which is keyed by credential query id.
func TestWallet_PresentDCQLHolderSelectionRequiresACredentialQueryID(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`
	req, endpoint := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, query))

	_, err := storelessPresentationWallet(t, fixture).PresentDCQLHolderSelection(
		req, endpoint, fixture.key,
		[]DCQLHolderSelection{{Credential: heldCredential(t, fixture, "urn:test:identity")}},
		nil,
	)
	require.ErrorContains(t, err, "names no credential query")
}

// A Presentation Exchange selection carries its credential by value on the same
// storeless wallet, so the Draft24 path needs no store either.
func TestWallet_PresentDraft24SelectionFromAStorelessWallet(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
	credential := heldCredential(t, fixture, "urn:test:identity")
	request, err := fixture.wallet.presenter.ParseDraft24RequestURI(draft24PresentationURI(fixture.baseURL, "direct_post", ""))
	require.NoError(t, err)
	endpoint, err := url.Parse(fixture.baseURL + "/response")
	require.NoError(t, err)

	redirect, err := storelessPresentationWallet(t, fixture).PresentDraft24Selection(
		request, *endpoint, fixture.key,
		[]Draft24CredentialSelection{{CredentialID: credential.Id, Credential: &credential, InputDescriptorIDs: []string{"identity"}}},
		nil,
	)
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)

	select {
	case form := <-fixture.posted:
		require.NotEmpty(t, form.Get("vp_token"))
	default:
		t.Fatal("no presentation submitted")
	}
}

// A storeless wallet has nothing to read a credential out of, and says so.
func TestWallet_StorelessWalletHasNoCredentialStore(t *testing.T) {
	wallet, err := NewWalletWithoutStore(Config{})
	require.NoError(t, err)

	_, _, err = wallet.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.ErrorIs(t, err, ErrNoCredentialStore)
	_, err = wallet.GetCredentialEntry("any")
	require.ErrorIs(t, err, ErrNoCredentialStore)

	_, err = NewWalletWithConfig(Config{Storeless: true, CredStore: fixtureCredStore(t)})
	require.ErrorContains(t, err, "storeless wallet cannot be configured with a credential store")
}

// The two sides of a consent screen name a claim differently: the Holder
// answers with disclosure names, while a claim set resolves to bare names and
// JSON claims path pointers. A set is chosen only when every claim in it,
// nested or array-indexed, was kept.
func TestHolderClaimSetMatchesDisclosureNames(t *testing.T) {
	sets := [][]string{{"given_name", `["address","locality"]`}, {`["nationalities",1]`}}

	chosen, ok := holderClaimSet(sets, nil)
	require.True(t, ok)
	require.Equal(t, sets[0], chosen)
	chosen, ok = holderClaimSet(sets, []string{"given_name", "locality"})
	require.True(t, ok)
	require.Equal(t, sets[0], chosen)
	chosen, ok = holderClaimSet(sets, []string{"locality", "nationalities"})
	require.True(t, ok)
	require.Equal(t, sets[1], chosen)
	_, ok = holderClaimSet(sets, []string{"locality"})
	require.False(t, ok)
}

// disclosureFor returns the stored disclosure of the credential whose
// given_name is value, which appears verbatim in any presentation of it.
func disclosureFor(t *testing.T, fixture sdjwtPresentationFixture, value string) string {
	t.Helper()
	raw := string(heldCredentialWithClaim(t, fixture, "given_name", value).Raw)
	parts := strings.Split(raw, "~")
	require.GreaterOrEqual(t, len(parts), 2)
	return parts[1]
}
