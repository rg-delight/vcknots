package oid4vp

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
)

func TestResolveSatisfiableDCQLCredentials(t *testing.T) {
	query := &DCQLQuery{
		Credentials: []DCQLCredentialQuery{
			{
				ID:     "pid",
				Format: "dc+sd-jwt",
				Meta:   map[string]any{"vct_values": []string{"urn:eudi:pid:1"}},
				Claims: []DCQLClaimQuery{
					{Path: []any{"given_name"}},
					{Path: []any{"family_name"}},
				},
			},
		},
	}
	candidates := []DCQLCredentialCandidate{
		{
			ID:     "wallet-credential-1",
			Format: "dc+sd-jwt",
			VCT:    "urn:eudi:pid:1",
			Claims: []string{"given_name", "family_name", "birthdate"},
		},
	}

	selections, err := ResolveSatisfiableDCQLCredentials(query, candidates)
	if err != nil {
		t.Fatalf("ResolveSatisfiableDCQLCredentials() error = %v", err)
	}
	if len(selections) != 1 {
		t.Fatalf("expected one selection, got %#v", selections)
	}
	selection := selections[0]
	if selection.QueryID != "pid" || selection.CandidateID != "wallet-credential-1" {
		t.Fatalf("selection IDs = %#v", selection)
	}
	if got := selection.RequestedClaims; len(got) != 2 || got[0] != "given_name" || got[1] != "family_name" {
		t.Fatalf("requested claims = %#v", got)
	}
}

func TestResolveSatisfiableDCQLCredentials_CredentialSets(t *testing.T) {
	required := true
	optional := false
	query := &DCQLQuery{
		Credentials: []DCQLCredentialQuery{
			{
				ID:     "pid",
				Format: "dc+sd-jwt",
				Claims: []DCQLClaimQuery{{Path: []any{"given_name"}}},
			},
			{
				ID:     "address",
				Format: "dc+sd-jwt",
				Claims: []DCQLClaimQuery{{Path: []any{"street_address"}}},
			},
			{
				ID:     "optional_email",
				Format: "dc+sd-jwt",
				Claims: []DCQLClaimQuery{{Path: []any{"email"}}},
			},
		},
		CredentialSets: []DCQLCredentialSet{
			{Required: &required, Options: [][]string{{"pid", "address"}, {"pid"}}},
			{Required: &optional, Options: [][]string{{"optional_email"}}},
		},
	}
	candidates := []DCQLCredentialCandidate{
		{ID: "wallet-pid", Format: "dc+sd-jwt", Claims: []string{"given_name"}},
	}

	selections, err := ResolveSatisfiableDCQLCredentials(query, candidates)
	if err != nil {
		t.Fatalf("ResolveSatisfiableDCQLCredentials() error = %v", err)
	}
	if len(selections) != 1 || selections[0].QueryID != "pid" {
		t.Fatalf("expected required fallback option to select pid only, got %#v", selections)
	}
}

func TestResolveSatisfiableDCQLCredentials_RequiredCredentialSetFailure(t *testing.T) {
	query := &DCQLQuery{
		Credentials: []DCQLCredentialQuery{
			{
				ID:     "pid",
				Format: "dc+sd-jwt",
				Claims: []DCQLClaimQuery{{Path: []any{"given_name"}}},
			},
		},
		CredentialSets: []DCQLCredentialSet{
			{Options: [][]string{{"pid"}}},
		},
	}

	_, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{
		{ID: "wallet-pid", Format: "dc+sd-jwt", Claims: []string{"family_name"}},
	})
	if err == nil {
		t.Fatal("expected required credential_set failure")
	}
}

func TestResolveDCQLClaimSetPreference(t *testing.T) {
	query, err := parseDcqlQuery(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},"claims":[{"id":"age","path":["age_over_18"],"values":[true]},{"id":"birth","path":["birthdate"]}],"claim_sets":[["age"],["birth"]]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name              string
		candidates        []DCQLCredentialCandidate
		wantID, wantClaim string
	}{
		{"first available option discloses only age", []DCQLCredentialCandidate{{ID: "both", Format: "dc+sd-jwt", Claims: []string{"age_over_18", "birthdate"}, ClaimValues: map[string]any{"age_over_18": true}}}, "both", "age_over_18"},
		{"fallback after value mismatch", []DCQLCredentialCandidate{{ID: "both", Format: "dc+sd-jwt", Claims: []string{"age_over_18", "birthdate"}, ClaimValues: map[string]any{"age_over_18": false}}}, "both", "birthdate"},
		{"fallback after missing claim", []DCQLCredentialCandidate{{ID: "birth", Format: "dc+sd-jwt", Claims: []string{"birthdate"}}}, "birth", "birthdate"},
		{"preferred option across candidates", []DCQLCredentialCandidate{{ID: "birth", Format: "dc+sd-jwt", Claims: []string{"birthdate"}}, {ID: "age", Format: "dc+sd-jwt", Claims: []string{"age_over_18"}, ClaimValues: map[string]any{"age_over_18": true}}}, "age", "age_over_18"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected, err := ResolveSatisfiableDCQLCredentials(query, tc.candidates)
			if err != nil || len(selected) != 1 {
				t.Fatalf("selection = %#v, %v", selected, err)
			}
			if selected[0].CandidateID != tc.wantID || !reflect.DeepEqual(selected[0].RequestedClaims, []string{tc.wantClaim}) {
				t.Fatalf("selection = %#v, want %s / %s", selected, tc.wantID, tc.wantClaim)
			}
		})
	}
	selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{{ID: "pid", Format: "dc+sd-jwt", Claims: []string{"age_over_18"}, ClaimValues: map[string]any{"age_over_18": false}}})
	if err == nil || len(selected) != 0 {
		t.Fatalf("unsatisfied claim sets returned a credential: %#v, %v", selected, err)
	}
}

func TestResolveDCQLEmptyClaimSetFallback(t *testing.T) {
	typed := &DCQLQuery{Credentials: []DCQLCredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt",
		Claims:    []DCQLClaimQuery{{ID: "age", Path: []any{"age_over_18"}, Values: []any{true}}},
		ClaimSets: [][]string{{"age"}, {}},
	}}}
	parsed, err := parseDcqlQuery(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},"claims":[{"id":"age","path":["age_over_18"],"values":[true]}],"claim_sets":[["age"],[]]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []struct {
		name  string
		query *DCQLQuery
	}{{"typed", typed}, {"raw", parsed}} {
		for _, ageOver18 := range []bool{true, false} {
			name := "empty fallback"
			wantClaims := []string{}
			if ageOver18 {
				name = "preferred age claim"
				wantClaims = []string{"age_over_18"}
			}
			t.Run(source.name+"/"+name, func(t *testing.T) {
				selected, err := ResolveSatisfiableDCQLCredentials(source.query, []DCQLCredentialCandidate{{
					ID: "identity", Format: "dc+sd-jwt", Claims: []string{"age_over_18", "birthdate"},
					ClaimValues: map[string]any{"age_over_18": ageOver18, "birthdate": "2000-01-01"},
				}})
				if err != nil || len(selected) != 1 {
					t.Fatalf("claim set selection = %#v, %v", selected, err)
				}
				if !reflect.DeepEqual(selected[0].RequestedClaims, wantClaims) {
					t.Fatalf("selected claims = %#v, want %#v", selected[0].RequestedClaims, wantClaims)
				}
			})
		}
	}
}

func TestResolveDCQLValuesRequireExactPrimitiveMatch(t *testing.T) {
	for _, tc := range []struct {
		name             string
		actual, expected any
		match            bool
	}{
		{"string", "Alice", "Alice", true},
		{"string case differs", "ALICE", "Alice", false},
		{"number is not string", 18, "18", false},
		{"string is not number", "18", 18, false},
		{"boolean", true, true, true},
		{"boolean differs", false, true, false},
		{"number is not boolean", 1, true, false},
		{"boolean is not number", true, 1, false},
		{"decoded integer", float64(18), 18, true},
		{"int64", int64(18), json.Number("18"), true},
		{"uint64", uint64(18446744073709551615), json.Number("18446744073709551615"), true},
		{"large integer exact", json.Number("9007199254740993"), json.Number("9007199254740993"), true},
		{"large integers do not round", json.Number("9007199254740992"), json.Number("9007199254740993"), false},
		{"rounded float cannot prove original integer", float64(9007199254740993), json.Number("9007199254740992"), false},
		{"rounded float32 cannot prove original integer", float32(16777217), json.Number("16777216"), false},
		{"fractional actual", 18.5, 18, false},
		{"object actual", map[string]any{"age": 18}, 18, false},
		{"null actual", nil, 18, false},
		{"float32", float32(18), 18, true},
		{"NaN", math.NaN(), 18, false},
		{"infinity", math.Inf(1), 18, false},
		{"negative zero", json.Number("-0.0"), 0, true},
		{"integer exponent", json.Number("18e3"), 18000, true},
		{"integer decimal", json.Number("18.000"), 18, true},
		{"huge exponent stays symbolic", json.Number("10e999999999"), json.Number("1e1000000000"), true},
		{"small fractional exponent", json.Number("1e-1000000000"), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := &DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{Path: []any{"value"}, Values: []any{tc.expected}}}}}}
			candidates := []DCQLCredentialCandidate{{ID: "value", Format: "dc+sd-jwt", Claims: []string{"value"}, ClaimValues: map[string]any{"value": tc.actual}}}
			selected, err := ResolveSatisfiableDCQLCredentials(query, candidates)
			if tc.match {
				if err != nil || len(selected) != 1 {
					t.Fatalf("matching value rejected: %#v, %v", selected, err)
				}
			} else if err == nil || len(selected) != 0 {
				t.Fatalf("nonmatching value disclosed: %#v, %v", selected, err)
			}
		})
	}
}

func TestResolveDCQLMissingValueFailsClosed(t *testing.T) {
	query := &DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{Path: []any{"name"}, Values: []any{"Alice", "Bob"}}}}}}
	candidate := DCQLCredentialCandidate{ID: "pid", Format: "dc+sd-jwt", Claims: []string{"name"}}
	if selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{candidate}); err == nil || len(selected) != 0 {
		t.Fatalf("claim name alone satisfied value restriction: %#v, %v", selected, err)
	}
	candidate.ClaimValues = map[string]any{"name": "Bob"}
	if selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{candidate}); err != nil || len(selected) != 1 {
		t.Fatalf("second expected value did not match: %#v, %v", selected, err)
	}
}

func TestResolveDCQLRequiredQueriesAreAtomic(t *testing.T) {
	query := &DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "available", Format: "dc+sd-jwt"}, {ID: "missing", Format: "jwt_vc_json"}}}
	selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{{ID: "pid", Format: "dc+sd-jwt"}})
	if err == nil || len(selected) != 0 {
		t.Fatalf("incomplete required query set returned credentials: %#v, %v", selected, err)
	}
}

func TestResolveDCQLValidatesDirectCallerConstraints(t *testing.T) {
	optional := false
	for _, tc := range []struct {
		name  string
		query DCQLQuery
	}{
		{"duplicate query id", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}, {ID: "pid", Format: "dc+sd-jwt"}}}},
		{"invalid query id", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "bad id", Format: "dc+sd-jwt"}}}},
		{"empty claims", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{}}}}},
		{"empty values", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{Path: []any{"name"}, Values: []any{}}}}}}},
		{"fractional value", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{Path: []any{"name"}, Values: []any{1.5}}}}}}},
		{"missing path", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{ID: "n"}}}}}},
		{"missing claim id", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{Path: []any{"name"}}}, ClaimSets: [][]string{{"n"}}}}}},
		{"duplicate claim id", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{ID: "n", Path: []any{"name"}}, {ID: "n", Path: []any{"birth"}}}}}}},
		{"empty claim sets", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", ClaimSets: [][]string{}}}}},
		{"claim sets without claims", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", ClaimSets: [][]string{{"n"}}}}}},
		{"empty claim set without claims", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", ClaimSets: [][]string{{}}}}}},
		{"null claim set", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{ID: "n", Path: []any{"name"}}}, ClaimSets: [][]string{nil}}}}},
		{"empty credential sets", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}}, CredentialSets: []DCQLCredentialSet{}}},
		{"empty optional credential option", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}}, CredentialSets: []DCQLCredentialSet{{Required: &optional, Options: [][]string{{}}}}}},
		{"unknown optional credential reference", DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt"}}, CredentialSets: []DCQLCredentialSet{{Required: &optional, Options: [][]string{{"unknown"}}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected, err := ResolveSatisfiableDCQLCredentials(&tc.query, []DCQLCredentialCandidate{{ID: "pid", Format: "dc+sd-jwt", Claims: []string{"name"}}})
			if err == nil || len(selected) != 0 {
				t.Fatalf("invalid constraints returned credentials: %#v, %v", selected, err)
			}
		})
	}
}

func TestResolveDCQLNestedClaimDoesNotBecomeRootClaim(t *testing.T) {
	query, err := parseDcqlQuery(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{},"claims":[{"path":["address","name"]}]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{{ID: "pid", Format: "dc+sd-jwt", Claims: []string{"name", "address"}}})
	if err == nil || len(selected) != 0 {
		t.Fatalf("unsupported path returned credentials: %#v, %v", selected, err)
	}
}

func TestResolveDCQLRepeatedClaimPathDisclosesOnce(t *testing.T) {
	query := &DCQLQuery{Credentials: []DCQLCredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Claims: []DCQLClaimQuery{{Path: []any{"name"}}, {Path: []any{"name"}}}}}}
	selected, err := ResolveSatisfiableDCQLCredentials(query, []DCQLCredentialCandidate{{ID: "pid", Format: "dc+sd-jwt", Claims: []string{"name"}}})
	if err != nil || len(selected) != 1 || !reflect.DeepEqual(selected[0].RequestedClaims, []string{"name"}) {
		t.Fatalf("duplicate claim paths were not deduplicated: %#v, %v", selected, err)
	}
}
