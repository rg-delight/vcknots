package oid4vp

import "testing"

func TestResolveSatisfiableDCQLCredentials(t *testing.T) {
	query := &DCQLQuery{
		Credentials: []DCQLCredentialQuery{
			{
				ID:     "pid",
				Format: "dc+sd-jwt",
				Meta:   &DCQLCredentialMeta{VctValues: []string{"urn:eudi:pid:1"}},
				Claims: []DCQLClaimQuery{
					{Path: []string{"given_name"}},
					{Path: []string{"family_name"}},
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
				Claims: []DCQLClaimQuery{{Path: []string{"given_name"}}},
			},
			{
				ID:     "address",
				Format: "dc+sd-jwt",
				Claims: []DCQLClaimQuery{{Path: []string{"street_address"}}},
			},
			{
				ID:     "optional_email",
				Format: "dc+sd-jwt",
				Claims: []DCQLClaimQuery{{Path: []string{"email"}}},
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
				Claims: []DCQLClaimQuery{{Path: []string{"given_name"}}},
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
