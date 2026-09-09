package oid4vp

import "fmt"

// DCQLCredentialCandidate describes a wallet credential that may satisfy a DCQL request.
type DCQLCredentialCandidate struct {
	ID     string
	Format string
	VCT    string
	Claims []string
}

// DCQLCredentialSelection describes the concrete wallet credential and claims
// selected for one DCQL credential query.
type DCQLCredentialSelection struct {
	QueryID         string
	CandidateID     string
	Format          string
	VCT             string
	RequestedClaims []string
}

func ResolveSatisfiableDCQLCredentials(query *DCQLQuery, candidates []DCQLCredentialCandidate) ([]DCQLCredentialSelection, error) {
	if query == nil {
		return nil, fmt.Errorf("dcql_query is required")
	}
	if len(query.Credentials) == 0 {
		return nil, fmt.Errorf("dcql_query.credentials must not be empty")
	}

	satisfiable := map[string]DCQLCredentialSelection{}
	for _, credentialQuery := range query.Credentials {
		selection, ok := resolveDCQLCredentialQuery(credentialQuery, candidates)
		if ok {
			satisfiable[credentialQuery.ID] = selection
		}
	}

	if len(query.CredentialSets) == 0 {
		selections := make([]DCQLCredentialSelection, 0, len(satisfiable))
		for _, credentialQuery := range query.Credentials {
			if selection, ok := satisfiable[credentialQuery.ID]; ok {
				selections = append(selections, selection)
			}
		}
		return selections, nil
	}

	selected := map[string]DCQLCredentialSelection{}
	for _, credentialSet := range query.CredentialSets {
		matchingOption := []string(nil)
		for _, option := range credentialSet.Options {
			if everyDCQLCredentialIDSatisfiable(option, satisfiable) {
				matchingOption = option
				break
			}
		}
		if matchingOption == nil {
			if credentialSet.Required == nil || *credentialSet.Required {
				return nil, fmt.Errorf("required DCQL credential_set cannot be satisfied")
			}
			continue
		}
		for _, queryID := range matchingOption {
			selected[queryID] = satisfiable[queryID]
		}
	}

	selections := make([]DCQLCredentialSelection, 0, len(selected))
	for _, credentialQuery := range query.Credentials {
		if selection, ok := selected[credentialQuery.ID]; ok {
			selections = append(selections, selection)
		}
	}
	return selections, nil
}

func resolveDCQLCredentialQuery(query DCQLCredentialQuery, candidates []DCQLCredentialCandidate) (DCQLCredentialSelection, bool) {
	requestedClaims, ok := requestedDCQLClaimNames(query)
	if !ok {
		return DCQLCredentialSelection{}, false
	}
	for _, candidate := range candidates {
		if candidate.Format != query.Format {
			continue
		}
		vctValues, validMeta := dcqlVCTValues(query.Meta)
		if !validMeta || (len(vctValues) > 0 && !containsString(vctValues, candidate.VCT)) {
			continue
		}
		if !everyStringContained(requestedClaims, candidate.Claims) {
			continue
		}
		return DCQLCredentialSelection{
			QueryID:         query.ID,
			CandidateID:     candidate.ID,
			Format:          candidate.Format,
			VCT:             candidate.VCT,
			RequestedClaims: requestedClaims,
		}, true
	}
	return DCQLCredentialSelection{}, false
}

func requestedDCQLClaimNames(query DCQLCredentialQuery) ([]string, bool) {
	claims := make([]string, 0, len(query.Claims))
	for _, claim := range query.Claims {
		if len(claim.Path) != 1 || claim.Path[0] == "" {
			return nil, false
		}
		claims = append(claims, claim.Path[0])
	}
	return claims, true
}

func everyDCQLCredentialIDSatisfiable(ids []string, satisfiable map[string]DCQLCredentialSelection) bool {
	if len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if _, ok := satisfiable[id]; !ok {
			return false
		}
	}
	return true
}

func everyStringContained(needles []string, haystack []string) bool {
	for _, needle := range needles {
		if !containsString(haystack, needle) {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// dcqlVCTValues handles both a directly constructed Go query and decoded JSON.
func dcqlVCTValues(meta map[string]any) ([]string, bool) {
	raw, exists := meta["vct_values"]
	if !exists {
		return nil, true
	}
	switch values := raw.(type) {
	case []string:
		return values, true
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, false
			}
			result = append(result, text)
		}
		return result, true
	default:
		return nil, false
	}
}
