package oid4vp

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// DCQLCredentialCandidate describes a wallet credential that may satisfy a DCQL request.
type DCQLCredentialCandidate struct {
	ID     string
	Format string
	VCT    string
	Claims []string
	// ClaimValues contains the actual top-level claim values used for values
	// restrictions. Existing callers can omit it for queries without values;
	// a restricted claim with no supplied value cannot satisfy the query.
	// Supply json.Number for integers beyond the exact float range.
	ClaimValues map[string]any
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

	ids := map[string]bool{}
	claimOptions := map[string][][]DCQLClaimQuery{}
	for _, credentialQuery := range query.Credentials {
		if !credentialQueryIDPattern.MatchString(credentialQuery.ID) || ids[credentialQuery.ID] {
			return nil, fmt.Errorf("DCQL credential query ids must be valid and unique")
		}
		ids[credentialQuery.ID] = true
		options, err := dcqlClaimOptions(credentialQuery)
		if err != nil {
			return nil, err
		}
		claimOptions[credentialQuery.ID] = options
	}
	if query.CredentialSets != nil && len(query.CredentialSets) == 0 {
		return nil, fmt.Errorf("DCQL credential_sets must not be empty")
	}
	for _, set := range query.CredentialSets {
		if err := validateDCQLTypedOptions(set.Options, ids, false); err != nil {
			return nil, fmt.Errorf("invalid DCQL credential_set: %w", err)
		}
	}

	satisfiable := map[string]DCQLCredentialSelection{}
	for _, credentialQuery := range query.Credentials {
		selection, ok := resolveDCQLCredentialQuery(credentialQuery, claimOptions[credentialQuery.ID], candidates)
		if ok {
			satisfiable[credentialQuery.ID] = selection
		}
	}

	if len(query.CredentialSets) == 0 {
		selections := make([]DCQLCredentialSelection, 0, len(satisfiable))
		for _, credentialQuery := range query.Credentials {
			if selection, ok := satisfiable[credentialQuery.ID]; ok {
				selections = append(selections, selection)
			} else {
				return nil, fmt.Errorf("required DCQL credential query %q cannot be satisfied", credentialQuery.ID)
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

func resolveDCQLCredentialQuery(query DCQLCredentialQuery, claimOptions [][]DCQLClaimQuery, candidates []DCQLCredentialCandidate) (DCQLCredentialSelection, bool) {
	vctValues, validMeta := dcqlVCTValues(query.Meta)
	if !validMeta {
		return DCQLCredentialSelection{}, false
	}
	// Prefer the first satisfiable claim set across all candidates, rather than
	// selecting a later claim set merely because its credential appeared first.
	for _, claims := range claimOptions {
		for _, candidate := range candidates {
			if candidate.Format != query.Format || (len(vctValues) > 0 && !containsString(vctValues, candidate.VCT)) {
				continue
			}
			requestedClaims, ok := matchDCQLClaims(claims, candidate)
			if !ok {
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
	}
	return DCQLCredentialSelection{}, false
}

func matchDCQLClaims(claimQueries []DCQLClaimQuery, candidate DCQLCredentialCandidate) ([]string, bool) {
	claims := make([]string, 0, len(claimQueries))
	for _, claim := range claimQueries {
		if len(claim.Path) != 1 || claim.Path[0] == "" {
			return nil, false
		}
		name := claim.Path[0]
		if !containsString(candidate.Claims, name) {
			return nil, false
		}
		if claim.Values != nil {
			value, exists := candidate.ClaimValues[name]
			matches := false
			for _, expected := range claim.Values {
				if exists && dcqlClaimValuesEqual(value, expected) {
					matches = true
					break
				}
			}
			if !matches {
				return nil, false
			}
		}
		if !containsString(claims, name) {
			claims = append(claims, name)
		}
	}
	return claims, true
}

func dcqlClaimOptions(query DCQLCredentialQuery) ([][]DCQLClaimQuery, error) {
	if query.Claims != nil && len(query.Claims) == 0 {
		return nil, fmt.Errorf("DCQL claims must not be empty")
	}
	if query.Claims == nil && query.ClaimSets != nil {
		return nil, fmt.Errorf("DCQL claim_sets requires claims")
	}
	ids := map[string]bool{}
	byID := map[string]DCQLClaimQuery{}
	for _, claim := range query.Claims {
		if claim.ID != "" || query.ClaimSets != nil {
			if !credentialQueryIDPattern.MatchString(claim.ID) || ids[claim.ID] {
				return nil, fmt.Errorf("DCQL claim ids must be valid and unique")
			}
			ids[claim.ID] = true
			byID[claim.ID] = claim
		}
		if len(claim.Path) == 0 || (claim.Values != nil && len(claim.Values) == 0) {
			return nil, fmt.Errorf("DCQL claim paths and values must not be empty")
		}
		for _, value := range claim.Values {
			if !isDCQLClaimValue(value) {
				return nil, fmt.Errorf("DCQL values must be strings, integers or booleans")
			}
		}
	}
	if query.ClaimSets == nil {
		return [][]DCQLClaimQuery{query.Claims}, nil
	}
	if err := validateDCQLTypedOptions(query.ClaimSets, ids, true); err != nil {
		return nil, fmt.Errorf("invalid DCQL claim_sets: %w", err)
	}
	options := make([][]DCQLClaimQuery, 0, len(query.ClaimSets))
	for _, option := range query.ClaimSets {
		claims := make([]DCQLClaimQuery, 0, len(option))
		for _, id := range option {
			claims = append(claims, byID[id])
		}
		options = append(options, claims)
	}
	return options, nil
}

func validateDCQLTypedOptions(options [][]string, ids map[string]bool, allowEmptyOption bool) error {
	if len(options) == 0 {
		return fmt.Errorf("options must not be empty")
	}
	for _, option := range options {
		if option == nil {
			return fmt.Errorf("each option must be an array, not null")
		}
		if !allowEmptyOption && len(option) == 0 {
			return fmt.Errorf("each option must not be empty")
		}
		for _, id := range option {
			if !ids[id] {
				return fmt.Errorf("option references undefined identifier %q", id)
			}
		}
	}
	return nil
}

func isDCQLClaimValue(value any) bool {
	switch value.(type) {
	case string, bool:
		return true
	default:
		_, ok := dcqlIntegerValue(value)
		return ok
	}
}

func dcqlClaimValuesEqual(actual, expected any) bool {
	switch expected := expected.(type) {
	case string:
		actual, ok := actual.(string)
		return ok && actual == expected
	case bool:
		actual, ok := actual.(bool)
		return ok && actual == expected
	default:
		expectedNumber, validExpected := dcqlIntegerValue(expected)
		actualNumber, validActual := dcqlIntegerValue(actual)
		return validExpected && validActual && expectedNumber == actualNumber
	}
}

// dcqlIntegerValue returns an exact coefficient/exponent representation of a
// JSON integer. Decimal exponents stay symbolic, so a short wire value such as
// 1e1000000000 never allocates a billion-digit integer. json.Number avoids
// rounding large input integers through float64.
func dcqlIntegerValue(value any) (string, bool) {
	switch number := value.(type) {
	case float64:
		// A decoder may already have rounded a large integer. Such a value
		// cannot safely prove equality with the original credential claim.
		if number < -(1<<53-1) || number > 1<<53-1 {
			return "", false
		}
	case float32:
		if number < -(1<<24-1) || number > 1<<24-1 {
			return "", false
		}
	case json.Number, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
	default:
		return "", false
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	mantissa := string(encoded)
	exponent := new(big.Int)
	if i := strings.IndexAny(mantissa, "eE"); i >= 0 {
		if _, ok := exponent.SetString(mantissa[i+1:], 10); !ok {
			return "", false
		}
		mantissa = mantissa[:i]
	}
	negative := strings.HasPrefix(mantissa, "-")
	mantissa = strings.TrimPrefix(mantissa, "-")
	if i := strings.IndexByte(mantissa, '.'); i >= 0 {
		exponent.Sub(exponent, big.NewInt(int64(len(mantissa)-i-1)))
		mantissa = mantissa[:i] + mantissa[i+1:]
	}
	mantissa = strings.TrimLeft(mantissa, "0")
	if mantissa == "" {
		return "0", true
	}
	coefficient := strings.TrimRight(mantissa, "0")
	exponent.Add(exponent, big.NewInt(int64(len(mantissa)-len(coefficient))))
	if exponent.Sign() < 0 {
		return "", false
	}
	if negative {
		coefficient = "-" + coefficient
	}
	return coefficient + "e" + exponent.String(), true
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
