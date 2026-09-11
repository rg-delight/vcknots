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
	// ClaimObject is the decoded credential root object with all selectively
	// disclosable claims applied, including nested object properties and array
	// element disclosures. When non-nil it is the authoritative source for
	// claims path pointer evaluation; Claims and ClaimValues remain the legacy
	// single-segment fallback.
	ClaimObject map[string]any
	// HolderBound reports whether the credential carries a cryptographic holder
	// binding key (SD-JWT VC cnf claim). A nil value means the caller did not
	// evaluate holder binding and the credential is not excluded for backward
	// compatibility. A query that requires holder binding must not be satisfied
	// by a candidate explicitly marked unbound (OID4VP 1.0 Appendix B.3).
	HolderBound *bool
	// AuthorityKeyIDs lists the base64url-encoded Authority Key Identifiers of
	// the X.509 certificates in the credential's issuer chain. It is matched
	// against aki trusted_authorities queries (OID4VP 1.0 Section 6.1.1.1).
	AuthorityKeyIDs []string
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

	satisfiable := map[string][]DCQLCredentialSelection{}
	for _, credentialQuery := range query.Credentials {
		selections := resolveDCQLCredentialQuery(credentialQuery, claimOptions[credentialQuery.ID], candidates)
		if len(selections) > 0 {
			satisfiable[credentialQuery.ID] = selections
		}
	}

	if len(query.CredentialSets) == 0 {
		selections := make([]DCQLCredentialSelection, 0, len(satisfiable))
		for _, credentialQuery := range query.Credentials {
			if querySelections, ok := satisfiable[credentialQuery.ID]; ok {
				selections = append(selections, querySelections...)
			} else {
				return nil, fmt.Errorf("required DCQL credential query %q cannot be satisfied", credentialQuery.ID)
			}
		}
		return selections, nil
	}

	selected := map[string][]DCQLCredentialSelection{}
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
		if querySelections, ok := selected[credentialQuery.ID]; ok {
			selections = append(selections, querySelections...)
		}
	}
	return selections, nil
}

// resolveDCQLCredentialQuery returns all candidates that satisfy the query for
// the first satisfiable claim set. When query.Multiple is false only the first
// matching candidate is returned (OID4VP 1.0 Section 6.1/8.1); otherwise every
// matching candidate is returned so it can be presented separately.
func resolveDCQLCredentialQuery(query DCQLCredentialQuery, claimOptions [][]DCQLClaimQuery, candidates []DCQLCredentialCandidate) []DCQLCredentialSelection {
	vctValues, validMeta := dcqlVCTValues(query.Meta)
	if !validMeta {
		return nil
	}
	// Prefer the first satisfiable claim set across all candidates, rather than
	// selecting a later claim set merely because its credential appeared first.
	for _, claims := range claimOptions {
		selections := []DCQLCredentialSelection{}
		for _, candidate := range candidates {
			if candidate.Format != query.Format || (len(vctValues) > 0 && !containsString(vctValues, candidate.VCT)) {
				continue
			}
			if query.Format == "dc+sd-jwt" && query.RequiresHolderBinding() &&
				candidate.HolderBound != nil && !*candidate.HolderBound {
				// OID4VP 1.0 Appendix B.3: "SD-JWTs that do not support Holder
				// Binding (i.e., do not have a cnf Claim) cannot be returned in
				// this case." Treat an unbound credential as absent so another
				// credential can satisfy the query.
				continue
			}
			if !candidateMatchesTrustedAuthorities(query.TrustedAuthorities, candidate) {
				// OID4VP 1.0 Section 6.4.2: "Credentials not matching the
				// respective constraints ... are treated as if they would not
				// exist in the Wallet."
				continue
			}
			requestedClaims, ok := matchDCQLClaims(claims, candidate)
			if !ok {
				continue
			}
			selections = append(selections, DCQLCredentialSelection{
				QueryID:         query.ID,
				CandidateID:     candidate.ID,
				Format:          candidate.Format,
				VCT:             candidate.VCT,
				RequestedClaims: requestedClaims,
			})
			if !query.Multiple {
				break
			}
		}
		if len(selections) > 0 {
			return selections
		}
	}
	return nil
}

func matchDCQLClaims(claimQueries []DCQLClaimQuery, candidate DCQLCredentialCandidate) ([]string, bool) {
	claims := make([]string, 0, len(claimQueries))
	for _, claim := range claimQueries {
		elements, satisfied := candidate.selectDCQLClaimElements(claim.Path)
		if !satisfied {
			return nil, false
		}
		if claim.Values != nil {
			matches := false
			for _, value := range elements {
				for _, expected := range claim.Values {
					if dcqlClaimValuesEqual(value, expected) {
						matches = true
						break
					}
				}
				if matches {
					break
				}
			}
			if !matches {
				return nil, false
			}
		}
		encoded := encodeDCQLClaimPath(claim.Path)
		if !containsString(claims, encoded) {
			claims = append(claims, encoded)
		}
	}
	return claims, true
}

// selectDCQLClaimElements applies a claims path pointer (OID4VP 1.0 Section 7.1.1)
// to the candidate. With a decoded ClaimObject the full nested path semantics
// apply; the legacy Claims/ClaimValues representation supports one-segment
// string paths only.
func (candidate DCQLCredentialCandidate) selectDCQLClaimElements(path []any) ([]any, bool) {
	if candidate.ClaimObject != nil {
		return evaluateDCQLClaimPath(candidate.ClaimObject, path)
	}
	if len(path) != 1 {
		return nil, false
	}
	name, ok := path[0].(string)
	if !ok || name == "" || !containsString(candidate.Claims, name) {
		return nil, false
	}
	if candidate.ClaimValues == nil {
		return []any{}, true
	}
	value, exists := candidate.ClaimValues[name]
	if !exists {
		return []any{}, true
	}
	return []any{value}, true
}

// evaluateDCQLClaimPath processes a claims path pointer from left to right over
// a decoded JSON credential root. It returns the selected elements and reports
// whether any element was selected.
func evaluateDCQLClaimPath(root map[string]any, path []any) ([]any, bool) {
	current := []any{root}
	for _, component := range path {
		next := []any{}
		switch value := component.(type) {
		case string:
			for _, element := range current {
				object, ok := element.(map[string]any)
				if !ok {
					continue
				}
				if selected, exists := object[value]; exists {
					next = append(next, selected)
				}
			}
		case nil:
			for _, element := range current {
				array, ok := element.([]any)
				if !ok {
					continue
				}
				next = append(next, array...)
			}
		default:
			index, ok := dcqlPathIndex(value)
			if !ok {
				return nil, false
			}
			for _, element := range current {
				array, ok := element.([]any)
				if !ok {
					continue
				}
				if index < int64(len(array)) {
					next = append(next, array[index])
				}
			}
		}
		if len(next) == 0 {
			return nil, false
		}
		current = next
	}
	return current, true
}

// encodeDCQLClaimPath serializes a path for the serializer's disclosure
// selector. A single string component keeps its plain name for backward
// compatibility; anything else is JSON-encoded, e.g. ["address","postal_code"]
// or ["degrees",null,"type"] or ["nationalities",1].
func encodeDCQLClaimPath(path []any) string {
	if len(path) == 1 {
		if name, ok := path[0].(string); ok {
			return name
		}
	}
	encoded, err := json.Marshal(path)
	if err != nil {
		return fmt.Sprintf("%v", path)
	}
	return string(encoded)
}

// dcqlPathIndex returns a non-negative integer path component. It accepts the
// json.Number produced by the DCQL decoder and the Go integer types used by
// programmatically constructed queries.
func dcqlPathIndex(value any) (int64, bool) {
	switch number := value.(type) {
	case json.Number:
		index, err := number.Int64()
		if err != nil || index < 0 {
			return 0, false
		}
		return index, true
	case float64:
		if number < 0 || number != float64(int64(number)) {
			return 0, false
		}
		return int64(number), true
	case int:
		if number < 0 {
			return 0, false
		}
		return int64(number), true
	case int64:
		if number < 0 {
			return 0, false
		}
		return number, true
	case int32:
		if number < 0 {
			return 0, false
		}
		return int64(number), true
	default:
		return 0, false
	}
}

// candidateMatchesTrustedAuthorities applies the OID4VP 1.0 Section 6.1.1
// matching rule: a credential matches when it matches one of the values of one
// of the entries. This wallet supports the HAIP 1.0 section 5 "aki" type; other
// types cannot be evaluated and are ignored. A query whose entries are all of an
// unknown type therefore places no constraint.
func candidateMatchesTrustedAuthorities(authorities []TrustedAuthority, candidate DCQLCredentialCandidate) bool {
	if len(authorities) == 0 {
		return true
	}
	supported := 0
	for _, authority := range authorities {
		if authority.Type != "aki" {
			continue
		}
		supported++
		for _, value := range authority.Values {
			if containsString(candidate.AuthorityKeyIDs, value) {
				return true
			}
		}
	}
	return supported == 0
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

func everyDCQLCredentialIDSatisfiable(ids []string, satisfiable map[string][]DCQLCredentialSelection) bool {
	if len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		selections, ok := satisfiable[id]
		if !ok || len(selections) == 0 {
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
