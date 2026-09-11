package sdjwtvc

import (
	"fmt"
	"slices"
)

// Preserve the existing low-level name selector, including nested names. The
// caller remains responsible for resolving name ambiguity and parent disclosure
// dependencies. Final DCQL root paths use selectTopLevelDisclosures instead.
func selectDisclosuresByName(disclosures []string, algorithm string, claims []string) ([]string, error) {
	selected := []string{}
	for _, encoded := range disclosures {
		disclosure, err := parseDisclosure(encoded, algorithm)
		if err != nil {
			return nil, err
		}
		if slices.Contains(claims, disclosure.Name) {
			selected = append(selected, encoded)
		}
	}
	if len(selected) != len(claims) {
		return nil, fmt.Errorf("selected claims are missing or ambiguous")
	}
	return selected, nil
}

// SelectedClaims currently addresses top-level claim names. Match those names
// only to root digest commitments; nested claims with the same name must never
// be substituted. Plaintext claims already present in the issuer JWT need no
// disclosure. General Claims Path Pointer support is a separate capability.
func selectTopLevelDisclosures(payload map[string]any, disclosures []string, algorithm string, claims []string) ([]string, error) {
	wanted := make(map[string]bool, len(claims))
	for _, name := range claims {
		if name == "" || name == "_sd" || name == "_sd_alg" || name == "..." {
			return nil, fmt.Errorf("invalid selected claim %q", name)
		}
		_, plaintext := payload[name]
		wanted[name] = plaintext
	}
	rootDigests := map[string]bool{}
	if raw, exists := payload["_sd"]; exists {
		values, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("_sd must be an array")
		}
		for _, value := range values {
			digest, ok := value.(string)
			if !ok || digest == "" || rootDigests[digest] {
				return nil, fmt.Errorf("_sd must contain unique non-empty digests")
			}
			rootDigests[digest] = true
		}
	}
	selected := []string{}
	for _, encoded := range disclosures {
		disclosure, err := parseDisclosure(encoded, algorithm)
		if err != nil {
			return nil, fmt.Errorf("invalid disclosure: %w", err)
		}
		if !rootDigests[disclosure.Digest] {
			continue
		}
		if disclosure.IsArrayElement {
			return nil, fmt.Errorf("root object digest refers to an array disclosure")
		}
		if matched, requested := wanted[disclosure.Name]; requested {
			if matched {
				return nil, fmt.Errorf("duplicate selected claim %q", disclosure.Name)
			}
			wanted[disclosure.Name] = true
			selected = append(selected, encoded)
		}
	}
	for name, matched := range wanted {
		if !matched {
			return nil, fmt.Errorf("selected claim %q does not exist at the credential root", name)
		}
	}
	return selected, nil
}
