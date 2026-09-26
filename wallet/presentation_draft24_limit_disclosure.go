package wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
)

// ErrLimitDisclosureUnsatisfiable reports a Draft 24 presentation that cannot
// honour an input descriptor's limit_disclosure "required" (DIF Presentation
// Exchange 2.0, Input Descriptor Object: "the Conformant Consumer MUST limit
// submitted fields to those listed in the fields array"): a credential format
// that cannot disclose selectively (a JWT or Data Integrity W3C VC, presented
// whole), disclosed claims beyond the listed fields, or a field path this
// library cannot map to a disclosure. Nothing is sent. Presentation Exchange
// lets a Wallet that cannot limit disclosure "return nothing (or cease the
// interaction with the Verifier)"; presenting the whole credential is not
// among the choices.
var ErrLimitDisclosureUnsatisfiable = common.NewCodedError("limit_disclosure_unsatisfiable", "the credential cannot limit disclosure to the fields the input descriptor lists")

// draft24InputDescriptor is the part of a Presentation Exchange input
// descriptor that limits disclosure.
type draft24InputDescriptor struct {
	ID          string `json:"id"`
	Constraints struct {
		LimitDisclosure string `json:"limit_disclosure"`
		Fields          []struct {
			Path []string `json:"path"`
		} `json:"fields"`
	} `json:"constraints"`
}

// draft24DisclosureLimits applies limit_disclosure "required" to the
// selections of a Draft 24 presentation: for each selection answering such a
// descriptor it returns the disclosure names the presentation may carry, nil
// for a selection no required descriptor constrains. A caller's
// DisclosedClaims must stay within them; without DisclosedClaims the
// presentation discloses exactly the listed fields the credential holds.
func draft24DisclosureLimits(rawDefinition json.RawMessage, selections []CredentialSelection, credentials []resolvedCredential) ([][]string, error) {
	var definition struct {
		InputDescriptors []draft24InputDescriptor `json:"input_descriptors"`
	}
	if len(rawDefinition) == 0 {
		return make([][]string, len(selections)), nil
	}
	if err := json.Unmarshal(rawDefinition, &definition); err != nil {
		return nil, fmt.Errorf("%w: presentation_definition: %w", ErrInvalidArgument, err)
	}
	limits := make([][]string, len(selections))
	for index, selection := range selections {
		required, allowed := false, []string{}
		for _, descriptor := range definition.InputDescriptors {
			if !slices.Contains(selection.QueryIDs, descriptor.ID) || descriptor.Constraints.LimitDisclosure != "required" {
				continue
			}
			required = true
			for _, field := range descriptor.Constraints.Fields {
				for _, path := range field.Path {
					// The listed claim and the claims enclosing it: a nested
					// selectively disclosable claim is reachable only through
					// the disclosure of its parent (RFC 9901, recursive disclosures).
					names, ok := jsonPathMemberNames(path)
					if !ok {
						return nil, fmt.Errorf("%w: input descriptor %q lists the path %q, which names no claim this library can disclose alone", ErrLimitDisclosureUnsatisfiable, descriptor.ID, path)
					}
					for _, name := range names {
						if !slices.Contains(allowed, name) {
							allowed = append(allowed, name)
						}
					}
				}
			}
		}
		if !required {
			continue
		}
		presented := credentials[index]
		flavor, err := presented.saved.Entry.SerializationFlavor()
		if err != nil || flavor != credential.SDJwtVC {
			return nil, fmt.Errorf("%w: credential %q is a %s credential, which is presented whole", ErrLimitDisclosureUnsatisfiable, presented.id, flavor)
		}
		if selection.DisclosedClaims != nil {
			for _, name := range selection.DisclosedClaims {
				if !slices.Contains(allowed, name) {
					return nil, fmt.Errorf("%w: credential %q would disclose %q, which no field of its input descriptors lists", ErrLimitDisclosureUnsatisfiable, presented.id, name)
				}
			}
			limits[index] = slices.Clone(selection.DisclosedClaims)
			continue
		}
		held := sdJWTDisclosureNames(presented.saved.Entry.Raw)
		limited := []string{}
		for _, name := range allowed {
			if slices.Contains(held, name) {
				limited = append(limited, name)
			}
		}
		limits[index] = limited
	}
	return limits, nil
}

// jsonPathLeafName returns the last member name of a JSONPath expression of
// the forms Presentation Exchange fields use - $.a.b, $['a'], $["a"], with
// array indexes or wildcards - which is the name of the disclosure that
// carries the claim. A filter or script expression names no claim.
func jsonPathLeafName(path string) (string, bool) {
	names, ok := jsonPathMemberNames(path)
	if !ok {
		return "", false
	}
	return names[len(names)-1], true
}

// jsonPathMemberNames returns the member names of such a JSONPath expression
// in order, the claim itself last. Array element disclosures (RFC 9901) carry
// no name and are not selected by one.
func jsonPathMemberNames(path string) ([]string, bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(path), "$")
	if !found {
		return nil, false
	}
	var names []string
	name := ""
	for rest != "" {
		switch {
		case strings.HasPrefix(rest, "["):
			end := strings.Index(rest, "]")
			if end < 0 {
				return nil, false
			}
			inner := strings.TrimSpace(rest[1:end])
			rest = rest[end+1:]
			switch {
			case len(inner) >= 2 && (inner[0] == '\'' || inner[0] == '"') && inner[len(inner)-1] == inner[0]:
				name = inner[1 : len(inner)-1]
				names = append(names, name)
			case inner == "*" || isJSONPathIndex(inner):
			default:
				return nil, false
			}
		case strings.HasPrefix(rest, "."):
			rest = strings.TrimLeft(rest, ".")
			end := strings.IndexAny(rest, ".[")
			if end < 0 {
				end = len(rest)
			}
			segment := rest[:end]
			rest = rest[end:]
			if segment == "" || strings.ContainsAny(segment, "?()@") {
				return nil, false
			}
			if segment != "*" {
				name = segment
				names = append(names, name)
			}
		default:
			return nil, false
		}
	}
	return names, name != ""
}

func isJSONPathIndex(text string) bool {
	if text == "" {
		return false
	}
	for _, character := range strings.TrimPrefix(text, "-") {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// sdJWTDisclosureNames returns the claim names of the object property
// disclosures of an SD-JWT (RFC 9901: [salt, name, value]).
func sdJWTDisclosureNames(raw []byte) []string {
	parts := strings.Split(string(raw), "~")
	names := []string{}
	for _, part := range parts[1:] {
		decoded, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			continue
		}
		var disclosure []any
		if json.Unmarshal(decoded, &disclosure) != nil || len(disclosure) != 3 {
			continue
		}
		if name, ok := disclosure[1].(string); ok && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}
