// Package profile selects the OpenID4VP protocol policy a caller wants the
// library to enforce. HAIP is a set of constraints on top of OpenID4VP 1.0
// Final, not a new wire protocol, so it is expressed as a policy value chosen
// per operation rather than as a separate plugin.
package profile

import "fmt"

// Profile is an explicit OpenID4VP protocol policy.
type Profile string

const (
	// Final is OpenID4VCI 1.0 / OpenID4VP 1.0 without additional constraints.
	Final Profile = "final"
	// HAIP is HAIP 1.0 constraints on top of Final.
	HAIP Profile = "haip"
)

// Normalize returns Final for the zero value and an error for unknown values.
func (p Profile) Normalize() (Profile, error) {
	switch p {
	case "":
		return Final, nil
	case Final:
		return Final, nil
	case HAIP:
		return HAIP, nil
	default:
		return "", fmt.Errorf("unknown OID4VP profile %q", string(p))
	}
}

// IsHAIP reports whether this profile is HAIP. Unknown and zero values are not
// HAIP; callers must Normalize first when they need a validated value.
func (p Profile) IsHAIP() bool {
	return p == HAIP
}
