// Package profile names the protocol profiles a wallet runs.
//
// A Profile is a protocol version and the constraints the wallet applies on
// top of it. The OpenID4VCI 1.0 / OpenID4VP 1.0 profiles carry those
// constraints as Options: Final adds none, and HAIP is Final with
// HAIPOptions, since HAIP 1.0 is a set of constraints on the 1.0
// specifications rather than a wire protocol of its own. The draft profiles
// (Draft13 for OpenID4VCI Draft 13, Draft24 for OpenID4VP Draft 24) name a
// protocol version and take no options.
package profile

import (
	"fmt"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
)

// Names of the base profiles, as Profile.Name reports them.
const (
	NameFinal   = "final"
	NameHAIP    = "haip"
	NameDraft13 = "draft13"
	NameDraft24 = "draft24"
)

// kind is the base profile a Profile was built from. The zero kind is Final,
// so the zero Profile is Final().
type kind uint8

const (
	kindFinal kind = iota
	kindHAIP
	kindDraft13
	kindDraft24
)

// Profile is a protocol profile. It is a comparable value: two Profiles are
// the same profile exactly when they are ==. The zero value is Final().
type Profile struct {
	kind    kind
	options Options
}

var (
	// ErrProfileMustOption reports a With that would weaken an option the
	// profile already carries. Every option of a Profile is a Must option of
	// it: HAIP() carries HAIPOptions(), and With only adds constraints.
	ErrProfileMustOption = common.NewCodedError("profile_must_option", "the profile requires this option")
	// ErrDraftProfile reports a draft profile where an OpenID4VCI 1.0 /
	// OpenID4VP 1.0 profile is required, or options given to a draft profile.
	ErrDraftProfile = common.NewCodedError("draft_profile", "a draft profile is not an OpenID4VCI 1.0 / OpenID4VP 1.0 profile")
)

// Final is OpenID4VCI 1.0 and OpenID4VP 1.0 with no additional constraint.
func Final() Profile {
	return Profile{kind: kindFinal}
}

// HAIP is HAIP 1.0 (OpenID4VC High Assurance Interoperability Profile): Final
// with HAIPOptions as Must options.
func HAIP() Profile {
	return Profile{kind: kindHAIP, options: HAIPOptions()}
}

// Draft13 is OpenID4VCI Draft 13 issuance.
func Draft13() Profile {
	return Profile{kind: kindDraft13}
}

// Draft24 is OpenID4VP Draft 24 presentation.
func Draft24() Profile {
	return Profile{kind: kindDraft24}
}

// Name names the base profile p was built from: NameFinal, NameHAIP,
// NameDraft13 or NameDraft24. Profiles built from the same base with
// different options share a Name; compare Profiles with == to tell them
// apart.
func (p Profile) Name() string {
	switch p.kind {
	case kindHAIP:
		return NameHAIP
	case kindDraft13:
		return NameDraft13
	case kindDraft24:
		return NameDraft24
	default:
		return NameFinal
	}
}

// String is Name, followed by "+options" when p carries options beyond those
// of its base profile.
func (p Profile) String() string {
	base := Profile{kind: p.kind}
	if p.kind == kindHAIP {
		base.options = HAIPOptions()
	}
	if p == base {
		return p.Name()
	}
	return p.Name() + "+options"
}

// Draft reports whether p is a draft protocol version profile (Draft13 or
// Draft24).
func (p Profile) Draft() bool {
	return p.kind == kindDraft13 || p.kind == kindDraft24
}

// Options returns the constraints p applies. A draft profile has none.
func (p Profile) Options() Options {
	return p.options
}

// With returns p with its options replaced by o. It only strengthens: every
// option p carries is a Must option of it, so o must keep each of them at
// least as strict, or With fails with ErrProfileMustOption naming the
// weakened options. Final().With(o) adds any part of HAIPOptions (or all of
// it) to Final; the result keeps the name "final", because HAIP is the
// profile HAIP() builds. A draft profile takes no options (ErrDraftProfile).
func (p Profile) With(o Options) (Profile, error) {
	if p.Draft() {
		if o == (Options{}) {
			return p, nil
		}
		return p, fmt.Errorf("%w: %s", ErrDraftProfile, p.Name())
	}
	if weakened := o.weakened(p.options); len(weakened) > 0 {
		return p, fmt.Errorf("%w: %s would weaken %s", ErrProfileMustOption, p.Name(), strings.Join(weakened, ", "))
	}
	return Profile{kind: p.kind, options: o}, nil
}

// RequireFinalVersion returns ErrDraftProfile when p is a draft profile, for a plugin
// field that takes an OpenID4VCI 1.0 / OpenID4VP 1.0 profile.
func (p Profile) RequireFinalVersion() error {
	if p.Draft() {
		return fmt.Errorf("%w: %s", ErrDraftProfile, p.Name())
	}
	return nil
}

// Carrier is implemented by protocol plugins that report the OpenID4VCI 1.0
// / OpenID4VP 1.0 profile they enforce. The wallet refuses a plugin whose
// profile differs from its own and, when its profile carries any option, a
// plugin that is not a Carrier, since it would not apply those options.
type Carrier interface {
	ProtocolProfile() Profile
}
