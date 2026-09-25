package wallet

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/credential/statuslist"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/profile"
)

// StatusListChecker returns a copy of base that checks Token Status Lists
// under the wallet's 1.0 profile. A Checker whose Profile is the zero value
// (which reads as profile.Final) gets the wallet's profile, so a HAIP wallet's
// checker applies HAIP 1.0 Section 6.1 - the Status List Token's key in its
// x5c header, no trust anchor in it, no self-signed leaf - without the caller
// repeating the profile. A Checker that names another profile is refused with
// ErrProfileMismatch, and under a profile with ForbidInsecureTransports one
// that sets Experimental is refused before anything is fetched.
func (w *Wallet) StatusListChecker(base statuslist.Checker) (*statuslist.Checker, error) {
	checker := base
	switch checker.Profile {
	case profile.Profile{}:
		checker.Profile = w.profile
	case w.profile:
	default:
		return nil, fmt.Errorf("%w: the Status List checker names %s, the wallet runs %s", ErrProfileMismatch, checker.Profile, w.profile)
	}
	if checker.Profile.Options().ForbidInsecureTransports && checker.Experimental != (experimental.Transport{}) {
		return nil, fmt.Errorf("%w: %s does not permit Checker.Experimental: %w", ErrInvalidArgument, checker.Profile, statuslist.ErrStatusListInsecureTransportForbidden)
	}
	return &checker, nil
}
