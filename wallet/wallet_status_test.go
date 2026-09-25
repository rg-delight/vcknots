package wallet

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustknots/vcknots/wallet/credential/statuslist"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/profile"
)

// Review of 2026-09-25 (HAIP 1.0 §6.1): a Status List checker built for a
// HAIP wallet ran under Final unless the caller repeated the profile, so its
// token x5c rules did not apply. StatusListChecker wires the wallet's profile.
func TestStatusListCheckerCarriesTheWalletProfile(t *testing.T) {
	strict, err := profile.Final().With(profile.HAIPOptions())
	require.NoError(t, err)
	for _, p := range []profile.Profile{profile.Final(), profile.HAIP(), strict} {
		t.Run(p.String(), func(t *testing.T) {
			w, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{p}, Storeless: true})
			require.NoError(t, err)
			checker, err := w.StatusListChecker(statuslist.Checker{})
			require.NoError(t, err)
			require.Equal(t, p, checker.Profile)
			require.Equal(t, p.Options().StatusListTokenX5C, checker.Profile.Options().StatusListTokenX5C)

			same, err := w.StatusListChecker(statuslist.Checker{Profile: p})
			require.NoError(t, err)
			require.Equal(t, p, same.Profile)
		})
	}

	haip, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.HAIP()}, Storeless: true})
	require.NoError(t, err)
	_, err = haip.StatusListChecker(statuslist.Checker{Profile: strict})
	requireCoded(t, err, ErrProfileMismatch)
	_, err = haip.StatusListChecker(statuslist.Checker{Experimental: experimental.Transport{AllowHTTP: true}})
	require.ErrorIs(t, err, statuslist.ErrStatusListInsecureTransportForbidden)

	final, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.Final()}, Storeless: true})
	require.NoError(t, err)
	checker, err := final.StatusListChecker(statuslist.Checker{Experimental: experimental.Transport{AllowHTTP: true}})
	require.NoError(t, err)
	require.True(t, checker.Experimental.AllowHTTP)
}
