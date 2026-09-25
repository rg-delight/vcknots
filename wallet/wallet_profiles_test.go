package wallet

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/mock"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestConfigProfilesDefaultEnablesFinalAndBothDrafts(t *testing.T) {
	w, err := NewWalletWithConfig(Config{Storeless: true})
	require.NoError(t, err)
	require.Equal(t, profile.Final(), w.profile)
	require.True(t, w.draft13)
	require.True(t, w.draft24)
	require.Equal(t, []profile.Profile{profile.Final(), profile.Draft13(), profile.Draft24()}, DefaultProfiles())
}

func TestConfigProfilesRefusesInvalidSets(t *testing.T) {
	strengthened, err := profile.Final().With(profile.Options{RequirePAR: true})
	require.NoError(t, err)
	for name, test := range map[string]struct {
		profiles []profile.Profile
		want     error
	}{
		"HAIP with Draft 13":        {[]profile.Profile{profile.HAIP(), profile.Draft13()}, ErrProfileForbidsDraft},
		"HAIP with Draft 24":        {[]profile.Profile{profile.Draft24(), profile.HAIP()}, ErrProfileForbidsDraft},
		"no 1.0 profile":            {[]profile.Profile{profile.Draft13(), profile.Draft24()}, ErrInvalidArgument},
		"two 1.0 profiles":          {[]profile.Profile{profile.Final(), strengthened}, ErrInvalidArgument},
		"a draft profile twice":     {[]profile.Profile{profile.Final(), profile.Draft13(), profile.Draft13()}, ErrInvalidArgument},
		"Final and HAIP both named": {[]profile.Profile{profile.Final(), profile.HAIP()}, ErrInvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewWalletWithConfig(Config{Profiles: test.profiles, Storeless: true})
			requireCoded(t, err, test.want)
		})
	}
}

func TestConfigProfilesAcceptsStrengthenedFinalWithDrafts(t *testing.T) {
	strengthened, err := profile.Final().With(profile.Options{RequireDPoP: true, RequirePAR: true})
	require.NoError(t, err)
	w, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{strengthened, profile.Draft13()}, Storeless: true})
	require.NoError(t, err)
	require.Equal(t, strengthened, w.profile)
	require.True(t, w.draft13)
	require.False(t, w.draft24)
	// The default receiver carries the strengthened profile.
	plugins := w.receiver.Plugins()
	require.Len(t, plugins, 1)
	require.Equal(t, strengthened, plugins[0].(profile.Carrier).ProtocolProfile())
}

func TestConfigProfilesWithOptionsRefusesPluginsWithoutProfile(t *testing.T) {
	strengthened, err := profile.Final().With(profile.Options{RequireDPoP: true})
	require.NoError(t, err)
	_, err = NewWalletWithConfig(Config{
		Profiles: []profile.Profile{strengthened},
		Receiver: receiverWith(t, mock.NewMockReceiver(t.TempDir())), Storeless: true,
	})
	requireCoded(t, err, ErrProfilePluginUnsupported)
}

func TestDraftEntryPointsNeedTheirDraftProfile(t *testing.T) {
	finalOnly, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.Final()}, Storeless: true})
	require.NoError(t, err)

	_, err = finalOnly.Draft13().RequestCredential(t.Context(), &IssuanceGrant{}, CredentialRequest{})
	requireCoded(t, err, ErrProfileForbidsDraft)
	_, err = finalOnly.Draft13().BeginIssuance(t.Context(), IssuanceRequest{})
	requireCoded(t, err, ErrProfileForbidsDraft)
	err = finalOnly.Draft13().NotifyIssuer(t.Context(), &IssuanceNotification{}, NotificationEvent("credential_accepted"), "")
	requireCoded(t, err, ErrProfileForbidsDraft)
	_, err = finalOnly.ReceiveCredential(ReceiveCredentialRequest{Type: receiverTypes.Oid4vci})
	requireCoded(t, err, ErrProfileForbidsDraft)
	_, err = finalOnly.Draft24().ParsePresentationRequest(t.Context(), "openid4vp://?client_id=x")
	requireCoded(t, err, ErrProfileForbidsDraft)

	// Each draft profile enables only its own entry points.
	vp24Only, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.Final(), profile.Draft24()}, Storeless: true})
	require.NoError(t, err)
	_, err = vp24Only.Draft13().RequestCredential(t.Context(), &IssuanceGrant{}, CredentialRequest{})
	requireCoded(t, err, ErrProfileForbidsDraft)
	_, err = vp24Only.Draft24().ParsePresentationRequest(t.Context(), "openid4vp://?client_id=x")
	require.NotErrorIs(t, err, ErrProfileForbidsDraft)
}

func TestTestHooksNeedADraftProfile(t *testing.T) {
	_, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.Final()}, Storeless: true, TestHooks: &TestHooks{}})
	requireCoded(t, err, ErrProfileForbidsDraft)
	_, err = NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.Final(), profile.Draft13()}, Storeless: true, TestHooks: &TestHooks{}})
	require.NoError(t, err)
}
