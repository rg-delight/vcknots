package wallet

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// RFC 6749 Section 7.1: "The client MUST NOT use an access token if it does
// not understand the token type", and Section 5.1 makes token_type REQUIRED.
// A Draft 13 grant is refused unless the token is Bearer, or DPoP with the
// wallet's DPoP key, before any Credential Request presents it.
func TestDraft13RefusesAnAccessTokenOfAnUnknownType(t *testing.T) {
	for name, test := range map[string]struct {
		tokenType any
		want      error
	}{
		"MAC":                     {"MAC", ErrTokenTypeUnsupported},
		"missing":                 {nil, ErrTokenTypeUnsupported},
		"empty":                   {"", ErrTokenTypeUnsupported},
		"DPoP without a DPoP key": {"DPoP", ErrDPoPRequired},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDraft13Fixture(t)
			fixture.set(func(f *draft13Fixture) {
				f.tokenResponse = func(url.Values) (int, any) {
					body := map[string]any{"access_token": "access-1", "c_nonce": "nonce-1"}
					if test.tokenType != nil {
						body["token_type"] = test.tokenType
					}
					return http.StatusOK, body
				}
			})
			_, err := fixture.wallet.Draft13().AuthorizePreAuthorizedIssuance(context.Background(), fixture.preAuthorizedRequest())
			require.ErrorIs(t, err, test.want)
			require.Empty(t, fixture.credentials())
		})
	}

	fixture := newDraft13Fixture(t)
	grant := fixture.preAuthorize(t, fixture.wallet)
	require.Equal(t, "Bearer", grant.AccessToken.TokenType)
}
