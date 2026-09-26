package wallet

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
)

// CX-VP A12: the Verifier's vp_formats_supported limits the algorithms of the
// SD-JWT VC it accepts (OpenID4VP 1.0 Appendix B.3.4); the fixture issuer
// signs with ES256, so a Verifier listing only ES384 gets nothing rather than
// a presentation it said it cannot verify.
func TestWallet_PresentationHonoursTheVerifiersAlgorithms(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	uri := func(algorithms string) string {
		return "openid4vp://present?" + url.Values{
			"client_id": {"redirect_uri:" + fixture.baseURL + "/response"}, "response_uri": {fixture.baseURL + "/response"},
			"response_type": {"vp_token"}, "response_mode": {"direct_post"}, "nonce": {"n"},
			"dcql_query":      {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`},
			"client_metadata": {`{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":` + algorithms + `}}}`},
		}.Encode()
	}

	err := submitSelectedForTest(t, fixture.wallet, uri(`["ES384"]`), fixture.key)
	require.ErrorIs(t, err, oid4vp.ErrVPFormatAlgUnsupported)
	select {
	case <-fixture.posted:
		t.Fatal("a presentation the Verifier cannot verify was sent")
	default:
	}

	require.NoError(t, submitSelectedForTest(t, fixture.wallet, uri(`["ES256","ES384"]`), fixture.key))
	<-fixture.posted
}
