package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/profile"
)

func dcapiDCQL() map[string]any {
	return map[string]any{"credentials": []any{map[string]any{
		"id": "pid", "format": "dc+sd-jwt",
		"meta": map[string]any{"vct_values": []string{"urn:eudi:pid:1"}},
	}}}
}

func dcapiRaw(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return raw
}

func signedDCAPIClaims(f *requestObjectFixture) map[string]any {
	claims := f.claims()
	claims["response_mode"] = "dc_api.jwt"
	delete(claims, "response_uri")
	claims["expected_origins"] = []any{"https://verifier.example"}
	return claims
}

func TestParseDCAPIRequestUnsigned(t *testing.T) {
	p := &Oid4vpPresenter{}
	invocation := DCAPIInvocation{
		Request: DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiRaw(t, map[string]any{
			"response_type": "vp_token", "response_mode": "dc_api", "nonce": "n-1", "dcql_query": dcapiDCQL(),
		})},
		Origin: "https://verifier.example",
	}
	request, err := p.ParseDCAPIRequest(invocation)
	require.NoError(t, err)
	require.Equal(t, "web-origin:https://verifier.example", request.ClientID)
	require.Equal(t, "origin:https://verifier.example", request.ResponseAudience)
	require.Equal(t, DCAPIProtocolUnsigned, request.DCAPIProtocol)
}

func TestParseDCAPIRequestUnsignedIgnoresClientIDAndOrigins(t *testing.T) {
	// A.2: the Wallet MUST ignore client_id and expected_origins in unsigned
	// requests and use the platform Origin as the effective identifier.
	p := &Oid4vpPresenter{}
	invocation := DCAPIInvocation{
		Request: DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiRaw(t, map[string]any{
			"client_id": "x509_hash:attacker", "expected_origins": []any{"https://attacker.example"},
			"response_type": "vp_token", "response_mode": "dc_api", "nonce": "n-1", "dcql_query": dcapiDCQL(),
		})},
		Origin: "https://verifier.example",
	}
	request, err := p.ParseDCAPIRequest(invocation)
	require.NoError(t, err)
	require.Equal(t, "web-origin:https://verifier.example", request.ClientID)
}

func TestParseDCAPIRequestRejectsResponseURI(t *testing.T) {
	p := &Oid4vpPresenter{}
	invocation := DCAPIInvocation{
		Request: DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiRaw(t, map[string]any{
			"response_type": "vp_token", "response_mode": "dc_api", "nonce": "n-1",
			"response_uri": "https://verifier.example/response", "dcql_query": dcapiDCQL(),
		})},
		Origin: "https://verifier.example",
	}
	_, err := p.ParseDCAPIRequest(invocation)
	require.Error(t, err)
	require.Contains(t, err.Error(), "response_uri")
}

func TestParseDCAPIRequestSigned(t *testing.T) {
	f := newRequestObjectFixture(t)
	obj := f.sign(t, signedDCAPIClaims(f), nil)
	invocation := DCAPIInvocation{
		Request: DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: dcapiRaw(t, map[string]any{"request": obj})},
		Origin:  "https://verifier.example",
	}
	request, err := f.presenter().ParseDCAPIRequest(invocation)
	require.NoError(t, err)
	require.Equal(t, f.clientID(), request.ClientID)
	require.Equal(t, "origin:https://verifier.example", request.ResponseAudience)
	require.NotNil(t, request.RequestObjectVerification)
	require.Equal(t, f.clientID(), request.RequestObjectVerification.ClientID)
}

func TestParseDCAPIRequestSignedWrongExpectedOrigins(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := signedDCAPIClaims(f)
	claims["expected_origins"] = []any{"https://attacker.example"}
	obj := f.sign(t, claims, nil)
	invocation := DCAPIInvocation{
		Request: DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: dcapiRaw(t, map[string]any{"request": obj})},
		Origin:  "https://verifier.example",
	}
	_, err := f.presenter().ParseDCAPIRequest(invocation)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected_origins")
}

func TestParseDCAPIRequestOriginComesFromInvocation(t *testing.T) {
	// The request names a different origin in expected_origins; the platform
	// Origin supplied by the invocation must be the one compared.
	f := newRequestObjectFixture(t)
	claims := signedDCAPIClaims(f)
	claims["expected_origins"] = []any{"https://verifier.example"}
	obj := f.sign(t, claims, nil)
	invocation := DCAPIInvocation{
		Request: DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: dcapiRaw(t, map[string]any{"request": obj})},
		Origin:  "https://attacker.example",
	}
	_, err := f.presenter().ParseDCAPIRequest(invocation)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected_origins")
}

func signDCAPIMultiPart(t *testing.T, key *ecdsa.PrivateKey, leaf *x509.Certificate, clientID string, payload []byte) string {
	t.Helper()
	options := (&jose.SignerOptions{}).
		WithType("oauth-authz-req+jwt").
		WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(leaf.Raw)}).
		WithHeader("client_id", clientID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, options)
	require.NoError(t, err)
	obj, err := signer.Sign(payload)
	require.NoError(t, err)
	compact, err := obj.CompactSerialize()
	require.NoError(t, err)
	return compact
}

func TestParseDCAPIRequestMultiSigned(t *testing.T) {
	trusted := newRequestObjectFixture(t)
	untrusted := newRequestObjectFixture(t)
	claims := signedDCAPIClaims(trusted)
	delete(claims, "client_id")
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	trustedCompact := signDCAPIMultiPart(t, trusted.key, trusted.leaf, trusted.clientID(), payload)
	untrustedCompact := signDCAPIMultiPart(t, untrusted.key, untrusted.leaf, untrusted.clientID(), payload)
	trustedParts := strings.Split(trustedCompact, ".")
	untrustedParts := strings.Split(untrustedCompact, ".")
	require.Len(t, trustedParts, 3)
	require.Len(t, untrustedParts, 3)
	multi := map[string]any{
		"payload": trustedParts[1],
		"signatures": []any{
			map[string]any{"protected": untrustedParts[0], "signature": untrustedParts[2]},
			map[string]any{"protected": trustedParts[0], "signature": trustedParts[2]},
		},
	}
	invocation := DCAPIInvocation{
		Request: DCAPIRequest{Protocol: DCAPIProtocolMultiSigned, Data: dcapiRaw(t, map[string]any{"request": multi})},
		Origin:  "https://verifier.example",
	}
	request, err := trusted.presenter().ParseDCAPIRequest(invocation)
	require.NoError(t, err)
	require.Equal(t, trusted.clientID(), request.ClientID)
	require.Equal(t, "origin:https://verifier.example", request.ResponseAudience)
	require.NotNil(t, request.RequestObjectVerification)
	require.Equal(t, trusted.clientID(), request.RequestObjectVerification.ClientID)
}

func newDCAPIRecipient(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return recipient
}

func dcapiUnsignedDataWithMetadata(t *testing.T, recipient *ecdsa.PrivateKey, encValues []string) []byte {
	t.Helper()
	metadata := map[string]any{
		"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &recipient.PublicKey, KeyID: "enc-key", Use: "enc", Algorithm: "ECDH-ES",
		}}},
		"encrypted_response_enc_values_supported": encValues,
	}
	return dcapiRaw(t, map[string]any{
		"response_type": "vp_token", "response_mode": "dc_api.jwt", "nonce": "n-1",
		"dcql_query": dcapiDCQL(), "client_metadata": metadata,
	})
}

func TestBuildDCAPIResponsePlaintext(t *testing.T) {
	p := &Oid4vpPresenter{}
	request := &CredentialPresentationRequest{
		OAuthAuthzRequest: &OAuthAuthzRequest{ResponseMode: OAuthAuthzReqResponseModeDCAPI},
		DCAPIProtocol:     DCAPIProtocolUnsigned,
	}
	vpToken := map[string][]string{"pid": {"credential"}}
	response, err := p.BuildDCAPIResponse(request, vpToken)
	require.NoError(t, err)
	require.Equal(t, DCAPIProtocolUnsigned, response.Protocol)
	require.Equal(t, vpToken, response.Data["vp_token"])
}

func TestBuildDCAPIResponseEncrypted(t *testing.T) {
	for _, tc := range []struct {
		name      string
		profile   profile.Profile
		encValues []string
		enc       jose.ContentEncryption
	}{
		{name: "final defaults to A128GCM", enc: jose.A128GCM},
		{name: "haip allows A256GCM", profile: profile.HAIP, encValues: []string{"A256GCM"}, enc: jose.A256GCM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recipient := newDCAPIRecipient(t)
			p := &Oid4vpPresenter{Profile: tc.profile}
			invocation := DCAPIInvocation{
				Request: DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiUnsignedDataWithMetadata(t, recipient, tc.encValues)},
				Origin:  "https://verifier.example",
			}
			request, err := p.ParseDCAPIRequest(invocation)
			require.NoError(t, err)
			response, err := p.BuildDCAPIResponse(request, map[string][]string{"pid": {"credential"}})
			require.NoError(t, err)
			require.Equal(t, DCAPIProtocolUnsigned, response.Protocol)
			token, ok := response.Data["response"].(string)
			require.True(t, ok)
			jwe, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{tc.enc})
			require.NoError(t, err)
			plaintext, err := jwe.Decrypt(recipient)
			require.NoError(t, err)
			var payload map[string]any
			require.NoError(t, json.Unmarshal(plaintext, &payload))
			vpToken, ok := payload["vp_token"].(map[string]any)
			require.True(t, ok)
			require.Equal(t, []any{"credential"}, vpToken["pid"])
		})
	}
}

func TestParseDCAPIRequestHAIPAcceptsAllRequestTypes(t *testing.T) {
	t.Run("unsigned", func(t *testing.T) {
		p := &Oid4vpPresenter{Profile: profile.HAIP}
		invocation := DCAPIInvocation{
			Request: DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiRaw(t, map[string]any{
				"response_type": "vp_token", "response_mode": "dc_api.jwt", "nonce": "n-1", "dcql_query": dcapiDCQL(),
			})},
			Origin: "https://verifier.example",
		}
		_, err := p.ParseDCAPIRequest(invocation)
		require.NoError(t, err)
	})

	t.Run("signed", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		obj := f.sign(t, signedDCAPIClaims(f), nil)
		invocation := DCAPIInvocation{
			Request: DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: dcapiRaw(t, map[string]any{"request": obj})},
			Origin:  "https://verifier.example",
		}
		p := f.presenterWithHAIP()
		_, err := p.ParseDCAPIRequest(invocation)
		require.NoError(t, err)
	})

	t.Run("multi-signed", func(t *testing.T) {
		trusted := newRequestObjectFixture(t)
		untrusted := newRequestObjectFixture(t)
		claims := signedDCAPIClaims(trusted)
		delete(claims, "client_id")
		payload, err := json.Marshal(claims)
		require.NoError(t, err)
		trustedCompact := signDCAPIMultiPart(t, trusted.key, trusted.leaf, trusted.clientID(), payload)
		untrustedCompact := signDCAPIMultiPart(t, untrusted.key, untrusted.leaf, untrusted.clientID(), payload)
		trustedParts := strings.Split(trustedCompact, ".")
		untrustedParts := strings.Split(untrustedCompact, ".")
		multi := map[string]any{
			"payload": trustedParts[1],
			"signatures": []any{
				map[string]any{"protected": untrustedParts[0], "signature": untrustedParts[2]},
				map[string]any{"protected": trustedParts[0], "signature": trustedParts[2]},
			},
		}
		invocation := DCAPIInvocation{
			Request: DCAPIRequest{Protocol: DCAPIProtocolMultiSigned, Data: dcapiRaw(t, map[string]any{"request": multi})},
			Origin:  "https://verifier.example",
		}
		p := trusted.presenterWithHAIP()
		_, err = p.ParseDCAPIRequest(invocation)
		require.NoError(t, err)
	})
}

func TestParseDCAPIRequestHAIPRejectsDirectPost(t *testing.T) {
	p := (&Oid4vpPresenter{Profile: profile.HAIP})
	invocation := DCAPIInvocation{
		Request: DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiRaw(t, map[string]any{
			"response_type": "vp_token", "response_mode": "direct_post.jwt", "nonce": "n-1", "dcql_query": dcapiDCQL(),
		})},
		Origin: "https://verifier.example",
	}
	_, err := p.ParseDCAPIRequest(invocation)
	require.Error(t, err)
}

// presenterWithHAIP mirrors requestObjectFixture.presenterWith for the HAIP
// profile without changing the shared fixture file.
func (f *requestObjectFixture) presenterWithHAIP() *Oid4vpPresenter {
	return f.presenterWith(requestFixtureOptions{Profile: profile.HAIP})
}
