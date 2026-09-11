package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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

// TestHAIPDCAPIRejectsAnchorInX5CWithRootCAs covers HAIP Section 5 on the DC
// API path: "The X.509 certificate of the trust anchor MUST NOT be included in
// the x5c JOSE header of the signed request." The rule used to be inert
// whenever trust was configured as a *x509.CertPool instead of explicit
// TrustAnchors.
func TestHAIPDCAPIRejectsAnchorInX5CWithRootCAs(t *testing.T) {
	f := newRequestObjectFixture(t)
	pool := x509.NewCertPool()
	pool.AddCert(f.root)
	options := RequestObjectValidationOptions{RootCAs: pool, Now: func() time.Time { return f.now }}
	invocation := DCAPIInvocation{
		Request: DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: dcapiRaw(t, map[string]any{
			"request": f.signWithRoot(t, signedDCAPIClaims(f), true),
		})},
		Origin: "https://verifier.example",
	}

	haip := &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &options, Profile: profile.HAIP}
	_, err := haip.ParseDCAPIRequest(invocation)
	require.ErrorContains(t, err, "HAIP forbids including the trust anchor certificate in the x5c header")

	final := &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &options}
	_, err = final.ParseDCAPIRequest(invocation)
	require.NoError(t, err, "Final must still accept a chain that includes the anchor")
}

// presenterWithHAIP mirrors requestObjectFixture.presenterWith for the HAIP
// profile without changing the shared fixture file.
func (f *requestObjectFixture) presenterWithHAIP() *Oid4vpPresenter {
	return f.presenterWith(requestFixtureOptions{Profile: profile.HAIP})
}

// TestParseRequestRejectsWebOriginClientIDFromTheWire pins that "web-origin" is
// an identifier the Wallet mints for itself, not one a Verifier may claim.
//
// OID4VP 1.0 Appendix A.2: "The `client_id` parameter MUST be omitted in
// unsigned requests defined in (#unsigned_request). The Wallet MUST ignore any
// `client_id` parameter that is present in an unsigned request." Accepting the
// prefix off the wire would reintroduce, under a different spelling, what
// Section 5.9.3 forbids for the companion prefix: "This reserved Client
// Identifier Prefix is defined in (#dc_api_request). The Wallet MUST NOT accept
// this Client Identifier Prefix in requests." Such a request derives no
// response endpoint binding from its Client Identifier, so a direct_post.jwt
// response_uri would be unauthenticated.
func TestParseRequestRejectsWebOriginClientIDFromTheWire(t *testing.T) {
	const webOriginClientID = "web-origin:https://verifier.example"

	t.Run("query parameters", func(t *testing.T) {
		p := &Oid4vpPresenter{}
		uri := "openid4vp://present?" + url.Values{
			"client_id":     {webOriginClientID},
			"response_type": {"vp_token"},
			"nonce":         {"n-1"},
			"response_mode": {"direct_post.jwt"},
			"response_uri":  {"https://attacker.example/cb"},
			"dcql_query":    {string(dcapiRaw(t, dcapiDCQL()))},
		}.Encode()
		_, err := p.ParsePresentationRequest(uri)
		require.Error(t, err)
		require.Contains(t, err.Error(), "web-origin")
	})

	t.Run("signed Request Object by value with an outer client_id", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["client_id"] = webOriginClientID
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {webOriginClientID},
			"request":   {f.sign(t, claims, nil)},
		}.Encode()
		_, err := f.presenter().ParsePresentationRequest(uri)
		require.Error(t, err)
		require.Contains(t, err.Error(), "web-origin")
	})

	t.Run("signed Request Object by reference", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["client_id"] = webOriginClientID
		f.requestObject = []byte(f.sign(t, claims, nil))
		uri := "openid4vp://authorize?" + url.Values{
			"client_id":   {webOriginClientID},
			"request_uri": {f.server.URL + "/request-object"},
		}.Encode()
		_, err := f.presenter().ParsePresentationRequest(uri)
		require.Error(t, err)
		require.Contains(t, err.Error(), "web-origin")
	})

	t.Run("Draft24 query parameters", func(t *testing.T) {
		p := &Oid4vpPresenter{}
		uri := "openid4vp://present?" + url.Values{
			"client_id":               {webOriginClientID},
			"response_type":           {"vp_token"},
			"nonce":                   {"n-1"},
			"response_mode":           {"direct_post"},
			"response_uri":            {"https://attacker.example/cb"},
			"presentation_definition": {`{"id":"pd","input_descriptors":[]}`},
		}.Encode()
		_, err := p.ParseDraft24PresentationRequest(uri)
		require.Error(t, err)
		require.Contains(t, err.Error(), "web-origin")
	})

	t.Run("Draft24 Request Object claim", func(t *testing.T) {
		// Draft24 accepts a Request Object without an outer client_id, so the
		// rejection here comes from the parameter assembly that reads the
		// Request Object's own client_id claim, not from the early outer check.
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["client_id"] = webOriginClientID
		claims["response_mode"] = "direct_post"
		claims["response_uri"] = "https://attacker.example/cb"
		uri := "openid4vp://authorize?" + url.Values{"request": {f.sign(t, claims, nil)}}.Encode()
		_, err := f.presenter().ParseDraft24PresentationRequest(uri)
		require.Error(t, err)
		require.Contains(t, err.Error(), "web-origin")
	})
}

// TestParseDCAPIRequestRequestObjectSentinels drives the DC API Request Object
// authentication sentinels through ParseDCAPIRequest, so each is proven
// reachable with errors.Is from the innermost return in dcapi.go rather than
// through a message-fragment classification.
func TestParseDCAPIRequestRequestObjectSentinels(t *testing.T) {
	tests := []struct {
		name     string
		sentinel error
		object   func(*testing.T, *requestObjectFixture) string
	}{
		{
			name:     "typ invalid",
			sentinel: ErrRequestObjectTypInvalid,
			object: func(t *testing.T, f *requestObjectFixture) string {
				options := (&jose.SignerOptions{}).
					WithType("JWT").
					WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
				return f.sign(t, signedDCAPIClaims(f), options)
			},
		},
		{
			name:     "signature invalid",
			sentinel: ErrRequestObjectSignatureInvalid,
			object: func(t *testing.T, f *requestObjectFixture) string {
				// Present f's certificate in x5c so the client_id binding
				// passes, but sign with another key so verification fails.
				other := newRequestObjectFixture(t)
				options := (&jose.SignerOptions{}).
					WithType("oauth-authz-req+jwt").
					WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: other.key}, options)
				require.NoError(t, err)
				token, err := jwt.Signed(signer).Claims(signedDCAPIClaims(f)).Serialize()
				require.NoError(t, err)
				return token
			},
		},
		{
			name:     "audience mismatch",
			sentinel: ErrRequestObjectAudienceMismatch,
			object: func(t *testing.T, f *requestObjectFixture) string {
				claims := signedDCAPIClaims(f)
				claims["aud"] = "another-wallet"
				return f.sign(t, claims, nil)
			},
		},
		{
			name:     "expired",
			sentinel: ErrRequestObjectExpired,
			object: func(t *testing.T, f *requestObjectFixture) string {
				claims := signedDCAPIClaims(f)
				claims["exp"] = f.now.Add(-time.Second).Unix()
				return f.sign(t, claims, nil)
			},
		},
		{
			name:     "x509_hash mismatch",
			sentinel: ErrX509HashMismatch,
			object: func(t *testing.T, f *requestObjectFixture) string {
				claims := signedDCAPIClaims(f)
				claims["client_id"] = "x509_hash:" + base64.RawURLEncoding.EncodeToString([]byte("wrong-leaf-hash"))
				return f.sign(t, claims, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRequestObjectFixture(t)
			invocation := DCAPIInvocation{
				Request: DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: dcapiRaw(t, map[string]any{"request": tt.object(t, f)})},
				Origin:  "https://verifier.example",
			}
			_, err := f.presenter().ParseDCAPIRequest(invocation)
			if !errors.Is(err, tt.sentinel) {
				t.Fatalf("ParseDCAPIRequest did not return %v: %v", tt.sentinel, err)
			}
		})
	}
}
