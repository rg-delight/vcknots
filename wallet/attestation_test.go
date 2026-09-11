package wallet

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/profile"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// testLeafCertificate builds a certificate for key. When selfSigned is true the
// certificate signs itself; otherwise it is issued by a throwaway CA, modelling
// an attester whose leaf chains to a Wallet Provider trust anchor.
func testLeafCertificate(t *testing.T, key jose.JSONWebKey, selfSigned bool) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{"attester.example"},
	}
	if selfSigned {
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public().Key, key.Key)
		require.NoError(t, err)
		certificate, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return certificate
	}
	caKey := newPrivateJWKForFinalVCITest(t, "ca-key")
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public().Key, caKey.Key)
	require.NoError(t, err)
	caCertificate, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, key.Public().Key, caKey.Key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate
}

func clientAttestationClaimsFor(clientKey jose.JSONWebKey) map[string]any {
	return map[string]any{
		"iss": "https://attester.example",
		"sub": "client-1",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
		"cnf": map[string]any{"jwk": publicHolderJWK(clientKey)},
	}
}

func TestStaticClientAttester_ProducesValidClientAttestation(t *testing.T) {
	clientKey := newPrivateJWKForFinalVCITest(t, "client-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-key-1")
	attesterKey.Certificates = []*x509.Certificate{testLeafCertificate(t, attesterKey, false)}

	attester := &StaticClientAttester{Key: attesterKey, Issuer: "https://attester.example"}
	request := ClientAttestationRequest{ClientID: "client-1", ClientKey: clientKey, AuthorizationServer: "https://as.example"}

	attestation, err := attester.ClientAttestation(context.Background(), request)
	require.NoError(t, err)
	require.NotEmpty(t, attestation.JWT)
	require.False(t, attestation.ExpiresAt.IsZero())

	// Final accepts without x5c, HAIP accepts the non-self-signed x5c leaf.
	require.NoError(t, validateClientAttestation(attestation, request, false, time.Now()))
	require.NoError(t, validateClientAttestation(attestation, request, true, time.Now()))

	header, claims, err := parseAttestationJWT(attestation.JWT)
	require.NoError(t, err)
	require.Equal(t, clientAttestationJWTType, header.Type)
	require.Len(t, header.X5C, 1)
	require.Equal(t, "https://attester.example", claims.Iss)
	require.Equal(t, "client-1", claims.Sub)
}

func TestValidateClientAttestation_RejectsBeforeUse(t *testing.T) {
	clientKey := newPrivateJWKForFinalVCITest(t, "client-key-1")
	otherKey := newPrivateJWKForFinalVCITest(t, "other-client-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-key-1")
	request := ClientAttestationRequest{ClientID: "client-1", ClientKey: clientKey}

	expired := clientAttestationClaimsFor(clientKey)
	expired["exp"] = time.Now().Add(-time.Minute).Unix()

	otherCnf := clientAttestationClaimsFor(otherKey)

	testCases := map[string]struct {
		typ     string
		claims  map[string]any
		wantErr string
	}{
		"wrong typ":     {typ: "JWT", claims: clientAttestationClaimsFor(clientKey), wantErr: "typ must be"},
		"wrong sub":     {typ: clientAttestationJWTType, claims: map[string]any{"sub": "someone-else"}, wantErr: "does not match client_id"},
		"other cnf key": {typ: clientAttestationJWTType, claims: mustMerge(clientAttestationClaimsFor(clientKey), otherCnf), wantErr: "cnf.jwk does not match"},
		"expired":       {typ: clientAttestationJWTType, claims: expired, wantErr: "expired"},
		"missing exp":   {typ: clientAttestationJWTType, claims: mustWithout(clientAttestationClaimsFor(clientKey), "exp"), wantErr: "missing exp"},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			token, err := signAttestationJWT(attesterKey, tc.typ, tc.claims)
			require.NoError(t, err)
			err = validateClientAttestation(&ClientAttestation{JWT: token}, request, false, time.Now())
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func mustMerge(base, override map[string]any) map[string]any {
	merged := map[string]any{}
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range override {
		merged[key] = value
	}
	return merged
}

func mustWithout(base map[string]any, key string) map[string]any {
	result := map[string]any{}
	for name, value := range base {
		if name == key {
			continue
		}
		result[name] = value
	}
	return result
}

func TestValidateClientAttestation_HAIPRequiresNonSelfSignedX5C(t *testing.T) {
	clientKey := newPrivateJWKForFinalVCITest(t, "client-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-key-1")
	request := ClientAttestationRequest{ClientID: "client-1", ClientKey: clientKey}

	withoutCert, err := signAttestationJWT(attesterKey, clientAttestationJWTType, clientAttestationClaimsFor(clientKey))
	require.NoError(t, err)
	require.ErrorContains(t, validateClientAttestation(&ClientAttestation{JWT: withoutCert}, request, true, time.Now()), "x5c")

	selfSignedKey := newPrivateJWKForFinalVCITest(t, "self-signed-attester")
	selfSignedKey.Certificates = []*x509.Certificate{testLeafCertificate(t, selfSignedKey, true)}
	selfSigned, err := signAttestationJWT(selfSignedKey, clientAttestationJWTType, clientAttestationClaimsFor(clientKey))
	require.NoError(t, err)
	require.ErrorContains(t, validateClientAttestation(&ClientAttestation{JWT: selfSigned}, request, true, time.Now()), "self-signed")
}

func TestStaticKeyAttester_ProducesValidKeyAttestation(t *testing.T) {
	holderKey := newPrivateJWKForFinalVCITest(t, "holder-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	attester := &StaticKeyAttester{Key: attesterKey, Issuer: "https://key-attester.example"}
	request := KeyAttestationRequest{Keys: []jose.JSONWebKey{holderKey}, Nonce: "cnonce-1", Audience: "https://issuer.example"}

	attestation, err := attester.KeyAttestation(context.Background(), request)
	require.NoError(t, err)
	require.NoError(t, validateKeyAttestation(attestation, request, false, time.Now()))

	header, claims, err := parseAttestationJWT(attestation.JWT)
	require.NoError(t, err)
	require.Equal(t, keyAttestationJWTType, header.Type)
	require.Equal(t, "cnonce-1", claims.Nonce)
	require.Len(t, claims.AttestedKeys, 1)
}

func TestValidateKeyAttestation_Rejects(t *testing.T) {
	holderKey := newPrivateJWKForFinalVCITest(t, "holder-key-1")
	otherKey := newPrivateJWKForFinalVCITest(t, "other-holder-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	attester := &StaticKeyAttester{Key: attesterKey, Issuer: "https://key-attester.example"}

	request := KeyAttestationRequest{Keys: []jose.JSONWebKey{holderKey}, Nonce: "cnonce-1"}

	missingHolder, err := attester.KeyAttestation(context.Background(), KeyAttestationRequest{Keys: []jose.JSONWebKey{otherKey}, Nonce: "cnonce-1"})
	require.NoError(t, err)
	require.ErrorContains(t, validateKeyAttestation(missingHolder, request, false, time.Now()), "does not attest the holder key")

	wrongNonce, err := attester.KeyAttestation(context.Background(), KeyAttestationRequest{Keys: []jose.JSONWebKey{holderKey}, Nonce: "stale"})
	require.NoError(t, err)
	require.ErrorContains(t, validateKeyAttestation(wrongNonce, request, false, time.Now()), "nonce")

	expired := mustSignKeyAttestation(t, attesterKey, holderKey, "cnonce-1", time.Now().Add(-time.Minute))
	require.ErrorContains(t, validateKeyAttestation(expired, request, false, time.Now()), "expired")

	withoutX5C := mustSignKeyAttestation(t, attesterKey, holderKey, "cnonce-1", time.Now().Add(time.Minute))
	require.ErrorContains(t, validateKeyAttestation(withoutX5C, request, true, time.Now()), "x5c")

	selfSignedKey := newPrivateJWKForFinalVCITest(t, "self-signed-key-attester")
	selfSignedKey.Certificates = []*x509.Certificate{testLeafCertificate(t, selfSignedKey, true)}
	selfSigned := mustSignKeyAttestation(t, selfSignedKey, holderKey, "cnonce-1", time.Now().Add(time.Minute))
	require.ErrorContains(t, validateKeyAttestation(selfSigned, request, true, time.Now()), "self-signed")

	wrongTyp, err := signAttestationJWT(attesterKey, "JWT", map[string]any{
		"iss":           "https://key-attester.example",
		"iat":           time.Now().Unix(),
		"exp":           time.Now().Add(time.Minute).Unix(),
		"nonce":         "cnonce-1",
		"attested_keys": []jose.JSONWebKey{publicHolderJWK(holderKey)},
	})
	require.NoError(t, err)
	require.ErrorContains(t, validateKeyAttestation(&KeyAttestation{JWT: wrongTyp}, request, false, time.Now()), "typ must be")
}

func mustSignKeyAttestation(t *testing.T, attesterKey, holderKey jose.JSONWebKey, nonce string, expiry time.Time) *KeyAttestation {
	t.Helper()
	token, err := signAttestationJWT(attesterKey, keyAttestationJWTType, map[string]any{
		"iss":           "https://key-attester.example",
		"iat":           time.Now().Unix(),
		"exp":           expiry.Unix(),
		"nonce":         nonce,
		"attested_keys": []jose.JSONWebKey{publicHolderJWK(holderKey)},
	})
	require.NoError(t, err)
	return &KeyAttestation{JWT: token}
}

func TestPlanOID4VCIKeyAttestation_HAIPNamesSection(t *testing.T) {
	metadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialConfigurationSupported: map[string]receiverTypes.CredentialConfiguration{
			"pid": {
				Format: "dc+sd-jwt",
				ProofTypesSupported: &map[string]receiverTypes.ProofType{
					"jwt": {KeyAttestationsRequired: &receiverTypes.KeyAttestationsRequired{}},
				},
			},
		},
	}
	w := &Wallet{profile: profile.HAIP}
	_, err := w.planOID4VCIKeyAttestation(metadata, "pid", false)
	require.ErrorContains(t, err, "§4.5.1")
}

// fixedClientAttestationProvider returns a prebuilt client attestation so tests
// can model an invalid provider result without a network round trip.
type fixedClientAttestationProvider struct {
	attestation *ClientAttestation
}

func (p fixedClientAttestationProvider) ClientAttestation(context.Context, ClientAttestationRequest) (*ClientAttestation, error) {
	return p.attestation, nil
}

// The attestation is validated before the receiver is touched: a nil receiver
// would panic if validation did not run first, so each case proves the provider
// result is rejected before any network call.
func TestCreateOID4VCIAttestationHeaders_RejectsBeforeNetwork(t *testing.T) {
	clientKey := newPrivateJWKForFinalVCITest(t, "client-key-1")
	otherKey := newPrivateJWKForFinalVCITest(t, "other-client-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-key-1")

	expired := clientAttestationClaimsFor(clientKey)
	expired["exp"] = time.Now().Add(-time.Minute).Unix()

	cases := map[string]struct {
		typ      string
		claims   map[string]any
		unsigned bool
		wantErr  string
	}{
		"wrong sub":     {typ: clientAttestationJWTType, claims: map[string]any{"sub": "someone-else"}, wantErr: "does not match client_id"},
		"other cnf key": {typ: clientAttestationJWTType, claims: clientAttestationClaimsFor(otherKey), wantErr: "cnf.jwk does not match"},
		"expired":       {typ: clientAttestationJWTType, claims: expired, wantErr: "expired"},
		"wrong typ":     {typ: "JWT", claims: clientAttestationClaimsFor(clientKey), wantErr: "typ must be"},
		// An attestation this wallet cannot authenticate is refused before its
		// claims are read, and still before any network call.
		"unauthenticatable": {typ: clientAttestationJWTType, claims: clientAttestationClaimsFor(clientKey), unsigned: true, wantErr: "cannot be authenticated"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			token, err := signAttestationJWT(attesterKey, tc.typ, tc.claims)
			require.NoError(t, err)
			w := &Wallet{clientAttestation: fixedClientAttestationProvider{attestation: &ClientAttestation{JWT: token}}}
			if !tc.unsigned {
				// The provider is not one of the bundled attesters, so the
				// wallet is told which key signs its attestations.
				w.attestationTrust = AttestationTrustPolicy{ResolveKey: func(AttestationJOSEHeader) (any, error) {
					return attesterKey.Public().Key, nil
				}}
			}
			req := OID4VCIFinalReceiveRequest{ClientID: "client-1", ClientKey: clientKey}
			_, _, err = w.createOID4VCIAttestationHeaders(t.Context(), nil, req, &receiverTypes.AuthorizationServerMetadata{}, "https://as.example")
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// HAIP §4.3.1: "Wallet Attestations MUST NOT be reused across different
// Issuers." A client attestation whose aud names a different authorization
// server is rejected.
func TestClientAttestationRejectsForeignAudience(t *testing.T) {
	clientKey := newPrivateJWKForFinalVCITest(t, "client-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-key-1")
	request := ClientAttestationRequest{ClientID: "client-1", ClientKey: clientKey, AuthorizationServer: "https://as.example"}

	claims := clientAttestationClaimsFor(clientKey)
	claims["aud"] = "https://other-as.example"
	token, err := signAttestationJWT(attesterKey, clientAttestationJWTType, claims)
	require.NoError(t, err)

	err = validateClientAttestation(&ClientAttestation{JWT: token}, request, false, time.Now())
	require.ErrorContains(t, err, "does not identify the authorization server")
}

func TestClientAttestationAcceptsMatchingAudience(t *testing.T) {
	clientKey := newPrivateJWKForFinalVCITest(t, "client-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-key-1")
	request := ClientAttestationRequest{ClientID: "client-1", ClientKey: clientKey, AuthorizationServer: "https://as.example"}

	audiences := map[string]any{
		"string": "https://as.example",
		"array":  []string{"https://other-as.example", "https://as.example"},
	}
	for name, audience := range audiences {
		t.Run(name, func(t *testing.T) {
			claims := clientAttestationClaimsFor(clientKey)
			claims["aud"] = audience
			token, err := signAttestationJWT(attesterKey, clientAttestationJWTType, claims)
			require.NoError(t, err)
			require.NoError(t, validateClientAttestation(&ClientAttestation{JWT: token}, request, false, time.Now()))
		})
	}
}

func TestClientAttestationAcceptsAbsentAudience(t *testing.T) {
	clientKey := newPrivateJWKForFinalVCITest(t, "client-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-key-1")
	request := ClientAttestationRequest{ClientID: "client-1", ClientKey: clientKey, AuthorizationServer: "https://as.example"}

	token, err := signAttestationJWT(attesterKey, clientAttestationJWTType, clientAttestationClaimsFor(clientKey))
	require.NoError(t, err)
	require.NoError(t, validateClientAttestation(&ClientAttestation{JWT: token}, request, false, time.Now()))
}

func TestKeyAttestationRejectsForeignAudience(t *testing.T) {
	holderKey := newPrivateJWKForFinalVCITest(t, "holder-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	request := KeyAttestationRequest{Keys: []jose.JSONWebKey{holderKey}, Audience: "https://issuer.example"}

	token, err := signAttestationJWT(attesterKey, keyAttestationJWTType, map[string]any{
		"iss":           "https://key-attester.example",
		"iat":           time.Now().Unix(),
		"exp":           time.Now().Add(time.Minute).Unix(),
		"attested_keys": []jose.JSONWebKey{publicHolderJWK(holderKey)},
		"aud":           "https://other-issuer.example",
	})
	require.NoError(t, err)

	err = validateKeyAttestation(&KeyAttestation{JWT: token}, request, false, time.Now())
	require.ErrorContains(t, err, "does not identify the credential issuer")
}

func TestKeyAttestationAcceptsAbsentAudience(t *testing.T) {
	holderKey := newPrivateJWKForFinalVCITest(t, "holder-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	request := KeyAttestationRequest{Keys: []jose.JSONWebKey{holderKey}, Audience: "https://issuer.example"}

	token, err := signAttestationJWT(attesterKey, keyAttestationJWTType, map[string]any{
		"iss":           "https://key-attester.example",
		"iat":           time.Now().Unix(),
		"exp":           time.Now().Add(time.Minute).Unix(),
		"attested_keys": []jose.JSONWebKey{publicHolderJWK(holderKey)},
	})
	require.NoError(t, err)
	require.NoError(t, validateKeyAttestation(&KeyAttestation{JWT: token}, request, false, time.Now()))
}

// testAttesterChain issues a leaf for key under a fresh CA and returns both, so
// a test can configure the CA as the trust anchor the x5c chain must reach.
func testAttesterChain(t *testing.T, key jose.JSONWebKey) (leaf *x509.Certificate, anchor *x509.Certificate) {
	t.Helper()
	caKey := newPrivateJWKForFinalVCITest(t, "attester-ca-key")
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "attester CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		MaxPathLen:            -1,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public().Key, caKey.Key)
	require.NoError(t, err)
	anchor, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + 1),
		Subject:               pkix.Name{CommonName: "attester"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{"attester.example"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, anchor, key.Public().Key, caKey.Key)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return leaf, anchor
}

// attestationTestNoNetwork fails the test if a revocation fetch is attempted.
// The fixtures advertise no CRL distribution point, so a trust path that stays
// inside the configured anchors never needs the network.
type attestationTestNoNetwork struct{ t *testing.T }

func (transport attestationTestNoNetwork) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.t.Errorf("unexpected revocation request: %s", request.URL)
	return nil, errors.New("network must not be used by this fixture")
}

func attestationTestTrustPolicy(t *testing.T, anchors ...*x509.Certificate) AttestationTrustPolicy {
	t.Helper()
	return AttestationTrustPolicy{
		TrustAnchors:                anchors,
		AllowUnadvertisedRevocation: true,
		CRL: commonX509.CRLCheckerOptions{
			HTTPClient: &http.Client{Transport: attestationTestNoNetwork{t}},
		},
	}
}

// TestValidateClientAttestationAuthenticatesTheAttester pins that the wallet
// establishes who signed a Wallet Attestation before it forwards it: the x5c
// leaf key or a caller-supplied resolver verifies the JWS, and an attestation
// offering neither is refused rather than accepted on its claims alone.
func TestValidateClientAttestationAuthenticatesTheAttester(t *testing.T) {
	clientKey := newPrivateJWKForFinalVCITest(t, "client-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-key-1")
	leaf, _ := testAttesterChain(t, attesterKey)
	withX5C := attesterKey
	withX5C.Certificates = []*x509.Certificate{leaf}
	request := ClientAttestationRequest{ClientID: "client-1", ClientKey: clientKey, AuthorizationServer: "https://as.example"}

	signedByAttester := func(key jose.JSONWebKey) *ClientAttestation {
		attester := &StaticClientAttester{Key: key, Issuer: "https://attester.example"}
		attestation, err := attester.ClientAttestation(context.Background(), request)
		require.NoError(t, err)
		return attestation
	}

	t.Run("the x5c leaf key verifies the signature", func(t *testing.T) {
		require.NoError(t, ValidateClientAttestation(t.Context(), signedByAttester(withX5C), request, AttestationTrustPolicy{}))
	})

	t.Run("a resolver verifies an attestation without x5c", func(t *testing.T) {
		policy := AttestationTrustPolicy{ResolveKey: func(AttestationJOSEHeader) (any, error) {
			return attesterKey.Public().Key, nil
		}}
		require.NoError(t, ValidateClientAttestation(t.Context(), signedByAttester(attesterKey), request, policy))
	})

	t.Run("an unauthenticatable attestation is refused", func(t *testing.T) {
		err := ValidateClientAttestation(t.Context(), signedByAttester(attesterKey), request, AttestationTrustPolicy{})
		require.ErrorContains(t, err, "no x5c chain")
	})

	t.Run("a signature made by another key is refused", func(t *testing.T) {
		impostorKey := newPrivateJWKForFinalVCITest(t, "impostor-key")
		impostor := signedByAttester(impostorKey)
		// The impostor presents the genuine attester's certificate, which is
		// exactly the substitution an unverified signature would let through.
		parts := strings.Split(impostor.JWT, ".")
		require.Len(t, parts, 3)
		forged := &ClientAttestation{JWT: strings.Join([]string{
			base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{
				"typ": clientAttestationJWTType,
				"alg": "ES256",
				"x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)},
			})), parts[1], parts[2],
		}, "."), ExpiresAt: impostor.ExpiresAt}
		err := ValidateClientAttestation(t.Context(), forged, request, AttestationTrustPolicy{})
		require.ErrorContains(t, err, "signature could not be verified")
	})

	t.Run("a resolver that returns the wrong key is refused", func(t *testing.T) {
		otherKey := newPrivateJWKForFinalVCITest(t, "other-key")
		policy := AttestationTrustPolicy{ResolveKey: func(AttestationJOSEHeader) (any, error) {
			return otherKey.Public().Key, nil
		}}
		err := ValidateClientAttestation(t.Context(), signedByAttester(withX5C), request, policy)
		require.ErrorContains(t, err, "signature could not be verified")
	})
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

// TestValidateClientAttestationValidatesTheChain pins the trust-anchor half:
// with anchors configured the x5c chain must reach one of them, and under the
// HAIP rules the anchor itself must not travel inside the header.
func TestValidateClientAttestationValidatesTheChain(t *testing.T) {
	clientKey := newPrivateJWKForFinalVCITest(t, "client-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-key-1")
	leaf, anchor := testAttesterChain(t, attesterKey)
	attesterKey.Certificates = []*x509.Certificate{leaf}
	request := ClientAttestationRequest{ClientID: "client-1", ClientKey: clientKey, AuthorizationServer: "https://as.example"}
	attester := &StaticClientAttester{Key: attesterKey, Issuer: "https://attester.example"}
	attestation, err := attester.ClientAttestation(context.Background(), request)
	require.NoError(t, err)

	t.Run("a chain reaching the configured anchor is trusted", func(t *testing.T) {
		require.NoError(t, ValidateClientAttestation(t.Context(), attestation, request, attestationTestTrustPolicy(t, anchor)))
	})

	t.Run("a chain reaching no configured anchor is refused", func(t *testing.T) {
		otherKey := newPrivateJWKForFinalVCITest(t, "unrelated-attester")
		_, unrelatedAnchor := testAttesterChain(t, otherKey)
		err := ValidateClientAttestation(t.Context(), attestation, request, attestationTestTrustPolicy(t, unrelatedAnchor))
		require.ErrorContains(t, err, "chain is not trusted")
	})

	t.Run("anchors without a revocation client are refused", func(t *testing.T) {
		err := ValidateClientAttestation(t.Context(), attestation, request, AttestationTrustPolicy{TrustAnchors: []*x509.Certificate{anchor}})
		require.ErrorContains(t, err, "no CRL HTTP client")
	})

	t.Run("HAIP refuses the trust anchor inside x5c", func(t *testing.T) {
		withAnchor := attesterKey
		withAnchor.Certificates = []*x509.Certificate{leaf, anchor}
		carrying := &StaticClientAttester{Key: withAnchor, Issuer: "https://attester.example"}
		carried, err := carrying.ClientAttestation(context.Background(), request)
		require.NoError(t, err)

		policy := attestationTestTrustPolicy(t, anchor)
		policy.RequireX5C = true
		err = ValidateClientAttestation(t.Context(), carried, request, policy)
		require.ErrorContains(t, err, "trust anchor")
	})
}

// TestStaticClientAttesterBindsTheAudience covers HAIP Section 4.4.1: "Wallet
// Attestations MUST NOT be reused across different Issuers". The bundled
// attester states the authorization server it minted the attestation for, so
// the same attestation cannot be replayed at another one.
func TestStaticClientAttesterBindsTheAudience(t *testing.T) {
	clientKey := newPrivateJWKForFinalVCITest(t, "client-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-key-1")
	leaf, _ := testAttesterChain(t, attesterKey)
	attesterKey.Certificates = []*x509.Certificate{leaf}
	attester := &StaticClientAttester{Key: attesterKey, Issuer: "https://attester.example"}
	request := ClientAttestationRequest{ClientID: "client-1", ClientKey: clientKey, AuthorizationServer: "https://as.example"}

	attestation, err := attester.ClientAttestation(context.Background(), request)
	require.NoError(t, err)
	_, claims, err := parseAttestationJWT(attestation.JWT)
	require.NoError(t, err)
	require.Equal(t, "https://as.example", claims.Aud)

	require.NoError(t, ValidateClientAttestation(t.Context(), attestation, request, AttestationTrustPolicy{}))

	elsewhere := request
	elsewhere.AuthorizationServer = "https://other-as.example"
	require.ErrorContains(t, ValidateClientAttestation(t.Context(), attestation, elsewhere, AttestationTrustPolicy{}), "does not identify the authorization server")
}

// TestValidateKeyAttestationAuthenticatesTheAttester is the key-attestation
// half of the same rule, including HAIP Section 4.4.2, which requires the
// signing certificate in x5c and forbids the trust anchor there.
func TestValidateKeyAttestationAuthenticatesTheAttester(t *testing.T) {
	holderKey := newPrivateJWKForFinalVCITest(t, "holder-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	leaf, anchor := testAttesterChain(t, attesterKey)
	withX5C := attesterKey
	withX5C.Certificates = []*x509.Certificate{leaf}
	request := KeyAttestationRequest{Keys: []jose.JSONWebKey{holderKey}, Nonce: "cnonce-1", Audience: "https://issuer.example"}

	attest := func(key jose.JSONWebKey) *KeyAttestation {
		attester := &StaticKeyAttester{Key: key, Issuer: "https://key-attester.example"}
		attestation, err := attester.KeyAttestation(context.Background(), request)
		require.NoError(t, err)
		return attestation
	}

	t.Run("the x5c leaf key verifies the signature", func(t *testing.T) {
		require.NoError(t, ValidateKeyAttestation(t.Context(), attest(withX5C), request, AttestationTrustPolicy{}))
	})

	t.Run("a chain reaching the configured anchor is trusted", func(t *testing.T) {
		policy := attestationTestTrustPolicy(t, anchor)
		policy.RequireX5C = true
		require.NoError(t, ValidateKeyAttestation(t.Context(), attest(withX5C), request, policy))
	})

	t.Run("an unauthenticatable attestation is refused", func(t *testing.T) {
		err := ValidateKeyAttestation(t.Context(), attest(attesterKey), request, AttestationTrustPolicy{})
		require.ErrorContains(t, err, "no x5c chain")
	})

	t.Run("a tampered payload is refused", func(t *testing.T) {
		attestation := attest(withX5C)
		parts := strings.Split(attestation.JWT, ".")
		require.Len(t, parts, 3)
		tampered := &KeyAttestation{JWT: strings.Join([]string{
			parts[0],
			base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{
				"iss":           "https://key-attester.example",
				"iat":           time.Now().Unix(),
				"exp":           time.Now().Add(time.Minute).Unix(),
				"nonce":         "cnonce-1",
				"attested_keys": []jose.JSONWebKey{publicHolderJWK(holderKey)},
			})), parts[2],
		}, ".")}
		require.ErrorContains(t, ValidateKeyAttestation(t.Context(), tampered, request, AttestationTrustPolicy{}), "signature could not be verified")
	})
}
