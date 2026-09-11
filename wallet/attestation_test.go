package wallet

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
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
