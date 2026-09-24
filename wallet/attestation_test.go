package wallet

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/keystore"
	"github.com/trustknots/vcknots/wallet/profile"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// testLeafCertificate builds a certificate for key: self-signed, or issued by
// a throwaway CA.
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
	issuer, issuerKey := template, key.Key
	if !selfSigned {
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
		issuer, err = x509.ParseCertificate(caDER)
		require.NoError(t, err)
		issuerKey = caKey.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public().Key, issuerKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate
}

// testKeyEntry wraps a private test JWK as the attester key a static attester
// signs with.
func testKeyEntry(t *testing.T, jwk jose.JSONWebKey) keystore.KeyEntry {
	t.Helper()
	entry, err := keystore.NewKeyEntryFromJWK(jwk)
	require.NoError(t, err)
	return entry
}

// signAttestationJWT signs arbitrary claims under typ, for attestations the
// static attesters would never produce.
func signAttestationJWT(t *testing.T, key jose.JSONWebKey, typ string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key.Key}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	require.NoError(t, err)
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
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
	_, err := w.planOID4VCIKeyAttestation(metadata, "pid", false, false)
	require.ErrorContains(t, err, "§4.5.1")

	// A caller that mints the attestation itself moves the fail-closed point
	// to the credential request (ErrKeyAttestationRequired).
	plan, err := w.planOID4VCIKeyAttestation(metadata, "pid", false, true)
	require.NoError(t, err)
	require.NotNil(t, plan)
	require.Nil(t, plan.provider)
	require.True(t, plan.required)
}

// fixedClientAttestationProvider returns a prebuilt client attestation.
type fixedClientAttestationProvider struct {
	attestation *ClientAttestation
}

func (p fixedClientAttestationProvider) ClientAttestation(context.Context, ClientAttestationRequest) (*ClientAttestation, error) {
	return p.attestation, nil
}

// The attestation is validated before the receiver is touched: a nil receiver
// would panic otherwise, so each case proves the rejection precedes any
// network call.
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
		"wrong sub":     {typ: "oauth-client-attestation+jwt", claims: map[string]any{"sub": "someone-else"}, wantErr: "does not match client_id"},
		"other cnf key": {typ: "oauth-client-attestation+jwt", claims: clientAttestationClaimsFor(otherKey), wantErr: "cnf.jwk does not match"},
		"expired":       {typ: "oauth-client-attestation+jwt", claims: expired, wantErr: "expired"},
		"wrong typ":     {typ: "JWT", claims: clientAttestationClaimsFor(clientKey), wantErr: "typ must be"},
		// Refused before its claims are read, and still before any network call.
		"unauthenticatable": {typ: "oauth-client-attestation+jwt", claims: clientAttestationClaimsFor(clientKey), unsigned: true, wantErr: "cannot be authenticated"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			token := signAttestationJWT(t, attesterKey, tc.typ, tc.claims)
			w := &Wallet{clientAttestation: fixedClientAttestationProvider{attestation: &ClientAttestation{JWT: token}}}
			if !tc.unsigned {
				w.attestationTrust = AttestationTrustPolicy{ResolveKey: func(AttestationJOSEHeader) (any, error) {
					return attesterKey.Public().Key, nil
				}}
			}
			req := OID4VCIFinalReceiveRequest{ClientID: "client-1", ClientKey: clientKey}
			_, _, err := w.createOID4VCIAttestationHeaders(t.Context(), nil, req, &receiverTypes.AuthorizationServerMetadata{}, "https://as.example")
			require.ErrorIs(t, err, ErrClientAttestationInvalid)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestAttestationPolicyForStaticAttesters pins that a bundled static attester
// without a chain is verified with its own key and no extra configuration,
// and that HAIP raises RequireX5C.
func TestAttestationPolicyForStaticAttesters(t *testing.T) {
	clientKey := newPrivateJWKForFinalVCITest(t, "client-key-1")
	attester := &StaticClientAttester{Key: testKeyEntry(t, newPrivateJWKForFinalVCITest(t, "attester-key-1")), Issuer: "https://attester.example"}
	request := ClientAttestationRequest{ClientID: "client-1", ClientKey: clientKey}
	attestation, err := attester.ClientAttestation(t.Context(), request)
	require.NoError(t, err)

	final := &Wallet{profile: profile.Final}
	require.NoError(t, ValidateClientAttestation(t.Context(), attestation, request, final.attestationPolicyFor(attester)))
	require.ErrorContains(t, ValidateClientAttestation(t.Context(), attestation, request, final.attestationPolicyFor(nil)), "no x5c chain")

	haip := &Wallet{profile: profile.HAIP}
	require.True(t, haip.attestationPolicyFor(attester).RequireX5C)
	require.ErrorContains(t, ValidateClientAttestation(t.Context(), attestation, request, haip.attestationPolicyFor(attester)), "x5c")
}

// TestAttestationJOSEHeaderFromJWT covers the header decode the key-proof
// algorithm check uses; it refuses what it cannot read rather than report an
// empty header.
func TestAttestationJOSEHeaderFromJWT(t *testing.T) {
	encode := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	header, err := AttestationJOSEHeaderFromJWT(encode(`{"typ":"key-attestation+jwt","alg":"ES256","kid":"a","x5c":["Zm9v"]}`) + "." + encode(`{}`) + ".sig")
	require.NoError(t, err)
	require.Equal(t, AttestationJOSEHeader{Type: "key-attestation+jwt", Algorithm: "ES256", KeyID: "a", X5C: []string{"Zm9v"}}, header)

	for name, token := range map[string]string{
		"not three parts":   "header.payload",
		"header not base64": "!!!." + encode(`{}`) + ".sig",
		"header not JSON":   encode("nope") + "." + encode(`{}`) + ".sig",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := AttestationJOSEHeaderFromJWT(token)
			require.Error(t, err)
		})
	}
}
