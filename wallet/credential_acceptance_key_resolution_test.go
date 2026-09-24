package wallet

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
)

// requireIssuerKey asserts that verification reports want as the key the
// issuer signature verified under, compared by RFC 7638 thumbprint.
func requireIssuerKey(t *testing.T, verification *CredentialVerification, want *ecdsa.PrivateKey) {
	t.Helper()
	require.NotNil(t, verification)
	require.NotNil(t, verification.IssuerKey)
	require.True(t, verification.IssuerKey.IsPublic(), "the reported issuer key must be public")
	got, err := verification.IssuerKey.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	expected, err := (&jose.JSONWebKey{Key: &want.PublicKey}).Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, expected, got)
}

// requireChainErrorCode asserts that err carries the x5c chain verdict code.
func requireChainErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var chainError *commonX509.SigningChainError
	require.ErrorAs(t, err, &chainError)
	require.Equal(t, code, chainError.ErrorCode())
}

// TestCredentialAcceptorKidOrdersResolvedKeys pins that the header kid is a
// hint for which resolved key to try first, not a filter: the header is
// unauthenticated until a key verifies it.
func TestCredentialAcceptorKidOrdersResolvedKeys(t *testing.T) {
	acceptor := newTestCredentialAcceptor(t)
	signer := newTestECKey(t)
	stale := newTestECKey(t)
	wire := []byte(buildAcceptanceWire(t, acceptanceWire{signingKey: signer, kid: "issuer-key-1"}))

	t.Run("a kid-matching key that does not verify does not refuse the credential", func(t *testing.T) {
		policy := CredentialAcceptancePolicy{ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
			return []jose.JSONWebKey{
				{Key: &stale.PublicKey, KeyID: "issuer-key-1"},
				{Key: &signer.PublicKey, KeyID: "issuer-key-2"},
			}, nil
		}}
		verification, err := acceptor.Verify(t.Context(), wire, policy)
		require.NoError(t, err)
		require.Equal(t, "issuer-key-2", verification.IssuerKeyID)
		requireIssuerKey(t, verification, signer)
	})

	t.Run("the kid-matching key is tried before the others", func(t *testing.T) {
		// Both entries hold the signing key, so whichever is tried first is
		// the one reported: the kid match wins although it is listed last.
		policy := CredentialAcceptancePolicy{ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
			return []jose.JSONWebKey{
				{Key: &signer.PublicKey, KeyID: "other-name"},
				{Key: &signer.PublicKey, KeyID: "issuer-key-1"},
			}, nil
		}}
		verification, err := acceptor.Verify(t.Context(), wire, policy)
		require.NoError(t, err)
		require.Equal(t, "issuer-key-1", verification.IssuerKeyID)
		requireIssuerKey(t, verification, signer)
	})

	t.Run("without a kid every resolved key is tried in order", func(t *testing.T) {
		unnamed := []byte(buildAcceptanceWire(t, acceptanceWire{signingKey: signer}))
		policy := CredentialAcceptancePolicy{ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
			return []jose.JSONWebKey{
				{Key: &stale.PublicKey, KeyID: "stale"},
				{Key: &signer.PublicKey, KeyID: "current"},
			}, nil
		}}
		verification, err := acceptor.Verify(t.Context(), unnamed, policy)
		require.NoError(t, err)
		require.Equal(t, "current", verification.IssuerKeyID)
		requireIssuerKey(t, verification, signer)
	})

	t.Run("no resolved key verifying is still a signature failure", func(t *testing.T) {
		policy := CredentialAcceptancePolicy{ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
			return []jose.JSONWebKey{{Key: &stale.PublicKey, KeyID: "issuer-key-1"}}, nil
		}}
		_, err := acceptor.Verify(t.Context(), wire, policy)
		require.ErrorIs(t, err, ErrIssuerSignatureInvalid)
	})
}

func TestResolveIssuerKeyCandidatesOrdersByKid(t *testing.T) {
	keys := []jose.JSONWebKey{{KeyID: "a"}, {KeyID: "b"}, {KeyID: "c"}, {KeyID: "b"}}
	policy := &CredentialAcceptancePolicy{ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
		return keys, nil
	}}
	kids := func(ordered []jose.JSONWebKey) []string {
		names := make([]string, 0, len(ordered))
		for _, key := range ordered {
			names = append(names, key.KeyID)
		}
		return names
	}

	ordered, err := resolveIssuerKeyCandidates(policy, "https://issuer.example.test", map[string]any{"kid": "b"}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"b", "b", "a", "c"}, kids(ordered))

	ordered, err = resolveIssuerKeyCandidates(policy, "https://issuer.example.test", map[string]any{"kid": "unknown"}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c", "b"}, kids(ordered))

	ordered, err = resolveIssuerKeyCandidates(policy, "https://issuer.example.test", map[string]any{}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c", "b"}, kids(ordered))
}

// revokedIssuerChain builds an anchored issuer chain whose leaf advertises a
// CRL distribution point served over HTTP, where the CA lists the leaf as
// revoked.
func revokedIssuerChain(t *testing.T) (testIssuerChain, *http.Client) {
	t.Helper()
	now := time.Now()
	caKey := newTestECKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Revoking Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafSerial := big.NewInt(7)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                now.Add(-time.Hour),
		NextUpdate:                now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: leafSerial, RevocationTime: now.Add(-time.Minute)}},
	}, caCert, caKey)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(crlDER)
	}))
	t.Cleanup(server.Close)

	leafKey := newTestECKey(t)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "Revoked Test Issuer"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		CRLDistributionPoints: []string{server.URL + "/issuer.crl"},
	}, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return testIssuerChain{caCert: caCert, caKey: caKey, leafCert: leafCert, leafKey: leafKey}, server.Client()
}

// TestCredentialAcceptorResolveIssuerKeysWhenX5CUntrusted pins when key
// resolution may take over from an x5c chain: only when the chain reaches none
// of the configured anchors, never when the chain says something about the
// signer such as a revoked certificate.
func TestCredentialAcceptorResolveIssuerKeysWhenX5CUntrusted(t *testing.T) {
	acceptor := newTestCredentialAcceptor(t)
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	unrelated := newTestIssuerChain(t, []string{"issuer.example.test"})
	untrustedWire := []byte(buildAcceptanceWire(t, acceptanceWire{signingKey: chain.leafKey, x5c: chain.x5c(), kid: "issuer-key-1"}))
	leafJWK := jose.JSONWebKey{Key: &chain.leafKey.PublicKey, KeyID: "issuer-key-1"}

	type resolution struct {
		calls int
		keys  []jose.JSONWebKey
		err   error
	}
	policy := func(anchors []*x509.Certificate, fallback bool, resolved *resolution) CredentialAcceptancePolicy {
		return CredentialAcceptancePolicy{
			IssuerX509: &IssuerX509TrustOptions{TrustAnchors: anchors, AllowUnadvertisedRevocation: true},
			ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
				resolved.calls++
				return resolved.keys, resolved.err
			},
			ResolveIssuerKeysWhenX5CUntrusted: fallback,
		}
	}

	t.Run("an unanchored chain hands over to the resolved key", func(t *testing.T) {
		resolved := &resolution{keys: []jose.JSONWebKey{leafJWK}}
		verification, err := acceptor.Verify(t.Context(), untrustedWire, policy(unrelated.anchors(), true, resolved))
		require.NoError(t, err)
		require.Equal(t, 1, resolved.calls)
		require.Equal(t, "issuer-key-1", verification.IssuerKeyID)
		require.Nil(t, verification.CertificateSHA256, "an unanchored chain must not be reported as verified")
		requireIssuerKey(t, verification, chain.leafKey)
	})

	t.Run("without the flag an unanchored chain is refused", func(t *testing.T) {
		resolved := &resolution{keys: []jose.JSONWebKey{leafJWK}}
		_, err := acceptor.Verify(t.Context(), untrustedWire, policy(unrelated.anchors(), false, resolved))
		require.Error(t, err)
		requireChainErrorCode(t, err, "x509_chain_untrusted")
		require.ErrorIs(t, err, commonX509.ErrNoTrustAnchor)
		require.Zero(t, resolved.calls)
	})

	t.Run("an anchored chain is still verified through x5c with the flag on", func(t *testing.T) {
		resolved := &resolution{keys: []jose.JSONWebKey{leafJWK}}
		verification, err := acceptor.Verify(t.Context(), untrustedWire, policy(chain.anchors(), true, resolved))
		require.NoError(t, err)
		require.Zero(t, resolved.calls)
		require.Len(t, verification.CertificateSHA256, 2)
		require.Equal(t, verification.CertificateSHA256[0], verification.IssuerKeyID)
		requireIssuerKey(t, verification, chain.leafKey)
	})

	t.Run("a revoked leaf is refused and never falls back to key resolution", func(t *testing.T) {
		revoked, crlClient := revokedIssuerChain(t)
		wire := []byte(buildAcceptanceWire(t, acceptanceWire{signingKey: revoked.leafKey, x5c: revoked.x5c()}))
		resolved := &resolution{keys: []jose.JSONWebKey{{Key: &revoked.leafKey.PublicKey, KeyID: "issuer-key-1"}}}
		revokingPolicy := policy(revoked.anchors(), true, resolved)
		revokingPolicy.IssuerX509.HTTPClient = crlClient

		_, err := acceptor.Verify(t.Context(), wire, revokingPolicy)
		require.Error(t, err)
		requireChainErrorCode(t, err, "x509_chain_revoked")
		var revocation *commonX509.CRLCheckError
		require.ErrorAs(t, err, &revocation)
		require.Equal(t, commonX509.CRLErrorRevoked, revocation.Kind)
		require.NotErrorIs(t, err, ErrIssuerKeyUnresolved)
		require.Zero(t, resolved.calls)
	})

	t.Run("a self-signed leaf is refused and never falls back to key resolution", func(t *testing.T) {
		signerKey := newTestECKey(t)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Self-signed Issuer"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &signerKey.PublicKey, signerKey)
		require.NoError(t, err)
		wire := []byte(buildAcceptanceWire(t, acceptanceWire{signingKey: signerKey, x5c: []string{base64.StdEncoding.EncodeToString(der)}}))
		resolved := &resolution{keys: []jose.JSONWebKey{{Key: &signerKey.PublicKey}}}

		_, err = acceptor.Verify(t.Context(), wire, policy(unrelated.anchors(), true, resolved))
		require.Error(t, err)
		require.NotErrorIs(t, err, commonX509.ErrNoTrustAnchor)
		require.Zero(t, resolved.calls)
	})

	t.Run("an expired leaf is refused and never falls back to key resolution", func(t *testing.T) {
		resolved := &resolution{keys: []jose.JSONWebKey{leafJWK}}
		expired := policy(unrelated.anchors(), true, resolved)
		expired.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }

		_, err := acceptor.Verify(t.Context(), untrustedWire, expired)
		requireChainErrorCode(t, err, "x509_chain_untrusted")
		require.NotErrorIs(t, err, commonX509.ErrNoTrustAnchor)
		require.Zero(t, resolved.calls)
	})

	t.Run("an unanchored chain with no resolved key is unresolved", func(t *testing.T) {
		resolved := &resolution{}
		_, err := acceptor.Verify(t.Context(), untrustedWire, policy(unrelated.anchors(), true, resolved))
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
		require.Equal(t, 1, resolved.calls)
	})

	t.Run("an unanchored chain whose resolver fails is unresolved", func(t *testing.T) {
		resolverFailure := errors.New("issuer JWKS unavailable")
		resolved := &resolution{err: resolverFailure}
		_, err := acceptor.Verify(t.Context(), untrustedWire, policy(unrelated.anchors(), true, resolved))
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
		require.ErrorIs(t, err, resolverFailure)
		require.Equal(t, 1, resolved.calls)
	})

	t.Run("an unanchored chain whose resolved key does not verify is a signature failure", func(t *testing.T) {
		stranger := newTestECKey(t)
		resolved := &resolution{keys: []jose.JSONWebKey{{Key: &stranger.PublicKey, KeyID: "issuer-key-1"}}}
		_, err := acceptor.Verify(t.Context(), untrustedWire, policy(unrelated.anchors(), true, resolved))
		require.ErrorIs(t, err, ErrIssuerSignatureInvalid)
	})
}
