package oid4vcisign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/trustknots/vcknots/wallet/receiver/types"
)

func newECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// parseWithEmbeddedJWK verifies a JWT against the jwk in its own protected
// header, as a DPoP or key proof verifier does, and returns the header and
// the claims.
func parseWithEmbeddedJWK(t *testing.T, token string, algs ...jose.SignatureAlgorithm) (jose.Header, map[string]any) {
	t.Helper()
	parsed, err := jwt.ParseSigned(token, algs)
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}
	header := parsed.Headers[0]
	if header.JSONWebKey == nil || !header.JSONWebKey.IsPublic() {
		t.Fatalf("jwk header = %#v, want a public key", header.JSONWebKey)
	}
	var claims map[string]any
	if err := parsed.Claims(header.JSONWebKey.Key, &claims); err != nil {
		t.Fatalf("signature does not verify with the embedded jwk: %v", err)
	}
	return header, claims
}

// RFC 9449 Section 4.2: a DPoP proof carries typ dpop+jwt, the public jwk,
// jti, htm, htu without query and fragment, iat, and nonce and ath when the
// request has them.
func TestCreateDpopProof(t *testing.T) {
	key := jose.JSONWebKey{Key: newECKey(t, elliptic.P256()), KeyID: "dpop-1"}
	signer := Default{}

	t.Run("with nonce and access token", func(t *testing.T) {
		proof, err := signer.CreateDpopProof(key, "post", "https://as.example/token?x=1#frag", "server-nonce", "access-token-1")
		if err != nil {
			t.Fatal(err)
		}
		header, claims := parseWithEmbeddedJWK(t, proof, jose.ES256)
		if typ := header.ExtraHeaders[jose.HeaderType]; typ != "dpop+jwt" {
			t.Errorf("typ = %v", typ)
		}
		if claims["htm"] != "POST" || claims["htu"] != "https://as.example/token" || claims["nonce"] != "server-nonce" {
			t.Errorf("claims = %#v", claims)
		}
		digest := sha256.Sum256([]byte("access-token-1"))
		if claims["ath"] != base64.RawURLEncoding.EncodeToString(digest[:]) {
			t.Errorf("ath = %v", claims["ath"])
		}
		if jti, _ := claims["jti"].(string); jti == "" {
			t.Error("jti is missing")
		}
		if iat, _ := claims["iat"].(float64); time.Since(time.Unix(int64(iat), 0)).Abs() > time.Minute {
			t.Errorf("iat = %v", claims["iat"])
		}
	})
	t.Run("without nonce and access token", func(t *testing.T) {
		proof, err := signer.CreateDpopProof(key, "GET", "https://issuer.example/credential", "", "")
		if err != nil {
			t.Fatal(err)
		}
		_, claims := parseWithEmbeddedJWK(t, proof, jose.ES256)
		if _, present := claims["nonce"]; present {
			t.Error("nonce must be omitted")
		}
		if _, present := claims["ath"]; present {
			t.Error("ath must be omitted")
		}
	})
	t.Run("every proof has its own jti", func(t *testing.T) {
		first, err := signer.CreateDpopProof(key, "POST", "https://as.example/token", "", "")
		if err != nil {
			t.Fatal(err)
		}
		second, err := signer.CreateDpopProof(key, "POST", "https://as.example/token", "", "")
		if err != nil {
			t.Fatal(err)
		}
		_, a := parseWithEmbeddedJWK(t, first, jose.ES256)
		_, b := parseWithEmbeddedJWK(t, second, jose.ES256)
		if a["jti"] == b["jti"] {
			t.Fatalf("jti repeated: %v", a["jti"])
		}
	})
}

// opaqueECSigner is a jose.OpaqueSigner over an ECDSA key, standing in for a
// hardware or remote key the wallet cannot export.
type opaqueECSigner struct {
	key *ecdsa.PrivateKey
}

func (s opaqueECSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: &s.key.PublicKey, KeyID: "hsm-1"}
}

func (s opaqueECSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256}
}

// SignPayload returns the RFC 7518 Section 3.4 ES256 signature, R || S.
func (s opaqueECSigner) SignPayload(payload []byte, _ jose.SignatureAlgorithm) ([]byte, error) {
	digest := sha256.Sum256(payload)
	r, sig, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	sig.FillBytes(out[32:])
	return out, nil
}

// A key held by a jose.OpaqueSigner signs proofs too; the jwk header is its
// public key.
func TestCreateDpopProofWithOpaqueSigner(t *testing.T) {
	private := newECKey(t, elliptic.P256())
	proof, err := Default{}.CreateDpopProof(jose.JSONWebKey{Key: opaqueECSigner{key: private}}, "POST", "https://as.example/token", "", "")
	if err != nil {
		t.Fatal(err)
	}
	header, _ := parseWithEmbeddedJWK(t, proof, jose.ES256)
	public, ok := header.JSONWebKey.Key.(*ecdsa.PublicKey)
	if !ok || !public.Equal(&private.PublicKey) || header.JSONWebKey.KeyID != "hsm-1" {
		t.Fatalf("jwk header = %#v", header.JSONWebKey)
	}
}

// OpenID4VCI 1.0 Section 8.2.1.1: the jwt key proof carries typ
// openid4vci-proof+jwt, the public jwk, aud, iat, the c_nonce when there is
// one, the key_attestation header when given, and an alg the issuer lists.
func TestCreateCredentialRequestJWTProofWithOptions(t *testing.T) {
	signer := Default{}
	p384 := jose.JSONWebKey{Key: newECKey(t, elliptic.P384())}

	t.Run("claims and headers", func(t *testing.T) {
		proof, err := signer.CreateCredentialRequestJWTProofWithOptions(p384, types.ProofOptions{
			Audience:         "https://issuer.example",
			Nonce:            "c-nonce-1",
			KeyAttestation:   "key-attestation-jwt",
			SigningAlgValues: []jose.SignatureAlgorithm{jose.ES256, jose.ES384},
		})
		if err != nil {
			t.Fatal(err)
		}
		header, claims := parseWithEmbeddedJWK(t, proof, jose.ES384)
		if header.Algorithm != string(jose.ES384) || header.ExtraHeaders[jose.HeaderType] != "openid4vci-proof+jwt" {
			t.Errorf("header = %#v", header)
		}
		if header.ExtraHeaders["key_attestation"] != "key-attestation-jwt" {
			t.Errorf("key_attestation = %v", header.ExtraHeaders["key_attestation"])
		}
		if claims["aud"] != "https://issuer.example" || claims["nonce"] != "c-nonce-1" || claims["iat"] == nil {
			t.Errorf("claims = %#v", claims)
		}
	})
	t.Run("no nonce and no key attestation", func(t *testing.T) {
		proof, err := signer.CreateCredentialRequestJWTProofWithOptions(p384, types.ProofOptions{Audience: "https://issuer.example"})
		if err != nil {
			t.Fatal(err)
		}
		header, claims := parseWithEmbeddedJWK(t, proof, jose.ES384)
		if _, present := claims["nonce"]; present {
			t.Error("nonce must be omitted")
		}
		if _, present := header.ExtraHeaders["key_attestation"]; present {
			t.Error("key_attestation must be omitted")
		}
	})
	t.Run("no listed algorithm the key can produce", func(t *testing.T) {
		_, err := signer.CreateCredentialRequestJWTProofWithOptions(p384, types.ProofOptions{
			Audience:         "https://issuer.example",
			SigningAlgValues: []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA},
		})
		if !errors.Is(err, ErrProofAlgorithmNotSupported) {
			t.Fatalf("err = %v, want ErrProofAlgorithmNotSupported", err)
		}
	})
}
