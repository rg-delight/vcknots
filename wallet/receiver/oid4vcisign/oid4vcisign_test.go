package oid4vcisign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// TestCreateClientAttestationAudience pins that the additive options entry
// point can bind a self-issued Wallet Attestation to one authorization server.
// HAIP §4.4.1: "Wallet Attestations MUST NOT be reused across different
// Issuers", which is why callers should set Audience. The legacy signature is
// exercised alongside it, because its behaviour must not change.
func TestCreateClientAttestationAudience(t *testing.T) {
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate attester key: %v", err)
	}
	clientJWK := jose.JSONWebKey{Key: clientKey, KeyID: "client-key-1", Algorithm: string(jose.ES256), Use: "sig"}
	attesterJWK := jose.JSONWebKey{Key: attesterKey, KeyID: "attester-key-1", Algorithm: string(jose.ES256), Use: "sig"}
	signer := Default{}

	claimsOf := func(t *testing.T, token string) map[string]any {
		t.Helper()
		parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Fatalf("failed to parse attestation JWT: %v", err)
		}
		var claims map[string]any
		if err := parsed.Claims(&attesterKey.PublicKey, &claims); err != nil {
			t.Fatalf("failed to verify attestation JWT: %v", err)
		}
		return claims
	}

	t.Run("aud is emitted when set", func(t *testing.T) {
		token, err := signer.CreateClientAttestationWithOptions(
			clientJWK, attesterJWK, "https://attester.example", "client-1", time.Minute,
			ClientAttestationOptions{Audience: "https://as.example"},
		)
		if err != nil {
			t.Fatalf("CreateClientAttestationWithOptions() error = %v", err)
		}
		if aud := claimsOf(t, token)["aud"]; aud != "https://as.example" {
			t.Fatalf("aud = %#v, want %q", aud, "https://as.example")
		}
	})

	t.Run("the legacy signature emits no aud", func(t *testing.T) {
		token, err := signer.CreateClientAttestation(clientJWK, attesterJWK, "https://attester.example", "client-1", time.Minute)
		if err != nil {
			t.Fatalf("CreateClientAttestation() error = %v", err)
		}
		if _, present := claimsOf(t, token)["aud"]; present {
			t.Fatal("CreateClientAttestation() added an aud claim; the legacy behaviour must not change")
		}
	})
}
