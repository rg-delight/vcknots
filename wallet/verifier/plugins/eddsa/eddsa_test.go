package eddsa

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/types"
)

func TestNewEdDSAVerifier(t *testing.T) {
	if NewEdDSAVerifier() == nil {
		t.Fatal("NewEdDSAVerifier() should not return nil")
	}
}

func TestEdDSAVerifier_Verify(t *testing.T) {
	verifier := NewEdDSAVerifier()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	publicKeyJWK := &jose.JSONWebKey{Key: publicKey, KeyID: "test-key-1", Algorithm: string(jose.EdDSA), Use: "sig"}
	payload := []byte("test message for signature")
	proof := credential.CredentialProof{Algorithm: jose.EdDSA, Signature: ed25519.Sign(privateKey, payload), Payload: payload}

	valid, err := verifier.Verify(&proof, publicKeyJWK)
	if err != nil {
		t.Errorf("Verify() should not return error: %v", err)
	}
	if !valid {
		t.Error("Verify() should return true for valid signature")
	}

	// Test with wrong algorithm
	wrongAlgProof := proof
	wrongAlgProof.Algorithm = jose.ES256
	if _, err := verifier.Verify(&wrongAlgProof, publicKeyJWK); !errors.Is(err, types.ErrUnsupportedAlgorithm) {
		t.Errorf("Verify() should reject a proof of another algorithm, got %v", err)
	}

	// Test with nil public key
	if _, err := verifier.Verify(&proof, nil); err == nil {
		t.Error("Verify() should return error for nil public key")
	}

	// Test with invalid key type
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	if _, err := verifier.Verify(&proof, &jose.JSONWebKey{Key: &ecKey.PublicKey}); !errors.Is(err, types.ErrInvalidPublicKey) {
		t.Errorf("Verify() should reject a key of another type, got %v", err)
	}

	// Test with invalid signature length
	invalidSigProof := proof
	invalidSigProof.Signature = []byte("invalid-signature")
	if _, err := verifier.Verify(&invalidSigProof, publicKeyJWK); !errors.Is(err, types.ErrInvalidSignature) {
		t.Errorf("Verify() should reject an invalid signature length, got %v", err)
	}

	// Test with tampered payload
	tamperedProof := proof
	tamperedProof.Payload = []byte("tampered message")
	if valid, err := verifier.Verify(&tamperedProof, publicKeyJWK); err == nil && valid {
		t.Error("Verify() should fail for tampered payload")
	}
}
