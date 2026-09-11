package es512

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/types"
)

func TestNewES512Verifier(t *testing.T) {
	if NewES512Verifier() == nil {
		t.Fatal("NewES512Verifier() should not return nil")
	}
}

func es512TestProof(t *testing.T, key *ecdsa.PrivateKey, payload []byte) credential.CredentialProof {
	t.Helper()
	hash := sha512.Sum512(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign test data: %v", err)
	}
	signature := make([]byte, 132)
	r.FillBytes(signature[:132/2])
	s.FillBytes(signature[132/2:])
	return credential.CredentialProof{Algorithm: jose.ES512, Signature: signature, Payload: payload}
}

func TestES512Verifier_Verify(t *testing.T) {
	verifier := NewES512Verifier()
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	publicKeyJWK := &jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: "test-key-1", Algorithm: string(jose.ES512), Use: "sig"}
	payload := []byte("test message for signature")
	proof := es512TestProof(t, privateKey, payload)

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

	// Test with a key on the wrong curve for this algorithm
	otherKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	if _, err := verifier.Verify(&proof, &jose.JSONWebKey{Key: &otherKey.PublicKey}); !errors.Is(err, types.ErrInvalidPublicKey) {
		t.Errorf("Verify() should reject a key on another curve, got %v", err)
	}

	// Test with invalid key type
	if _, err := verifier.Verify(&proof, &jose.JSONWebKey{Key: "not-an-ecdsa-key"}); !errors.Is(err, types.ErrInvalidPublicKey) {
		t.Errorf("Verify() should reject an invalid key type, got %v", err)
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
