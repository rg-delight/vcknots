package ps512

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/types"
)

func TestNewPS512Verifier(t *testing.T) {
	if NewPS512Verifier() == nil {
		t.Fatal("NewPS512Verifier() should not return nil")
	}
}

func ps512TestProof(t *testing.T, key *rsa.PrivateKey, payload []byte) credential.CredentialProof {
	t.Helper()
	hash := sha512.Sum512(payload)
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA512, hash[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512})
	if err != nil {
		t.Fatalf("Failed to sign test data: %v", err)
	}
	return credential.CredentialProof{Algorithm: jose.PS512, Signature: signature, Payload: payload}
}

func TestPS512Verifier_Verify(t *testing.T) {
	verifier := NewPS512Verifier()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	publicKeyJWK := &jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: "test-key-1", Algorithm: string(jose.PS512), Use: "sig"}
	payload := []byte("test message for signature")
	proof := ps512TestProof(t, privateKey, payload)

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

	// Test with an RSA key below the 2048 bit minimum of RFC 7518
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	// The modulus is refused before the signature is read, so the proof that
	// accompanies the weak key does not matter.
	if _, err := verifier.Verify(&proof, &jose.JSONWebKey{Key: &weakKey.PublicKey}); !errors.Is(err, types.ErrInvalidPublicKey) {
		t.Errorf("Verify() should reject an RSA key below 2048 bits, got %v", err)
	}

	// Test with tampered payload
	tamperedProof := proof
	tamperedProof.Payload = []byte("tampered message")
	if valid, err := verifier.Verify(&tamperedProof, publicKeyJWK); err == nil && valid {
		t.Error("Verify() should fail for tampered payload")
	}
}
