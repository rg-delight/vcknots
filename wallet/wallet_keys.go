package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// IKeyEntry represents a key entry interface for signing operations.
// Sign signs the input bytes. ECDSA implementations may return either
// DER-encoded ASN.1 signatures or raw IEEE P1363 (R || S) signatures.
// Callers that require JWS-compatible ES256 signatures should prefer
// using JWKSigner, which normalizes DER-encoded signatures to IEEE P1363.
type IKeyEntry interface {
	ID() string
	PublicKey() jose.JSONWebKey
	Sign(data []byte) ([]byte, error)
}
type inMemoryECKeyEntry struct {
	id      string
	privKey *ecdsa.PrivateKey
	pubJWK  jose.JSONWebKey
}
type keyEntryWithoutPublicKeyID struct {
	IKeyEntry
}

func (k keyEntryWithoutPublicKeyID) PublicKey() jose.JSONWebKey {
	jwk := k.IKeyEntry.PublicKey()
	jwk.KeyID = ""
	return jwk
}
func newInMemoryECKeyEntry() (*inMemoryECKeyEntry, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	id := uuid.NewString()
	pubJWK := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     id,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	return &inMemoryECKeyEntry{
		id:      id,
		privKey: privKey,
		pubJWK:  pubJWK,
	}, nil
}
func (k *inMemoryECKeyEntry) ID() string {
	return k.id
}
func (k *inMemoryECKeyEntry) PublicKey() jose.JSONWebKey {
	return k.pubJWK
}
func (k *inMemoryECKeyEntry) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, k.privKey, digest[:])
}
