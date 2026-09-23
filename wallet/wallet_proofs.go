package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	joseutil "github.com/trustknots/vcknots/wallet/common/jose"
	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

type credentialRequestProofBindingMethod string

const (
	credentialRequestProofBindingMethodKID credentialRequestProofBindingMethod = "kid"
	credentialRequestProofBindingMethodJWK credentialRequestProofBindingMethod = "jwk"
)

func resolveCredentialRequestProofBindingMethod(
	credentialConfiguration *receiverTypes.CredentialConfiguration,
) credentialRequestProofBindingMethod {
	if credentialConfiguration == nil {
		return credentialRequestProofBindingMethodKID
	}

	format := strings.ToLower(strings.TrimSpace(credentialConfiguration.Format))
	if format == "jwt_vc_json" || format == "jwt_vc" {
		return credentialRequestProofBindingMethodKID
	}

	if credentialConfiguration.CryptographicBindingMethodsSupported == nil {
		return credentialRequestProofBindingMethodKID
	}

	for _, method := range *credentialConfiguration.CryptographicBindingMethodsSupported {
		normalized := strings.ToLower(strings.TrimSpace(method))
		if strings.HasPrefix(normalized, "did:") {
			return credentialRequestProofBindingMethodKID
		}

		if strings.EqualFold(strings.TrimSpace(method), string(credentialRequestProofBindingMethodJWK)) {
			return credentialRequestProofBindingMethodJWK
		}
	}

	return credentialRequestProofBindingMethodKID
}

// generateJWTProof generates a JWT proof for credential requests.
// When clientID is nil, iss is omitted (anonymous pre-authorized flow).
// When clientID is provided, it must be non-empty.
//
// It is generateJWTProofWithTransform with a zero ProofTransform: the proof is
// the one the library builds, untouched.
func (w *Wallet) generateJWTProof(
	key IKeyEntry,
	did *idprofTypes.IdentityProfile,
	nonce *string,
	aud string,
	clientID *string,
	proofBindingMethod credentialRequestProofBindingMethod,
) (string, error) {
	keyID := ""
	if proofBindingMethod != credentialRequestProofBindingMethodJWK {
		if did == nil {
			return "", fmt.Errorf("did is required for kid proof binding")
		}
		if strings.TrimSpace(did.ID) == "" {
			return "", fmt.Errorf("did.ID is required for kid proof binding")
		}
		keyID = did.ID
	}
	return w.generateJWTProofWithTransform(key, keyID, nonce, aud, clientID, proofBindingMethod, ProofTransform{})
}

func (w *Wallet) generateDPoPProof(key IKeyEntry, method, targetURL, accessToken string, nonce *string) (string, error) {
	if key == nil {
		return "", fmt.Errorf("dpop key is required")
	}

	publicJWK := key.PublicKey()

	var pub *ecdsa.PublicKey

	switch k := publicJWK.Key.(type) {
	case *ecdsa.PublicKey:
		pub = k
	case ecdsa.PublicKey:
		pub = &k
	default:
		return "", fmt.Errorf("dpop key must be ECDSA public key")
	}

	if pub.Curve != elliptic.P256() {
		return "", fmt.Errorf("dpop key must use P-256 curve")
	}

	signerAdapter, err := joseutil.NewJWKSigner(key, jose.ES256)
	if err != nil {
		return "", fmt.Errorf("failed to create dpop signer adapter: %w", err)
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       signerAdapter,
	}

	signerOpts := (&jose.SignerOptions{}).WithType("dpop+jwt")

	publicOnlyJWK := jose.JSONWebKey{
		Key:       pub,
		KeyID:     publicJWK.KeyID,
		Algorithm: string(jose.ES256),
		Use:       publicJWK.Use,
	}

	signerOpts = signerOpts.WithHeader("jwk", publicOnlyJWK)

	signer, err := jose.NewSigner(signingKey, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create dpop signer: %w", err)
	}

	claims := map[string]any{
		"jti": uuid.NewString(),
		"htm": strings.ToUpper(method),
		"htu": targetURL,
		"iat": time.Now().Unix(),
	}

	if accessToken != "" {
		accessTokenHash := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(accessTokenHash[:])
	}
	if nonce != nil && *nonce != "" {
		claims["nonce"] = *nonce
	}

	proof, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize dpop proof: %w", err)
	}

	return proof, nil
}
