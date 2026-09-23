package wallet

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	joseutil "github.com/trustknots/vcknots/wallet/common/jose"
	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
)

// ProofJWTContent is the JOSE header and the claim set of a key proof after the
// library has built them and before they are signed. Both maps are the
// library's own copies: a transform may add, replace or remove members without
// affecting anything else.
type ProofJWTContent struct {
	// Header is the protected header. "alg" is not present and cannot be set
	// here: the algorithm is a property of the signing key, and a header that
	// disagreed with the signature would not be a JWS. Everything else the
	// library put there ("typ", and one of "kid" or "jwk") may be changed.
	Header map[string]any
	// Claims is the claim set: "iat" and "aud" always, plus "iss" and "nonce"
	// when the flow has them.
	Claims map[string]any
}

// ProofTransform lets a caller observe and rewrite a key proof at the two
// points where a proof can be changed: before it is signed, and after.
//
// It exists because a wallet is not only a client of an issuer but also a tool
// for testing one. An issuer implementer needs to see what their deployment
// does with a proof whose nonce is wrong, whose key identifier resolves to
// nothing, or whose signature does not verify, and building those proofs by
// hand outside the library means reimplementing the flow around them.
//
// The two members are separate because they break different things. Content
// runs before signing, so a proof it rewrites is still correctly signed over
// the content it now carries and a rejection is attributable to that content.
// Serialized runs on the finished compact JWS, which is the only place a
// signature itself can be damaged.
//
// A zero ProofTransform is the identity: the proof is exactly the one the
// library would have produced, byte for byte. Neither member is called when it
// is nil, so a caller that wants one point does not have to supply the other.
type ProofTransform struct {
	// Content rewrites the header and claims before signing. Returning an
	// error aborts the issuance.
	Content func(ProofJWTContent) (ProofJWTContent, error)
	// Serialized rewrites the finished compact JWS. Returning an error aborts
	// the issuance.
	Serialized func(string) (string, error)
}

func (t ProofTransform) applyContent(content ProofJWTContent) (ProofJWTContent, error) {
	if t.Content == nil {
		return content, nil
	}
	transformed, err := t.Content(content)
	if err != nil {
		return ProofJWTContent{}, fmt.Errorf("%w: %w", ErrDraft13ProofTransformFailed, err)
	}
	if transformed.Header == nil {
		transformed.Header = map[string]any{}
	}
	if transformed.Claims == nil {
		transformed.Claims = map[string]any{}
	}
	return transformed, nil
}

func (t ProofTransform) applySerialized(proof string) (string, error) {
	if t.Serialized == nil {
		return proof, nil
	}
	transformed, err := t.Serialized(proof)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrDraft13ProofTransformFailed, err)
	}
	return transformed, nil
}

// proofJWTContent builds the header and claims of an OpenID4VCI §7.2.1 (Draft
// 13; §8.2.1.1 in 1.0) "jwt" key proof. It is separated from the signing so a
// transform sees exactly what the library would have signed.
//
// keyID is the value of the "kid" header of a kid-bound proof, and is ignored
// for a jwk-bound one, whose header carries the public key instead.
func proofJWTContent(
	key IKeyEntry,
	keyID string,
	nonce *string,
	aud string,
	clientID *string,
	proofBindingMethod credentialRequestProofBindingMethod,
	now time.Time,
) (ProofJWTContent, error) {
	header := map[string]any{"typ": "openid4vci-proof+jwt"}
	if proofBindingMethod == credentialRequestProofBindingMethodJWK {
		publicJWK := key.PublicKey()
		header["jwk"] = publicJWK.Public()
	} else {
		if strings.TrimSpace(keyID) == "" {
			return ProofJWTContent{}, fmt.Errorf("a key identifier is required for kid proof binding")
		}
		header["kid"] = keyID
	}

	claims := map[string]any{
		"iat": now.Unix(),
		"aud": aud,
	}
	if clientID != nil {
		if strings.TrimSpace(*clientID) == "" {
			return ProofJWTContent{}, fmt.Errorf("clientID must be non-empty when provided")
		}
		claims["iss"] = *clientID
	}
	if nonce != nil && *nonce != "" {
		claims["nonce"] = *nonce
	}
	return ProofJWTContent{Header: header, Claims: claims}, nil
}

// didKeyVerificationMethod returns the DID URL of the one verification method
// a did:key document has, `did:key:<mb>#<mb>` (did:key Method §3.1.2). Draft 13
// §7.2.1.1 says a kid-bound proof's kid "refers to a DID URL which identifies a
// particular key in the DID Document", which the bare DID does not.
func didKeyVerificationMethod(did *idprofTypes.IdentityProfile) (string, error) {
	if did == nil || strings.TrimSpace(did.ID) == "" {
		return "", fmt.Errorf("did is required for kid proof binding")
	}
	identifier, ok := strings.CutPrefix(did.ID, "did:key:")
	if !ok || identifier == "" {
		return "", fmt.Errorf("did %q is not a did:key", did.ID)
	}
	if strings.Contains(did.ID, "#") {
		return did.ID, nil
	}
	return did.ID + "#" + identifier, nil
}

// signProofJWT signs the content with key and applies transform's serialized
// half to the result.
func signProofJWT(
	key IKeyEntry,
	content ProofJWTContent,
	transform ProofTransform,
) (string, error) {
	// The protected header is exactly the content's header plus "alg": the
	// signer would otherwise add a "kid" of its own from the key entry, which a
	// jwk-bound proof must not carry and a kid-bound one already names.
	signingKeyEntry := keyEntryWithoutPublicKeyID{IKeyEntry: key}

	signerOpts := &jose.SignerOptions{}
	// A map has no order and the header of a JWS does, so the members are
	// applied in a stable order: two runs with the same content produce the
	// same bytes, which is what the untouched path guarantees.
	names := make([]string, 0, len(content.Header))
	for name := range content.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.EqualFold(name, "alg") {
			// The algorithm belongs to the signature, which is produced below.
			continue
		}
		signerOpts = signerOpts.WithHeader(jose.HeaderKey(name), content.Header[name])
	}

	signerAdapter, err := joseutil.NewJWKSigner(signingKeyEntry, jose.ES256)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT proof signer adapter: %w", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signerAdapter}, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT proof signer: %w", err)
	}
	proof, err := jwt.Signed(signer).Claims(map[string]any(content.Claims)).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWT proof: %w", err)
	}
	return transform.applySerialized(proof)
}

// generateJWTProofWithTransform builds the key proof generateJWTProof builds and
// passes it through transform. A zero transform produces the same bytes as
// generateJWTProof.
func (w *Wallet) generateJWTProofWithTransform(
	key IKeyEntry,
	keyID string,
	nonce *string,
	aud string,
	clientID *string,
	proofBindingMethod credentialRequestProofBindingMethod,
	transform ProofTransform,
) (string, error) {
	content, err := proofJWTContent(key, keyID, nonce, aud, clientID, proofBindingMethod, time.Now())
	if err != nil {
		return "", err
	}
	content, err = transform.applyContent(content)
	if err != nil {
		return "", err
	}
	return signProofJWT(key, content, transform)
}
