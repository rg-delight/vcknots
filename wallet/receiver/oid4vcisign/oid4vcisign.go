// Package oid4vcisign provides the software implementation of the private-key
// operations an OpenID4VCI 1.0 Final / HAIP issuance needs: the RFC 9449 DPoP
// proof, the Section 8.2.1.1 "jwt" key proof and the client attestation JWTs of
// draft-ietf-oauth-attestation-based-client-auth.
//
// It exists so those primitives are no longer welded to the bundled transport
// plugin. A wallet keeps the default by doing nothing, replaces it with a
// hardware or remote signer through the Wallet configuration, and a transport
// plugin written outside this repository embeds Default to inherit the
// software behaviour.
package oid4vcisign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// ErrProofAlgorithmNotSupported reports that the holder key cannot produce any
// of the algorithms the Credential Issuer published in
// proof_signing_alg_values_supported. Callers use errors.Is to tell this apart
// from a signing failure.
var ErrProofAlgorithmNotSupported = errors.New("no proof signing algorithm shared with the issuer")

// defaultAttestationLifetime is the validity applied to a client attestation
// JWT when the caller passes no explicit lifetime.
const defaultAttestationLifetime = 5 * time.Minute

// Default is the software implementation of types.OID4VCIFinalSigner. The zero
// value is ready to use and holds no state, so it can be embedded in a
// transport plugin or passed by value.
type Default struct{}

var _ types.OID4VCIFinalSigner = Default{}

// CreateDpopProof builds the RFC 9449 Section 4.2 DPoP proof for a single HTTP
// request, with the public JWK in the protected header, the htm/htu/iat/jti
// claims, the server-supplied nonce when one is known and the ath hash of the
// access token when the request carries one.
func (Default) CreateDpopProof(key jose.JSONWebKey, method string, rawURL string, nonce string, accessToken string) (string, error) {
	htu, err := dpopHTU(rawURL)
	if err != nil {
		return "", err
	}

	payload := map[string]any{
		"htm": strings.ToUpper(method),
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": uuid.NewString(),
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}
	if accessToken != "" {
		ath := sha256.Sum256([]byte(accessToken))
		payload["ath"] = base64.RawURLEncoding.EncodeToString(ath[:])
	}

	token, err := signJWTWithPublicJWKHeader(key, "dpop+jwt", payload)
	if err != nil {
		return "", fmt.Errorf("failed to create DPoP proof: %w", err)
	}
	return token, nil
}

// CreateCredentialRequestJWTProof builds the Section 8.2.1.1 "jwt" key proof
// with no issuer algorithm constraint and no key attestation.
//
// Deprecated: use CreateCredentialRequestJWTProofWithOptions, which honours the
// Credential Configuration's proof_signing_alg_values_supported.
func (d Default) CreateCredentialRequestJWTProof(key jose.JSONWebKey, audience string, nonce string) (string, error) {
	return d.CreateCredentialRequestJWTProofWithKeyAttestation(key, audience, nonce, "")
}

// CreateCredentialRequestJWTProofWithKeyAttestation builds the same proof as
// CreateCredentialRequestJWTProof and, when keyAttestation is non-empty, adds
// the OpenID4VCI 1.0 Appendix D key_attestation header parameter.
//
// Deprecated: use CreateCredentialRequestJWTProofWithOptions, which takes the
// key attestation in ProofOptions alongside the issuer algorithm constraint.
func (d Default) CreateCredentialRequestJWTProofWithKeyAttestation(key jose.JSONWebKey, audience string, nonce string, keyAttestation string) (string, error) {
	return d.CreateCredentialRequestJWTProofWithOptions(key, types.ProofOptions{
		Audience:       audience,
		Nonce:          nonce,
		KeyAttestation: keyAttestation,
	})
}

// CreateCredentialRequestJWTProofWithOptions builds the Section 8.2.1.1 "jwt"
// key proof for a Credential Request, signing it with an algorithm the
// Credential Issuer accepts.
func (Default) CreateCredentialRequestJWTProofWithOptions(key jose.JSONWebKey, opts types.ProofOptions) (string, error) {
	alg, err := SelectProofSigningAlgorithm(key, opts.SigningAlgValues)
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"aud": opts.Audience,
		"iat": time.Now().Unix(),
	}
	if opts.Nonce != "" {
		payload["nonce"] = opts.Nonce
	}

	var extraHeaders map[string]any
	if opts.KeyAttestation != "" {
		extraHeaders = map[string]any{"key_attestation": opts.KeyAttestation}
	}
	token, err := signJWTWithPublicJWKHeaderAndExtras(key, alg, "openid4vci-proof+jwt", payload, extraHeaders)
	if err != nil {
		return "", fmt.Errorf("failed to create credential request JWT proof: %w", err)
	}
	return token, nil
}

// CreateClientAttestation self-issues the Client Attestation JWT of
// draft-ietf-oauth-attestation-based-client-auth Section 3, signing it with a
// locally held attester key.
//
// A wallet does not hold the attester's private key: the attestation is issued
// by the attester and reaches the wallet through a ClientAttestationProvider,
// which is why this method is not part of types.OID4VCIFinalSigner. It remains
// available for tests, examples and single-operator deployments that act as
// their own attester.
func (Default) CreateClientAttestation(clientKey jose.JSONWebKey, attesterKey jose.JSONWebKey, attesterIssuer string, clientID string, lifetime time.Duration) (string, error) {
	if lifetime == 0 {
		lifetime = defaultAttestationLifetime
	}
	now := time.Now()
	clientPublicJWK := clientKey.Public()
	clientPublicJWK.Algorithm = orDefault(clientPublicJWK.Algorithm, "ES256")
	clientPublicJWK.Use = orDefault(clientPublicJWK.Use, "sig")
	clientPublicJWK.KeyID = orDefault(clientPublicJWK.KeyID, clientKey.KeyID)

	payload := map[string]any{
		"iss": attesterIssuer,
		"sub": clientID,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
		"cnf": map[string]any{
			"jwk": clientPublicJWK,
		},
	}

	token, err := signJWT(attesterKey, "oauth-client-attestation+jwt", payload, x5cHeaders(attesterKey))
	if err != nil {
		return "", fmt.Errorf("failed to create client attestation JWT: %w", err)
	}
	return token, nil
}

// CreateClientAttestationPop builds the Client Attestation PoP JWT of
// draft-ietf-oauth-attestation-based-client-auth Section 4, signed with the
// wallet instance key and bound to the authorization server; the challenge
// claim is added when the server issued one.
func (Default) CreateClientAttestationPop(clientKey jose.JSONWebKey, clientID string, authorizationServerIssuer string, attestationChallenge string, lifetime time.Duration) (string, error) {
	if lifetime == 0 {
		lifetime = defaultAttestationLifetime
	}
	now := time.Now()
	payload := map[string]any{
		"iss": clientID,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
		"aud": authorizationServerIssuer,
		"jti": uuid.NewString(),
	}
	if attestationChallenge != "" {
		payload["challenge"] = attestationChallenge
	}

	token, err := signJWT(clientKey, "oauth-client-attestation-pop+jwt", payload, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create client attestation PoP JWT: %w", err)
	}
	return token, nil
}

// SelectProofSigningAlgorithm returns the algorithm to sign a jwt key proof with.
// OpenID4VCI 1.0 Section 12.2.4.1 makes proof_signing_alg_values_supported
// "REQUIRED. A non-empty array of algorithm identifiers that the Issuer supports
// for this proof type. The Wallet uses one of them to sign the proof", and
// Section 8.2.1.1 requires that "the `alg` JWT header of the key proof ... MUST
// match one of the values listed in the `proof_signing_alg_values_supported`
// metadata parameter".
//
// The holder key's own algorithm is preferred when the issuer lists it, so a
// configured key keeps its algorithm; otherwise the first listed algorithm the
// key's type and curve can produce is chosen, in the issuer's order of
// preference. An empty list is no constraint and yields the key's own algorithm.
func SelectProofSigningAlgorithm(key jose.JSONWebKey, supported []jose.SignatureAlgorithm) (jose.SignatureAlgorithm, error) {
	preferred := defaultSignatureAlgorithm(key)
	if len(supported) == 0 {
		return preferred, nil
	}
	// Section 8.2.1.1 compares the identifiers as the case sensitive strings
	// Section 8.2.2.2 says they are, so no case folding happens here.
	if slices.Contains(supported, preferred) {
		return preferred, nil
	}
	producible := signatureAlgorithmsForKey(key)
	for _, candidate := range supported {
		if slices.Contains(producible, candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("holder key cannot produce any of the issuer's proof_signing_alg_values_supported %v: %w", supported, ErrProofAlgorithmNotSupported)
}

// defaultSignatureAlgorithm reports the algorithm a key signs with when nothing
// constrains the choice: the key's own alg member when it has one, otherwise the
// algorithm its type and curve imply. ES256 remains the last resort for a key
// this package cannot classify, which is the behaviour callers had before the
// issuer's metadata was consulted at all.
func defaultSignatureAlgorithm(key jose.JSONWebKey) jose.SignatureAlgorithm {
	if key.Algorithm != "" {
		return jose.SignatureAlgorithm(key.Algorithm)
	}
	if algorithms := signatureAlgorithmsForKey(key); len(algorithms) > 0 {
		return algorithms[0]
	}
	return jose.ES256
}

// signatureAlgorithmsForKey lists the JWS algorithms a key can actually produce,
// in the order this wallet prefers them. An EC key is bound to the single
// algorithm of its curve (RFC 7518 Section 3.4), so listing anything else would
// only produce a signature the issuer cannot verify. A key type this package does
// not recognise, including an opaque crypto.Signer backed by hardware, yields no
// algorithms; such a key states its algorithm in the JWK alg member instead.
func signatureAlgorithmsForKey(key jose.JSONWebKey) []jose.SignatureAlgorithm {
	public := key.Key
	if signer, ok := key.Key.(crypto.Signer); ok {
		public = signer.Public()
	}
	switch typed := public.(type) {
	case *ecdsa.PublicKey:
		return ellipticCurveAlgorithms(typed.Curve)
	case ecdsa.PublicKey:
		return ellipticCurveAlgorithms(typed.Curve)
	case ed25519.PublicKey:
		return []jose.SignatureAlgorithm{jose.EdDSA}
	case *rsa.PublicKey:
		return []jose.SignatureAlgorithm{jose.PS256, jose.PS384, jose.PS512, jose.RS256, jose.RS384, jose.RS512}
	default:
		return nil
	}
}

func ellipticCurveAlgorithms(curve elliptic.Curve) []jose.SignatureAlgorithm {
	switch curve {
	case elliptic.P256():
		return []jose.SignatureAlgorithm{jose.ES256}
	case elliptic.P384():
		return []jose.SignatureAlgorithm{jose.ES384}
	case elliptic.P521():
		return []jose.SignatureAlgorithm{jose.ES512}
	default:
		return nil
	}
}

// dpopHTU strips the query and fragment from rawURL, which RFC 9449 Section
// 4.2 requires of the htu claim.
func dpopHTU(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse DPoP htu URL: %w", err)
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func signJWTWithPublicJWKHeader(key jose.JSONWebKey, typ string, payload map[string]any) (string, error) {
	return signJWTWithPublicJWKHeaderAndExtras(key, "", typ, payload, nil)
}

// signJWTWithPublicJWKHeaderAndExtras signs payload with the jwk protected
// header the DPoP proof (RFC 9449 Section 4.2) and the jwt key proof
// (OpenID4VCI 1.0 Section 8.2.1.1) both carry. An empty alg lets the key decide,
// which is what a caller with no issuer constraint to honour passes.
func signJWTWithPublicJWKHeaderAndExtras(key jose.JSONWebKey, alg jose.SignatureAlgorithm, typ string, payload map[string]any, extraHeaders map[string]any) (string, error) {
	if alg == "" {
		alg = defaultSignatureAlgorithm(key)
	}
	publicJWK := key.Public()
	publicJWK.Algorithm = string(alg)
	if publicJWK.Use == "" {
		publicJWK.Use = "sig"
	}
	if publicJWK.KeyID == "" {
		publicJWK.KeyID = key.KeyID
	}
	options := (&jose.SignerOptions{}).
		WithType(jose.ContentType(typ)).
		WithHeader("jwk", publicJWK)
	for name, value := range extraHeaders {
		options = options.WithHeader(jose.HeaderKey(name), value)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key.Key}, options)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(payload).Serialize()
}

func signJWT(key jose.JSONWebKey, typ string, payload map[string]any, extraHeaders map[string]any) (string, error) {
	alg := defaultSignatureAlgorithm(key)

	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	if key.KeyID != "" {
		options = options.WithHeader("kid", key.KeyID)
	}
	for name, value := range extraHeaders {
		options = options.WithHeader(jose.HeaderKey(name), value)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, options)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(payload).Serialize()
}

func x5cHeaders(key jose.JSONWebKey) map[string]any {
	if len(key.Certificates) == 0 {
		return nil
	}
	values := make([]string, 0, len(key.Certificates))
	for _, cert := range key.Certificates {
		values = append(values, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	return map[string]any{"x5c": values}
}

// orDefault returns fallback when value is empty.
func orDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
