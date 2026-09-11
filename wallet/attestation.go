package wallet

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Attestation JWT typ values from the OAuth 2.0 Attestation-Based Client
// Authentication draft (draft-ietf-oauth-attestation-based-client-auth) and
// OpenID4VCI 1.0 Appendix D.
const (
	clientAttestationJWTType = "oauth-client-attestation+jwt"
	keyAttestationJWTType    = "key_attestation+jwt"

	defaultAttestationLifetime = 5 * time.Minute
)

// ClientAttestationProvider obtains a Wallet (Client) Attestation for this
// wallet instance from an attester chosen by the caller. The library never
// handles the attester's private key.
type ClientAttestationProvider interface {
	ClientAttestation(ctx context.Context, request ClientAttestationRequest) (*ClientAttestation, error)
}

// ClientAttestationRequest is the input to a ClientAttestationProvider. The
// authorization server identifier is passed so the provider can scope the
// attestation to a single issuer: HAIP §4.4.1 forbids reusing a client
// attestation across authorization servers.
type ClientAttestationRequest struct {
	ClientID            string
	ClientKey           jose.JSONWebKey // public key of the wallet instance (cnf.jwk)
	AuthorizationServer string          // issuer identifier the attestation will be used with
}

// ClientAttestation is a provider-issued Client Attestation JWT.
type ClientAttestation struct {
	JWT       string
	ExpiresAt time.Time
}

// KeyAttestationProvider obtains an OpenID4VCI 1.0 Appendix D key attestation
// for holder keys.
type KeyAttestationProvider interface {
	KeyAttestation(ctx context.Context, request KeyAttestationRequest) (*KeyAttestation, error)
}

// KeyAttestationRequest is the input to a KeyAttestationProvider.
type KeyAttestationRequest struct {
	Keys     []jose.JSONWebKey // public holder keys to attest, in proof order
	Nonce    string            // c_nonce when the issuer provides one
	Audience string            // credential issuer identifier
}

// KeyAttestation is a provider-issued key_attestation+jwt.
type KeyAttestation struct {
	JWT string
}

// StaticClientAttester self-issues attestations with a locally held attester
// key. It exists for tests and single-operator deployments; production wallets
// use a remote provider.
type StaticClientAttester struct {
	Key      jose.JSONWebKey // private signing key; Certificates (x5c) are copied into the header
	Issuer   string
	Lifetime time.Duration // default 5 minutes
}

// StaticKeyAttester likewise self-issues key attestations (tests / local
// operators only).
type StaticKeyAttester struct {
	Key      jose.JSONWebKey
	Issuer   string
	Lifetime time.Duration
}

var _ ClientAttestationProvider = (*StaticClientAttester)(nil)
var _ KeyAttestationProvider = (*StaticKeyAttester)(nil)

// ClientAttestation implements ClientAttestationProvider. The returned JWT has
// typ oauth-client-attestation+jwt, iss = the configured attester, sub = the
// client_id and cnf.jwk = the wallet instance public key, per
// draft-ietf-oauth-attestation-based-client-auth §3.1.
func (a *StaticClientAttester) ClientAttestation(_ context.Context, request ClientAttestationRequest) (*ClientAttestation, error) {
	if a == nil || a.Key.Key == nil {
		return nil, fmt.Errorf("static client attester key is required")
	}
	if strings.TrimSpace(a.Issuer) == "" {
		return nil, fmt.Errorf("static client attester issuer is required")
	}
	if request.ClientKey.Key == nil {
		return nil, fmt.Errorf("client key is required")
	}
	if strings.TrimSpace(request.ClientID) == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	lifetime := a.Lifetime
	if lifetime <= 0 {
		lifetime = defaultAttestationLifetime
	}
	now := time.Now()
	payload := map[string]any{
		"iss": a.Issuer,
		"sub": request.ClientID,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
		"cnf": map[string]any{"jwk": publicHolderJWK(request.ClientKey)},
	}
	token, err := signAttestationJWT(a.Key, clientAttestationJWTType, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create client attestation: %w", err)
	}
	return &ClientAttestation{JWT: token, ExpiresAt: now.Add(lifetime)}, nil
}

// KeyAttestation implements KeyAttestationProvider. The returned JWT has typ
// key_attestation+jwt and lists every requested holder key in attested_keys,
// with nonce copied from the c_nonce when one was supplied (OpenID4VCI 1.0
// Appendix D).
func (a *StaticKeyAttester) KeyAttestation(_ context.Context, request KeyAttestationRequest) (*KeyAttestation, error) {
	if a == nil || a.Key.Key == nil {
		return nil, fmt.Errorf("static key attester key is required")
	}
	if strings.TrimSpace(a.Issuer) == "" {
		return nil, fmt.Errorf("static key attester issuer is required")
	}
	if len(request.Keys) == 0 {
		return nil, fmt.Errorf("at least one holder key is required")
	}
	lifetime := a.Lifetime
	if lifetime <= 0 {
		lifetime = defaultAttestationLifetime
	}
	now := time.Now()
	attested := make([]jose.JSONWebKey, 0, len(request.Keys))
	for index := range request.Keys {
		if request.Keys[index].Key == nil {
			return nil, fmt.Errorf("holder key at index %d is missing a key", index)
		}
		attested = append(attested, publicHolderJWK(request.Keys[index]))
	}
	payload := map[string]any{
		"iss":           a.Issuer,
		"iat":           now.Unix(),
		"exp":           now.Add(lifetime).Unix(),
		"attested_keys": attested,
	}
	if request.Nonce != "" {
		payload["nonce"] = request.Nonce
	}
	token, err := signAttestationJWT(a.Key, keyAttestationJWTType, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create key attestation: %w", err)
	}
	return &KeyAttestation{JWT: token}, nil
}

// validateClientAttestation checks a provider result before the wallet sends it
// to an authorization server. The attester signature is intentionally not
// verified because the wallet does not hold the attester key; only the shape
// and the binding to this wallet instance are checked. Under HAIP the x5c
// chain must be present and its leaf must not be self-signed (HAIP §4.4.1).
func validateClientAttestation(attestation *ClientAttestation, request ClientAttestationRequest, requireX5C bool, now time.Time) error {
	if attestation == nil || strings.TrimSpace(attestation.JWT) == "" {
		return fmt.Errorf("client attestation provider returned an empty attestation")
	}
	header, claims, err := parseAttestationJWT(attestation.JWT)
	if err != nil {
		return fmt.Errorf("client attestation is malformed: %w", err)
	}
	if header.Type != clientAttestationJWTType {
		return fmt.Errorf("client attestation typ must be %q, got %q", clientAttestationJWTType, header.Type)
	}
	if claims.Sub != request.ClientID {
		return fmt.Errorf("client attestation sub %q does not match client_id %q", claims.Sub, request.ClientID)
	}
	if claims.Cnf == nil || claims.Cnf.JWK.Key == nil {
		return fmt.Errorf("client attestation is missing cnf.jwk")
	}
	if err := requireJWKThumbprint(request.ClientKey, claims.Cnf.JWK); err != nil {
		return fmt.Errorf("client attestation cnf.jwk does not match the wallet client key: %w", err)
	}
	if claims.Exp == nil {
		return fmt.Errorf("client attestation is missing exp")
	}
	expiry := time.Unix(int64(*claims.Exp), 0)
	if !attestation.ExpiresAt.IsZero() && attestation.ExpiresAt.Before(expiry) {
		expiry = attestation.ExpiresAt
	}
	if !now.Before(expiry) {
		return fmt.Errorf("client attestation is expired")
	}
	if requireX5C {
		if err := requireNonSelfSignedX5C(header, "client attestation"); err != nil {
			return err
		}
	}
	return nil
}

// validateKeyAttestation checks a provider result before it is embedded in a
// credential request proof. Every requested holder key must appear in
// attested_keys, the nonce must echo the c_nonce when one was given, exp must
// be in the future, and under HAIP the x5c leaf must not be self-signed.
func validateKeyAttestation(attestation *KeyAttestation, request KeyAttestationRequest, requireX5C bool, now time.Time) error {
	if attestation == nil || strings.TrimSpace(attestation.JWT) == "" {
		return fmt.Errorf("key attestation provider returned an empty attestation")
	}
	header, claims, err := parseAttestationJWT(attestation.JWT)
	if err != nil {
		return fmt.Errorf("key attestation is malformed: %w", err)
	}
	if header.Type != keyAttestationJWTType {
		return fmt.Errorf("key attestation typ must be %q, got %q", keyAttestationJWTType, header.Type)
	}
	if claims.Exp == nil {
		return fmt.Errorf("key attestation is missing exp")
	}
	if !now.Before(time.Unix(int64(*claims.Exp), 0)) {
		return fmt.Errorf("key attestation is expired")
	}
	if request.Nonce != "" && claims.Nonce != request.Nonce {
		return fmt.Errorf("key attestation nonce %q does not match the issuer c_nonce %q", claims.Nonce, request.Nonce)
	}
	attested := make(map[string]struct{}, len(claims.AttestedKeys))
	for index := range claims.AttestedKeys {
		thumbprint, err := jwkThumbprint(claims.AttestedKeys[index])
		if err != nil {
			return fmt.Errorf("key attestation attested_keys[%d] is invalid: %w", index, err)
		}
		attested[thumbprint] = struct{}{}
	}
	for index := range request.Keys {
		thumbprint, err := jwkThumbprint(request.Keys[index])
		if err != nil {
			return fmt.Errorf("holder key at index %d is invalid: %w", index, err)
		}
		if _, ok := attested[thumbprint]; !ok {
			return fmt.Errorf("key attestation does not attest the holder key at index %d", index)
		}
	}
	if requireX5C {
		if err := requireNonSelfSignedX5C(header, "key attestation"); err != nil {
			return err
		}
	}
	return nil
}

type attestationJWTHeader struct {
	Type string   `json:"typ"`
	X5C  []string `json:"x5c"`
}

type attestationJWTClaims struct {
	Iss          string            `json:"iss"`
	Sub          string            `json:"sub"`
	Exp          *float64          `json:"exp"`
	Nonce        string            `json:"nonce"`
	AttestedKeys []jose.JSONWebKey `json:"attested_keys"`
	Cnf          *struct {
		JWK jose.JSONWebKey `json:"jwk"`
	} `json:"cnf"`
}

// parseAttestationJWT decodes the protected header and claims of a compact JWS
// without verifying the signature.
func parseAttestationJWT(token string) (attestationJWTHeader, attestationJWTClaims, error) {
	var header attestationJWTHeader
	var claims attestationJWTClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return header, claims, fmt.Errorf("expected a compact JWS with three parts")
	}
	headerBytes, err := decodeJWSSegment(parts[0])
	if err != nil {
		return header, claims, fmt.Errorf("invalid protected header encoding: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return header, claims, fmt.Errorf("invalid protected header JSON: %w", err)
	}
	payloadBytes, err := decodeJWSSegment(parts[1])
	if err != nil {
		return header, claims, fmt.Errorf("invalid payload encoding: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return header, claims, fmt.Errorf("invalid payload JSON: %w", err)
	}
	return header, claims, nil
}

func decodeJWSSegment(segment string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(segment, "="))
}

func requireNonSelfSignedX5C(header attestationJWTHeader, label string) error {
	if len(header.X5C) == 0 {
		return fmt.Errorf("%s must include an x5c header chain", label)
	}
	der, err := base64.StdEncoding.DecodeString(header.X5C[0])
	if err != nil {
		return fmt.Errorf("%s x5c leaf certificate is not base64 DER: %w", label, err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("%s x5c leaf certificate is invalid: %w", label, err)
	}
	if isSelfSignedCertificate(certificate) {
		return fmt.Errorf("%s x5c leaf certificate must not be self-signed", label)
	}
	return nil
}

func isSelfSignedCertificate(certificate *x509.Certificate) bool {
	if certificate == nil || certificate.Issuer.String() != certificate.Subject.String() {
		return false
	}
	return certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) == nil
}

// requireJWKThumbprint fails when the RFC 7638 thumbprint of want does not
// equal the thumbprint of got.
func requireJWKThumbprint(want jose.JSONWebKey, got jose.JSONWebKey) error {
	wantThumbprint, err := jwkThumbprint(want)
	if err != nil {
		return err
	}
	gotThumbprint, err := jwkThumbprint(got)
	if err != nil {
		return err
	}
	if wantThumbprint != gotThumbprint {
		return fmt.Errorf("thumbprint mismatch")
	}
	return nil
}

func jwkThumbprint(key jose.JSONWebKey) (string, error) {
	if key.Key == nil {
		return "", fmt.Errorf("missing key")
	}
	public := key.Public()
	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// publicHolderJWK normalizes a holder key to a public JWK with the defaults the
// attestation profile expects.
func publicHolderJWK(key jose.JSONWebKey) jose.JSONWebKey {
	public := key.Public()
	if public.Algorithm == "" {
		public.Algorithm = string(jose.ES256)
	}
	if public.Use == "" {
		public.Use = "sig"
	}
	if public.KeyID == "" {
		public.KeyID = key.KeyID
	}
	return public
}

func signAttestationJWT(key jose.JSONWebKey, typ string, payload map[string]any) (string, error) {
	if key.Key == nil {
		return "", fmt.Errorf("attester signing key is required")
	}
	alg := jose.SignatureAlgorithm(key.Algorithm)
	if alg == "" {
		alg = jose.ES256
	}
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	if key.KeyID != "" {
		options = options.WithHeader("kid", key.KeyID)
	}
	if len(key.Certificates) > 0 {
		values := make([]string, 0, len(key.Certificates))
		for _, certificate := range key.Certificates {
			values = append(values, base64.StdEncoding.EncodeToString(certificate.Raw))
		}
		options = options.WithHeader("x5c", values)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key.Key}, options)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(payload).Serialize()
}
