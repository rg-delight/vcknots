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
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
)

// Attestation JWT typ values from the OAuth 2.0 Attestation-Based Client
// Authentication draft (draft-ietf-oauth-attestation-based-client-auth) and
// OpenID4VCI 1.0 Appendix D.
const (
	clientAttestationJWTType = "oauth-client-attestation+jwt"
	keyAttestationJWTType    = "key-attestation+jwt"

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

// KeyAttestationRequest is the input to a KeyAttestationProvider. Audience is
// the credential issuer identifier the attestation is for: it is genuine
// provider input and, when the produced attestation carries an aud claim, the
// value is checked against it.
type KeyAttestationRequest struct {
	Keys     []jose.JSONWebKey // public holder keys to attest, in proof order
	Nonce    string            // c_nonce when the issuer provides one
	Audience string            // credential issuer identifier
}

// KeyAttestation is a provider-issued key-attestation+jwt.
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
	// HAIP Section 4.4.1: "Wallet Attestations MUST NOT be reused across
	// different Issuers." An audience-restricted attestation is what lets the
	// authorization server, and ValidateClientAttestation here, detect the
	// reuse; an attestation issued without an audience asserts nothing about
	// which server it was minted for.
	if server := strings.TrimSpace(request.AuthorizationServer); server != "" {
		payload["aud"] = server
	}
	token, err := signAttestationJWT(a.Key, clientAttestationJWTType, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create client attestation: %w", err)
	}
	return &ClientAttestation{JWT: token, ExpiresAt: now.Add(lifetime)}, nil
}

// KeyAttestation implements KeyAttestationProvider. The returned JWT has typ
// key-attestation+jwt and lists every requested holder key in attested_keys,
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

// ValidateClientAttestation authenticates a provider result before the wallet
// sends it to an authorization server, and is the only path the wallet itself
// uses. It verifies the attester's signature (policy.ResolveKey, else the x5c
// leaf key), validates the x5c chain against the policy's trust anchors when
// any are configured, and then checks the binding to this wallet instance: typ,
// sub against the client_id, cnf.jwk against the wallet key, aud against the
// authorization server and exp.
//
// There is no opt-out: an attestation whose signature this wallet cannot check
// is refused rather than forwarded, because a Wallet Attestation is the
// wallet's own client credential and a provider that returns an unverifiable
// one has failed.
//
// A present aud claim must identify the authorization server, because HAIP
// Section 4.4.1 states that "Wallet Attestations MUST NOT be reused across
// different Issuers". With policy.RequireX5C the x5c chain must be present and
// its leaf must not be self-signed: HAIP Section 4.4.1 requires that "the
// public key certificate, and optionally a trust certificate chain excluding
// the trust anchor, used to validate the signature on the Wallet Attestation
// MUST be included in the x5c JOSE header of the Client Attestation JWT".
func ValidateClientAttestation(ctx context.Context, attestation *ClientAttestation, request ClientAttestationRequest, policy AttestationTrustPolicy) error {
	if attestation == nil || strings.TrimSpace(attestation.JWT) == "" {
		return fmt.Errorf("client attestation provider returned an empty attestation")
	}
	header, _, err := parseAttestationJWT(attestation.JWT)
	if err != nil {
		return fmt.Errorf("client attestation is malformed: %w", err)
	}
	if err := authenticateAttestationJWT(ctx, attestation.JWT, header, policy, "client attestation", policy.now()); err != nil {
		return err
	}
	return validateClientAttestation(attestation, request, policy.RequireX5C, policy.now())
}

// validateClientAttestation checks the claims of an already authenticated
// Wallet Attestation against the request it was obtained for. It is the second
// half of ValidateClientAttestation, which is the only entry point that also
// establishes who signed the attestation.
func validateClientAttestation(attestation *ClientAttestation, request ClientAttestationRequest, requireX5C bool, now time.Time) error {
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
	// HAIP §4.3.1: "Wallet Attestations MUST NOT be reused across different
	// Issuers." An absent aud is permitted; a present-but-wrong one is the
	// reuse the profile forbids.
	if !attestationAudienceMatches(claims.Aud, request.AuthorizationServer) {
		return fmt.Errorf("client attestation aud %v does not identify the authorization server %q",
			claims.Aud, request.AuthorizationServer)
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
		chain, err := commonX509.DecodeX5CChain(header.X5C)
		if err != nil {
			return err
		}
		if err := commonX509.RequireNonSelfSignedLeaf(chain, "client attestation"); err != nil {
			return err
		}
	}
	return nil
}

// ValidateKeyAttestation authenticates a provider result before it is embedded
// in a credential request proof, the same way ValidateClientAttestation does:
// the attester signature is verified (policy.ResolveKey, else the x5c leaf key)
// and the chain is validated against the configured trust anchors. Then every
// requested holder key must appear in attested_keys, the nonce must echo the
// c_nonce when one was given, a present aud claim must identify the request
// audience, and exp must be in the future.
//
// With policy.RequireX5C the chain must be present and its leaf must not be
// self-signed, which is HAIP Section 4.4.2: "The public key used to validate
// the signature on the key attestation MUST be included in the x5c JOSE header
// of the key attestation. The X.509 certificate of the trust anchor MUST NOT be
// included in the x5c JOSE header of the key attestation. The X.509 certificate
// signing the key attestation MUST NOT be self-signed."
func ValidateKeyAttestation(ctx context.Context, attestation *KeyAttestation, request KeyAttestationRequest, policy AttestationTrustPolicy) error {
	if attestation == nil || strings.TrimSpace(attestation.JWT) == "" {
		return fmt.Errorf("key attestation provider returned an empty attestation")
	}
	header, _, err := parseAttestationJWT(attestation.JWT)
	if err != nil {
		return fmt.Errorf("key attestation is malformed: %w", err)
	}
	if err := authenticateAttestationJWT(ctx, attestation.JWT, header, policy, "key attestation", policy.now()); err != nil {
		return err
	}
	return validateKeyAttestation(attestation, request, policy.RequireX5C, policy.now())
}

// validateKeyAttestation checks the claims of an already authenticated key
// attestation against the request it was obtained for. It is the second half of
// ValidateKeyAttestation, which is the only entry point that also establishes
// who signed the attestation.
func validateKeyAttestation(attestation *KeyAttestation, request KeyAttestationRequest, requireX5C bool, now time.Time) error {
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
	if !attestationAudienceMatches(claims.Aud, request.Audience) {
		return fmt.Errorf("key attestation aud %v does not identify the credential issuer %q",
			claims.Aud, request.Audience)
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
		chain, err := commonX509.DecodeX5CChain(header.X5C)
		if err != nil {
			return err
		}
		if err := commonX509.RequireNonSelfSignedLeaf(chain, "key attestation"); err != nil {
			return err
		}
	}
	return nil
}

type attestationJWTHeader struct {
	Type      string   `json:"typ"`
	Algorithm string   `json:"alg"`
	KeyID     string   `json:"kid"`
	X5C       []string `json:"x5c"`
}

type attestationJWTClaims struct {
	Iss          string            `json:"iss"`
	Sub          string            `json:"sub"`
	Aud          any               `json:"aud"`
	Exp          *float64          `json:"exp"`
	Nonce        string            `json:"nonce"`
	AttestedKeys []jose.JSONWebKey `json:"attested_keys"`
	Cnf          *struct {
		JWK jose.JSONWebKey `json:"jwk"`
	} `json:"cnf"`
}

// attestationAudienceMatches reports whether the aud claim of an attestation
// identifies audience. aud may be a string or an array of strings (the shape
// encoding/json produces for a JSON array is []any, []string is also accepted
// for callers that have already normalised it). An absent aud (nil) is
// permitted: the attestation then makes no audience assertion.
func attestationAudienceMatches(aud any, audience string) bool {
	switch value := aud.(type) {
	case nil:
		return true
	case string:
		return value == audience
	case []string:
		for _, entry := range value {
			if entry == audience {
				return true
			}
		}
		return false
	case []any:
		for _, entry := range value {
			if text, ok := entry.(string); ok && text == audience {
				return true
			}
		}
		return false
	default:
		return false
	}
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

// AttestationJOSEHeader is the protected header of an attestation JWT, as much
// of it as a key resolver needs to choose the verification key. X5C holds the
// header entries unchanged, as base64 (not base64url) DER strings.
type AttestationJOSEHeader struct {
	// Type is the typ header: oauth-client-attestation+jwt for a Wallet
	// Attestation, key-attestation+jwt for a key attestation.
	Type string
	// Algorithm is the alg header.
	Algorithm string
	// KeyID is the kid header, empty when the attester sent none.
	KeyID string
	// X5C holds the x5c header entries, empty when the attester sent none.
	X5C []string
}

// AttestationKeyResolver returns the public key that verifies an attestation
// JWT, for an attester that does not carry its certificate in x5c: a Wallet
// Provider JWKS looked up by kid, or the locally held key of a self-issued
// attestation. Returning an error refuses the attestation.
//
// The returned value is passed to go-jose, so it may be a crypto.PublicKey, a
// jose.JSONWebKey or a *jose.JSONWebKey.
type AttestationKeyResolver func(header AttestationJOSEHeader) (any, error)

// AttestationTrustPolicy is how the wallet authenticates the attestation JWTs
// its providers return. It replaces the bare requireX5C flag the validators
// used to take, because checking the shape of an attestation without checking
// who signed it establishes nothing.
//
// There is deliberately no flag that accepts an unverified attestation: unlike
// a credential, which arrives from an issuer the wallet may know nothing about,
// an attestation is issued to this wallet by its own provider, so a resolver or
// an x5c chain is always available to whoever configured that provider.
type AttestationTrustPolicy struct {
	// RequireX5C enforces the HAIP rules that the attestation carries its
	// certificate chain in x5c and that the leaf is not self-signed. The wallet
	// sets it from the selected protocol profile.
	RequireX5C bool
	// TrustAnchors and RootCAs are the Wallet Provider anchors an x5c chain is
	// validated against. Supply at most one of them; RootCAs preserves
	// *x509.CertPool integrations. When neither is configured the chain is not
	// validated and only the attester's signature is checked, so a deployment
	// that wants the chain verified configures its anchors here.
	TrustAnchors []*x509.Certificate
	RootCAs      *x509.CertPool
	// KeyUsages constrains the extended key usage of the attester certificate.
	// Empty means no additional EKU policy, not TLS server authentication.
	KeyUsages []x509.ExtKeyUsage
	// AllowUnadvertisedRevocation keeps certificates that advertise no CRL
	// distribution point on the trust path, matching the issuer, Request Object
	// and signed issuer metadata trust policies.
	AllowUnadvertisedRevocation bool
	// CRL tunes the revocation retrieval the trust path performs. Its
	// RequireStatus is derived from AllowUnadvertisedRevocation and must not be
	// set here as well, and its HTTPClient is required whenever anchors are
	// configured: the wallet never falls back to an unguarded default client
	// for an outbound fetch a certificate chose.
	CRL commonX509.CRLCheckerOptions
	// ResolveKey supplies the verification key for an attester that does not
	// use x5c. It takes precedence over the x5c leaf.
	ResolveKey AttestationKeyResolver
	// Now supplies the verification time, for tests and for callers with their
	// own clock. Nil means time.Now.
	Now func() time.Time
}

// now resolves the verification time of one validation run.
func (p AttestationTrustPolicy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// attestationSignatureAlgorithms lists the signature algorithms an attestation
// JWT may be signed with. OpenID4VCI 1.0 Appendix D requires of the alg header
// that "It MUST NOT be `none` or an identifier for a symmetric algorithm
// (MAC)", which this allowlist enforces by construction; the Wallet Attestation
// of Appendix E follows Section 5.1 of
// draft-ietf-oauth-attestation-based-client-auth, which states the same.
func attestationSignatureAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.RS256, jose.RS384, jose.RS512,
		jose.EdDSA,
	}
}

// authenticateAttestationJWT verifies who signed an attestation before any of
// its claims are believed. The verification key is the caller's resolver when
// one is configured and the x5c leaf otherwise; an attestation offering
// neither is refused, because nothing about it could be checked. label names
// the artifact in the error ("client attestation" or "key attestation").
func authenticateAttestationJWT(ctx context.Context, token string, header attestationJWTHeader, policy AttestationTrustPolicy, label string, now time.Time) error {
	var chain []*x509.Certificate
	if len(header.X5C) > 0 {
		decoded, err := commonX509.DecodeX5CChain(header.X5C)
		if err != nil {
			return fmt.Errorf("%s x5c header is invalid: %w", label, err)
		}
		chain = decoded
	}
	if policy.RequireX5C {
		// HAIP Sections 4.4.1 and 4.4.2 require the signing certificate in the
		// x5c header and forbid a self-signed one.
		if err := commonX509.RequireNonSelfSignedLeaf(chain, label); err != nil {
			return err
		}
	}
	if len(chain) > 0 {
		if err := verifyAttestationChain(ctx, chain, policy, label, now); err != nil {
			return err
		}
	}

	key, err := attestationVerificationKey(header, chain, policy, label)
	if err != nil {
		return err
	}
	signed, err := jose.ParseSigned(token, attestationSignatureAlgorithms())
	if err != nil {
		return fmt.Errorf("%s is not a verifiable JWS: %w", label, err)
	}
	if len(signed.Signatures) != 1 {
		return fmt.Errorf("%s must carry exactly one signature", label)
	}
	if _, err := signed.Verify(key); err != nil {
		return fmt.Errorf("%s signature could not be verified: %w", label, err)
	}
	return nil
}

// attestationVerificationKey chooses the key the attestation signature is
// verified with: the caller's resolver first, then the x5c leaf.
func attestationVerificationKey(header attestationJWTHeader, chain []*x509.Certificate, policy AttestationTrustPolicy, label string) (any, error) {
	if policy.ResolveKey != nil {
		// attestationJWTHeader and AttestationJOSEHeader hold the same fields
		// and differ only in their JSON tags, so the conversion is exact.
		key, err := policy.ResolveKey(AttestationJOSEHeader(header))
		if err != nil {
			return nil, fmt.Errorf("%s signing key could not be resolved: %w", label, err)
		}
		if key == nil {
			return nil, fmt.Errorf("%s signing key could not be resolved: the resolver returned no key", label)
		}
		return key, nil
	}
	if len(chain) > 0 {
		return chain[0].PublicKey, nil
	}
	return nil, fmt.Errorf("%s cannot be authenticated: it carries no x5c chain and the attestation trust policy configures no key resolver", label)
}

// verifyAttestationChain validates an attestation's x5c chain against the
// configured anchors. Without anchors there is nothing to validate against, so
// only the signature is checked and the chain is left untrusted; the HAIP rule
// that the trust anchor is not carried inside x5c is enforced wherever anchors
// are configured and the profile asks for x5c.
func verifyAttestationChain(ctx context.Context, chain []*x509.Certificate, policy AttestationTrustPolicy, label string, now time.Time) error {
	if len(policy.TrustAnchors) == 0 && policy.RootCAs == nil {
		return nil
	}
	if policy.RequireX5C {
		// HAIP Sections 4.4.1 and 4.4.2: "The X.509 certificate of the trust
		// anchor MUST NOT be included in the x5c JOSE header of the key
		// attestation", and the Wallet Attestation chain is "optionally a trust
		// certificate chain excluding the trust anchor".
		containsAnchor, err := commonX509.ContainsTrustAnchor(chain, policy.TrustAnchors, policy.RootCAs)
		if err != nil {
			return fmt.Errorf("%s x5c header is invalid: %w", label, err)
		}
		if containsAnchor {
			return fmt.Errorf("HAIP forbids including the trust anchor certificate in the x5c header of the %s", label)
		}
	}
	if policy.CRL.HTTPClient == nil {
		return fmt.Errorf("%s trust anchors are configured but the policy supplies no CRL HTTP client", label)
	}
	if _, err := commonX509.VerifySigningChainWithPolicy(ctx, chain, commonX509.SigningChainPolicy{
		TrustAnchors:                policy.TrustAnchors,
		Roots:                       policy.RootCAs,
		KeyUsages:                   policy.KeyUsages,
		CRL:                         policy.CRL,
		AllowUnadvertisedRevocation: policy.AllowUnadvertisedRevocation,
		CurrentTime:                 now,
	}); err != nil {
		return fmt.Errorf("%s certificate chain is not trusted: %w", label, err)
	}
	return nil
}

// staticAttesterKeyResolver verifies a self-issued attestation against the
// attester key the wallet itself holds. The bundled StaticClientAttester and
// StaticKeyAttester sign with a local key, so the wallet needs no resolver
// configuration to authenticate what they return; a remote provider has no such
// key here and its attestation must carry x5c or be given a resolver.
func staticAttesterKeyResolver(key jose.JSONWebKey) AttestationKeyResolver {
	if key.Key == nil {
		return nil
	}
	public := key.Public()
	return func(AttestationJOSEHeader) (any, error) {
		return public.Key, nil
	}
}

// attestationProviderKeyResolver returns the resolver for a provider whose
// signing key this process holds. It is the bundled static attesters only;
// every other provider resolves its key through the caller's policy.
func attestationProviderKeyResolver(provider any) AttestationKeyResolver {
	switch attester := provider.(type) {
	case *StaticClientAttester:
		if attester == nil {
			return nil
		}
		return staticAttesterKeyResolver(attester.Key)
	case *StaticKeyAttester:
		if attester == nil {
			return nil
		}
		return staticAttesterKeyResolver(attester.Key)
	default:
		return nil
	}
}

// attestationPolicyFor resolves the trust policy one attestation is validated
// under: the wallet's configured policy, with RequireX5C raised by the HAIP
// profile (HAIP Sections 4.4.1 and 4.4.2 require the signing certificate in the
// x5c header) and with the bundled static attesters' own key filled in as the
// resolver, so a self-issued attestation is verified against the key this
// process signed it with without any extra configuration.
func (w *Wallet) attestationPolicyFor(provider any) AttestationTrustPolicy {
	policy := w.attestationTrust
	if w.profile.IsHAIP() {
		policy.RequireX5C = true
	}
	if policy.ResolveKey == nil {
		policy.ResolveKey = attestationProviderKeyResolver(provider)
	}
	return policy
}
