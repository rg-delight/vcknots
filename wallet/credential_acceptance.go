package wallet

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/credential"
)

// CredentialAcceptancePolicy decides whether a received credential may be stored.
// A nil policy keeps the minimum rules: the credential must parse, and a cnf that
// does not match the holder key used for the credential request is rejected.
type CredentialAcceptancePolicy struct {
	// IssuerX509 authenticates the issuer key from the credential's x5c JOSE header.
	IssuerX509 *IssuerX509TrustOptions
	// ResolveIssuerKeys returns candidate issuer public keys when the credential has
	// no x5c header (JWKS, DID or a static registry chosen by the caller). header is
	// the issuer JWT's protected header. Never called when x5c is present.
	ResolveIssuerKeys func(issuer string, header map[string]any) ([]jose.JSONWebKey, error)
	// RequireHolderBinding rejects credentials without a cnf claim.
	RequireHolderBinding bool
	// UnverifiedIssuer stores credentials without authenticating the issuer
	// key, which is what a nil policy does implicitly. It only takes effect
	// when neither IssuerX509 nor ResolveIssuerKeys is configured: with either
	// of them present the issuer signature is still verified. Everything else
	// the policy checks — holder binding, exp/nbf and SD-JWT disclosure
	// integrity — keeps applying, so this opts out of issuer authentication
	// alone. It exists so that a deployment which accepts unauthenticated
	// issuers says so in one greppable place instead of expressing it as an
	// absent policy.
	UnverifiedIssuer bool
	// SigningAlgorithms lists the JWS "alg" values an issuer may sign a
	// credential with. An empty list means DefaultCredentialSigningAlgorithms.
	//
	// It is a separate decision from which algorithms the verification
	// dispatcher can compute: a registered plugin makes an algorithm
	// verifiable, this list makes it acceptable. Keeping them apart means that
	// adding a plugin — including the ones NewVerificationDispatcher registers
	// by default — never widens what a deployment accepts on its own, and that
	// a caller can narrow acceptance without rebuilding the dispatcher. An
	// algorithm listed here that no plugin implements is still rejected.
	SigningAlgorithms []jose.SignatureAlgorithm
	Now               func() time.Time
	ClockSkew         time.Duration
}

// DefaultCredentialSigningAlgorithms is the issuer signature algorithm policy
// applied when a CredentialAcceptancePolicy leaves SigningAlgorithms empty, and
// when no policy is configured at all.
//
// It holds ES256 alone. HAIP Section "Requirements for Digital Signatures"
// states that "Issuers, Verifiers, and Wallets MUST, at a minimum, support
// ECDSA with P-256 and SHA-256 (JOSE algorithm identifier ES256 ...)" and that
// "ecosystem-specific profiles of this specification MAY mandate additional
// cryptographic suites": the floor is interoperable everywhere, anything above
// it is an ecosystem decision, so a deployment that accepts more says so in its
// policy. The wallet never modifies the slice; callers may read it and must not
// modify it either.
var DefaultCredentialSigningAlgorithms = []jose.SignatureAlgorithm{jose.ES256}

// acceptedSigningAlgorithms resolves the issuer signature algorithms one
// acceptance run allows.
func acceptedSigningAlgorithms(policy *CredentialAcceptancePolicy) []jose.SignatureAlgorithm {
	if policy == nil || len(policy.SigningAlgorithms) == 0 {
		return DefaultCredentialSigningAlgorithms
	}
	return policy.SigningAlgorithms
}

// IssuerX509TrustOptions is relying-party trust configuration for issuer x5c chains.
type IssuerX509TrustOptions struct {
	TrustAnchors                []*x509.Certificate
	RootCAs                     *x509.CertPool     // exactly one of TrustAnchors / RootCAs
	CertificateKeyUsages        []x509.ExtKeyUsage // optional ecosystem EKU policy
	CRL                         commonX509.CRLCheckerOptions
	AllowUnadvertisedRevocation bool // certificates without any CRL DP stay on the trust path, reported separately
	// RequireIssuerDNSBinding is an ecosystem policy, not an SD-JWT VC §3.5 requirement:
	// when iss is an https URL, the leaf certificate must carry a dNSName SAN equal to its host.
	RequireIssuerDNSBinding bool
	HTTPClient              *http.Client // CRL fetches; nil uses a bounded default
}

// CredentialVerification records what the library verified before storing.
type CredentialVerification struct {
	IssuerKeyID            string   // kid of the key used, or the leaf certificate SHA-256 fingerprint
	CertificateSHA256      []string // x5c path fingerprints, leaf first; nil when no x5c
	RevocationChecked      int
	RevocationUnadvertised int
	HolderBound            bool // cnf present and matched the holder key
}

// verifyCredentialForAcceptanceContext authenticates a raw credential before it
// is persisted. Any returned error means nothing may be stored.
//
// requirePolicy makes Config.CredentialAcceptance mandatory: with it set, a nil
// policy is a fail-closed error rather than the permissive parse the Draft-13
// entrypoints keep. The OpenID4VCI Final and HAIP issuance paths pass true,
// because a credential arriving there has an issuer identity that the flow can
// and must check. Draft-13 passes false: Config.CredentialAcceptance is
// optional by design there, and SD-JWT VC Section 3.5 leaves issuer key
// resolution to ecosystem policy.
//
// ctx bounds the network work the policy performs, which today is CRL retrieval
// while the issuer certificate chain is verified.
func (w *Wallet) verifyCredentialForAcceptanceContext(ctx context.Context, raw []byte, flavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey, requirePolicy bool) (*credential.Credential, *CredentialVerification, error) {
	return w.verifyCredentialForAcceptanceWithPolicy(ctx, raw, flavor, holderKey, w.credentialAcceptance, requirePolicy)
}

// VerifyCredentialForAcceptance authenticates a raw credential under the
// wallet's configured Config.CredentialAcceptance and reports what it verified,
// without storing anything. It is the check the OpenID4VCI Final and HAIP
// issuance paths run before a credential is persisted, exposed so that an
// integrator can run it on a credential it already holds — one received out of
// band, re-checked after a policy change, or inspected before it is offered to
// a user.
//
// A nil Config.CredentialAcceptance is a fail-closed error
// (ErrCredentialAcceptancePolicyRequired): a caller that means to accept
// unauthenticated issuers says so with CredentialAcceptancePolicy.UnverifiedIssuer.
// Every other failure wraps one of the sentinels declared in errors_final.go,
// so errors.Is decides what went wrong.
//
// It is unrelated to VerifyCredential, which checks one already parsed
// credential against one public key the caller supplies.
func (w *Wallet) VerifyCredentialForAcceptance(ctx context.Context, raw []byte, flavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey) (*credential.Credential, *CredentialVerification, error) {
	return w.verifyCredentialForAcceptanceWithPolicy(ctx, raw, flavor, holderKey, w.credentialAcceptance, true)
}

// VerifyCredentialWithPolicy is VerifyCredentialForAcceptance with the policy
// supplied per call instead of taken from the wallet configuration, for an
// integrator that decides the trust rules per credential — a different trust
// anchor set, a different issuer key resolution, a different clock — without
// building a wallet for each. Nothing is written to the wallet's credential
// store on this path, by either entrypoint.
//
// A nil policy runs the minimum rules only: the credential must parse, its typ
// and alg must be acceptable, and a cnf that does not match holderKey is
// rejected. No issuer is authenticated and no validity period is checked, which
// is what the Draft-13 entrypoints do when Config.CredentialAcceptance is
// absent. Pass a policy, or use VerifyCredentialForAcceptance, to fail closed
// instead.
func (w *Wallet) VerifyCredentialWithPolicy(ctx context.Context, raw []byte, flavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey, policy *CredentialAcceptancePolicy) (*credential.Credential, *CredentialVerification, error) {
	return w.verifyCredentialForAcceptanceWithPolicy(ctx, raw, flavor, holderKey, policy, false)
}

// verifyCredentialForAcceptanceWithPolicy is the acceptance check itself, run
// against an explicit policy so that the wallet-configured and the per-call
// entrypoints share one implementation.
func (w *Wallet) verifyCredentialForAcceptanceWithPolicy(ctx context.Context, raw []byte, flavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey, policy *CredentialAcceptancePolicy, requirePolicy bool) (*credential.Credential, *CredentialVerification, error) {
	if requirePolicy && policy == nil {
		return nil, nil, fmt.Errorf("issuer verification is not configured for the Final issuance path: %w", ErrCredentialAcceptancePolicyRequired)
	}

	issuerJWT := issuerSignedJWT(flavor, raw)
	jwtParts := strings.Split(issuerJWT, ".")
	if len(jwtParts) != 3 {
		return nil, nil, fmt.Errorf("%w: issuer JWT must have exactly three parts", ErrCredentialParse)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: issuer JWT header is not base64url: %w", ErrCredentialParse, err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: issuer JWT payload is not base64url: %w", ErrCredentialParse, err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("%w: issuer JWT header is not JSON: %w", ErrCredentialParse, err)
	}
	payload := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(payloadBytes))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, nil, fmt.Errorf("%w: issuer JWT payload is not JSON: %w", ErrCredentialParse, err)
	}

	if flavor == credential.SDJwtVC {
		typ, _ := header["typ"].(string)
		if !strings.EqualFold(typ, "dc+sd-jwt") && !strings.EqualFold(typ, "vc+sd-jwt") {
			return nil, nil, fmt.Errorf("%w: SD-JWT VC typ header must be dc+sd-jwt or vc+sd-jwt, got %q", ErrCredentialTypInvalid, typ)
		}
	}

	if w.profile.IsHAIP() && flavor == credential.SDJwtVC {
		if _, present := header["x5c"]; !present {
			// HAIP §6.1.1: "The SD-JWT VC MUST contain the credential issuer's
			// signing certificate along with a trust chain in the x5c JOSE
			// header".
			return nil, nil, ErrHAIPX5CRequired
		}
	}

	algorithm, _ := header["alg"].(string)
	// RFC 7515 Section 3.6's unsigned JWS is refused before anything else is
	// read: there is no signature to verify, so no issuer could be
	// authenticated whatever the rest of the policy says.
	if algorithm == "" || strings.EqualFold(algorithm, "none") {
		return nil, nil, fmt.Errorf("%w: issuer JWT alg header is missing or none", ErrCredentialAlgUnsupported)
	}
	if !slices.Contains(acceptedSigningAlgorithms(policy), jose.SignatureAlgorithm(algorithm)) {
		return nil, nil, fmt.Errorf("%w: issuer JWT alg %q is not listed by the credential acceptance policy", ErrCredentialAlgUnsupported, algorithm)
	}
	if !slices.Contains(w.verifier.GetSupportedAlgorithms(), jose.SignatureAlgorithm(algorithm)) {
		return nil, nil, fmt.Errorf("%w: issuer JWT alg %q is not supported by the verifier", ErrCredentialAlgUnsupported, algorithm)
	}

	// The JOSE header decides the credential's fate before its body is read:
	// an algorithm the wallet will not accept, or a typ it did not ask for,
	// must be reported as such rather than as whatever the deserializer makes
	// of the credential.
	parsedCredential, err := w.serializer.DeserializeCredential(flavor, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrCredentialParse, err)
	}

	verification := &CredentialVerification{}
	if cnfRaw, cnfPresent := payload["cnf"]; cnfPresent {
		cnf, ok := cnfRaw.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("%w: cnf claim must be a JSON object", ErrCredentialParse)
		}
		jwkRaw, jwkPresent := cnf["jwk"]
		if !jwkPresent {
			// RFC 7800 defines several confirmation members, but only cnf.jwk
			// hands the wallet the key itself. A cnf.kid or cnf."x5t#S256"
			// names a key the wallet would have to resolve out of band before
			// it could sign a Key Binding JWT, so the credential is refused
			// rather than stored with a binding it cannot exercise.
			return nil, nil, fmt.Errorf("%w (cnf members: %s)", ErrHolderBindingConfirmationUnsupported, strings.Join(sortedMemberNames(cnf), ", "))
		}
		if holderKey != nil {
			claimedKey, err := jsonWebKeyFromValue(jwkRaw)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: cnf jwk is invalid: %w", ErrCredentialParse, err)
			}
			claimedThumbprint, err := claimedKey.Thumbprint(crypto.SHA256)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: cnf jwk thumbprint failed: %w", ErrCredentialParse, err)
			}
			holderThumbprint, err := holderKey.Thumbprint(crypto.SHA256)
			if err != nil {
				return nil, nil, fmt.Errorf("holder key thumbprint failed: %w", err)
			}
			if !bytes.Equal(claimedThumbprint, holderThumbprint) {
				return nil, nil, ErrHolderBindingMismatch
			}
			verification.HolderBound = true
		}
	} else if policy != nil && policy.RequireHolderBinding {
		return nil, nil, ErrHolderBindingMissing
	}

	if policy == nil {
		return parsedCredential, verification, nil
	}

	now := time.Now()
	if policy.Now != nil {
		now = policy.Now()
	}

	issuer, _ := payload["iss"].(string)
	if err := w.resolveAndVerifyIssuerKey(ctx, parsedCredential, policy, header, issuer, now, verification); err != nil {
		return nil, nil, err
	}

	if err := verifyCredentialValidity(payload, now, policy.ClockSkew); err != nil {
		return nil, nil, err
	}

	if flavor == credential.SDJwtVC {
		if err := verifySDJWTDisclosureIntegrity(payload, parsedCredential); err != nil {
			return nil, nil, err
		}
	}

	return parsedCredential, verification, nil
}

// resolveAndVerifyIssuerKey authenticates the issuer key and verifies the
// issuer signature, recording the authentication outcome in verification. ctx
// bounds the CRL retrieval the trust path may perform.
func (w *Wallet) resolveAndVerifyIssuerKey(ctx context.Context, parsedCredential *credential.Credential, policy *CredentialAcceptancePolicy, header map[string]any, issuer string, now time.Time, verification *CredentialVerification) error {
	var candidateKeys []jose.JSONWebKey

	// An x5c header is trust evidence only when the caller configured X.509
	// issuer trust. A caller that resolves issuer keys itself (JWKS, DID or a
	// static registry, SD-JWT VC §3.5 leaves the mechanism to ecosystem policy)
	// keeps that mechanism even when the credential also carries x5c; the chain
	// is then not consulted. Neither configured is a fail-closed error unless
	// the policy opts out of issuer authentication in writing.
	x5cRaw, x5cPresent := header["x5c"]
	if policy.IssuerX509 == nil && policy.ResolveIssuerKeys == nil {
		if policy.UnverifiedIssuer {
			// verification keeps no issuer key and no certificate
			// fingerprints, so a caller can still tell an authenticated
			// issuer from one accepted under this opt-out.
			return nil
		}
		if x5cPresent {
			return fmt.Errorf("%w: x5c issuer authentication is not configured", ErrIssuerKeyUnresolved)
		}
		return fmt.Errorf("%w: issuer key resolution is not configured", ErrIssuerKeyUnresolved)
	}
	if x5cPresent && policy.IssuerX509 != nil {
		certificates, err := commonX509.DecodeX5CChain(x5cRaw)
		if err != nil {
			return err
		}
		if w.profile.IsHAIP() {
			// HAIP §6.1.1: "The X.509 certificate of the trust anchor MUST NOT
			// be included" in the x5c header. Both anchor forms are consulted,
			// so configuring trust as a *x509.CertPool does not silently
			// exempt a deployment from the rule.
			containsAnchor, err := commonX509.ContainsTrustAnchor(certificates, policy.IssuerX509.TrustAnchors, policy.IssuerX509.RootCAs)
			if err != nil {
				return err
			}
			if containsAnchor {
				return ErrHAIPTrustAnchorInX5C
			}
		}
		crlOptions := policy.IssuerX509.CRL
		if crlOptions.RequireStatus && policy.IssuerX509.AllowUnadvertisedRevocation {
			return fmt.Errorf("conflicting issuer revocation policies")
		}
		crlOptions.RequireStatus = !policy.IssuerX509.AllowUnadvertisedRevocation
		if crlOptions.HTTPClient == nil {
			crlOptions.HTTPClient = policy.IssuerX509.HTTPClient
			if crlOptions.HTTPClient == nil {
				crlOptions.HTTPClient = &http.Client{Timeout: 15 * time.Second}
			}
		}
		checker, err := commonX509.NewCRLChecker(crlOptions)
		if err != nil {
			return fmt.Errorf("failed to create issuer revocation checker: %w", err)
		}
		result, err := commonX509.VerifySigningCertificateChain(ctx, certificates, commonX509.SigningChainOptions{
			TrustAnchors: policy.IssuerX509.TrustAnchors,
			Roots:        policy.IssuerX509.RootCAs,
			CurrentTime:  now,
			KeyUsages:    policy.IssuerX509.CertificateKeyUsages,
			Revocation:   checker,
		})
		if err != nil {
			return fmt.Errorf("issuer certificate chain is not trusted: %w", err)
		}
		if policy.IssuerX509.RequireIssuerDNSBinding {
			if err := requireIssuerDNSBinding(certificates[0], issuer); err != nil {
				return err
			}
		}
		candidateKeys = []jose.JSONWebKey{{Key: certificates[0].PublicKey}}
		verification.CertificateSHA256 = result.Fingerprints
		verification.RevocationChecked = result.Revocation.CheckedCertificates
		verification.RevocationUnadvertised = result.Revocation.NoMechanismCertificates
		if len(result.Fingerprints) > 0 {
			verification.IssuerKeyID = result.Fingerprints[0]
		}
	} else {
		if policy.ResolveIssuerKeys == nil {
			return fmt.Errorf("%w: issuer key resolution is not configured", ErrIssuerKeyUnresolved)
		}
		keys, err := policy.ResolveIssuerKeys(issuer, header)
		if err != nil {
			return fmt.Errorf("%w: issuer key resolution failed: %w", ErrIssuerKeyUnresolved, err)
		}
		if len(keys) == 0 {
			return fmt.Errorf("%w: no issuer key could be resolved", ErrIssuerKeyUnresolved)
		}
		headerKeyID, _ := header["kid"].(string)
		if headerKeyID != "" {
			for _, key := range keys {
				if key.KeyID == headerKeyID {
					candidateKeys = append(candidateKeys, key)
					break
				}
			}
		}
		if len(candidateKeys) == 0 {
			candidateKeys = keys
		}
	}

	verifiedKey := -1
	for i := range candidateKeys {
		ok, err := w.verifier.Verify(parsedCredential.Proof, &candidateKeys[i])
		if err == nil && ok {
			verifiedKey = i
			break
		}
	}
	if verifiedKey < 0 {
		return ErrIssuerSignatureInvalid
	}
	if verification.IssuerKeyID == "" {
		verification.IssuerKeyID = candidateKeys[verifiedKey].KeyID
	}
	return nil
}

func verifyCredentialValidity(payload map[string]any, now time.Time, skew time.Duration) error {
	nowUnix := float64(now.Unix()) + float64(now.Nanosecond())/1e9
	if exp, present, err := numericDateClaim(payload, "exp"); err != nil {
		return err
	} else if present && exp <= nowUnix-skew.Seconds() {
		return ErrCredentialExpired
	}
	if nbf, present, err := numericDateClaim(payload, "nbf"); err != nil {
		return err
	} else if present && nbf > nowUnix+skew.Seconds() {
		return ErrCredentialNotYetValid
	}
	return nil
}

func numericDateClaim(payload map[string]any, name string) (float64, bool, error) {
	raw, present := payload[name]
	if !present {
		return 0, false, nil
	}
	switch value := raw.(type) {
	case json.Number:
		parsed, err := value.Float64()
		if err != nil {
			return 0, false, fmt.Errorf("%w: %s claim is not a numeric date: %w", ErrCredentialParse, name, err)
		}
		return parsed, true, nil
	case float64:
		return value, true, nil
	case string:
		return 0, false, fmt.Errorf("%w: %s claim must be a numeric date, not a string", ErrCredentialParse, name)
	default:
		return 0, false, fmt.Errorf("%w: %s claim must be a numeric date", ErrCredentialParse, name)
	}
}

func jsonWebKeyFromValue(value any) (jose.JSONWebKey, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(raw); err != nil {
		return jose.JSONWebKey{}, err
	}
	return key, nil
}

// sortedMemberNames lists an object's members in a stable order, so an error
// naming them reads the same way on every run.
func sortedMemberNames(object map[string]any) []string {
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func requireIssuerDNSBinding(leaf *x509.Certificate, issuer string) error {
	parsed, err := url.Parse(issuer)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return nil
	}
	host := parsed.Hostname()
	for _, name := range leaf.DNSNames {
		if strings.EqualFold(name, host) {
			return nil
		}
	}
	return fmt.Errorf("%w: issuer certificate is not bound to issuer host %q", ErrIssuerDNSBindingFailed, host)
}

func issuerSignedJWT(flavor credential.SupportedSerializationFlavor, raw []byte) string {
	if flavor == credential.SDJwtVC {
		if index := bytes.IndexByte(raw, '~'); index >= 0 {
			return string(raw[:index])
		}
	}
	return string(raw)
}

// AcceptedSDAlgorithms lists the _sd_alg values this wallet accepts on an
// SD-JWT VC, written as the lowercase IANA "Named Information Hash Algorithm"
// names that SD-JWT (draft-ietf-oauth-selective-disclosure-jwt) Section 4.1.1
// requires. A credential naming anything else is rejected rather than verified
// under a substituted hash, and "sha-256" is the default when _sd_alg is
// absent. The wallet never modifies the slice; callers may read it to report
// what they support and must not modify it either.
var AcceptedSDAlgorithms = []string{"sha-256", "sha-384", "sha-512"}

func verifySDJWTDisclosureIntegrity(payload map[string]any, parsedCredential *credential.Credential) error {
	sdAlg := "sha-256"
	if raw, present := payload["_sd_alg"]; present {
		text, ok := raw.(string)
		if !ok {
			return fmt.Errorf("%w: _sd_alg must be a string", ErrSDAlgUnsupported)
		}
		sdAlg = strings.ToLower(text)
		if !slices.Contains(AcceptedSDAlgorithms, sdAlg) {
			return fmt.Errorf("%w: unsupported _sd_alg %q", ErrSDAlgUnsupported, text)
		}
	}
	if parsedCredential.SDJwt == nil || len(parsedCredential.SDJwt.Disclosures) == 0 {
		return nil
	}
	references := make(map[string]int)
	collectDigestReferences(payload, references)
	for _, disclosure := range parsedCredential.SDJwt.Disclosures {
		collectDigestReferences(disclosure.Value, references)
	}
	for _, disclosure := range parsedCredential.SDJwt.Disclosures {
		digest, err := disclosureDigest(disclosure.EncodedValue, sdAlg)
		if err != nil {
			return err
		}
		switch {
		case references[digest] == 0:
			return fmt.Errorf("%w: disclosure is not referenced by any digest", ErrDisclosureIntegrity)
		case references[digest] > 1:
			return fmt.Errorf("%w: disclosure digest is referenced more than once", ErrDisclosureIntegrity)
		}
	}
	return nil
}

func collectDigestReferences(value any, references map[string]int) {
	switch typed := value.(type) {
	case map[string]any:
		if digest, ok := typed["..."].(string); ok && digest != "" {
			references[digest]++
		}
		if sd, ok := typed["_sd"].([]any); ok {
			for _, entry := range sd {
				if digest, ok := entry.(string); ok && digest != "" {
					references[digest]++
				}
			}
		}
		for _, child := range typed {
			collectDigestReferences(child, references)
		}
	case []any:
		for _, child := range typed {
			collectDigestReferences(child, references)
		}
	}
}

func disclosureDigest(encodedDisclosure, algorithm string) (string, error) {
	var hasher hash.Hash
	switch algorithm {
	case "sha-256":
		hasher = sha256.New()
	case "sha-384":
		hasher = sha512.New384()
	case "sha-512":
		hasher = sha512.New()
	default:
		return "", fmt.Errorf("%w: unsupported disclosure hash algorithm %q", ErrSDAlgUnsupported, algorithm)
	}
	hasher.Write([]byte(encodedDisclosure))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)), nil
}
