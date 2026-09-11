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
	Now                  func() time.Time
	ClockSkew            time.Duration
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

// verifyCredentialForAcceptance authenticates a raw credential before it is
// persisted. Any returned error means nothing may be stored.
func (w *Wallet) verifyCredentialForAcceptance(raw []byte, flavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey) (*credential.Credential, *CredentialVerification, error) {
	parsedCredential, err := w.serializer.DeserializeCredential(flavor, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("credential could not be parsed: %w", err)
	}

	issuerJWT := issuerSignedJWT(flavor, raw)
	jwtParts := strings.Split(issuerJWT, ".")
	if len(jwtParts) != 3 {
		return nil, nil, fmt.Errorf("issuer JWT must have exactly three parts")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("issuer JWT header is not base64url: %w", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("issuer JWT payload is not base64url: %w", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("issuer JWT header is not JSON: %w", err)
	}
	payload := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(payloadBytes))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, nil, fmt.Errorf("issuer JWT payload is not JSON: %w", err)
	}

	if flavor == credential.SDJwtVC {
		typ, _ := header["typ"].(string)
		if !strings.EqualFold(typ, "dc+sd-jwt") && !strings.EqualFold(typ, "vc+sd-jwt") {
			return nil, nil, fmt.Errorf("SD-JWT VC typ header must be dc+sd-jwt or vc+sd-jwt")
		}
	}

	algorithm, _ := header["alg"].(string)
	if algorithm == "" || strings.EqualFold(algorithm, "none") {
		return nil, nil, fmt.Errorf("issuer JWT alg header is missing or none")
	}
	supported := false
	for _, candidate := range w.verifier.GetSupportedAlgorithms() {
		if string(candidate) == algorithm {
			supported = true
			break
		}
	}
	if !supported {
		return nil, nil, fmt.Errorf("issuer JWT alg %q is not supported by the verifier", algorithm)
	}

	verification := &CredentialVerification{}
	if cnfRaw, cnfPresent := payload["cnf"]; cnfPresent {
		cnf, ok := cnfRaw.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("cnf claim must be a JSON object")
		}
		jwkRaw, jwkPresent := cnf["jwk"]
		if !jwkPresent {
			return nil, nil, fmt.Errorf("cnf claim must contain a jwk")
		}
		if holderKey != nil {
			claimedKey, err := jsonWebKeyFromValue(jwkRaw)
			if err != nil {
				return nil, nil, fmt.Errorf("cnf jwk is invalid: %w", err)
			}
			claimedThumbprint, err := claimedKey.Thumbprint(crypto.SHA256)
			if err != nil {
				return nil, nil, fmt.Errorf("cnf jwk thumbprint failed: %w", err)
			}
			holderThumbprint, err := holderKey.Thumbprint(crypto.SHA256)
			if err != nil {
				return nil, nil, fmt.Errorf("holder key thumbprint failed: %w", err)
			}
			if !bytes.Equal(claimedThumbprint, holderThumbprint) {
				return nil, nil, fmt.Errorf("credential is bound to a different holder key")
			}
			verification.HolderBound = true
		}
	} else if w.credentialAcceptance != nil && w.credentialAcceptance.RequireHolderBinding {
		return nil, nil, fmt.Errorf("credential does not contain a cnf holder binding")
	}

	if w.credentialAcceptance == nil {
		return parsedCredential, verification, nil
	}
	policy := w.credentialAcceptance

	now := time.Now()
	if policy.Now != nil {
		now = policy.Now()
	}

	issuer, _ := payload["iss"].(string)
	if err := w.resolveAndVerifyIssuerKey(parsedCredential, header, payload, issuer, now, verification); err != nil {
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
// issuer signature, recording the authentication outcome in verification.
func (w *Wallet) resolveAndVerifyIssuerKey(parsedCredential *credential.Credential, header, payload map[string]any, issuer string, now time.Time, verification *CredentialVerification) error {
	policy := w.credentialAcceptance
	var candidateKeys []jose.JSONWebKey

	if x5cRaw, x5cPresent := header["x5c"]; x5cPresent {
		if policy.IssuerX509 == nil {
			return fmt.Errorf("x5c issuer authentication is not configured")
		}
		certificates, err := decodeX5CCertificates(x5cRaw)
		if err != nil {
			return err
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
		result, err := commonX509.VerifySigningCertificateChain(context.Background(), certificates, commonX509.SigningChainOptions{
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
			return fmt.Errorf("issuer key resolution is not configured")
		}
		keys, err := policy.ResolveIssuerKeys(issuer, header)
		if err != nil {
			return fmt.Errorf("issuer key resolution failed: %w", err)
		}
		if len(keys) == 0 {
			return fmt.Errorf("no issuer key could be resolved")
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
		return fmt.Errorf("issuer signature could not be verified")
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
		return fmt.Errorf("credential has expired")
	}
	if nbf, present, err := numericDateClaim(payload, "nbf"); err != nil {
		return err
	} else if present && nbf > nowUnix+skew.Seconds() {
		return fmt.Errorf("credential is not yet valid")
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
			return 0, false, fmt.Errorf("%s claim is not a numeric date: %w", name, err)
		}
		return parsed, true, nil
	case float64:
		return value, true, nil
	case string:
		return 0, false, fmt.Errorf("%s claim must be a numeric date, not a string", name)
	default:
		return 0, false, fmt.Errorf("%s claim must be a numeric date", name)
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

func decodeX5CCertificates(raw any) ([]*x509.Certificate, error) {
	entries, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("x5c header must be an array")
	}
	if len(entries) == 0 || len(entries) > 16 {
		return nil, fmt.Errorf("x5c header must contain between 1 and 16 certificates")
	}
	certificates := make([]*x509.Certificate, 0, len(entries))
	for _, entry := range entries {
		encoded, ok := entry.(string)
		if !ok {
			return nil, fmt.Errorf("x5c header entries must be strings")
		}
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("x5c header entry is not valid base64: %w", err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("x5c header entry is not a valid certificate: %w", err)
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
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
	return fmt.Errorf("issuer certificate is not bound to issuer host %q", host)
}

func issuerSignedJWT(flavor credential.SupportedSerializationFlavor, raw []byte) string {
	if flavor == credential.SDJwtVC {
		if index := bytes.IndexByte(raw, '~'); index >= 0 {
			return string(raw[:index])
		}
	}
	return string(raw)
}

func verifySDJWTDisclosureIntegrity(payload map[string]any, parsedCredential *credential.Credential) error {
	sdAlg := "sha-256"
	if raw, present := payload["_sd_alg"]; present {
		text, ok := raw.(string)
		if !ok {
			return fmt.Errorf("_sd_alg must be a string")
		}
		sdAlg = strings.ToLower(text)
		switch sdAlg {
		case "sha-256", "sha-384", "sha-512":
		default:
			return fmt.Errorf("unsupported _sd_alg %q", text)
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
			return fmt.Errorf("disclosure is not referenced by any digest")
		case references[digest] > 1:
			return fmt.Errorf("disclosure digest is referenced more than once")
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
		return "", fmt.Errorf("unsupported disclosure hash algorithm %q", algorithm)
	}
	hasher.Write([]byte(encodedDisclosure))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)), nil
}
