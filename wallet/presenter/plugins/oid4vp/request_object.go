package oid4vp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
)

// RequestObjectValidationOptions is relying-party configuration, never data
// obtained from client_metadata in the request being authenticated.
type RequestObjectValidationOptions struct {
	TrustAnchors []*x509.Certificate
	RootCAs      *x509.CertPool
	// CertificateKeyUsages is an optional ecosystem EKU constraint. A signing
	// certificate need not be a TLS server certificate in general OpenID4VP.
	CertificateKeyUsages []x509.ExtKeyUsage
	CRL                  commonX509.CRLCheckerOptions
	// AllowUnadvertisedRevocation explicitly retains ecosystems which accept
	// certificates without any published CRL/OCSP information. Such certificates
	// are reported separately, never as positively checked for revocation.
	// The default requires positive status for every certificate below the anchor.
	AllowUnadvertisedRevocation bool
	// WalletAudience defaults to the static OpenID4VP identifier. Dynamic
	// discovery integrations supply their Wallet issuer identifier instead.
	WalletAudience []string
	Now            func() time.Time
	ClockSkew      time.Duration
	// SigningAlgorithms defaults to ES256 and RS256. This is independent of
	// encryption keys and algorithms carried in client_metadata.
	SigningAlgorithms []jose.SignatureAlgorithm
}

// RequestObjectVerification records the authentication performed by this
// library. No request parameter can populate this field.
type RequestObjectVerification struct {
	ClientID               string
	CertificateSHA256      []string
	RevocationChecked      int
	RevocationUnadvertised int
}

// WithRequestObjectValidation configures the public builder before loading a
// Request Object. The presenter configures it once for each parse operation.
func (b *requestBuilder) WithRequestObjectValidation(options RequestObjectValidationOptions) *requestBuilder {
	options.TrustAnchors = append([]*x509.Certificate(nil), options.TrustAnchors...)
	options.CertificateKeyUsages = append([]x509.ExtKeyUsage(nil), options.CertificateKeyUsages...)
	options.WalletAudience = append([]string(nil), options.WalletAudience...)
	options.SigningAlgorithms = append([]jose.SignatureAlgorithm(nil), options.SigningAlgorithms...)
	b.requestObjectValidation = &options
	return b
}

// WithExpectedClientID supplies the outer Authorization Request client_id that
// a Final Request Object's client_id claim must equal.
func (b *requestBuilder) WithExpectedClientID(clientID string) *requestBuilder {
	b.expectedClientID = strings.TrimSpace(clientID)
	return b
}

// WithRequestObject authenticates Final Request Objects. Draft24 keeps its
// original behavior behind the explicit Draft24 builder and parse entrypoint.
func (b *requestBuilder) WithRequestObject(obj string) *requestBuilder {
	b.requestSource = "value"
	if b.draft24 {
		return b.withDraft24RequestObject(obj)
	}
	if b.errValidation != nil {
		return b
	}
	b.errorResponseAllowed = false
	if b.insecureSkipX509Verify {
		b.errValidation = errors.New("final Request Object authentication cannot skip X.509 verification")
		return b
	}
	if err := b.authenticateFinalRequestObject(obj); err != nil {
		b.errValidation = err
	}
	return b
}

func (b *requestBuilder) authenticateFinalRequestObject(obj string) error {
	if b.expectedClientID == "" {
		return errors.New("client_id Authorization Request parameter is required with a Request Object")
	}
	options := RequestObjectValidationOptions{RootCAs: b.x509TrustChainRoots}
	if b.requestObjectValidation != nil {
		options = *b.requestObjectValidation
		if b.x509TrustChainRoots != nil && (options.RootCAs != nil || len(options.TrustAnchors) != 0) {
			return errors.New("configure Request Object trust roots in only one place")
		}
		if options.RootCAs == nil && len(options.TrustAnchors) == 0 {
			options.RootCAs = b.x509TrustChainRoots
		}
	}
	if options.ClockSkew < 0 {
		return errors.New("request object clock skew cannot be negative")
	}
	algs := options.SigningAlgorithms
	if len(algs) == 0 {
		algs = []jose.SignatureAlgorithm{jose.ES256, jose.RS256}
	}
	// A compact JWS keeps all authentication parameters in the protected
	// header. Do not accept the general JSON serialization's unprotected x5c.
	if strings.Count(obj, ".") != 2 || len(obj) > 1<<20 {
		return errors.New("request object must be a bounded compact signed JWT")
	}
	parsed, err := jwt.ParseSigned(obj, algs)
	if err != nil {
		return fmt.Errorf("failed to parse request object JWT: %w", err)
	}
	if len(parsed.Headers) != 1 {
		return errors.New("request object JWT must have one protected header")
	}
	typ, exists := parsed.Headers[0].ExtraHeaders["typ"]
	if !exists {
		return errors.New("request object JWT must include 'typ' header parameter")
	}
	if typ != "oauth-authz-req+jwt" {
		return errors.New("request object JWT 'typ' header must be 'oauth-authz-req+jwt'")
	}
	claims := make(commonJOSE.Claims)
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return fmt.Errorf("failed to decode request object claims: %w", err)
	}
	if _, present := claims["request"]; present {
		return errors.New("request object must not contain request or request_uri")
	}
	if _, present := claims["request_uri"]; present {
		return errors.New("request object must not contain request or request_uri")
	}
	b.setParamsWithAnyMap(claims)
	if err := b.validate(); err != nil {
		return err
	}
	clientID, err := parseOID4VPClientID(b.req.ClientID)
	if err != nil {
		return err
	}
	if clientID.prefix != OID4VPClientIDPrefixX509Hash && clientID.prefix != OID4VPClientIDPrefixX509SanDNS {
		// Final 5.1: client_metadata keys are never request-signature keys.
		return errors.New("signed Request Object client identifier has no configured authentication method")
	}
	certificates, err := parseX5CCertificatesFromJWT(obj)
	if err != nil {
		return err
	}
	if len(certificates) == 0 || len(certificates) > 16 {
		return errors.New("x5c header must contain between 1 and 16 certificates")
	}
	if b.profile.IsHAIP() {
		// HAIP §5: "The X.509 certificate of the trust anchor MUST NOT be
		// included in the x5c JOSE header of the signed request." Anchors are
		// only enumerable when configured as TrustAnchors; with RootCAs this
		// check cannot be performed here.
		for _, certificate := range certificates {
			for _, anchor := range options.TrustAnchors {
				if anchor != nil && bytes.Equal(certificate.Raw, anchor.Raw) {
					return errors.New("HAIP profile does not permit the trust anchor certificate in the x5c header")
				}
			}
		}
	}
	if err := bindX509ClientID(clientID, certificates[0], b.req); err != nil {
		return err
	}
	verified := make(commonJOSE.Claims)
	if err := parsed.Claims(certificates[0].PublicKey, &verified); err != nil {
		return fmt.Errorf("failed to verify request object with x5c certificate: %w", err)
	}
	now := time.Now()
	if options.Now != nil {
		now = options.Now()
	}
	if err := validateRequestObjectClaims(verified, options.WalletAudience, now, options.ClockSkew); err != nil {
		return fmt.Errorf("JWT standard claims validation failed: %w", err)
	}
	crlOptions := options.CRL
	if crlOptions.RequireStatus && options.AllowUnadvertisedRevocation {
		return errors.New("conflicting Request Object revocation policies")
	}
	crlOptions.RequireStatus = !options.AllowUnadvertisedRevocation
	if crlOptions.HTTPClient == nil {
		crlOptions.HTTPClient = b.httpClient
		if crlOptions.HTTPClient == nil {
			crlOptions.HTTPClient = (&Oid4vpPresenter{}).httpClient()
		}
	}
	checker, err := commonX509.NewCRLChecker(crlOptions)
	if err != nil {
		return err
	}
	result, err := commonX509.VerifySigningCertificateChain(context.Background(), certificates, commonX509.SigningChainOptions{
		TrustAnchors: options.TrustAnchors, Roots: options.RootCAs, CurrentTime: now,
		KeyUsages: options.CertificateKeyUsages, Revocation: checker,
	})
	if err != nil {
		return fmt.Errorf("request object certificate chain is not trusted: %w", err)
	}
	b.req.RequestObjectVerification = &RequestObjectVerification{
		ClientID: b.req.ClientID, CertificateSHA256: result.Fingerprints,
		RevocationChecked:      result.Revocation.CheckedCertificates,
		RevocationUnadvertised: result.Revocation.NoMechanismCertificates,
	}
	return nil
}

func bindX509ClientID(clientID *OID4VPClientID, leaf *x509.Certificate, request *CredentialPresentationRequest) error {
	if clientID.prefix == OID4VPClientIDPrefixX509Hash {
		digest := sha256.Sum256(leaf.Raw)
		if base64.RawURLEncoding.EncodeToString(digest[:]) != clientID.original {
			return errors.New("x509_hash client_id mismatch")
		}
		// Final 5.9.3 and HAIP 5: x509_hash does not imply a DNS binding.
		return nil
	}
	matched := false
	for _, name := range leaf.DNSNames {
		if strings.EqualFold(name, clientID.original) {
			matched = true
			break
		}
	}
	if !matched {
		return errors.New("SAN of the certificate and client_id did not match")
	}
	boundURI := request.RedirectURI
	if request.ResponseMode == OAuthAuthzReqResponseModeDirectPost || request.ResponseMode == OAuthAuthzReqResponseModeDirectPostJWT {
		boundURI = request.ResponseURI
	}
	uri, err := url.Parse(boundURI)
	if err != nil || !strings.EqualFold(uri.Hostname(), clientID.original) {
		return errors.New("redirect_uri/response_uri and client_id (origin) must be same")
	}
	return nil
}

func validateRequestObjectClaims(claims commonJOSE.Claims, audiences []string, now time.Time, skew time.Duration) error {
	if now.IsZero() {
		return errors.New("verification time is required")
	}
	if len(audiences) == 0 {
		audiences = []string{"https://self-issued.me/v2"}
	}
	var actual []string
	switch aud := claims["aud"].(type) {
	case string:
		actual = []string{aud}
	case []any:
		for _, value := range aud {
			text, ok := value.(string)
			if !ok || text == "" {
				return errors.New("invalid audience claim")
			}
			actual = append(actual, text)
		}
	default:
		return errors.New("request object audience is required")
	}
	matched := false
	for _, expected := range audiences {
		for _, value := range actual {
			if expected != "" && expected == value {
				matched = true
			}
		}
	}
	if !matched {
		return errors.New("request object audience does not identify this Wallet")
	}
	for _, name := range []string{"exp", "nbf", "iat"} {
		value, present := claims[name]
		if !present {
			continue
		}
		number, ok := value.(json.Number)
		if !ok {
			return fmt.Errorf("%s must be a NumericDate", name)
		}
		text := number.String()
		if len(text) > 128 {
			return fmt.Errorf("%s NumericDate exceeds supported precision", name)
		}
		if exponentIndex := strings.IndexAny(text, "eE"); exponentIndex >= 0 {
			exponent, err := strconv.Atoi(text[exponentIndex+1:])
			if err != nil || exponent < -1024 || exponent > 1024 {
				return fmt.Errorf("%s NumericDate exceeds supported exponent range", name)
			}
		}
		timestamp, ok := new(big.Rat).SetString(text)
		if !ok {
			return fmt.Errorf("invalid %s NumericDate", name)
		}
		// NumericDate permits fractions; compare exactly, without truncating or
		// losing precision through float64. iat imposes no maximum token age.
		at := now
		if name == "exp" {
			at = now.Add(-skew)
		} else if name == "nbf" {
			at = now.Add(skew)
		}
		current := new(big.Rat).SetInt64(at.Unix())
		current.Add(current, new(big.Rat).SetFrac64(int64(at.Nanosecond()), 1e9))
		if (name == "exp" && current.Cmp(timestamp) >= 0) || (name == "nbf" && current.Cmp(timestamp) < 0) {
			return fmt.Errorf("request object is outside its %s validity", name)
		}
	}
	// iss is ignored, including its type, as required by Final section 5.
	return nil
}
