package oid4vp

import (
	"context"
	"crypto/x509"
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
	// DeliveredByReference is a caller attestation: the application obtained
	// this Request Object through request_uri (OpenID4VP 1.0 §5.10) and
	// re-submits it by value, so HAIP §5.1's delivery-by-reference requirement
	// is already satisfied. Set it only when that is recorded by the
	// application's own admission path. It is honoured for the HAIP delivery
	// check only and never for the wallet_nonce echo, which stays bound to an
	// actual request_uri POST in this process.
	DeliveredByReference bool
	// RequireExpiry rejects a Request Object that carries no exp claim.
	// OpenID4VP 1.0 states no exp rule for the Authorization Request Object
	// itself and leaves it to JAR (RFC 9101), and HAIP 1.0 adds none, so this
	// is relying-party hardening policy rather than a specification
	// requirement. It is off by default in every profile; the official
	// conformance verifiers sign Request Objects without exp.
	RequireExpiry bool
	// MaxAge bounds the lifetime of a Request Object, measured as exp - iat,
	// or as exp - now when iat is absent. Zero means unbounded. The HAIP
	// profile substitutes haipRequestObjectMaxAge when the caller left it
	// zero, and honours a caller-supplied value as given.
	MaxAge time.Duration
	// Context scopes the revocation fetches performed while authenticating one
	// Request Object. These options describe a single parse operation rather
	// than long-lived configuration, which is why the context belongs here; a
	// nil Context means context.Background().
	Context context.Context
}

// haipRequestObjectMaxAge is the Request Object lifetime the HAIP profile
// applies when the caller configured no MaxAge.
const haipRequestObjectMaxAge = 10 * time.Minute

// RequestObjectVerification records the authentication performed by this
// library. No request parameter can populate this field.
type RequestObjectVerification struct {
	ClientID               string
	CertificateSHA256      []string
	RevocationChecked      int
	RevocationUnadvertised int
	// WalletNonce is the wallet_nonce sent with a Final request_uri POST and
	// echoed by the authenticated Request Object. It is empty for GET and when
	// no nonce was sent (OID4VP 1.0 §5.10.1).
	WalletNonce string
	// Delivery records how this library observed the Request Object arrive:
	// "reference" (request_uri), "value" (request=), or "query" (plain query
	// parameters). It is empty when the library did not observe one of those
	// paths.
	Delivery string
	// DeliveryAttested is true when a caller DeliveredByReference attestation
	// was accepted for the HAIP delivery check, letting a request= Request
	// Object satisfy the request_uri requirement.
	DeliveryAttested bool
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

// requestObjectValidationOptions resolves the effective trust, time and
// signing policy from the builder's explicit validation options and the legacy
// X509TrustChainRoots, rejecting a configuration that specifies trust roots in
// both places.
func (b *requestBuilder) requestObjectValidationOptions() (RequestObjectValidationOptions, error) {
	options := RequestObjectValidationOptions{RootCAs: b.x509TrustChainRoots}
	if b.requestObjectValidation != nil {
		options = *b.requestObjectValidation
		if b.x509TrustChainRoots != nil && (options.RootCAs != nil || len(options.TrustAnchors) != 0) {
			return options, errors.New("configure Request Object trust roots in only one place")
		}
		if options.RootCAs == nil && len(options.TrustAnchors) == 0 {
			options.RootCAs = b.x509TrustChainRoots
		}
	}
	if options.ClockSkew < 0 {
		return options, errors.New("request object clock skew cannot be negative")
	}
	return options, nil
}

// verifyRequestObjectCertificateChain runs the configured X.509 chain and
// revocation checks for a leaf-first certificate list. It is shared by the
// request_uri signed Request Object path and the signed DC API paths.
func (b *requestBuilder) verifyRequestObjectCertificateChain(certificates []*x509.Certificate, options RequestObjectValidationOptions, now time.Time) (*commonX509.SigningChainResult, error) {
	client := options.CRL.HTTPClient
	if client == nil {
		client = b.httpClient
		if client == nil {
			client = (&Oid4vpPresenter{}).httpClient()
		}
	}
	return commonX509.VerifySigningChainWithPolicy(options.resolveContext(), certificates, commonX509.SigningChainPolicy{
		TrustAnchors:                options.TrustAnchors,
		Roots:                       options.RootCAs,
		KeyUsages:                   options.CertificateKeyUsages,
		CRL:                         options.CRL,
		AllowUnadvertisedRevocation: options.AllowUnadvertisedRevocation,
		CurrentTime:                 now,
		HTTPClient:                  client,
	})
}

// resolveContext returns the context the revocation fetches of one Request
// Object authentication run under.
func (options RequestObjectValidationOptions) resolveContext() context.Context {
	if options.Context != nil {
		return options.Context
	}
	return context.Background()
}

// resolveRequestObjectAlgorithms returns the signature algorithms a Request
// Object may be signed with, defaulting to ES256 and RS256.
func resolveRequestObjectAlgorithms(options RequestObjectValidationOptions) []jose.SignatureAlgorithm {
	if len(options.SigningAlgorithms) != 0 {
		return options.SigningAlgorithms
	}
	return []jose.SignatureAlgorithm{jose.ES256, jose.RS256}
}

// requestObjectNow is the verification time of one Request Object. Every check
// of one authentication run reads it once, so a chain, a revocation list and a
// registered claim are never judged against different clocks.
func requestObjectNow(options RequestObjectValidationOptions) time.Time {
	if options.Now != nil {
		return options.Now()
	}
	return time.Now()
}

// haipRequestObjectPolicy reports whether the HAIP Request Object rules apply.
// The Draft24 entrypoints are exempt from the profile, exactly as
// enforceHAIPProfile is, so a Draft24 request keeps its own wire contract even
// when the presenter is configured for HAIP.
func (b *requestBuilder) haipRequestObjectPolicy() bool {
	return !b.draft24 && b.profile.IsHAIP()
}

// requestObjectClaimPolicy is the resolved registered-claim policy applied to
// one authenticated Request Object.
type requestObjectClaimPolicy struct {
	Audiences []string
	// AudienceOptional keeps the Draft24 contract, which authenticated an
	// X.509 Request Object without ever reading aud. A Draft24 caller opts
	// into the check by naming its WalletAudience.
	AudienceOptional bool
	Now              time.Time
	ClockSkew        time.Duration
	RequireExpiry    bool
	MaxAge           time.Duration
}

// resolveClaimPolicy resolves the caller's options against the active profile
// and wire contract.
func (b *requestBuilder) resolveClaimPolicy(options RequestObjectValidationOptions, now time.Time) requestObjectClaimPolicy {
	policy := requestObjectClaimPolicy{
		Audiences:        options.WalletAudience,
		AudienceOptional: b.draft24 && len(options.WalletAudience) == 0,
		Now:              now,
		ClockSkew:        options.ClockSkew,
		RequireExpiry:    options.RequireExpiry,
		MaxAge:           options.MaxAge,
	}
	if b.haipRequestObjectPolicy() && policy.MaxAge == 0 {
		// HAIP bounds the lifetime of a Request Object that does carry exp;
		// it does not require exp (see RequireExpiry).
		policy.MaxAge = haipRequestObjectMaxAge
	}
	return policy
}

// rejectTrustAnchorInX5C enforces HAIP Sections 5 and 6.1.1: "The X.509
// certificate of the trust anchor MUST NOT be included in the x5c JOSE header
// of the signed request." The shared check also sees anchors configured as a
// *x509.CertPool, which the TrustAnchors-only loop it replaces silently
// ignored. It is inert outside the HAIP profile.
func (b *requestBuilder) rejectTrustAnchorInX5C(certificates []*x509.Certificate, options RequestObjectValidationOptions) error {
	if !b.haipRequestObjectPolicy() {
		return nil
	}
	anchored, err := commonX509.ContainsTrustAnchor(certificates, options.TrustAnchors, options.RootCAs)
	if err != nil {
		return err
	}
	if anchored {
		return errors.New("HAIP forbids including the trust anchor certificate in the x5c header")
	}
	return nil
}

func (b *requestBuilder) authenticateFinalRequestObject(obj string) error {
	if b.expectedClientID == "" {
		return errors.New("client_id Authorization Request parameter is required with a Request Object")
	}
	options, err := b.requestObjectValidationOptions()
	if err != nil {
		return err
	}
	// A compact JWS keeps all authentication parameters in the protected
	// header. Do not accept the general JSON serialization's unprotected x5c.
	if strings.Count(obj, ".") != 2 || len(obj) > 1<<20 {
		return errors.New("request object must be a bounded compact signed JWT")
	}
	parsed, err := jwt.ParseSigned(obj, resolveRequestObjectAlgorithms(options))
	if err != nil {
		return fmt.Errorf("failed to parse request object JWT: %w: %w", err, ErrRequestObjectSignatureInvalid)
	}
	if len(parsed.Headers) != 1 {
		return fmt.Errorf("request object JWT must have one protected header: %w", ErrRequestObjectTypInvalid)
	}
	typ, exists := parsed.Headers[0].ExtraHeaders["typ"]
	if !exists {
		return fmt.Errorf("request object JWT must include 'typ' header parameter: %w", ErrRequestObjectTypInvalid)
	}
	if typ != "oauth-authz-req+jwt" {
		return fmt.Errorf("request object JWT 'typ' header must be 'oauth-authz-req+jwt': %w", ErrRequestObjectTypInvalid)
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
	return b.authenticateX509RequestObject(obj, parsed, options)
}

// authenticateX509RequestObject is the one X.509 Request Object authentication
// path. Final reaches it through WithRequestObject and Draft24 through
// withDraft24RequestObject, so both wire contracts authenticate a signed
// Request Object against the same RequestObjectValidationOptions: the same
// chain and revocation policy, the same Client Identifier binding and the same
// registered-claim policy. Only the differences the two contracts actually have
// are resolved per profile, in requestObjectClaimPolicy and
// haipRequestObjectPolicy.
//
// The Authorization Request parameters must already be set on b.req: the
// Client Identifier binding reads the response endpoint from them, and the
// claims verified here are the ones that set them.
func (b *requestBuilder) authenticateX509RequestObject(obj string, parsed *jwt.JSONWebToken, options RequestObjectValidationOptions) error {
	clientID, err := parseOID4VPClientID(b.req.ClientID)
	if err != nil {
		return err
	}
	if clientID.prefix != OID4VPClientIDPrefixX509Hash && clientID.prefix != OID4VPClientIDPrefixX509SanDNS {
		// Final 5.1: client_metadata keys are never request-signature keys.
		return errors.New("signed Request Object client identifier has no configured authentication method")
	}
	certificates, err := commonX509.DecodeX5CFromJWTHeader(obj)
	if err != nil {
		return err
	}
	if err := b.rejectTrustAnchorInX5C(certificates, options); err != nil {
		return err
	}
	if err := bindX509ClientID(clientID, certificates[0], b.req); err != nil {
		return err
	}
	verified := make(commonJOSE.Claims)
	if err := parsed.Claims(certificates[0].PublicKey, &verified); err != nil {
		return fmt.Errorf("failed to verify request object with x5c certificate: %w: %w", err, ErrRequestObjectSignatureInvalid)
	}
	// OID4VP 1.0 §5.10.1: "if the Wallet passed a wallet_nonce in the POST
	// request, the Wallet MUST validate whether the request object contains the
	// respective nonce value in a wallet_nonce claim. If it does not, the Wallet
	// MUST terminate request processing." GET never sends a nonce, so a present
	// wallet_nonce claim is ignored in that case.
	if b.sentWalletNonce != "" {
		claimedNonce, ok := verified["wallet_nonce"].(string)
		if !ok || claimedNonce != b.sentWalletNonce {
			return newAuthorizationRequestError(InvalidRequestError, "Request Object wallet_nonce does not match")
		}
	}
	now := requestObjectNow(options)
	if err := validateRequestObjectClaims(verified, b.resolveClaimPolicy(options, now)); err != nil {
		return fmt.Errorf("JWT standard claims validation failed: %w", err)
	}
	result, err := b.verifyRequestObjectCertificateChain(certificates, options, now)
	if err != nil {
		return fmt.Errorf("request object certificate chain is not trusted: %w", err)
	}
	b.req.RequestObjectVerification = &RequestObjectVerification{
		ClientID: b.req.ClientID, CertificateSHA256: result.Fingerprints,
		RevocationChecked:      result.Revocation.CheckedCertificates,
		RevocationUnadvertised: result.Revocation.NoMechanismCertificates,
		WalletNonce:            b.sentWalletNonce,
	}
	return nil
}

// bindX509ClientID binds an x509_hash or x509_san_dns Client Identifier to the
// leaf certificate that signed the Request Object, and then to the response
// endpoint the request names.
//
// The DNS match is exact, never wildcard (commonX509.RequireLeafDNSName is
// called with wildcard=false): OID4VP 1.0 Section 5.9.3 requires that the
// original Client Identifier "MUST be a DNS name and match a `dNSName` Subject
// Alternative Name (SAN) [@!RFC5280] entry in the leaf certificate passed with
// the request", so a wildcard SAN such as *.example.com must not let one
// certificate speak for every subdomain of a Verifier.
func bindX509ClientID(clientID *OID4VPClientID, leaf *x509.Certificate, request *CredentialPresentationRequest) error {
	if clientID.prefix == OID4VPClientIDPrefixX509Hash {
		// Final 5.9.3 and HAIP 5: x509_hash does not imply a DNS binding.
		if err := commonX509.RequireLeafThumbprint(leaf, clientID.original); err != nil {
			return fmt.Errorf("%w: %w", err, ErrX509HashMismatch)
		}
		return nil
	}
	if err := commonX509.RequireLeafDNSName(leaf, clientID.original, false); err != nil {
		return fmt.Errorf("%w: %w", err, ErrRequestObjectClientIDMismatch)
	}
	boundURI := request.RedirectURI
	if request.ResponseMode == OAuthAuthzReqResponseModeDirectPost || request.ResponseMode == OAuthAuthzReqResponseModeDirectPostJWT {
		boundURI = request.ResponseURI
	}
	uri, err := url.Parse(boundURI)
	if err != nil || !strings.EqualFold(uri.Hostname(), clientID.original) {
		return fmt.Errorf("redirect_uri/response_uri and client_id (origin) must be same: %w", ErrRequestObjectClientIDMismatch)
	}
	return nil
}

// validateRequestObjectClaims applies the registered-claim policy to the claims
// of an already signature-verified Request Object.
func validateRequestObjectClaims(claims commonJOSE.Claims, policy requestObjectClaimPolicy) error {
	if policy.Now.IsZero() {
		return errors.New("verification time is required")
	}
	if err := validateRequestObjectAudience(claims, policy); err != nil {
		return err
	}
	dates := map[string]*big.Rat{}
	for _, name := range []string{"exp", "nbf", "iat"} {
		value, err := requestObjectNumericDate(claims, name)
		if err != nil {
			return err
		}
		if value != nil {
			dates[name] = value
		}
	}
	if dates["exp"] == nil && policy.RequireExpiry {
		return fmt.Errorf("request object is missing exp: %w", ErrRequestObjectExpired)
	}
	// NumericDate permits fractions; compare exactly, without truncating or
	// losing precision through float64. iat imposes no maximum token age of its
	// own; MaxAge is the policy that bounds the distance between iat and exp.
	if expiry := dates["exp"]; expiry != nil {
		if requestObjectInstant(policy.Now.Add(-policy.ClockSkew)).Cmp(expiry) >= 0 {
			return fmt.Errorf("request object is outside its exp validity: %w", ErrRequestObjectExpired)
		}
		if err := validateRequestObjectMaxAge(expiry, dates["iat"], policy); err != nil {
			return err
		}
	}
	if notBefore := dates["nbf"]; notBefore != nil {
		if requestObjectInstant(policy.Now.Add(policy.ClockSkew)).Cmp(notBefore) < 0 {
			return fmt.Errorf("request object is outside its nbf validity: %w", ErrRequestObjectExpired)
		}
	}
	// iss is ignored, including its type, as required by Final section 5.
	return nil
}

// validateRequestObjectAudience requires the Request Object to identify this
// Wallet. An absent policy audience means the static OpenID4VP identifier,
// unless the wire contract makes the claim optional.
func validateRequestObjectAudience(claims commonJOSE.Claims, policy requestObjectClaimPolicy) error {
	audiences := policy.Audiences
	if len(audiences) == 0 {
		if policy.AudienceOptional {
			return nil
		}
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
				return fmt.Errorf("invalid audience claim: %w", ErrRequestObjectAudienceMismatch)
			}
			actual = append(actual, text)
		}
	default:
		return fmt.Errorf("request object audience is required: %w", ErrRequestObjectAudienceMismatch)
	}
	for _, expected := range audiences {
		for _, value := range actual {
			if expected != "" && expected == value {
				return nil
			}
		}
	}
	return fmt.Errorf("request object audience does not identify this Wallet: %w", ErrRequestObjectAudienceMismatch)
}

// validateRequestObjectMaxAge bounds the lifetime a Request Object claims for
// itself: exp - iat, or exp - now when the issuing time is absent.
func validateRequestObjectMaxAge(expiry, issuedAt *big.Rat, policy requestObjectClaimPolicy) error {
	if policy.MaxAge <= 0 {
		return nil
	}
	from := issuedAt
	if from == nil {
		from = requestObjectInstant(policy.Now)
	}
	lifetime := new(big.Rat).Sub(expiry, from)
	maximum := new(big.Rat).SetFrac64(int64(policy.MaxAge), int64(time.Second))
	if lifetime.Cmp(maximum) <= 0 {
		return nil
	}
	seconds, _ := lifetime.Float64()
	return fmt.Errorf("request object exp is %s in the future, exceeding the configured maximum of %s: %w",
		(time.Duration(seconds * float64(time.Second))).Round(time.Second), policy.MaxAge, ErrRequestObjectExpired)
}

// requestObjectNumericDate reads one optional NumericDate claim exactly,
// rejecting a precision or exponent no relying party needs to represent.
func requestObjectNumericDate(claims commonJOSE.Claims, name string) (*big.Rat, error) {
	value, present := claims[name]
	if !present {
		return nil, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return nil, fmt.Errorf("%s must be a NumericDate", name)
	}
	text := number.String()
	if len(text) > 128 {
		return nil, fmt.Errorf("%s NumericDate exceeds supported precision", name)
	}
	if exponentIndex := strings.IndexAny(text, "eE"); exponentIndex >= 0 {
		exponent, err := strconv.Atoi(text[exponentIndex+1:])
		if err != nil || exponent < -1024 || exponent > 1024 {
			return nil, fmt.Errorf("%s NumericDate exceeds supported exponent range", name)
		}
	}
	timestamp, ok := new(big.Rat).SetString(text)
	if !ok {
		return nil, fmt.Errorf("invalid %s NumericDate", name)
	}
	return timestamp, nil
}

// requestObjectInstant renders a wall-clock instant as the exact rational
// number of seconds a NumericDate is compared against.
func requestObjectInstant(at time.Time) *big.Rat {
	instant := new(big.Rat).SetInt64(at.Unix())
	return instant.Add(instant, new(big.Rat).SetFrac64(int64(at.Nanosecond()), 1e9))
}
