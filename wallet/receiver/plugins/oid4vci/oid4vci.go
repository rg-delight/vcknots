package oid4vci

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/trustknots/vcknots/wallet/common"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

type Oid4vciReceiver struct {
	HTTPClient *http.Client
	// AllowHTTP permits HTTP endpoints for a local test issuer. The zero value requires HTTPS.
	AllowHTTP bool
	// Profile selects the OpenID4VCI Final/HAIP policy. The zero value normalizes
	// to profile.Final, which applies no HAIP constraints. Set it to profile.HAIP
	// to enforce HAIP 1.0 on the Final path.
	Profile profile.Profile
	// IssuerMetadataSigning configures OpenID4VCI 1.0 Section 12.2.3 signed
	// Credential Issuer Metadata. A nil value requests signed metadata under
	// HAIP and accepts an unsigned application/json document in every profile;
	// see IssuerMetadataSigningOptions for the defaults each field takes.
	IssuerMetadataSigning *IssuerMetadataSigningOptions
}

var _ types.OID4VCIFinalReceiver = (*Oid4vciReceiver)(nil)
var _ profile.Carrier = (*Oid4vciReceiver)(nil)

// ProtocolProfile reports the normalized OID4VCI profile this receiver enforces.
func (o *Oid4vciReceiver) ProtocolProfile() profile.Profile {
	normalized, err := o.Profile.Normalize()
	if err != nil {
		return o.Profile
	}
	return normalized
}

// SetProtocolProfile is used by the wallet root to propagate its profile to the
// default receiver plugin it constructs itself.
func (o *Oid4vciReceiver) SetProtocolProfile(p profile.Profile) {
	o.Profile = p
}

// normalizedProfile normalizes the configured profile once. Unknown values fail
// closed before any network access so every checkpoint reads a validated value.
func (o *Oid4vciReceiver) normalizedProfile() (profile.Profile, error) {
	normalized, err := o.Profile.Normalize()
	if err != nil {
		return "", fmt.Errorf("invalid OID4VCI profile: %w", err)
	}
	return normalized, nil
}

// requireHAIPTransport rejects the test-only HTTP escape when HAIP is selected.
// HAIP §4 requires TLS for issuer and authorization server endpoints.
func (o *Oid4vciReceiver) requireHAIPTransport(normalized profile.Profile) error {
	if normalized.IsHAIP() && o.AllowHTTP {
		return fmt.Errorf("HAIP profile does not permit AllowHTTP")
	}
	return nil
}

// requireDPoPTokenType enforces HAIP §4 "Sender-constrained access token: MUST
// support DPoP" on a parsed token response. A token_type other than DPoP
// (case-insensitive) cannot bind the access token to the wallet's key.
func requireDPoPTokenType(normalized profile.Profile, tokenType string) error {
	if normalized.IsHAIP() && !strings.EqualFold(strings.TrimSpace(tokenType), "DPoP") {
		return fmt.Errorf("HAIP requires a DPoP-bound access token")
	}
	return nil
}

type DPoPProofFactory = types.DPoPProofFactory

type OAuthClientAttestationHeadersFactory = types.OAuthClientAttestationHeadersFactory

type CredentialEndpointHTTPResponse = types.CredentialEndpointHTTPResponse

type CredentialRequestBodyFactory = types.CredentialRequestBodyFactory

// httpClient returns the client every OpenID4VCI request is sent through. The
// caller's client is wrapped rather than mutated, and the wrapper is rebuilt per
// call because a caller may replace HTTPClient between requests; the wrapper
// shares the caller's Transport, so connection pooling is unaffected.
func (o *Oid4vciReceiver) httpClient() *http.Client {
	return NoRedirectClient(o.HTTPClient)
}

const (
	wellKnownCredentialIssuer    = "/.well-known/openid-credential-issuer"
	wellKnownAuthorizationServer = "/.well-known/oauth-authorization-server"
)

type credentialNonceResponse struct {
	CNonce *string `json:"c_nonce"`
	Nonce  *string `json:"nonce"`
}

const maxNonceResponseBodyBytes int64 = 4 << 10

var oid4vciHTTPClient = &http.Client{Timeout: 15 * time.Second, CheckRedirect: rejectOID4VCIRedirect}

// ErrHTTPRedirectNotAllowed reports that an OpenID4VCI endpoint answered with a
// redirect. No OpenID4VCI endpoint is defined to redirect, and following one is
// never safe: a 307 or 308 replays the request body together with the
// Authorization, DPoP and OAuth-Client-Attestation headers against an origin the
// response chose, and a redirected metadata document substitutes the Credential
// Issuer's identity for another. The root wallet package cannot be imported from
// a plugin, so it declares its own alias of this sentinel.
var ErrHTTPRedirectNotAllowed = errors.New("OID4VCI endpoint redirected; redirects are not followed")

// ErrProofAlgorithmNotSupported reports that the holder key cannot produce any
// of the algorithms the Credential Issuer lists in
// proof_signing_alg_values_supported. The root wallet package declares its own
// alias of this sentinel for the same reason as ErrHTTPRedirectNotAllowed.
var ErrProofAlgorithmNotSupported = errors.New("no proof signing algorithm shared with the issuer")

// rejectOID4VCIRedirect refuses to follow a redirect on any OpenID4VCI request,
// metadata retrieval included. Credential Issuer Metadata is fetched from the
// path Section 12.2.2 fixes inside the Credential Issuer Identifier, so a
// redirect can only move the document to an origin the identifier does not name.
func rejectOID4VCIRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("OID4VCI endpoint redirected to %s: %w", req.URL.Redacted(), ErrHTTPRedirectNotAllowed)
}

// NoRedirectClient returns a shallow copy of client whose CheckRedirect refuses
// every 3xx with ErrHTTPRedirectNotAllowed. The caller's *http.Client is never
// mutated: its Transport, Timeout, Jar and every other field are carried over to
// the copy, which shares the same Transport. A nil client yields this package's
// default client, which already refuses redirects.
func NoRedirectClient(client *http.Client) *http.Client {
	if client == nil {
		return oid4vciHTTPClient
	}
	noRedirect := *client
	noRedirect.CheckRedirect = rejectOID4VCIRedirect
	return &noRedirect
}

// OID4VCICredentialFormatToSerializationFlavor maps OID4VCI credential format identifiers
// to wallet serialization flavors.
func OID4VCICredentialFormatToSerializationFlavor(format string) (credential.SupportedSerializationFlavor, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "jwt_vc_json", "jwt_vc", string(credential.JwtVc):
		return credential.JwtVc, nil
	case "dc+sd-jwt", string(credential.SDJwtVC):
		return credential.SDJwtVC, nil
	default:
		return "", fmt.Errorf("unsupported credential format: %q", format)
	}
}

// doRequest performs an HTTP request and unmarshals the JSON response into target.
// It handles common patterns: URL construction, status checking, body reading, and JSON parsing.
func (o *Oid4vciReceiver) doRequest(method string, endpoint common.URIField, path string, body io.Reader, target interface{}) error {
	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	if path == "/.well-known/oauth-authorization-server" {
		// Special handling for metadata discovery as per RFC 8414 §3
		// The well-known string MUST be inserted between the host component and the path component.
		// RFC 8414 §3.1 excludes the trailing slash from the AS path component.
		originalPath := strings.TrimSuffix(endpointURL.Path, "/")
		if !strings.HasPrefix(originalPath, path) {
			endpointURL.Path = path + originalPath
		}
	} else {
		// OID4VCI Draft 13 (ID1) §11.2.2, etc...
		if !strings.HasSuffix(endpointURL.Path, path) {
			endpointURL = *endpointURL.JoinPath(path)
		}
	}

	return o.doRequestURL(method, endpointURL, body, target)
}

func (o *Oid4vciReceiver) doRequestURL(method string, endpointURL url.URL, body io.Reader, target interface{}) error {
	if method != http.MethodGet && method != http.MethodPost {
		return fmt.Errorf("unsupported HTTP method: %s", method)
	}
	if method == "POST" && body == nil {
		return fmt.Errorf("POST request requires a body")
	}
	req, err := http.NewRequest(method, endpointURL.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return &metadataHTTPStatusError{statusCode: resp.StatusCode, body: string(bodyBytes)}
	}

	if len(bodyBytes) == 0 {
		return fmt.Errorf("empty response body")
	}
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	return nil
}

func (o *Oid4vciReceiver) FetchIssuerMetadata(endpoint common.URIField, receivingTypes types.SupportedReceivingTypes) (*types.CredentialIssuerMetadata, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported serialization flavor")
	}
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
	}
	if err := o.requireHAIPTransport(normalized); err != nil {
		return nil, err
	}

	signing := o.issuerMetadataSigningOptions(normalized)
	identifier := credentialIssuerIdentifier(url.URL(endpoint))

	var finalMetadata types.CredentialIssuerMetadata
	err = o.fetchFinalIssuerMetadata(endpoint, identifier, signing, normalized, &finalMetadata)
	if err == nil {
		return &finalMetadata, nil
	}
	// Keep the legacy discovery path only for local test issuers that explicitly
	// report the Final endpoint missing. Never retry malformed or forbidden metadata,
	// and never repeat the same URL. Each attempt decodes into a fresh value.
	endpointURL := url.URL(endpoint)
	var statusError *metadataHTTPStatusError
	if !o.AllowHTTP || !strings.EqualFold(endpointURL.Scheme, "http") ||
		strings.Trim(endpointURL.Path, "/") == "" ||
		strings.Contains(endpointURL.Path, "/.well-known/openid-credential-issuer") ||
		!errors.As(err, &statusError) || statusError.statusCode != http.StatusNotFound {
		return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
	}
	var metadata types.CredentialIssuerMetadata
	legacyURL := endpointURL
	if !strings.HasSuffix(legacyURL.Path, wellKnownCredentialIssuer) {
		legacyURL = *legacyURL.JoinPath(wellKnownCredentialIssuer)
	}
	if err := o.fetchIssuerMetadataDocument(legacyURL, identifier, signing, normalized, &metadata); err != nil {
		return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
	}

	return &metadata, nil
}

// issuerMetadataSigningOptions resolves the signed metadata policy for one
// fetch. HAIP Section 4.1 requires signed Credential Issuer Metadata to be
// supported "When Ecosystem policies require Issuer Authentication to a higher
// level than possible with TLS alone", which makes the capability mandatory and
// its use conditional: an unconfigured HAIP receiver therefore asks for signed
// metadata but still accepts the unsigned application/json document every
// Credential Issuer MUST publish (Section 12.2.2). A caller that supplies
// options keeps them verbatim, so opting out of the request is possible.
func (o *Oid4vciReceiver) issuerMetadataSigningOptions(normalized profile.Profile) IssuerMetadataSigningOptions {
	if o.IssuerMetadataSigning != nil {
		return *o.IssuerMetadataSigning
	}
	return IssuerMetadataSigningOptions{Request: normalized.IsHAIP()}
}

// credentialIssuerIdentifier recovers the Credential Issuer Identifier from the
// endpoint a fetch was addressed to. Section 12.2.2 forms the metadata URL by
// inserting the well-known path between the host and path components of the
// identifier, so removing that prefix is the inverse; an endpoint that is
// already the identifier is returned unchanged. Query and fragment components
// are dropped because Section 12.2.1 forbids them in an identifier.
func credentialIssuerIdentifier(endpointURL url.URL) string {
	identifier := endpointURL
	identifier.RawQuery = ""
	identifier.Fragment = ""
	identifier.ForceQuery = false
	if rest, found := strings.CutPrefix(identifier.Path, wellKnownCredentialIssuer); found {
		identifier.Path = rest
	}
	return strings.TrimSuffix(identifier.String(), "/")
}

type metadataHTTPStatusError struct {
	statusCode int
	body       string
}

func (e *metadataHTTPStatusError) Error() string {
	return fmt.Sprintf("unexpected status code: %d, body: %s", e.statusCode, e.body)
}

func (o *Oid4vciReceiver) fetchFinalIssuerMetadata(endpoint common.URIField, identifier string, signing IssuerMetadataSigningOptions, normalized profile.Profile, target *types.CredentialIssuerMetadata) error {
	endpointURL := url.URL(endpoint)
	originalPath := endpointURL.Path
	if originalPath == "/" {
		originalPath = ""
	}
	if !strings.HasPrefix(originalPath, wellKnownCredentialIssuer) {
		endpointURL.Path = wellKnownCredentialIssuer + originalPath
	}
	return o.fetchIssuerMetadataDocument(endpointURL, identifier, signing, normalized, target)
}

// IssuerMetadataSigningOptions configures OpenID4VCI 1.0 Section 12.2.3 signed
// Credential Issuer Metadata. Section 12.2.2 lets a Credential Issuer answer the
// metadata request with either an unsigned application/json document or a signed
// application/jwt one, and the Wallet signals which it accepts through the
// Accept header; Section 12.2.3 then requires that "When requesting signed
// metadata, the Wallet MUST establish trust in the signer of the metadata.
// Otherwise, the Wallet MUST reject the signed metadata."
type IssuerMetadataSigningOptions struct {
	// Request sends "Accept: application/jwt, application/json;q=0.9". It has no
	// effect unless trust material is configured, because metadata whose signer
	// cannot be authenticated must be rejected rather than requested.
	Request bool
	// Require rejects an unsigned application/json response. It defaults to
	// false in every profile, HAIP included: HAIP Section 4.1 makes signed
	// metadata a capability both sides MUST support, not a step every flow
	// performs. It cannot be satisfied without trust material, so setting it
	// without anchors fails the fetch instead of silently accepting.
	Require bool
	// TrustAnchors and RootCAs carry the signer trust configuration. Supply
	// exactly one of them; RootCAs preserves *x509.CertPool integrations.
	TrustAnchors []*x509.Certificate
	RootCAs      *x509.CertPool
	// KeyUsages constrains the extended key usage of the signing certificate.
	// Empty means no additional EKU policy, not TLS server authentication.
	KeyUsages []x509.ExtKeyUsage
	// AllowUnadvertisedRevocation keeps certificates that advertise no CRL
	// distribution point on the trust path, matching the issuer and Request
	// Object trust policies.
	AllowUnadvertisedRevocation bool
	// CRL tunes the revocation retrieval the trust path performs. Its
	// RequireStatus is derived from AllowUnadvertisedRevocation and must not be
	// set here as well.
	CRL commonX509.CRLCheckerOptions
	// Now supplies the verification time, for tests and for callers with their
	// own clock. Nil means time.Now.
	Now func() time.Time
}

// signedIssuerMetadataJWTType is the media type Section 12.2.3 requires in the
// typ JOSE header of signed Credential Issuer Metadata.
const signedIssuerMetadataJWTType = "openidvci-issuer-metadata+jwt"

// signedIssuerMetadataAlgorithms lists the signature algorithms accepted for
// signed metadata. Section 12.2.3 requires the alg header to be a digital
// signature algorithm and that it "MUST NOT be `none` or an identifier for a
// symmetric algorithm (MAC)", which this allowlist enforces by construction.
func signedIssuerMetadataAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.RS256, jose.RS384, jose.RS512,
		jose.EdDSA,
	}
}

// fetchIssuerMetadataDocument performs one Credential Issuer Metadata request
// and decodes the response by its media type, per Section 12.2.2. identifier is
// the Credential Issuer Identifier the request was derived from; signed metadata
// is bound to it through the sub claim.
func (o *Oid4vciReceiver) fetchIssuerMetadataDocument(requestURL url.URL, identifier string, signing IssuerMetadataSigningOptions, normalized profile.Profile, target *types.CredentialIssuerMetadata) error {
	if !o.AllowHTTP && !strings.EqualFold(requestURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", requestURL.Scheme)
	}
	trustConfigured := len(signing.TrustAnchors) > 0 || signing.RootCAs != nil
	if signing.Require && !trustConfigured {
		return fmt.Errorf("signed issuer metadata is required but no trust anchors are configured")
	}

	req, err := http.NewRequest(http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return err
	}
	// Section 12.2.2: the Wallet is RECOMMENDED to send an Accept header
	// "to indicate the Content Type(s) it supports, and by doing so, signaling
	// whether it supports signed metadata". Asking for a signed document the
	// wallet could not authenticate would only invite a response it must reject.
	if signing.Request && trustConfigured {
		req.Header.Set("Accept", "application/jwt, application/json;q=0.9")
	} else {
		req.Header.Set("Accept", "application/json")
	}

	resp, err := o.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return &metadataHTTPStatusError{statusCode: resp.StatusCode, body: string(bodyBytes)}
	}
	if len(bodyBytes) == 0 {
		return fmt.Errorf("empty response body")
	}

	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/jwt") {
		return o.decodeSignedIssuerMetadata(strings.TrimSpace(string(bodyBytes)), identifier, signing, normalized, target)
	}
	if signing.Require {
		return fmt.Errorf("issuer metadata is not signed but signed metadata is required")
	}
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	return nil
}

// decodeSignedIssuerMetadata verifies a signed metadata JWT and takes its
// payload as the metadata. Section 12.2.3 requires that "All metadata parameters
// used by the Credential Issuer MUST be added as top-level claims in the JWS
// payload", so the verified payload is the complete document and nothing is
// merged from an unsigned one.
func (o *Oid4vciReceiver) decodeSignedIssuerMetadata(compact string, identifier string, signing IssuerMetadataSigningOptions, normalized profile.Profile, target *types.CredentialIssuerMetadata) error {
	verification, payload, err := o.verifySignedIssuerMetadata(compact, identifier, signing, normalized)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return fmt.Errorf("failed to parse signed issuer metadata payload: %w", err)
	}
	target.SignedMetadata = compact
	target.MetadataSignature = verification
	return nil
}

// verifySignedIssuerMetadata authenticates the signer of a signed Credential
// Issuer Metadata JWT and returns the verified payload. Key resolution is the
// x5c JOSE header, which HAIP Section 4.1 requires: "Key resolution for the
// signed Credential Issuer Metadata MUST be supported using the `x5c` JOSE
// header parameter"; the same section forbids the trust anchor inside x5c and a
// self-signed signing certificate.
func (o *Oid4vciReceiver) verifySignedIssuerMetadata(compact string, identifier string, signing IssuerMetadataSigningOptions, normalized profile.Profile) (*types.MetadataVerification, []byte, error) {
	if len(signing.TrustAnchors) == 0 && signing.RootCAs == nil {
		return nil, nil, fmt.Errorf("signed issuer metadata is not trusted: no trust anchors are configured")
	}
	signed, err := jose.ParseSigned(compact, signedIssuerMetadataAlgorithms())
	if err != nil {
		return nil, nil, fmt.Errorf("signed issuer metadata is not trusted: %w", err)
	}
	if len(signed.Signatures) != 1 {
		return nil, nil, fmt.Errorf("signed issuer metadata must carry exactly one signature")
	}
	typ, _ := signed.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	if typ != signedIssuerMetadataJWTType {
		return nil, nil, fmt.Errorf("signed issuer metadata typ must be %q, got %q", signedIssuerMetadataJWTType, typ)
	}

	chain, err := commonX509.DecodeX5CFromJWTHeader(compact)
	if err != nil {
		return nil, nil, fmt.Errorf("signed issuer metadata is not trusted: %w", err)
	}
	if normalized.IsHAIP() {
		containsAnchor, err := commonX509.ContainsTrustAnchor(chain, signing.TrustAnchors, signing.RootCAs)
		if err != nil {
			return nil, nil, err
		}
		if containsAnchor {
			return nil, nil, fmt.Errorf("HAIP forbids including the trust anchor certificate in the x5c header")
		}
		if err := commonX509.RequireNonSelfSignedLeaf(chain, "signed issuer metadata"); err != nil {
			return nil, nil, err
		}
	}

	now := time.Now()
	if signing.Now != nil {
		now = signing.Now()
	}
	crlOptions := signing.CRL
	if crlOptions.RequireStatus && signing.AllowUnadvertisedRevocation {
		return nil, nil, fmt.Errorf("conflicting signed issuer metadata revocation policies")
	}
	crlOptions.RequireStatus = !signing.AllowUnadvertisedRevocation
	if crlOptions.HTTPClient == nil {
		crlOptions.HTTPClient = o.httpClient()
	}
	checker, err := commonX509.NewCRLChecker(crlOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create signed issuer metadata revocation checker: %w", err)
	}
	result, err := commonX509.VerifySigningCertificateChain(context.Background(), chain, commonX509.SigningChainOptions{
		TrustAnchors: signing.TrustAnchors,
		Roots:        signing.RootCAs,
		CurrentTime:  now,
		KeyUsages:    signing.KeyUsages,
		Revocation:   checker,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("signed issuer metadata is not trusted: %w", err)
	}

	payload, err := signed.Verify(result.Chain[0].PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("signed issuer metadata is not trusted: %w", err)
	}

	var claims struct {
		Sub string `json:"sub"`
		Iat *int64 `json:"iat"`
		Exp *int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, nil, fmt.Errorf("failed to parse signed issuer metadata payload: %w", err)
	}
	// Section 12.2.3: sub is "REQUIRED. String matching the Credential Issuer
	// Identifier". Binding it to the identifier the metadata was requested from
	// is what stops one issuer's signed document from standing in for another's.
	if strings.TrimSuffix(claims.Sub, "/") != identifier {
		return nil, nil, fmt.Errorf("signed issuer metadata sub %q does not match the credential issuer %q", claims.Sub, identifier)
	}
	if claims.Iat == nil {
		return nil, nil, fmt.Errorf("signed issuer metadata is missing the required iat claim")
	}
	verification := &types.MetadataVerification{
		LeafCertificateSHA256: result.Fingerprints[0],
		Subject:               result.Chain[0].Subject.String(),
		IssuedAt:              time.Unix(*claims.Iat, 0).UTC(),
	}
	if claims.Exp != nil {
		expiresAt := time.Unix(*claims.Exp, 0).UTC()
		if !expiresAt.After(now) {
			return nil, nil, fmt.Errorf("signed issuer metadata expired at %s", expiresAt.Format(time.RFC3339))
		}
		verification.ExpiresAt = &expiresAt
	}
	return verification, payload, nil
}

func (o *Oid4vciReceiver) FetchAuthorizationServerMetadata(endpoint common.URIField, receivingTypes types.SupportedReceivingTypes) (*types.AuthorizationServerMetadata, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
	}
	if err := o.requireHAIPTransport(normalized); err != nil {
		return nil, err
	}

	var metadata types.AuthorizationServerMetadata
	if err := o.doRequest("GET", endpoint, wellKnownAuthorizationServer, nil, &metadata); err != nil {
		return nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}

	return &metadata, nil
}

func (o *Oid4vciReceiver) FetchAccessToken(
	receivingTypes types.SupportedReceivingTypes,
	endpoint common.URIField,
	authzCode string,
	txCode string,
	opts ...types.TokenRequestOption,
) (*types.CredentialIssuanceAccessToken, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
	}
	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	formData.Set("pre-authorized_code", authzCode)
	if txCode != "" {
		formData.Set("tx_code", txCode)
	}
	requestConfig := types.NewTokenRequestConfig(opts...)
	if requestConfig.ClientAssertion != "" {
		// private_key_jwt identifies the client by client_id, and an empty one
		// would only be rejected at the authorization server, where the cause
		// is far harder to see.
		if strings.TrimSpace(requestConfig.ClientID) == "" {
			return nil, fmt.Errorf("client_id is required when a client assertion is sent")
		}
		formData.Set("client_assertion", requestConfig.ClientAssertion)
		formData.Set("client_assertion_type", types.ClientAssertionTypeJWTBearer)
	}
	// Sent for both authenticated and unauthenticated requests: client_id is
	// OPTIONAL for the pre-authorized code grant, so it is included whenever the
	// caller configured one.
	if strings.TrimSpace(requestConfig.ClientID) != "" {
		formData.Set("client_id", requestConfig.ClientID)
	}
	endpointURLString := types.ResolveTokenEndpointURL(endpoint)
	endpointURL, err := url.Parse(endpointURLString)
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint URL: %w", err)
	}

	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	// A client assertion proves possession of the registered client key, and
	// RFC 6749 section 10.8 requires client credentials never to travel in the
	// clear. VCKNOTS_WALLET_HTTP_ALLOWED exists so that the local samples can
	// talk to a development server on this machine, which is why loopback
	// stays permitted; it is not a licence to send the assertion across a
	// network unprotected.
	if requestConfig.ClientAssertion != "" &&
		!strings.EqualFold(endpointURL.Scheme, "https") &&
		!common.IsLoopbackHost(endpointURL.Hostname()) {
		return nil, fmt.Errorf(
			"refusing to send a client assertion to %q over %q: https is required for any host other than loopback",
			endpointURL.Host, endpointURL.Scheme)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		endpointURL.String(),
		strings.NewReader(formData.Encode()),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if requestConfig.DPoPProof != "" {
		req.Header.Set("DPoP", requestConfig.DPoPProof)
	}
	resp, err := o.httpClient().Do(req)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if isUseDPoPNonceResponse(resp, bodyBytes) {
			return nil, types.NewDPoPNonceError(resp.Header.Get("DPoP-Nonce"), types.ErrTokenRequestFailed)
		}
		if resp.StatusCode == http.StatusBadRequest {
			if errorCode := tokenErrorCode(bodyBytes); errorCode != "" {
				return nil, fmt.Errorf(
					"token request failed: %s; status: %d; response: %s: %w",
					errorCode,
					resp.StatusCode,
					string(bodyBytes),
					types.ErrTokenRequestFailed,
				)
			}
		}
		return nil, fmt.Errorf(
			"unexpected status code: %d response: %s",
			resp.StatusCode,
			string(bodyBytes),
		)
	}

	var accessToken types.CredentialIssuanceAccessToken
	if err := json.Unmarshal(bodyBytes, &accessToken); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	if err := requireDPoPTokenType(normalized, accessToken.TokenType); err != nil {
		return nil, err
	}
	return &accessToken, nil

}

func (o *Oid4vciReceiver) FetchNonce(receivingTypes types.SupportedReceivingTypes, endpoint common.URIField) (*string, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}
	if _, err := o.normalizedProfile(); err != nil {
		return nil, err
	}

	nonceEndpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(nonceEndpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", nonceEndpointURL.Scheme)
	}

	req, err := http.NewRequest(http.MethodPost, nonceEndpointURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxNonceResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read nonce response: %w", err)
	}

	if int64(len(bodyBytes)) > maxNonceResponseBodyBytes {
		return nil, fmt.Errorf("nonce endpoint response exceeds %d bytes", maxNonceResponseBodyBytes)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("nonce endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("nonce endpoint returned empty response")
	}

	var nonceResponse credentialNonceResponse
	if err := json.Unmarshal(bodyBytes, &nonceResponse); err != nil {
		return nil, fmt.Errorf("failed to parse nonce response: %w", err)
	}

	if nonceResponse.CNonce != nil && *nonceResponse.CNonce != "" {
		return nonceResponse.CNonce, nil
	}
	if nonceResponse.Nonce != nil && *nonceResponse.Nonce != "" {
		return nonceResponse.Nonce, nil
	}

	return nil, fmt.Errorf("nonce response does not contain c_nonce or nonce")
}

func (o *Oid4vciReceiver) PushAuthorizationRequest(endpoint common.URIField, request types.PushedAuthorizationRequest, headers types.OAuthClientAttestationHeaders) (*types.PushedAuthorizationResponse, error) {
	if _, err := o.normalizedProfile(); err != nil {
		return nil, err
	}
	formData := url.Values{}
	formData.Set("response_type", request.ResponseType)
	formData.Set("client_id", request.ClientID)
	formData.Set("redirect_uri", request.RedirectURI)
	// OpenID4VCI 1.0 §5.1.1/§5.1.2: scope and authorization_details are
	// alternative ways to select the requested Credential Configuration; an
	// empty value omits the parameter so the other method is unambiguous.
	if request.Scope != "" {
		formData.Set("scope", request.Scope)
	}
	if len(request.AuthorizationDetails) > 0 {
		encoded, err := json.Marshal(request.AuthorizationDetails)
		if err != nil {
			return nil, fmt.Errorf("failed to encode authorization_details: %w", err)
		}
		formData.Set("authorization_details", string(encoded))
	}
	formData.Set("state", request.State)
	formData.Set("code_challenge", request.CodeChallenge)
	formData.Set("code_challenge_method", request.CodeChallengeMethod)
	if request.IssuerState != "" {
		formData.Set("issuer_state", request.IssuerState)
	}
	// RFC 9126 §2: a PAR request carries the token endpoint's client
	// authentication. Client attestation headers and a client assertion are
	// different mechanisms and may coexist on the wire, but a deployment uses
	// one of them.
	setClientAssertionForm(formData, request.ClientAssertion, request.ClientAssertionType)

	var response types.PushedAuthorizationResponse
	if err := o.doFinalRequest(http.MethodPost, endpoint, strings.NewReader(formData.Encode()), "application/x-www-form-urlencoded", headersToMap(headers), &response); err != nil {
		return nil, fmt.Errorf("failed to push authorization request: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) ExchangeAuthorizationCode(endpoint common.URIField, request types.AuthorizationCodeTokenRequest, headers types.OAuthClientAttestationHeaders, dpopProof string) (*types.CredentialIssuanceAccessToken, error) {
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
	}
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", request.Code)
	formData.Set("redirect_uri", request.RedirectURI)
	formData.Set("code_verifier", request.CodeVerifier)
	formData.Set("client_id", request.ClientID)
	setClientAssertionForm(formData, request.ClientAssertion, request.ClientAssertionType)

	requestHeaders := headersToMap(headers)
	if dpopProof != "" {
		requestHeaders["DPoP"] = dpopProof
	}

	var response types.CredentialIssuanceAccessToken
	if err := o.doFinalRequest(http.MethodPost, endpoint, strings.NewReader(formData.Encode()), "application/x-www-form-urlencoded", requestHeaders, &response); err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}
	if err := requireDPoPTokenType(normalized, response.TokenType); err != nil {
		return nil, err
	}
	return &response, nil
}

func (o *Oid4vciReceiver) ExchangeAuthorizationCodeWithDpopRetry(endpoint common.URIField, request types.AuthorizationCodeTokenRequest, headers types.OAuthClientAttestationHeaders, proofFactory DPoPProofFactory) (*types.CredentialIssuanceAccessToken, error) {
	return o.ExchangeAuthorizationCodeWithDpopAndAttestationRetry(endpoint, request, func() (types.OAuthClientAttestationHeaders, error) {
		return headers, nil
	}, proofFactory)
}

func (o *Oid4vciReceiver) ExchangeAuthorizationCodeWithDpopAndAttestationRetry(endpoint common.URIField, request types.AuthorizationCodeTokenRequest, headersFactory OAuthClientAttestationHeadersFactory, proofFactory DPoPProofFactory) (*types.CredentialIssuanceAccessToken, error) {
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
	}
	// The form is rebuilt for every attempt so a fresh client_assertion
	// (unique jti, RFC 7523 §3) accompanies each re-sent request.
	buildBody := func() ([]byte, error) {
		assertion := request.ClientAssertion
		if request.ClientAssertionFactory != nil {
			fresh, err := request.ClientAssertionFactory()
			if err != nil {
				return nil, fmt.Errorf("failed to generate client assertion: %w", err)
			}
			assertion = fresh
		}
		formData := url.Values{}
		formData.Set("grant_type", "authorization_code")
		formData.Set("code", request.Code)
		formData.Set("redirect_uri", request.RedirectURI)
		formData.Set("code_verifier", request.CodeVerifier)
		formData.Set("client_id", request.ClientID)
		setClientAssertionForm(formData, assertion, request.ClientAssertionType)
		return []byte(formData.Encode()), nil
	}

	var response types.CredentialIssuanceAccessToken
	if err := o.doFormRequestWithDpopAndAttestationRetry(endpoint, buildBody, headersFactory, proofFactory, &response); err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code with DPoP retry: %w", err)
	}
	if err := requireDPoPTokenType(normalized, response.TokenType); err != nil {
		return nil, err
	}
	return &response, nil
}

func (o *Oid4vciReceiver) FetchClientAttestationChallenge(endpoint common.URIField) (*types.ClientAttestationChallengeResponse, error) {
	var response types.ClientAttestationChallengeResponse
	if err := o.doFinalRequest(http.MethodPost, endpoint, nil, "", nil, &response); err != nil {
		return nil, fmt.Errorf("failed to fetch client attestation challenge: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) FetchNonceResponse(endpoint common.URIField) (*types.NonceResponse, error) {
	var response types.NonceResponse
	if err := o.doFinalRequest(http.MethodPost, endpoint, nil, "", nil, &response); err != nil {
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}
	return &response, nil
}

// ValidateCredentialConfigurationForProfile applies the HAIP 1.0 constraints on
// a single Credential Configuration. Under Final every configuration is
// accepted. HAIP §4.1: "The Credential Issuer metadata MUST include a scope for
// every Credential Configuration it supports"; HAIP §5.3.2 and §6 restrict the
// offered credential formats to SD-JWT VC (dc+sd-jwt) and ISO mdoc (mso_mdoc).
func (o *Oid4vciReceiver) ValidateCredentialConfigurationForProfile(config types.CredentialConfiguration) error {
	normalized, err := o.normalizedProfile()
	if err != nil {
		return err
	}
	if !normalized.IsHAIP() {
		return nil
	}
	if strings.TrimSpace(config.Scope) == "" {
		return fmt.Errorf("HAIP requires a scope for every credential configuration")
	}
	switch strings.ToLower(strings.TrimSpace(config.Format)) {
	case "dc+sd-jwt", "mso_mdoc":
		return nil
	default:
		return fmt.Errorf("HAIP requires credential format dc+sd-jwt or mso_mdoc, got %q", config.Format)
	}
}

// ValidateIssuerMetadataForProfile applies the HAIP 1.0 constraints on the
// Credential Issuer metadata. Under Final the metadata is accepted unchanged.
// HAIP §4.1: "the nonce_endpoint MUST be present ... if the Credential Issuer
// metadata ... includes cryptographic_binding_methods_supported".
func (o *Oid4vciReceiver) ValidateIssuerMetadataForProfile(metadata *types.CredentialIssuerMetadata) error {
	normalized, err := o.normalizedProfile()
	if err != nil {
		return err
	}
	if !normalized.IsHAIP() {
		return nil
	}
	if metadata == nil {
		return fmt.Errorf("issuer metadata is required")
	}
	if metadata.NonceEndpoint != nil {
		return nil
	}
	for id, config := range metadata.CredentialConfigurationSupported {
		if config.CryptographicBindingMethodsSupported != nil && len(*config.CryptographicBindingMethodsSupported) > 0 {
			return fmt.Errorf("HAIP requires nonce_endpoint when credential configuration %q advertises cryptographic_binding_methods_supported", id)
		}
	}
	return nil
}

func (o *Oid4vciReceiver) RequestCredential(endpoint common.URIField, accessToken string, credentialRequest types.CredentialRequest, dpopProof string) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequest(endpoint, dpopBoundToken(accessToken), credentialRequest, dpopProof, &response); err != nil {
		return nil, fmt.Errorf("failed to request credential: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) RequestCredentialWithDpopRetry(endpoint common.URIField, accessToken string, credentialRequest types.CredentialRequest, proofFactory DPoPProofFactory) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequestWithDpopRetry(endpoint, dpopBoundToken(accessToken), credentialRequest, proofFactory, &response); err != nil {
		return nil, fmt.Errorf("failed to request credential with DPoP retry: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) PostCredentialEndpointWithDpopRetry(endpoint common.URIField, accessToken string, body []byte, contentType string, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, error) {
	return o.postCredentialEndpointForToken(endpoint, dpopBoundToken(accessToken), body, contentType, proofFactory)
}

func (o *Oid4vciReceiver) postCredentialEndpointForToken(endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, body []byte, contentType string, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, error) {
	responseBody, responseContentType, err := o.doBearerRequestWithDpopRetry(endpoint, accessToken, body, contentType, proofFactory)
	if err != nil {
		return nil, fmt.Errorf("failed to post credential endpoint request with DPoP retry: %w", err)
	}
	return &CredentialEndpointHTTPResponse{
		Body:        responseBody,
		ContentType: responseContentType,
	}, nil
}

// PostCredentialEndpointWithNonceRetryForToken is
// PostCredentialEndpointWithNonceRetry taking the parsed token response instead
// of the bare access token string, so that the Authorization header carries the
// scheme the authorization server issued. A Credential Issuer that returns
// token_type "Bearer" (RFC 6750 Section 2.1) must be addressed with the Bearer
// scheme; only a DPoP-bound token (RFC 9449 Section 7.1) takes the DPoP scheme
// and an accompanying DPoP proof header. Callers that still pass a bare string
// keep the DPoP scheme this plugin has always sent.
func (o *Oid4vciReceiver) PostCredentialEndpointWithNonceRetryForToken(endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, nonceEndpoint *common.URIField, initialCNonce string, build CredentialRequestBodyFactory, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, string, error) {
	return o.postCredentialEndpointWithNonceRetry(endpoint, accessToken, nonceEndpoint, initialCNonce, build, proofFactory)
}

// SendCredentialNotificationWithDpopRetryForToken is
// SendCredentialNotificationWithDpopRetry taking the parsed token response, for
// the same reason as PostCredentialEndpointWithNonceRetryForToken.
func (o *Oid4vciReceiver) SendCredentialNotificationWithDpopRetryForToken(endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, notification types.NotificationRequest, proofFactory DPoPProofFactory) error {
	return o.doBearerJSONRequestWithDpopRetry(endpoint, accessToken, notification, proofFactory, nil)
}

// dpopBoundToken adapts the access token string the established signatures take.
// Those entry points predate the token_type being plumbed through, and every one
// of them was sending the DPoP scheme unconditionally, so that is the scheme
// they keep.
func dpopBoundToken(accessToken string) types.CredentialIssuanceAccessToken {
	return types.CredentialIssuanceAccessToken{Token: accessToken, TokenType: "DPoP"}
}

// PostCredentialEndpointWithNonceRetry posts the credential request body built
// for the current c_nonce. OpenID4VCI 1.0 §8.3.1 requires the wallet to include
// the latest c_nonce in the proof, and §8.3.1.2 defines the "invalid_nonce"
// error an issuer returns when the proof carries a stale one; the wallet SHOULD
// obtain a fresh c_nonce from the nonce endpoint and retry. Exactly one such
// retry is performed so a misbehaving issuer cannot keep the wallet in a loop.
// DPoP challenges are still handled by PostCredentialEndpointWithDpopRetry
// underneath. It returns the response and the c_nonce actually used; when
// nonceEndpoint is nil the invalid_nonce error is returned without a retry.
func (o *Oid4vciReceiver) PostCredentialEndpointWithNonceRetry(endpoint common.URIField, accessToken string, nonceEndpoint *common.URIField, initialCNonce string, build CredentialRequestBodyFactory, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, string, error) {
	return o.postCredentialEndpointWithNonceRetry(endpoint, dpopBoundToken(accessToken), nonceEndpoint, initialCNonce, build, proofFactory)
}

func (o *Oid4vciReceiver) postCredentialEndpointWithNonceRetry(endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, nonceEndpoint *common.URIField, initialCNonce string, build CredentialRequestBodyFactory, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, string, error) {
	if build == nil {
		return nil, initialCNonce, fmt.Errorf("credential request body factory is required")
	}

	body, contentType, err := build(initialCNonce)
	if err != nil {
		return nil, initialCNonce, err
	}

	response, err := o.postCredentialEndpointForToken(endpoint, accessToken, body, contentType, proofFactory)
	if err == nil {
		return response, initialCNonce, nil
	}
	if !errors.Is(err, types.ErrInvalidNonce) || nonceEndpoint == nil {
		return nil, initialCNonce, err
	}

	nonceResponse, err := o.FetchNonceResponse(*nonceEndpoint)
	if err != nil {
		return nil, initialCNonce, fmt.Errorf("failed to refresh c_nonce after invalid_nonce: %w", err)
	}
	freshCNonce := nonceResponse.CNonce

	body, contentType, err = build(freshCNonce)
	if err != nil {
		return nil, freshCNonce, err
	}

	response, err = o.postCredentialEndpointForToken(endpoint, accessToken, body, contentType, proofFactory)
	if err != nil {
		return nil, freshCNonce, err
	}
	return response, freshCNonce, nil
}

func (o *Oid4vciReceiver) RequestDeferredCredential(endpoint common.URIField, accessToken string, deferredRequest types.DeferredCredentialRequest, dpopProof string) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequest(endpoint, dpopBoundToken(accessToken), deferredRequest, dpopProof, &response); err != nil {
		return nil, fmt.Errorf("failed to request deferred credential: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) RequestDeferredCredentialWithDpopRetry(endpoint common.URIField, accessToken string, deferredRequest types.DeferredCredentialRequest, proofFactory DPoPProofFactory) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequestWithDpopRetry(endpoint, dpopBoundToken(accessToken), deferredRequest, proofFactory, &response); err != nil {
		return nil, fmt.Errorf("failed to request deferred credential with DPoP retry: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) SendCredentialNotification(endpoint common.URIField, accessToken string, notification types.NotificationRequest, dpopProof string) error {
	return o.doBearerJSONRequest(endpoint, dpopBoundToken(accessToken), notification, dpopProof, nil)
}

func (o *Oid4vciReceiver) SendCredentialNotificationWithDpopRetry(endpoint common.URIField, accessToken string, notification types.NotificationRequest, proofFactory DPoPProofFactory) error {
	return o.doBearerJSONRequestWithDpopRetry(endpoint, dpopBoundToken(accessToken), notification, proofFactory, nil)
}

// EncodeCredentialRequest serializes a Credential Request or Deferred Credential
// Request, encrypting it when the Credential Issuer advertises
// credential_request_encryption (OpenID4VCI 1.0 Section 8.1 and Section 9.1:
// "When performing Credential Request encryption, the Client MUST encode the
// information in the Credential Request in a JWT as specified by
// [Encrypted Messages], using the parameters from the
// `credential_request_encryption` object in the Credential Issuer Metadata").
//
// It fails closed when the request asks for an encrypted response that it cannot
// protect: Section 8.2 states that "Credential Request encryption MUST be used if
// the `credential_response_encryption` parameter is included, to prevent it being
// substituted by an attacker", so a request carrying that parameter in the clear
// hands an attacker the wallet's response encryption key to replace.
func (o *Oid4vciReceiver) EncodeCredentialRequest(request any, issuerMetadata *types.CredentialIssuerMetadata) ([]byte, string, error) {
	plaintext, err := json.Marshal(request)
	if err != nil {
		return nil, "", err
	}
	if issuerMetadata == nil || issuerMetadata.CredentialRequestEncryption == nil {
		if requestCarriesResponseEncryption(plaintext) {
			return nil, "", fmt.Errorf("credential_response_encryption was requested but the issuer does not advertise credential_request_encryption")
		}
		return plaintext, "application/json", nil
	}

	encryptionKey, err := selectEncryptionKey(&issuerMetadata.CredentialRequestEncryption.Jwks)
	if err != nil {
		return nil, "", err
	}
	alg := encryptionKey.Algorithm
	if alg == "" {
		alg = firstOrDefault(issuerMetadata.CredentialRequestEncryption.AlgValuesSupported, "ECDH-ES")
	}
	enc := firstOrDefault(issuerMetadata.CredentialRequestEncryption.EncValuesSupported, "A128GCM")

	keyAlg, err := parseJWEKeyAlgorithm(alg)
	if err != nil {
		return nil, "", err
	}
	contentEnc, err := parseJWEContentEncryption(enc)
	if err != nil {
		return nil, "", err
	}

	encrypter, err := jose.NewEncrypter(
		contentEnc,
		jose.Recipient{
			Algorithm: keyAlg,
			Key:       encryptionKey.Key,
			KeyID:     encryptionKey.KeyID,
		},
		(&jose.EncrypterOptions{}).WithContentType("json"),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create credential request encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt credential request: %w", err)
	}
	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return nil, "", fmt.Errorf("failed to serialize credential request JWE: %w", err)
	}
	return []byte(serialized), "application/jwt", nil
}

// CredentialResponseEncryptionParameters builds the OpenID4VCI 1.0 §8.2
// "credential_response_encryption" request parameter from the §12.2.4 issuer
// metadata and the wallet's public encryption key. Final §8.2 defines exactly
// jwk, enc and zip (there is no top-level alg, unlike earlier drafts). enc is
// the first advertised value this library can decrypt; zip is included only when
// zip_values_supported lists DEF, matching the §10 encrypted-messages rules. A
// missing key is an error when the issuer marks
// credential_response_encryption.encryption_required true.
func CredentialResponseEncryptionParameters(metadata *types.CredentialIssuerMetadata, key *jose.JSONWebKey) (map[string]any, error) {
	if metadata == nil || metadata.CredentialResponseEncryption == nil {
		return nil, nil
	}
	encryption := metadata.CredentialResponseEncryption
	required := encryption.EncryptionRequired != nil && *encryption.EncryptionRequired
	if key == nil {
		if required {
			return nil, fmt.Errorf("credential response encryption is required but no encryption key was provided")
		}
		return nil, nil
	}

	enc, err := selectSupportedResponseEncryption(encryption.EncValuesSupported)
	if err != nil {
		return nil, err
	}

	parameters := map[string]any{
		"jwk": key.Public(),
		"enc": enc,
	}
	if containsZipDeflate(encryption.ZipValuesSupported) {
		parameters["zip"] = "DEF"
	}
	return parameters, nil
}

// requestCarriesResponseEncryption reports whether a marshalled credential or
// deferred credential request carries a non-empty credential_response_encryption
// member. The serialized form is inspected rather than the Go value so that a
// map body, a typed struct and a caller-supplied shape are all read the same way.
func requestCarriesResponseEncryption(payload []byte) bool {
	var body map[string]json.RawMessage
	if err := json.Unmarshal(payload, &body); err != nil {
		return false
	}
	raw, present := body["credential_response_encryption"]
	if !present {
		return false
	}
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "{}":
		return false
	default:
		return true
	}
}

func selectSupportedResponseEncryption(encValues []string) (string, error) {
	for _, enc := range encValues {
		if enc == "" {
			continue
		}
		if _, err := parseJWEContentEncryption(enc); err == nil {
			return enc, nil
		}
	}
	return "", fmt.Errorf("credential response encryption: issuer advertises no supported enc value in %v", encValues)
}

func containsZipDeflate(zipValues []string) bool {
	for _, value := range zipValues {
		if strings.EqualFold(strings.TrimSpace(value), "DEF") {
			return true
		}
	}
	return false
}

func (o *Oid4vciReceiver) DecodeCredentialResponse(body []byte, contentType string, decryptionKey any) (*types.CredentialResponse, error) {
	payload := body
	if strings.Contains(strings.ToLower(contentType), "application/jwt") {
		if decryptionKey == nil {
			return nil, fmt.Errorf("decryption key is required for encrypted credential response")
		}
		jwe, err := jose.ParseEncrypted(string(body), supportedJWEKeyAlgorithms(), supportedJWEContentEncryptions())
		if err != nil {
			return nil, fmt.Errorf("failed to parse credential response JWE: %w", err)
		}
		// OpenID4VCI 1.0 §8.2 / §10 (Encrypted Credential Requests and Responses)
		// permits the issuer to signal DEFLATE with the JWE protected "zip":"DEF"
		// header. go-jose v4 (>= 4.1.4) inflates the plaintext inside Decrypt when
		// that header is present, so no manual flate step is required here;
		// TestOid4vciReceiver_DecodeCredentialResponseZip pins that behavior.
		payload, err = jwe.Decrypt(decryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt credential response JWE: %w", err)
		}
	}

	var response types.CredentialResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, fmt.Errorf("failed to parse credential response JSON: %w", err)
	}
	return &response, nil
}

func (o *Oid4vciReceiver) CreateDpopProof(key jose.JSONWebKey, method string, rawURL string, nonce string, accessToken string) (string, error) {
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

func (o *Oid4vciReceiver) CreateCredentialRequestJWTProof(key jose.JSONWebKey, audience string, nonce string) (string, error) {
	return o.CreateCredentialRequestJWTProofWithKeyAttestation(key, audience, nonce, "")
}

func (o *Oid4vciReceiver) CreateCredentialRequestJWTProofWithKeyAttestation(key jose.JSONWebKey, audience string, nonce string, keyAttestation string) (string, error) {
	return o.CreateCredentialRequestJWTProofWithOptions(key, ProofOptions{
		Audience:       audience,
		Nonce:          nonce,
		KeyAttestation: keyAttestation,
	})
}

// ProofOptions carries the inputs of an OpenID4VCI 1.0 Section 8.2.1.1 jwt key
// proof. It exists so the proof can honour issuer metadata without widening the
// two established CreateCredentialRequestJWTProof signatures, which delegate here
// with no algorithm constraint.
type ProofOptions struct {
	// Audience is the Credential Issuer Identifier the proof is bound to.
	Audience string
	// Nonce is the c_nonce the issuer supplied, omitted when empty.
	Nonce string
	// KeyAttestation is the Appendix D key attestation JWT, carried in the
	// key_attestation JOSE header when non-empty.
	KeyAttestation string
	// SigningAlgValues is the proof_signing_alg_values_supported list of the
	// credential configuration being requested, that is
	// CredentialConfigurationSupported[id].ProofTypesSupported["jwt"]. An empty
	// list means the issuer published no constraint.
	SigningAlgValues []jose.SignatureAlgorithm
}

// CreateCredentialRequestJWTProofWithOptions builds the jwt key proof for a
// Credential Request, signing it with an algorithm the Credential Issuer accepts.
func (o *Oid4vciReceiver) CreateCredentialRequestJWTProofWithOptions(key jose.JSONWebKey, opts ProofOptions) (string, error) {
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

func (o *Oid4vciReceiver) CreateClientAttestation(clientKey jose.JSONWebKey, attesterKey jose.JSONWebKey, attesterIssuer string, clientID string, lifetime time.Duration) (string, error) {
	if lifetime == 0 {
		lifetime = 5 * time.Minute
	}
	now := time.Now()
	clientPublicJWK := clientKey.Public()
	clientPublicJWK.Algorithm = firstOrDefault([]string{clientPublicJWK.Algorithm}, "ES256")
	clientPublicJWK.Use = firstOrDefault([]string{clientPublicJWK.Use}, "sig")
	clientPublicJWK.KeyID = firstOrDefault([]string{clientPublicJWK.KeyID}, clientKey.KeyID)

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

func (o *Oid4vciReceiver) CreateClientAttestationPop(clientKey jose.JSONWebKey, clientID string, authorizationServerIssuer string, attestationChallenge string, lifetime time.Duration) (string, error) {
	if lifetime == 0 {
		lifetime = 5 * time.Minute
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

func (o *Oid4vciReceiver) doBearerJSONRequest(endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, payload any, dpopProof string, target any) error {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	scheme := authorizationScheme(accessToken.TokenType)
	headers := map[string]string{"Authorization": scheme + " " + accessToken.Token}
	if scheme == dpopAuthorizationScheme {
		headers["DPoP"] = dpopProof
	}

	return o.doFinalRequest(http.MethodPost, endpoint, bytes.NewReader(bodyBytes), "application/json", headers, target)
}

func (o *Oid4vciReceiver) doBearerJSONRequestWithDpopRetry(endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, payload any, proofFactory DPoPProofFactory, target any) error {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	respBody, _, err := o.doBearerRequestWithDpopRetry(endpoint, accessToken, bodyBytes, "application/json", proofFactory)
	if err != nil {
		return err
	}
	if target == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	return nil
}

func (o *Oid4vciReceiver) doBearerRequestWithDpopRetry(endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, bodyBytes []byte, contentType string, proofFactory DPoPProofFactory) ([]byte, string, error) {
	if proofFactory == nil {
		return nil, "", fmt.Errorf("DPoP proof factory is required")
	}
	scheme := authorizationScheme(accessToken.TokenType)

	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, "", fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	var dpopNonce string
	var lastStatus int
	var lastContentType string
	var lastBody []byte
	var lastNonce string
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(http.MethodPost, endpointURL.String(), bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Accept", "application/json")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Authorization", scheme+" "+accessToken.Token)
		// RFC 9449 Section 7.1 pairs the DPoP proof header with the DPoP
		// scheme. A bearer token is not bound to the wallet key, so a proof
		// alongside it would prove nothing and is not built at all.
		if scheme == dpopAuthorizationScheme {
			dpopProof, err := proofFactory(dpopNonce)
			if err != nil {
				return nil, "", err
			}
			req.Header.Set("DPoP", dpopProof)
		}

		resp, err := o.httpClient().Do(req)
		if err != nil {
			return nil, "", err
		}
		respBody, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			return nil, "", readErr
		}
		if closeErr != nil {
			return nil, "", closeErr
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return respBody, resp.Header.Get("Content-Type"), nil
		}
		nonce := resp.Header.Get("DPoP-Nonce")
		if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized) && nonce != "" {
			dpopNonce = nonce
			lastStatus, lastContentType, lastBody, lastNonce = resp.StatusCode, resp.Header.Get("Content-Type"), respBody, nonce
			continue
		}
		return nil, "", newCredentialEndpointError(resp.StatusCode, resp.Header.Get("Content-Type"), respBody, nonce)
	}

	if lastStatus != 0 {
		return nil, "", newCredentialEndpointError(lastStatus, lastContentType, lastBody, lastNonce)
	}
	return nil, "", fmt.Errorf("DPoP nonce retry exhausted for %s", endpointURL.String())
}

// newCredentialEndpointError converts a non-2xx credential, deferred credential
// or notification response into the OpenID4VCI 1.0 §8.3.1.2 typed error (see
// also §9.2 and §11.3 for the deferred and notification error responses). The
// HTTP status is always retained. For 4xx responses served as JSON, the
// "error", "error_description" and "interval" members are parsed so callers can
// use errors.Is; any other content type (or unparseable body) leaves Code empty.
func newCredentialEndpointError(statusCode int, contentType string, body []byte, dpopNonce string) *types.CredentialEndpointError {
	credentialErr := &types.CredentialEndpointError{
		StatusCode: statusCode,
		DPoPNonce:  strings.TrimSpace(dpopNonce),
	}
	if statusCode < 400 || statusCode >= 500 || !strings.Contains(strings.ToLower(contentType), "json") {
		return credentialErr
	}
	var payload struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		Interval    int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return credentialErr
	}
	credentialErr.Code = payload.Error
	credentialErr.Description = payload.Description
	credentialErr.Interval = payload.Interval
	return credentialErr
}

func (o *Oid4vciReceiver) doFormRequestWithDpopAndAttestationRetry(endpoint common.URIField, bodyFactory func() ([]byte, error), headersFactory OAuthClientAttestationHeadersFactory, proofFactory DPoPProofFactory, target any) error {
	if headersFactory == nil {
		return fmt.Errorf("OAuth client attestation headers factory is required")
	}
	return o.doFormRequestWithDpopAndHeadersRetry(endpoint, bodyFactory, func() (map[string]string, error) {
		headers, err := headersFactory()
		if err != nil {
			return nil, err
		}
		return headersToMap(headers), nil
	}, proofFactory, target)
}

func (o *Oid4vciReceiver) doFormRequestWithDpopAndHeadersRetry(endpoint common.URIField, bodyFactory func() ([]byte, error), headersFactory func() (map[string]string, error), proofFactory DPoPProofFactory, target any) error {
	if proofFactory == nil {
		return fmt.Errorf("DPoP proof factory is required")
	}
	if headersFactory == nil {
		return fmt.Errorf("headers factory is required")
	}
	if bodyFactory == nil {
		return fmt.Errorf("body factory is required")
	}

	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	var dpopNonce string
	for attempt := 0; attempt < 2; attempt++ {
		dpopProof, err := proofFactory(dpopNonce)
		if err != nil {
			return err
		}
		headers, err := headersFactory()
		if err != nil {
			return err
		}
		bodyBytes, err := bodyFactory()
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodPost, endpointURL.String(), bytes.NewReader(bodyBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", dpopProof)
		for key, value := range headers {
			if value != "" {
				req.Header.Set(key, value)
			}
		}

		resp, err := o.httpClient().Do(req)
		if err != nil {
			return err
		}
		respBody, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if target == nil || len(respBody) == 0 {
				return nil
			}
			if err := json.Unmarshal(respBody, target); err != nil {
				return fmt.Errorf("failed to parse JSON: %w", err)
			}
			return nil
		}
		nonce := resp.Header.Get("DPoP-Nonce")
		if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized) && nonce != "" {
			dpopNonce = nonce
			continue
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(respBody))
	}

	return fmt.Errorf("DPoP nonce retry exhausted for %s", endpointURL.String())
}

// setClientAssertionForm adds the RFC 7523 §2.2 private_key_jwt client
// authentication parameters to a form. Both members are omitted when no
// assertion is present, so an unauthenticated request carries no client
// authentication parameters. A supplied assertion without an explicit type is
// sent with the JWT bearer value, the only type private_key_jwt uses.
func setClientAssertionForm(formData url.Values, clientAssertion, clientAssertionType string) {
	if strings.TrimSpace(clientAssertion) == "" {
		return
	}
	if strings.TrimSpace(clientAssertionType) == "" {
		clientAssertionType = types.ClientAssertionTypeJWTBearer
	}
	formData.Set("client_assertion", clientAssertion)
	formData.Set("client_assertion_type", clientAssertionType)
}

func headersToMap(headers types.OAuthClientAttestationHeaders) map[string]string {
	result := map[string]string{}
	if headers.ClientAttestation != "" {
		result["OAuth-Client-Attestation"] = headers.ClientAttestation
	}
	if headers.ClientAttestationPop != "" {
		result["OAuth-Client-Attestation-PoP"] = headers.ClientAttestationPop
	}
	return result
}

func (o *Oid4vciReceiver) doFinalRequest(method string, endpoint common.URIField, body io.Reader, contentType string, headers map[string]string, target any) error {
	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	req, err := http.NewRequest(method, endpointURL.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for key, value := range headers {
		if value != "" {
			req.Header.Set(key, value)
		}
	}

	resp, err := o.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}
	if target == nil || len(bodyBytes) == 0 {
		return nil
	}
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	return nil
}

func selectEncryptionKey(jwks *jose.JSONWebKeySet) (*jose.JSONWebKey, error) {
	if jwks == nil || len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("encryption JWKS does not contain a key")
	}
	for i := range jwks.Keys {
		if jwks.Keys[i].Use == "enc" {
			return &jwks.Keys[i], nil
		}
	}
	return &jwks.Keys[0], nil
}

func firstOrDefault(values []string, fallback string) string {
	if len(values) > 0 && values[0] != "" {
		return values[0]
	}
	return fallback
}

func parseJWEKeyAlgorithm(alg string) (jose.KeyAlgorithm, error) {
	switch alg {
	case "ECDH-ES":
		return jose.ECDH_ES, nil
	case "ECDH-ES+A128KW":
		return jose.ECDH_ES_A128KW, nil
	case "ECDH-ES+A192KW":
		return jose.ECDH_ES_A192KW, nil
	case "ECDH-ES+A256KW":
		return jose.ECDH_ES_A256KW, nil
	default:
		return "", fmt.Errorf("unsupported encryption algorithm: %s", alg)
	}
}

func parseJWEContentEncryption(enc string) (jose.ContentEncryption, error) {
	switch enc {
	case "A128GCM":
		return jose.A128GCM, nil
	case "A192GCM":
		return jose.A192GCM, nil
	case "A256GCM":
		return jose.A256GCM, nil
	case "A128CBC-HS256":
		return jose.A128CBC_HS256, nil
	case "A192CBC-HS384":
		return jose.A192CBC_HS384, nil
	case "A256CBC-HS512":
		return jose.A256CBC_HS512, nil
	default:
		return "", fmt.Errorf("unsupported encryption encoding: %s", enc)
	}
}

func supportedJWEKeyAlgorithms() []jose.KeyAlgorithm {
	return []jose.KeyAlgorithm{jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW}
}

func supportedJWEContentEncryptions() []jose.ContentEncryption {
	return []jose.ContentEncryption{jose.A128GCM, jose.A192GCM, jose.A256GCM, jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512}
}

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

func (o *Oid4vciReceiver) ReceiveCredential(
	receivingTypes types.SupportedReceivingTypes,
	endpoint common.URIField,
	credentialConfigurationID string,
	credentialIdentifier *string,
	accessToken types.CredentialIssuanceAccessToken,
	credentialDefinition *types.CredentialDefinition,
	jwtProof *string,
	options ...*types.CredentialRequestOptions,
) (*string, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}

	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	// Prepare credential request body
	reqBody := map[string]interface{}{}
	if credentialIdentifier != nil && *credentialIdentifier != "" {
		reqBody["credential_identifier"] = *credentialIdentifier
	} else {
		reqBody["credential_configuration_id"] = credentialConfigurationID
	}

	if jwtProof != nil {
		reqBody["proofs"] = map[string]interface{}{
			"jwt": []string{*jwtProof},
		}
	}

	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", endpointURL.String(), bytes.NewReader(reqBodyBytes))
	if err != nil {
		return nil, err
	}

	requestOptions := firstCredentialRequestOptions(options)

	// Set headers
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	tokenType := authorizationScheme(accessToken.TokenType)
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken.Token))
	if strings.EqualFold(accessToken.TokenType, "DPoP") {
		if requestOptions == nil || requestOptions.DPoPProofJWT == nil || *requestOptions.DPoPProofJWT == "" {
			return nil, fmt.Errorf("DPoP proof JWT is required for DPoP access token")
		}
		req.Header.Set("DPoP", *requestOptions.DPoPProofJWT)
	}
	req.Header.Set("Accept", "application/json")
	req.ContentLength = int64(len(reqBodyBytes))

	// Execute request
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		if isUseDPoPNonceResponse(resp, bodyBytes) {
			return nil, fmt.Errorf(
				"%w; status: %d; endpoint: %s; response: %s",
				types.NewDPoPNonceError(resp.Header.Get("DPoP-Nonce"), types.ErrUseDPoPNonce),
				resp.StatusCode,
				endpointURL.String(),
				string(bodyBytes),
			)
		}
		return nil, fmt.Errorf("failed to receive credential; status: %d; endpoint: %s; response: %s", resp.StatusCode, endpointURL.String(), string(bodyBytes))
	}

	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("credential response is empty")
	}

	// Extract credential from response
	var credentialResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &credentialResponse); err != nil {
		return nil, err
	}

	var credential interface{}

	credentialsRaw, hasCredentials := credentialResponse["credentials"]
	if hasCredentials {
		credentials, ok := credentialsRaw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("credentials response has invalid type")
		}
		if len(credentials) != 1 {
			return nil, fmt.Errorf("credentials response must contain exactly one credential, got %d", len(credentials))
		}
		credentialWrapper, ok := credentials[0].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("first credential entry has invalid format")
		}
		var found bool
		credential, found = credentialWrapper["credential"]
		if !found {
			return nil, fmt.Errorf("credential field missing in first credentials entry")
		}
	} else {
		var ok bool
		credential, ok = credentialResponse["credential"]
		if !ok {
			return nil, fmt.Errorf("no credential found in response")
		}
	}

	credentialStr, ok := credential.(string)
	if !ok {
		// If credential is not a string, marshal it back to JSON
		credentialBytes, err := json.Marshal(credential)
		if err != nil {
			return nil, err
		}
		credentialStr = string(credentialBytes)
	}

	return &credentialStr, nil
}

func firstCredentialRequestOptions(options []*types.CredentialRequestOptions) *types.CredentialRequestOptions {
	for _, option := range options {
		if option != nil {
			return option
		}
	}
	return nil
}

// dpopAuthorizationScheme is the RFC 9449 Section 7.1 authentication scheme for
// a DPoP-bound access token.
const dpopAuthorizationScheme = "DPoP"

// authorizationScheme maps a token response's token_type to the authentication
// scheme its access token is sent with. token_type is compared case
// insensitively, as RFC 6749 Section 7.1 defines it. Anything that is not DPoP
// takes the Bearer scheme of RFC 6750 Section 2.1: those are the only two
// schemes this wallet holds credentials for, so echoing back an unrecognised
// token_type would only build a header no issuer could act on.
func authorizationScheme(tokenType string) string {
	if strings.EqualFold(strings.TrimSpace(tokenType), dpopAuthorizationScheme) {
		return dpopAuthorizationScheme
	}
	return "Bearer"
}

func tokenErrorCode(bodyBytes []byte) string {
	var errorResponse struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errorResponse); err != nil {
		return ""
	}
	return strings.TrimSpace(errorResponse.Error)
}

func isUseDPoPNonceError(bodyBytes []byte) bool {
	return tokenErrorCode(bodyBytes) == "use_dpop_nonce"
}

func isUseDPoPNonceResponse(resp *http.Response, bodyBytes []byte) bool {
	if isUseDPoPNonceError(bodyBytes) {
		return true
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "use_dpop_nonce")
}
