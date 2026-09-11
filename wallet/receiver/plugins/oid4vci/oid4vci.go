package oid4vci

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver/oid4vcisign"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// Oid4vciReceiver is the bundled OpenID4VCI receiver plugin. It implements the
// Draft 13 types.Receiver contract, the Final 1.0 / HAIP
// types.OID4VCIFinalTransport contract and, through the embedded
// oid4vcisign.Default, the types.OID4VCIFinalSigner contract.
type Oid4vciReceiver struct {
	// Default supplies the OpenID4VCI 1.0 Final signing primitives (DPoP proof,
	// jwt key proof, client attestation JWTs) so this plugin satisfies
	// types.OID4VCIFinalSigner as well as types.OID4VCIFinalTransport. A wallet
	// that signs elsewhere configures its own signer and uses this plugin only
	// as a transport.
	oid4vcisign.Default

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

	// dpopNonceMu guards dpopNonces. The map is created on first use because
	// every caller builds this struct as a literal, so there is no constructor
	// that could allocate it. A zero Oid4vciReceiver is therefore usable and,
	// once in use, must not be copied.
	dpopNonceMu sync.Mutex
	// dpopNonces is the RFC 9449 Section 8.2 per-server nonce store: "The DPoP
	// nonce ... is provided by the server to the client in the DPoP-Nonce HTTP
	// header ... Clients should expect that a server will use the same nonce
	// for all requests to that server". It is keyed by the endpoint's scheme
	// and authority, because that is the granularity RFC 9449 Section 8.2
	// assigns a nonce to, and it holds the most recent value the wallet has
	// seen from that server on any endpoint.
	dpopNonces map[string]string
}

// dpopNonceServerKey identifies the server an RFC 9449 Section 8.2 DPoP nonce
// belongs to. Section 8.2 scopes a nonce to the server ("Clients should expect
// that a server will use the same nonce for all requests to that server"), not
// to a single endpoint path, so the key is the scheme and authority only. Both
// are compared case insensitively, as RFC 3986 Section 6.2.2.1 requires.
func dpopNonceServerKey(endpointURL url.URL) string {
	return strings.ToLower(endpointURL.Scheme) + "://" + strings.ToLower(endpointURL.Host)
}

// rememberDPoPNonce records a DPoP-Nonce the wallet observed on any response
// from a server, so the next request to that same server can carry a proof that
// already satisfies it. RFC 9449 Section 8.2: "The DPoP-Nonce HTTP header field
// is used ... to provide the client with a nonce value to be used in a
// subsequent DPoP proof". An empty value is ignored: a response without the
// header does not revoke the nonce the wallet already holds.
func (o *Oid4vciReceiver) rememberDPoPNonce(endpointURL url.URL, nonce string) {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return
	}
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	if o.dpopNonces == nil {
		o.dpopNonces = make(map[string]string, 1)
	}
	o.dpopNonces[dpopNonceServerKey(endpointURL)] = nonce
}

// dpopNonceFor returns the latest DPoP nonce the wallet holds for the server
// endpointURL addresses, or the empty string when it holds none. Seeding the
// first proof of a request with it is what RFC 9449 Section 8.2 asks for:
// "Clients should expect that a server will use the same nonce for all requests
// to that server", which spares the wasted request that would otherwise be
// rejected with "use_dpop_nonce" only to be repeated.
func (o *Oid4vciReceiver) dpopNonceFor(endpointURL url.URL) string {
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	return o.dpopNonces[dpopNonceServerKey(endpointURL)]
}

// ExportDPoPNonces returns a snapshot of the RFC 9449 §8.2 per-server DPoP
// nonce store, keyed by dpopNonceServerKey. A copy is returned so a caller can
// carry the protocol state across an interruption (for example into an
// OID4VCIFinalTokenGrant.DPoPNonces and back out of it) without holding or
// mutating the receiver's map. An empty store exports an empty, non-nil map.
func (o *Oid4vciReceiver) ExportDPoPNonces() map[string]string {
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	exported := make(map[string]string, len(o.dpopNonces))
	for server, nonce := range o.dpopNonces {
		exported[server] = nonce
	}
	return exported
}

// ImportDPoPNonces restores the per-server nonces ExportDPoPNonces produced.
// Each value is remembered for its server, so the first DPoP proof built after
// a resume already carries the nonce that server last issued instead of paying
// the wasted challenge round trip RFC 9449 §8.2 exists to avoid. Blank values
// are ignored, matching rememberDPoPNonce.
func (o *Oid4vciReceiver) ImportDPoPNonces(nonces map[string]string) {
	if len(nonces) == 0 {
		return
	}
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	if o.dpopNonces == nil {
		o.dpopNonces = make(map[string]string, len(nonces))
	}
	for server, nonce := range nonces {
		if strings.TrimSpace(nonce) == "" {
			continue
		}
		o.dpopNonces[server] = nonce
	}
}

var (
	_ types.OID4VCIFinalTransport = (*Oid4vciReceiver)(nil)
	_ types.OID4VCIFinalSigner    = (*Oid4vciReceiver)(nil)
	_ profile.Carrier             = (*Oid4vciReceiver)(nil)
)

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

// RequireBearerTokenType enforces the Final 1.0 default for the anonymous
// Pre-Authorized Code path: the token response must carry a plain Bearer access
// token. OpenID4VCI 1.0 §6.1 makes token_type REQUIRED ("The type of the access
// token"), and RFC 6749 §7.1 defines it as case insensitive, so "Bearer",
// "bearer" and "BEARER" are the same value. A DPoP-bound token (RFC 9449 §7.1)
// is refused with ErrDPoPRequired because an anonymous client holds no key to
// build the proof that scheme requires; any other value is an unsupported
// token_type rather than a silent fallback to Bearer.
func RequireBearerTokenType(t *types.CredentialIssuanceAccessToken) error {
	if t == nil {
		return fmt.Errorf("token response is required")
	}
	switch {
	case strings.EqualFold(strings.TrimSpace(t.TokenType), "Bearer"):
		return nil
	case strings.EqualFold(strings.TrimSpace(t.TokenType), dpopAuthorizationScheme):
		return fmt.Errorf("%w: token endpoint issued a DPoP-bound access token, which the anonymous Pre-Authorized Code path cannot present", ErrDPoPRequired)
	default:
		return fmt.Errorf("token response returned unsupported token_type %q (Bearer required)", t.TokenType)
	}
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

// ErrDPoPRequired reports that a Credential, Deferred Credential or Notification
// response demanded a DPoP proof (an RFC 9449 §8 DPoP-Nonce header, or a
// WWW-Authenticate challenge naming the DPoP scheme of §7.1) while the access
// token was presented with a scheme that has no key-bound proof to offer. It is
// the fail-closed answer for a client that holds no DPoP key: continuing would
// either replay the request without the proof the resource server asked for or
// invent one the wallet cannot sign.
var ErrDPoPRequired = errors.New("credential endpoint requires DPoP")

// ErrProofAlgorithmNotSupported reports that the holder key cannot produce any
// of the algorithms the Credential Issuer lists in
// proof_signing_alg_values_supported. It is the oid4vcisign sentinel of the same
// name, re-exported here because the key proof used to be built by this package;
// errors.Is matches either spelling.
var ErrProofAlgorithmNotSupported = oid4vcisign.ErrProofAlgorithmNotSupported

// ErrIssuerIdentifierMismatch reports that a Credential Issuer Metadata document
// states a credential_issuer that is not identical to the Credential Issuer
// Identifier the metadata was requested from. OpenID4VCI 1.0 Section 12.2.4:
// "The value MUST be identical to the Credential Issuer's identifier value into
// which the well-known URI string was inserted to create the URL used to retrieve
// the metadata. If these values are not identical (when compared using a simple
// string comparison with no normalization), the data contained in the response
// MUST NOT be used." The root wallet package cannot import a plugin, so it
// declares its own alias of this sentinel.
var ErrIssuerIdentifierMismatch = errors.New("credential_issuer does not match the requested Credential Issuer Identifier")

// requireMatchingCredentialIssuer enforces the OpenID4VCI 1.0 Section 12.2.4
// identity rule on a decoded Credential Issuer Metadata document: the
// credential_issuer member MUST be the Credential Issuer Identifier the wallet
// requested the document from, compared as a simple string with no
// normalization. A document that names any other identifier is not the
// requested issuer's, whatever it contains, so decoding fails closed before the
// metadata is returned. Both the unsigned application/json document and the
// payload of a signed application/jwt one pass through here.
func requireMatchingCredentialIssuer(declared, identifier string) error {
	if declared != identifier {
		return fmt.Errorf(
			"issuer metadata credential_issuer %q does not match the requested Credential Issuer Identifier %q: %w",
			declared, identifier, ErrIssuerIdentifierMismatch)
	}
	return nil
}

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
// ctx bounds the request.
func (o *Oid4vciReceiver) doRequest(ctx context.Context, method string, endpoint common.URIField, path string, body io.Reader, target interface{}) error {
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

	return o.doRequestURL(ctx, method, endpointURL, body, target)
}

func (o *Oid4vciReceiver) doRequestURL(ctx context.Context, method string, endpointURL url.URL, body io.Reader, target interface{}) error {
	if method != http.MethodGet && method != http.MethodPost {
		return fmt.Errorf("unsupported HTTP method: %s", method)
	}
	if method == "POST" && body == nil {
		return fmt.Errorf("POST request requires a body")
	}
	req, err := http.NewRequestWithContext(ctx, method, endpointURL.String(), body)
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

// FetchIssuerMetadata fetches the Section 12.2 Credential Issuer Metadata. It
// is a legacy Draft 13 types.Receiver method and therefore carries no context;
// it binds its requests to context.Background().
func (o *Oid4vciReceiver) FetchIssuerMetadata(endpoint common.URIField, receivingTypes types.SupportedReceivingTypes) (*types.CredentialIssuerMetadata, error) {
	ctx := context.Background()
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
	err = o.fetchFinalIssuerMetadata(ctx, endpoint, identifier, signing, normalized, &finalMetadata)
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
	if err := o.fetchIssuerMetadataDocument(ctx, legacyURL, identifier, signing, normalized, &metadata); err != nil {
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

func (o *Oid4vciReceiver) fetchFinalIssuerMetadata(ctx context.Context, endpoint common.URIField, identifier string, signing IssuerMetadataSigningOptions, normalized profile.Profile, target *types.CredentialIssuerMetadata) error {
	endpointURL := url.URL(endpoint)
	originalPath := endpointURL.Path
	if originalPath == "/" {
		originalPath = ""
	}
	if !strings.HasPrefix(originalPath, wellKnownCredentialIssuer) {
		endpointURL.Path = wellKnownCredentialIssuer + originalPath
	}
	return o.fetchIssuerMetadataDocument(ctx, endpointURL, identifier, signing, normalized, target)
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
func (o *Oid4vciReceiver) fetchIssuerMetadataDocument(ctx context.Context, requestURL url.URL, identifier string, signing IssuerMetadataSigningOptions, normalized profile.Profile, target *types.CredentialIssuerMetadata) error {
	if !o.AllowHTTP && !strings.EqualFold(requestURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", requestURL.Scheme)
	}
	trustConfigured := len(signing.TrustAnchors) > 0 || signing.RootCAs != nil
	if signing.Require && !trustConfigured {
		return fmt.Errorf("signed issuer metadata is required but no trust anchors are configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
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
		return o.decodeSignedIssuerMetadata(ctx, strings.TrimSpace(string(bodyBytes)), identifier, signing, normalized, target)
	}
	if signing.Require {
		return fmt.Errorf("issuer metadata is not signed but signed metadata is required")
	}
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	if err := requireMatchingCredentialIssuer(target.CredentialIssuer, identifier); err != nil {
		return err
	}
	return nil
}

// decodeSignedIssuerMetadata verifies a signed metadata JWT and takes its
// payload as the metadata. Section 12.2.3 requires that "All metadata parameters
// used by the Credential Issuer MUST be added as top-level claims in the JWS
// payload", so the verified payload is the complete document and nothing is
// merged from an unsigned one.
func (o *Oid4vciReceiver) decodeSignedIssuerMetadata(ctx context.Context, compact string, identifier string, signing IssuerMetadataSigningOptions, normalized profile.Profile, target *types.CredentialIssuerMetadata) error {
	verification, payload, err := o.verifySignedIssuerMetadata(ctx, compact, identifier, signing, normalized)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return fmt.Errorf("failed to parse signed issuer metadata payload: %w", err)
	}
	// Section 12.2.4 binds the credential_issuer member of the payload to the
	// requested identifier just as Section 12.2.3 binds the sub claim, so a
	// signed document is rejected on either mismatch.
	if err := requireMatchingCredentialIssuer(target.CredentialIssuer, identifier); err != nil {
		return err
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
func (o *Oid4vciReceiver) verifySignedIssuerMetadata(ctx context.Context, compact string, identifier string, signing IssuerMetadataSigningOptions, normalized profile.Profile) (*types.MetadataVerification, []byte, error) {
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
	result, err := commonX509.VerifySigningChainWithPolicy(ctx, chain, commonX509.SigningChainPolicy{
		TrustAnchors:                signing.TrustAnchors,
		Roots:                       signing.RootCAs,
		KeyUsages:                   signing.KeyUsages,
		CRL:                         signing.CRL,
		AllowUnadvertisedRevocation: signing.AllowUnadvertisedRevocation,
		CurrentTime:                 now,
		HTTPClient:                  o.httpClient(),
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
	//
	// The comparison is exact. Section 12.2.4 states the rule for the identity
	// of a Credential Issuer: "The value MUST be identical to the Credential
	// Issuer's identifier value into which the well-known URI string was
	// inserted to create the URL used to retrieve the metadata. If these values
	// are not identical (when compared using a simple string comparison with no
	// normalization), the data contained in the response MUST NOT be used." A
	// wallet that trimmed a trailing slash first would be normalizing, and would
	// accept a document signed for a different identifier than the one it asked.
	if claims.Sub != identifier {
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

// FetchAuthorizationServerMetadata fetches the RFC 8414 authorization server
// metadata. It is a legacy Draft 13 types.Receiver method and therefore carries
// no context; it binds its request to context.Background().
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
	if err := o.doRequest(context.Background(), "GET", endpoint, wellKnownAuthorizationServer, nil, &metadata); err != nil {
		return nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}

	return &metadata, nil
}

// FetchAccessToken performs the pre-authorized code token request. It is a
// legacy Draft 13 types.Receiver method and therefore carries no context; it
// binds its request to context.Background().
func (o *Oid4vciReceiver) FetchAccessToken(
	receivingTypes types.SupportedReceivingTypes,
	endpoint common.URIField,
	authzCode string,
	txCode string,
	opts ...types.TokenRequestOption,
) (*types.CredentialIssuanceAccessToken, error) {
	ctx := context.Background()
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

	req, err := http.NewRequestWithContext(
		ctx,
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
	o.rememberDPoPNonce(*endpointURL, resp.Header.Get("DPoP-Nonce"))
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

// FetchNonce fetches a c_nonce from the Section 7 Nonce Endpoint. It is a
// legacy Draft 13 types.Receiver method and therefore carries no context; it
// binds its request to context.Background().
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

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, nonceEndpointURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}
	defer resp.Body.Close()
	// Section 7.2 Nonce Response: "The Credential Issuer MAY provide a DPoP
	// nonce in an HTTP header as defined in Section 8.2 of [@!RFC9449]. In this
	// case, the Wallet uses the new nonce value in the DPoP proof when
	// presenting an access token at the Credential Endpoint."
	o.rememberDPoPNonce(nonceEndpointURL, resp.Header.Get("DPoP-Nonce"))

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

// PushAuthorizationRequest sends the RFC 9126 Pushed Authorization Request of
// OpenID4VCI 1.0 Section 5.1. ctx bounds the request.
func (o *Oid4vciReceiver) PushAuthorizationRequest(ctx context.Context, endpoint common.URIField, request types.PushedAuthorizationRequest, headers types.OAuthClientAttestationHeaders) (*types.PushedAuthorizationResponse, error) {
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
	if err := o.doFinalRequest(ctx, http.MethodPost, endpoint, strings.NewReader(formData.Encode()), "application/x-www-form-urlencoded", headersToMap(headers), &response); err != nil {
		return nil, fmt.Errorf("failed to push authorization request: %w", err)
	}
	return &response, nil
}

// ExchangeAuthorizationCode performs a single Section 6.1 token request with a
// pre-built DPoP proof. It is not part of types.OID4VCIFinalTransport and
// carries no context; it binds its request to context.Background(). Use
// ExchangeAuthorizationCodeWithDpopAndAttestationRetry, which owns the RFC 9449
// Section 8 nonce retry and takes a context.
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
	if err := o.doFinalRequest(context.Background(), http.MethodPost, endpoint, strings.NewReader(formData.Encode()), "application/x-www-form-urlencoded", requestHeaders, &response); err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}
	if err := requireDPoPTokenType(normalized, response.TokenType); err != nil {
		return nil, err
	}
	return &response, nil
}

// ExchangeAuthorizationCodeWithDpopRetry exchanges the authorization code with
// fixed Client Attestation headers. It is not part of
// types.OID4VCIFinalTransport and carries no context; it binds its requests to
// context.Background().
func (o *Oid4vciReceiver) ExchangeAuthorizationCodeWithDpopRetry(endpoint common.URIField, request types.AuthorizationCodeTokenRequest, headers types.OAuthClientAttestationHeaders, proofFactory DPoPProofFactory) (*types.CredentialIssuanceAccessToken, error) {
	return o.ExchangeAuthorizationCodeWithDpopAndAttestationRetry(context.Background(), endpoint, request, func() (types.OAuthClientAttestationHeaders, error) {
		return headers, nil
	}, proofFactory)
}

// ExchangeAuthorizationCodeWithDpopAndAttestationRetry exchanges the
// authorization code at the Section 6.1 Token Endpoint and owns the RFC 9449
// Section 8 DPoP nonce retry: both factories are called once per attempt, so a
// re-sent request carries a freshly signed proof and freshly built attestation
// headers rather than a replayed jti. ctx bounds every attempt.
func (o *Oid4vciReceiver) ExchangeAuthorizationCodeWithDpopAndAttestationRetry(ctx context.Context, endpoint common.URIField, request types.AuthorizationCodeTokenRequest, headersFactory OAuthClientAttestationHeadersFactory, proofFactory DPoPProofFactory) (*types.CredentialIssuanceAccessToken, error) {
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
	if err := o.doFormRequestWithDpopAndAttestationRetry(ctx, endpoint, buildBody, headersFactory, proofFactory, &response); err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code with DPoP retry: %w", err)
	}
	if err := requireDPoPTokenType(normalized, response.TokenType); err != nil {
		return nil, err
	}
	return &response, nil
}

// FetchClientAttestationChallenge fetches a challenge from the authorization
// server's challenge endpoint. ctx bounds the request.
func (o *Oid4vciReceiver) FetchClientAttestationChallenge(ctx context.Context, endpoint common.URIField) (*types.ClientAttestationChallengeResponse, error) {
	var response types.ClientAttestationChallengeResponse
	if err := o.doFinalRequest(ctx, http.MethodPost, endpoint, nil, "", nil, &response); err != nil {
		return nil, fmt.Errorf("failed to fetch client attestation challenge: %w", err)
	}
	return &response, nil
}

// FetchNonceResponse performs the Section 7.1 Nonce Request and returns the
// Section 7.2 Nonce Response. Besides the c_nonce body member it surfaces the
// RFC 9449 Section 8.2 DPoP-Nonce response header, which Section 7.2 makes
// binding on the next credential request: "The Credential Issuer MAY provide a
// DPoP nonce in an HTTP header as defined in Section 8.2 of [@!RFC9449]. In this
// case, the Wallet uses the new nonce value in the DPoP proof when presenting an
// access token at the Credential Endpoint." The value is also recorded in this
// receiver's per-server nonce store, so the next DPoP proof this plugin builds
// for that server already carries it. ctx bounds the request.
func (o *Oid4vciReceiver) FetchNonceResponse(ctx context.Context, endpoint common.URIField) (*types.NonceResponse, error) {
	var response types.NonceResponse
	responseHeader, err := o.doFinalRequestWithResponseHeader(ctx, http.MethodPost, endpoint, nil, "", nil, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}
	// OpenID4VCI 1.0 §7.2: "c_nonce: REQUIRED. String containing a challenge to
	// be used when creating a proof of possession of the key." A 2xx Nonce
	// Response that omits it, or returns it empty, hands the wallet no nonce to
	// put in the proof, so it fails closed instead of proceeding without one.
	if strings.TrimSpace(response.CNonce) == "" {
		return nil, fmt.Errorf("nonce response does not contain a c_nonce: %w", types.ErrNonceResponseInvalid)
	}
	response.DPoPNonce = strings.TrimSpace(responseHeader.Get("DPoP-Nonce"))
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

// RequestCredential posts a single Section 8 Credential Request with a
// pre-built DPoP proof. It is not part of types.OID4VCIFinalTransport and
// carries no context; it binds its request to context.Background().
func (o *Oid4vciReceiver) RequestCredential(endpoint common.URIField, accessToken string, credentialRequest types.CredentialRequest, dpopProof string) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequest(context.Background(), endpoint, dpopBoundToken(accessToken), credentialRequest, dpopProof, &response); err != nil {
		return nil, fmt.Errorf("failed to request credential: %w", err)
	}
	return &response, nil
}

// RequestCredentialWithDpopRetry posts a Section 8 Credential Request with the
// RFC 9449 Section 8 nonce retry. It is not part of
// types.OID4VCIFinalTransport and carries no context; it binds its requests to
// context.Background().
func (o *Oid4vciReceiver) RequestCredentialWithDpopRetry(endpoint common.URIField, accessToken string, credentialRequest types.CredentialRequest, proofFactory DPoPProofFactory) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequestWithDpopRetry(context.Background(), endpoint, dpopBoundToken(accessToken), credentialRequest, proofFactory, &response); err != nil {
		return nil, fmt.Errorf("failed to request credential with DPoP retry: %w", err)
	}
	return &response, nil
}

// PostCredentialEndpointWithDpopRetry posts a pre-encoded Credential Request
// body with the RFC 9449 Section 8 nonce retry. It is not part of
// types.OID4VCIFinalTransport and carries no context; it binds its requests to
// context.Background().
func (o *Oid4vciReceiver) PostCredentialEndpointWithDpopRetry(endpoint common.URIField, accessToken string, body []byte, contentType string, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, error) {
	return o.postCredentialEndpointForToken(context.Background(), endpoint, dpopBoundToken(accessToken), body, contentType, proofFactory)
}

func (o *Oid4vciReceiver) postCredentialEndpointForToken(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, body []byte, contentType string, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, error) {
	responseBody, responseContentType, err := o.doBearerRequestWithDpopRetry(ctx, endpoint, accessToken, body, contentType, proofFactory)
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
// keep the DPoP scheme this plugin has always sent. ctx bounds every attempt,
// the Nonce Endpoint refresh included.
func (o *Oid4vciReceiver) PostCredentialEndpointWithNonceRetryForToken(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, nonceEndpoint *common.URIField, initialCNonce string, build CredentialRequestBodyFactory, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, string, error) {
	return o.postCredentialEndpointWithNonceRetry(ctx, endpoint, accessToken, nonceEndpoint, initialCNonce, build, proofFactory)
}

// SendCredentialNotificationWithDpopRetryForToken is
// SendCredentialNotificationWithDpopRetry taking the parsed token response, for
// the same reason as PostCredentialEndpointWithNonceRetryForToken.
// ctx bounds every attempt.
func (o *Oid4vciReceiver) SendCredentialNotificationWithDpopRetryForToken(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, notification types.NotificationRequest, proofFactory DPoPProofFactory) error {
	return o.doBearerJSONRequestWithDpopRetry(ctx, endpoint, accessToken, notification, proofFactory, nil)
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
// It is not part of types.OID4VCIFinalTransport and carries no context; it
// binds its requests to context.Background().
func (o *Oid4vciReceiver) PostCredentialEndpointWithNonceRetry(endpoint common.URIField, accessToken string, nonceEndpoint *common.URIField, initialCNonce string, build CredentialRequestBodyFactory, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, string, error) {
	return o.postCredentialEndpointWithNonceRetry(context.Background(), endpoint, dpopBoundToken(accessToken), nonceEndpoint, initialCNonce, build, proofFactory)
}

func (o *Oid4vciReceiver) postCredentialEndpointWithNonceRetry(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, nonceEndpoint *common.URIField, initialCNonce string, build CredentialRequestBodyFactory, proofFactory DPoPProofFactory) (*CredentialEndpointHTTPResponse, string, error) {
	if build == nil {
		return nil, initialCNonce, fmt.Errorf("credential request body factory is required")
	}

	body, contentType, err := build(initialCNonce)
	if err != nil {
		return nil, initialCNonce, err
	}

	response, err := o.postCredentialEndpointForToken(ctx, endpoint, accessToken, body, contentType, proofFactory)
	if err == nil {
		return response, initialCNonce, nil
	}
	if !errors.Is(err, types.ErrInvalidNonce) || nonceEndpoint == nil {
		return nil, initialCNonce, err
	}

	nonceResponse, err := o.FetchNonceResponse(ctx, *nonceEndpoint)
	if err != nil {
		return nil, initialCNonce, fmt.Errorf("failed to refresh c_nonce after invalid_nonce: %w", err)
	}
	freshCNonce := nonceResponse.CNonce

	body, contentType, err = build(freshCNonce)
	if err != nil {
		return nil, freshCNonce, err
	}

	response, err = o.postCredentialEndpointForToken(ctx, endpoint, accessToken, body, contentType, proofFactory)
	if err != nil {
		return nil, freshCNonce, err
	}
	return response, freshCNonce, nil
}

// RequestDeferredCredential posts a single Section 9 Deferred Credential
// Request with a pre-built DPoP proof. It is not part of
// types.OID4VCIFinalTransport and carries no context; it binds its request to
// context.Background().
func (o *Oid4vciReceiver) RequestDeferredCredential(endpoint common.URIField, accessToken string, deferredRequest types.DeferredCredentialRequest, dpopProof string) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequest(context.Background(), endpoint, dpopBoundToken(accessToken), deferredRequest, dpopProof, &response); err != nil {
		return nil, fmt.Errorf("failed to request deferred credential: %w", err)
	}
	return &response, nil
}

// RequestDeferredCredentialWithDpopRetry posts a Section 9 Deferred Credential
// Request with the RFC 9449 Section 8 nonce retry. It is not part of
// types.OID4VCIFinalTransport and carries no context; it binds its requests to
// context.Background().
func (o *Oid4vciReceiver) RequestDeferredCredentialWithDpopRetry(endpoint common.URIField, accessToken string, deferredRequest types.DeferredCredentialRequest, proofFactory DPoPProofFactory) (*types.CredentialResponse, error) {
	var response types.CredentialResponse
	if err := o.doBearerJSONRequestWithDpopRetry(context.Background(), endpoint, dpopBoundToken(accessToken), deferredRequest, proofFactory, &response); err != nil {
		return nil, fmt.Errorf("failed to request deferred credential with DPoP retry: %w", err)
	}
	return &response, nil
}

// SendCredentialNotification sends a single Section 11 notification with a
// pre-built DPoP proof. It is not part of types.OID4VCIFinalTransport and
// carries no context; it binds its request to context.Background().
func (o *Oid4vciReceiver) SendCredentialNotification(endpoint common.URIField, accessToken string, notification types.NotificationRequest, dpopProof string) error {
	return o.doBearerJSONRequest(context.Background(), endpoint, dpopBoundToken(accessToken), notification, dpopProof, nil)
}

// SendCredentialNotificationWithDpopRetry sends a Section 11 notification with
// the RFC 9449 Section 8 nonce retry. It is not part of
// types.OID4VCIFinalTransport and carries no context; it binds its requests to
// context.Background().
func (o *Oid4vciReceiver) SendCredentialNotificationWithDpopRetry(endpoint common.URIField, accessToken string, notification types.NotificationRequest, proofFactory DPoPProofFactory) error {
	return o.doBearerJSONRequestWithDpopRetry(context.Background(), endpoint, dpopBoundToken(accessToken), notification, proofFactory, nil)
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
	// Section 10 (Encrypted Credential Requests and Responses): "The `alg`
	// parameter MUST be present. The JWE `alg` algorithm used MUST be equal to
	// the `alg` value of the chosen JWK." The JWE alg therefore comes from the
	// key, never from the metadata: Section 12.2.4 defines no
	// alg_values_supported member on credential_request_encryption.
	alg, err := credentialRequestEncryptionAlgorithm(encryptionKey)
	if err != nil {
		return nil, "", err
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

// ProofOptions carries the inputs of an OpenID4VCI 1.0 Section 8.2.1.1 jwt key
// proof. It is an alias of types.ProofOptions, which the OID4VCIFinalSigner
// interface names, so a plugin outside this repository can build the same proof
// without importing this package.
type ProofOptions = types.ProofOptions

// SelectProofSigningAlgorithm returns the algorithm to sign a jwt key proof
// with, honouring the Credential Configuration's
// proof_signing_alg_values_supported.
//
// Deprecated: use oid4vcisign.SelectProofSigningAlgorithm, which this function
// calls.
func SelectProofSigningAlgorithm(key jose.JSONWebKey, supported []jose.SignatureAlgorithm) (jose.SignatureAlgorithm, error) {
	return oid4vcisign.SelectProofSigningAlgorithm(key, supported)
}

func (o *Oid4vciReceiver) doBearerJSONRequest(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, payload any, dpopProof string, target any) error {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	scheme := authorizationScheme(accessToken.TokenType)
	headers := map[string]string{"Authorization": scheme + " " + accessToken.Token}
	if scheme == dpopAuthorizationScheme {
		headers["DPoP"] = dpopProof
	}

	return o.doFinalRequest(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes), "application/json", headers, target)
}

func (o *Oid4vciReceiver) doBearerJSONRequestWithDpopRetry(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, payload any, proofFactory DPoPProofFactory, target any) error {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	respBody, _, err := o.doBearerRequestWithDpopRetry(ctx, endpoint, accessToken, bodyBytes, "application/json", proofFactory)
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

// doBearerRequestWithDpopRetry posts bodyBytes to a protected endpoint and owns
// the RFC 9449 Section 8 DPoP nonce retry. The first proof is built for the
// nonce this receiver already holds for that server, so a server that has
// already issued one is not made to reject a proof it cannot accept; the
// challenge retry remains the fallback for the first contact and for a rotated
// nonce. ctx bounds every attempt.
func (o *Oid4vciReceiver) doBearerRequestWithDpopRetry(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, bodyBytes []byte, contentType string, proofFactory DPoPProofFactory) ([]byte, string, error) {
	if proofFactory == nil {
		return nil, "", fmt.Errorf("DPoP proof factory is required")
	}
	scheme := authorizationScheme(accessToken.TokenType)

	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, "", fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	dpopNonce := o.dpopNonceFor(endpointURL)
	var lastStatus int
	var lastContentType string
	var lastBody []byte
	var lastNonce string
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL.String(), bytes.NewReader(bodyBytes))
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
		o.rememberDPoPNonce(endpointURL, resp.Header.Get("DPoP-Nonce"))
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return respBody, resp.Header.Get("Content-Type"), nil
		}
		responseContentType := resp.Header.Get("Content-Type")
		nonce := resp.Header.Get("DPoP-Nonce")
		// OpenID4VCI 1.0 §8.3.1.2: an "invalid_nonce" error means the proof
		// carried a stale c_nonce, and the wallet has to refresh it from the
		// Nonce Endpoint. It takes priority over the RFC 9449 §8 DPoP challenge
		// below: an issuer may set a DPoP-Nonce header on the same response, and
		// treating that as the challenge would spend the one retry on a DPoP
		// proof instead of the c_nonce the error actually named.
		if isCredentialNonceError(responseContentType, respBody) {
			return nil, "", newCredentialEndpointError(resp.StatusCode, responseContentType, respBody, nonce)
		}
		// A response may also demand a DPoP proof the wallet cannot build when
		// the access token is not DPoP-bound. Failing closed here reports the
		// real reason instead of repeating a request that carried no proof.
		if scheme != dpopAuthorizationScheme && dpopChallengeRequested(nonce, resp.Header.Get("WWW-Authenticate")) {
			return nil, "", ErrDPoPRequired
		}
		if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized) && nonce != "" {
			dpopNonce = nonce
			lastStatus, lastContentType, lastBody, lastNonce = resp.StatusCode, responseContentType, respBody, nonce
			continue
		}
		return nil, "", newCredentialEndpointError(resp.StatusCode, responseContentType, respBody, nonce)
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

func (o *Oid4vciReceiver) doFormRequestWithDpopAndAttestationRetry(ctx context.Context, endpoint common.URIField, bodyFactory func() ([]byte, error), headersFactory OAuthClientAttestationHeadersFactory, proofFactory DPoPProofFactory, target any) error {
	if headersFactory == nil {
		return fmt.Errorf("OAuth client attestation headers factory is required")
	}
	return o.doFormRequestWithDpopAndHeadersRetry(ctx, endpoint, bodyFactory, func() (map[string]string, error) {
		headers, err := headersFactory()
		if err != nil {
			return nil, err
		}
		return headersToMap(headers), nil
	}, proofFactory, target)
}

// doFormRequestWithDpopAndHeadersRetry posts a form-encoded body and owns the
// RFC 9449 Section 8 DPoP nonce retry, rebuilding the proof, the headers and the
// body on every attempt so no jti is replayed. Like the bearer path, the first
// proof is seeded with the nonce this receiver already holds for that server.
// ctx bounds every attempt.
func (o *Oid4vciReceiver) doFormRequestWithDpopAndHeadersRetry(ctx context.Context, endpoint common.URIField, bodyFactory func() ([]byte, error), headersFactory func() (map[string]string, error), proofFactory DPoPProofFactory, target any) error {
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

	dpopNonce := o.dpopNonceFor(endpointURL)
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
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL.String(), bytes.NewReader(bodyBytes))
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
		o.rememberDPoPNonce(endpointURL, resp.Header.Get("DPoP-Nonce"))
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

// doFinalRequest performs one OpenID4VCI 1.0 Final request and decodes a JSON
// body into target, discarding the response headers. ctx bounds the request.
func (o *Oid4vciReceiver) doFinalRequest(ctx context.Context, method string, endpoint common.URIField, body io.Reader, contentType string, headers map[string]string, target any) error {
	_, err := o.doFinalRequestWithResponseHeader(ctx, method, endpoint, body, contentType, headers, target)
	return err
}

// doFinalRequestWithResponseHeader is doFinalRequest, returning the response
// header as well. Some OpenID4VCI responses carry protocol state outside the
// body: the Section 7.2 Nonce Response may carry an RFC 9449 Section 8.2
// DPoP-Nonce the wallet has to use on the next request. The header is returned
// non-nil whenever a response was received, so a caller may read it without a
// nil check; on a transport error it is nil and the error is returned.
func (o *Oid4vciReceiver) doFinalRequestWithResponseHeader(ctx context.Context, method string, endpoint common.URIField, body io.Reader, contentType string, headers map[string]string, target any) (http.Header, error) {
	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpointURL.String(), body)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	defer resp.Body.Close()
	o.rememberDPoPNonce(endpointURL, resp.Header.Get("DPoP-Nonce"))

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.Header, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.Header, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}
	if target == nil || len(bodyBytes) == 0 {
		return resp.Header, nil
	}
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return resp.Header, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return resp.Header, nil
}

// selectEncryptionKey picks the Credential Request encryption key out of the
// Section 12.2.4 jwks. Section 10 leaves the choice to the Wallet: "In the case
// where multiple public keys are available, any may be selected based on the
// information about each key, such as the `kty` (Key Type), `use` (Public Key
// Use), `alg` (Algorithm), and other JWK parameters."
//
// A key published with use "sig" is never selected: RFC 7517 Section 4.2 makes
// "use" the key's intended use, and encrypting to a signature key is both
// outside that use and, for a key this wallet could otherwise encrypt to,
// harmful. Among the remaining keys the first one whose algorithm this wallet
// can actually perform wins, so that a JWKS mixing an unsupported key with a
// usable one still yields an encrypted request; only if none is usable does the
// first eligible key stand, so the caller reports the real algorithm error.
func selectEncryptionKey(jwks *jose.JSONWebKeySet) (*jose.JSONWebKey, error) {
	if jwks == nil || len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("encryption JWKS does not contain a key")
	}
	var firstEligible *jose.JSONWebKey
	for i := range jwks.Keys {
		key := &jwks.Keys[i]
		if key.Use == "sig" {
			continue
		}
		if firstEligible == nil {
			firstEligible = key
		}
		alg, err := credentialRequestEncryptionAlgorithm(key)
		if err != nil {
			continue
		}
		if _, err := parseJWEKeyAlgorithm(alg); err == nil {
			return key, nil
		}
	}
	if firstEligible != nil {
		return firstEligible, nil
	}
	return nil, fmt.Errorf("encryption JWKS contains no key usable for encryption")
}

// credentialRequestEncryptionAlgorithm resolves the JWE "alg" to encrypt a
// Credential Request with. Section 10 requires it to come from the chosen key:
// "The `alg` parameter MUST be present. The JWE `alg` algorithm used MUST be
// equal to the `alg` value of the chosen JWK."
//
// A Credential Issuer that publishes a key without "alg" is not conformant with
// that requirement, so rather than guess one algorithm for every key type the
// wallet derives the only key agreement or key encryption algorithm the key
// type admits: EC and OKP keys are used with ECDH-ES (RFC 7518 Section 4.6) and
// RSA keys with RSA-OAEP-256 (RFC 7518 Section 4.3). Any other key type - a
// symmetric "oct" key above all, which no Credential Issuer can publish as a
// public encryption key - is an error rather than a silent fallback.
func credentialRequestEncryptionAlgorithm(key *jose.JSONWebKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("credential request encryption key is missing")
	}
	if alg := strings.TrimSpace(key.Algorithm); alg != "" {
		return alg, nil
	}
	switch key.Key.(type) {
	case *ecdsa.PublicKey, *ecdsa.PrivateKey:
		return "ECDH-ES", nil
	case ed25519.PublicKey, ed25519.PrivateKey:
		return "ECDH-ES", nil
	case *rsa.PublicKey, *rsa.PrivateKey:
		return "RSA-OAEP-256", nil
	default:
		return "", fmt.Errorf(
			"credential request encryption key %q omits the required alg parameter and its key type %T admits no default",
			key.KeyID, key.Key)
	}
}

func firstOrDefault(values []string, fallback string) string {
	if len(values) > 0 && values[0] != "" {
		return values[0]
	}
	return fallback
}

// parseJWEKeyAlgorithm maps a JWE "alg" identifier to the go-jose key algorithm
// this wallet will encrypt a Credential Request with. The list is an allowlist:
// RSA1_5 is deliberately absent because RFC 8017 Section 7.2 RSAES-PKCS1-v1_5
// is the Bleichenbacher-attackable scheme this library must never be talked
// into using, and so are the RSA-OAEP variants go-jose v4 does not implement
// (only RSA-OAEP-256 is available; there is no RSA-OAEP-384 or RSA-OAEP-512),
// as well as RSA-OAEP itself, whose SHA-1 mask generation function is obsolete.
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
	case "RSA-OAEP-256":
		return jose.RSA_OAEP_256, nil
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

// supportedJWEKeyAlgorithms lists the JWE key management algorithms accepted
// when decrypting an encrypted Credential Response (Section 8.2 / Section 10).
// The wallet may publish either an EC or an RSA response-encryption key, so
// both RFC 7518 Section 4.6 ECDH-ES and Section 4.3 RSA-OAEP-256 are accepted;
// omitting RSA-OAEP-256 would leave an RSA key the wallet itself advertised
// undecryptable. RSA1_5 is deliberately absent: RFC 8017 Section 7.2
// RSAES-PKCS1-v1_5 is the Bleichenbacher-attackable scheme this library must
// never be talked into using. go-jose v4 implements only RSA-OAEP-256 among the
// OAEP variants.
func supportedJWEKeyAlgorithms() []jose.KeyAlgorithm {
	return []jose.KeyAlgorithm{jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW, jose.RSA_OAEP_256}
}

func supportedJWEContentEncryptions() []jose.ContentEncryption {
	return []jose.ContentEncryption{jose.A128GCM, jose.A192GCM, jose.A256GCM, jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512}
}

// ReceiveCredential performs a Draft 13 credential request. It is a legacy
// types.Receiver method and therefore carries no context; it binds its request
// to context.Background().
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
	req, err := http.NewRequestWithContext(context.Background(), "POST", endpointURL.String(), bytes.NewReader(reqBodyBytes))
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
	o.rememberDPoPNonce(endpointURL, resp.Header.Get("DPoP-Nonce"))

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

// isCredentialNonceError reports whether a non-2xx Credential Endpoint response
// is the OpenID4VCI 1.0 §8.3.1.2 "invalid_nonce" Credential Error Response. The
// error is read from the body, so a response that also carries a DPoP-Nonce
// header is still recognised as the c_nonce failure it names. A body that is not
// JSON cannot be a §8.3.1.2 error object.
func isCredentialNonceError(contentType string, body []byte) bool {
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return false
	}
	return tokenErrorCode(body) == types.ErrInvalidNonce.Error()
}

// dpopChallengeRequested reports whether a response asks the client for a DPoP
// proof: RFC 9449 §8 provides a DPoP-Nonce response header, and §7.1 names the
// DPoP scheme in a WWW-Authenticate challenge. Either signal means the request
// has to carry a proof bound to a key the client holds.
func dpopChallengeRequested(dpopNonce, wwwAuthenticate string) bool {
	if strings.TrimSpace(dpopNonce) != "" {
		return true
	}
	scheme, _, _ := strings.Cut(strings.TrimSpace(wwwAuthenticate), " ")
	scheme, _, _ = strings.Cut(scheme, ",")
	return strings.EqualFold(scheme, dpopAuthorizationScheme)
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
