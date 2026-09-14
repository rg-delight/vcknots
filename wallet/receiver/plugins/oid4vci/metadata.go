package oid4vci

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

const (
	wellKnownCredentialIssuer    = "/.well-known/openid-credential-issuer"
	wellKnownAuthorizationServer = "/.well-known/oauth-authorization-server"
)

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
	var statusError *httpStatusError
	if !o.AllowHTTP || !strings.EqualFold(endpointURL.Scheme, "http") ||
		strings.Trim(endpointURL.Path, "/") == "" ||
		strings.Contains(endpointURL.Path, "/.well-known/openid-credential-issuer") ||
		!errors.As(err, &statusError) || !statusError.isNotFound() {
		return nil, stageError(StageIssuerMetadata, fmt.Errorf("failed to fetch issuer metadata: %w", err))
	}
	var metadata types.CredentialIssuerMetadata
	legacyURL := endpointURL
	if !strings.HasSuffix(legacyURL.Path, wellKnownCredentialIssuer) {
		legacyURL = *legacyURL.JoinPath(wellKnownCredentialIssuer)
	}
	if err := o.fetchIssuerMetadataDocument(ctx, legacyURL, identifier, signing, normalized, &metadata); err != nil {
		return nil, stageError(StageIssuerMetadata, fmt.Errorf("failed to fetch issuer metadata: %w", err))
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
// are dropped because Section 12.2.1 forbids them in an identifier. Nothing
// else is normalised: Section 12.2.4 compares the metadata's credential_issuer
// with this value "using a simple string comparison with no normalization", so
// a trailing slash the issuer chose is part of its identity and is kept.
func credentialIssuerIdentifier(endpointURL url.URL) string {
	identifier := endpointURL
	identifier.RawQuery = ""
	identifier.Fragment = ""
	identifier.ForceQuery = false
	if rest, found := strings.CutPrefix(identifier.Path, wellKnownCredentialIssuer); found {
		identifier.Path = rest
	}
	return identifier.String()
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
		return &httpStatusError{statusCode: resp.StatusCode, body: string(bodyBytes)}
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
		return nil, stageError(StageAuthorizationServerMetadata, fmt.Errorf("failed to fetch authorization server metadata: %w", err))
	}

	return &metadata, nil
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
