package oid4vp

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/common/observe"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/profile"
)

type requestBuilder struct {
	req                     *CredentialPresentationRequest
	httpClient              *http.Client
	allowHTTP               bool
	draft24                 bool
	profile                 profile.Profile
	x509TrustChainRoots     *x509.CertPool
	insecureSkipX509Verify  bool
	requestObjectValidation *RequestObjectValidationOptions
	expectedClientID        string
	// expectedClientIDAbsent records that this parse has no Authorization
	// Request client_id parameter to cross-check the Request Object against,
	// because the caller supplied the Request Object by value and named none.
	// The client_id claim is still authenticated against the certificate that
	// signed the Request Object; only the equality with an outer parameter that
	// does not exist is skipped.
	expectedClientIDAbsent bool
	walletMetadata         map[string]any
	requestURINonce        func() (string, error)
	// supportedTransactionDataTypes is copied from the presenter for the Final
	// transaction_data validation.
	supportedTransactionDataTypes []string
	// preRegisteredClients and resolvePreRegisteredClient are copied from the
	// presenter so a pre-registered Client Identifier can be resolved during
	// parameter validation (OID4VP 1.0 §5.9.2).
	preRegisteredClients       map[string]PreRegisteredClient
	resolvePreRegisteredClient PreRegisteredClientResolver
	// preRegisteredClient is the registry entry that authenticated the Client
	// Identifier of this request, when its prefix is the pre-registered one. It
	// is nil for every other Client Identifier Prefix.
	preRegisteredClient *PreRegisteredClient
	// sentWalletNonce records the wallet_nonce sent with a Final request_uri
	// POST so the returned Request Object can be required to echo it
	// (OID4VP 1.0 §5.10.1). It is empty for GET and when no nonce was sent.
	sentWalletNonce string
	errValidation   error
	// requestSource records how the Authorization Request parameters arrived:
	// "query" for plain query parameters, "value" for a Request Object supplied
	// with the request= parameter, and "reference" for a Request Object fetched
	// through request_uri. HAIP §5.1 requires reference.
	requestSource string
	// errorResponseAllowed marks that the request parameters came from plain
	// query parameters (user-initiated URI). Validation failures on the
	// Request Object paths occur before the object's signature is verified,
	// so their response_uri is unauthenticated and must not receive an error
	// authorization response (unauthenticated outbound POST / SSRF primitive).
	errorResponseAllowed bool
}

// NewRequestBuilder creates a builder for OpenID4VP 1.0 Final Authorization
// Requests. It initializes profile.Final explicitly, so a builder obtained here
// never applies HAIP rules by accident: the zero Profile value would leave every
// HAIP checkpoint inert without saying so.
//
// Deprecated: use NewRequestBuilderForProfile, which makes the enforced
// protocol policy part of the call.
func NewRequestBuilder() *requestBuilder {
	return &requestBuilder{
		req: &CredentialPresentationRequest{
			OAuthAuthzRequest: &OAuthAuthzRequest{},
			ClientMetadata:    &VerifierMetadata{},
		},
		profile:                profile.Final,
		x509TrustChainRoots:    nil,
		insecureSkipX509Verify: false,
	}
}

// NewDraft24RequestBuilder creates a builder for Presentation Exchange requests.
// The Draft24 path ignores the protocol profile entirely.
//
// Deprecated: new integrations use NewRequestBuilderForProfile and the Final
// entrypoints.
func NewDraft24RequestBuilder() *requestBuilder {
	b := NewRequestBuilder()
	b.draft24 = true
	return b
}

// NewRequestBuilderForProfile creates a builder that enforces p. The profile is
// normalized first, so an unknown value fails here rather than silently
// disabling the HAIP checkpoints.
func NewRequestBuilderForProfile(p profile.Profile) (*requestBuilder, error) {
	normalized, err := p.Normalize()
	if err != nil {
		return nil, fmt.Errorf("invalid OID4VP profile: %w", err)
	}
	b := NewRequestBuilder()
	b.profile = normalized
	return b, nil
}

// WithProfile selects the protocol policy of an existing builder, for fluent
// call sites that cannot use NewRequestBuilderForProfile. An unknown profile is
// recorded as a validation error and surfaces from Build.
func (b *requestBuilder) WithProfile(p profile.Profile) *requestBuilder {
	normalized, err := p.Normalize()
	if err != nil {
		b.errValidation = fmt.Errorf("invalid OID4VP profile: %w", err)
		return b
	}
	b.profile = normalized
	return b
}

// lookupPreRegisteredClient resolves a pre-registered Client Identifier against
// the wallet's registry: the in-memory map first, then the caller's resolver.
// OID4VP 1.0 §5.9.2: "the Client Identifier needs to be known to the Wallet in
// advance of the Authorization Request", so an unresolved identifier is an
// error rather than an unauthenticated Verifier.
func (b *requestBuilder) lookupPreRegisteredClient(clientID string) (*PreRegisteredClient, error) {
	if registered, exists := b.preRegisteredClients[clientID]; exists {
		return preRegisteredClientWithID(&registered, clientID), nil
	}
	if b.resolvePreRegisteredClient != nil {
		resolved, err := b.resolvePreRegisteredClient(clientID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve pre-registered client_id %q: %w", clientID, err)
		}
		if resolved != nil {
			copied := *resolved
			return preRegisteredClientWithID(&copied, clientID), nil
		}
	}
	return nil, fmt.Errorf("pre-registered client_id %q is not known to this wallet: %w", clientID, ErrPreRegisteredClientUnknown)
}

// preRegisteredClientWithID fills in the registration's ClientID from the
// request when a map registration left it empty, so consumers never have to
// consult the map key.
func preRegisteredClientWithID(client *PreRegisteredClient, clientID string) *PreRegisteredClient {
	if client.ClientID == "" {
		client.ClientID = clientID
	}
	return client
}

// isDirectPostMode reports whether the Response Mode delivers the Authorization
// Response to the Verifier's Response URI (OID4VP 1.0 §8.2), which is what
// binds response_uri to the Client Identifier in §5.9.3 and makes redirect_uri
// and response_uri mutually exclusive.
func isDirectPostMode(mode OAuthAuthzReqResponseMode) bool {
	return mode == OAuthAuthzReqResponseModeDirectPost || mode == OAuthAuthzReqResponseModeDirectPostJWT
}

// WithHTTPAllowed enables HTTP response endpoints for local tests only.
func (b *requestBuilder) WithHTTPAllowed(allow bool) *requestBuilder {
	b.allowHTTP = allow
	return b
}
func (b *requestBuilder) validate() error {
	if b.errValidation != nil {
		return b.errValidation
	}

	if b.draft24 {
		// Draft24 Section 5.1 names three ways to express the Presentation
		// Definition - by value, by reference in presentation_definition_uri,
		// or through a scope the Wallet maps to one - besides DCQL. Resolving
		// a reference or a scope is the Wallet's own step after the request is
		// admitted, so their presence is what is required here.
		hasDefinition := b.req.PresentationDefinition != nil && b.req.PresentationDefinition.ID != ""
		hasDefinitionReference := b.req.PresentationDefinitionURI != "" || b.req.Scope != ""
		if !hasDefinition && !hasDefinitionReference && (b.req.DcqlQuery == nil || len(b.req.DcqlQuery.Credentials) == 0) {
			return newAuthorizationRequestError(InvalidRequestError, "presentation_definition, presentation_definition_uri, scope or dcql_query is required for Draft24")
		}
	} else if b.req.DcqlQuery == nil || len(b.req.DcqlQuery.Credentials) == 0 {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query is required")
	}

	if b.req.ResponseType == "" {
		return newAuthorizationRequestError(InvalidRequestError, "response_type is required")
	}

	if !b.draft24 && b.req.ResponseType != "vp_token" {
		// OID4VP 1.0 §5.6 defines the Response Type vp_token; §8 Table 1 leaves
		// the VP Token behavior unspecified for any other value. This wallet
		// presents vp_token only and rejects the others as invalid_request.
		return newAuthorizationRequestError(InvalidRequestError, "response_type must be vp_token, got %q", b.req.ResponseType)
	}

	if b.req.ClientID == "" {
		return newAuthorizationRequestError(InvalidRequestError, "client_id is required")
	}

	// OID4VP 1.0 Appendix A.2: dc_api and dc_api.jwt return the response through
	// the platform, so no redirect_uri is required. The response endpoint is the
	// DC API, validated where the response is built.
	if b.req.ResponseMode != OAuthAuthzReqResponseModeDirectPost &&
		b.req.ResponseMode != OAuthAuthzReqResponseModeDirectPostJWT &&
		b.req.ResponseMode != OAuthAuthzReqResponseModeDCAPI &&
		b.req.ResponseMode != OAuthAuthzReqResponseModeDCAPIJWT &&
		b.req.RedirectURI == "" {
		return newAuthorizationRequestError(InvalidRequestError, "redirect_uri is required")
	}

	if b.req.Nonce == "" {
		return newAuthorizationRequestError(InvalidRequestError, "%w", ErrNonceRequired)
	}

	if isDirectPostMode(b.req.ResponseMode) {
		if _, err := parseResponseURI(b.req.ResponseURI, b.allowHTTP); err != nil {
			return newAuthorizationRequestError(InvalidRequestError, "%v", err)
		}
	}

	return nil
}

// WithQueryParams populates the CredentialPresentationRequest fields from URL query parameters.
func (b *requestBuilder) WithQueryParams(params map[string][]string) *requestBuilder {
	if b.errValidation != nil {
		return b
	}

	b.errorResponseAllowed = true
	b.requestSource = "query"

	singleParams := make(map[string]any)
	for key, values := range params {
		if len(values) > 1 {
			b.errValidation = fmt.Errorf("multiple values provided for parameter: %s", key)
			return b
		}
		singleParams[key] = values[0]
	}

	// OID4VP 1.0 §5.9.3: an "x509_san_dns" or "x509_hash" Client Identifier is
	// authenticated by the certificate that signed the Request Object, so the
	// same identifier delivered in plain query parameters authenticates
	// nothing. The Draft24 wire contract names the same two prefixes and has no
	// other way to authenticate them either, so both parse entry points refuse
	// the unsigned form rather than returning a request a caller could consent
	// to. It is decided before any other parameter is read, so the refusal is
	// never answered to the Verifier: the response_uri of an unauthenticated
	// request must not receive an outbound POST.
	if value, isString := singleParams["client_id"].(string); isString {
		clientID, err := b.parseClientID(strings.TrimSpace(value))
		if err == nil && clientID.RequiresRequestObjectSignature() {
			b.errorResponseAllowed = false
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%w", ErrRequestObjectSignatureRequired)
			return b
		}
		// An unsigned openid_federation request names its response endpoint
		// in parameters nothing has authenticated until the Trust Chain has
		// been resolved, so no refusal of it is ever answered to that endpoint.
		if err == nil && clientID.prefix == OID4VPClientIDPrefixOIDFederation {
			b.errorResponseAllowed = false
		}
	}

	b.setParamsWithAnyMap(singleParams)

	if err := b.validate(); err != nil {
		b.errValidation = err
		return b
	}
	if err := b.authenticateUnsignedFederationRequest(singleParams); err != nil {
		b.errValidation = err
		return b
	}

	return b
}

// WithRequestObjectURI constructs the CredentialPresentationRequest
// with fetching the request object from the given URI using the specified method,
// and validates its claims and signature as per OID4VP and RFC9101.
//
// Per OID4VP draft 24 §5.11, when method is POST the request MUST use the
// https scheme, set Content-Type: application/x-www-form-urlencoded and
// Accept: application/oauth-authz-req+jwt. The https requirement is also
// applied to the GET method for project-wide consistency with the same
// guard in wallet/receiver/plugins/oid4vci/oid4vci.go (Issue #29).
// It can be relaxed by setting the VCKNOTS_WALLET_HTTP_ALLOWED environment
// variable for testing.
func (b *requestBuilder) WithRequestObjectURI(uri string, method RequestURIMethod) *requestBuilder {
	if b.errValidation != nil {
		return b
	}

	parsedURI, err := url.Parse(uri)
	if err != nil {
		b.errValidation = fmt.Errorf("failed to parse request_uri %q: %w", uri, err)
		return b
	}
	scheme := parsedURI.Scheme
	if strings.EqualFold(scheme, "https") {
		// HTTPS is always allowed
	} else if strings.EqualFold(scheme, "http") {
		if !b.allowHTTP {
			b.errValidation = fmt.Errorf("unsupported URL scheme for request_uri: %q (https required; explicit HTTP policy required for local tests)", parsedURI.Scheme)
			return b
		}
	} else {
		b.errValidation = fmt.Errorf("unsupported URL scheme for request_uri: %q (https required; explicit HTTP policy required for local tests)", parsedURI.Scheme)
		return b
	}

	var req *http.Request

	switch method {
	case RequestURIMethodGET:
		req, err = http.NewRequest(http.MethodGet, parsedURI.String(), nil)
	case RequestURIMethodPOST:
		formData := url.Values{}
		if b.draft24 {
			formData.Set("wallet_metadata", "{}")
		} else {
			// OID4VP 1.0 §5.10: the Final POST always carries a fresh
			// wallet_nonce and includes wallet_metadata only when the Wallet has
			// metadata to convey.
			nonce, nonceErr := b.newRequestURINonce()
			if nonceErr != nil {
				b.errValidation = fmt.Errorf("failed to generate wallet_nonce: %w", nonceErr)
				return b
			}
			b.sentWalletNonce = nonce
			formData.Set("wallet_nonce", nonce)
			if b.walletMetadata != nil {
				metadataJSON, marshalErr := json.Marshal(b.walletMetadata)
				if marshalErr != nil {
					b.errValidation = fmt.Errorf("failed to marshal wallet_metadata: %w", marshalErr)
					return b
				}
				formData.Set("wallet_metadata", string(metadataJSON))
			}
		}
		req, err = http.NewRequest(http.MethodPost, parsedURI.String(), strings.NewReader(formData.Encode()))
	default:
		b.errValidation = fmt.Errorf("unsupported request_uri_method: %s", method)
		return b
	}

	if err != nil {
		b.errValidation = fmt.Errorf("failed to create %s request to %s: %w", method, uri, err)
		return b
	}

	req = req.WithContext(observe.WithEndpoint(req.Context(), observe.EndpointRequestObject))
	req.Header.Set("User-Agent", "")
	req.Header.Set("Accept", "application/oauth-authz-req+jwt")
	if b.draft24 {
		req.Header.Set("Accept", "application/oauth-authz-req+jwt, application/jwt, text/plain, */*")
	}
	if method == RequestURIMethodPOST {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	client := b.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		b.errValidation = fmt.Errorf("failed to send %s request to %s: %w", method, uri, err)
		return b
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b.errValidation = fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
		return b
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		b.errValidation = fmt.Errorf("failed to read response body: %w", err)
		return b
	}
	if len(body) > 1<<20 {
		b.errValidation = fmt.Errorf("request_uri response exceeds 1 MiB")
		return b
	}

	b.WithRequestObject(string(body))
	// The Request Object arrived by reference; HAIP §5.1 distinguishes this from
	// a Request Object supplied by value in the request= parameter.
	b.requestSource = "reference"
	return b
}

// newRequestURINonce returns the wallet_nonce for a Final request_uri POST. It
// delegates to the presenter-supplied generator when present and otherwise
// generates 32 cryptographically random bytes, base64url-encoded without
// padding (OID4VP 1.0 §5.10).
func (b *requestBuilder) newRequestURINonce() (string, error) {
	if b.requestURINonce != nil {
		return b.requestURINonce()
	}
	return defaultRequestURINonce()
}
func defaultRequestURINonce() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// AuthorityKeyIdentifiersFromCredential returns the base64url-encoded Authority
// Key Identifiers (RFC 5280 Section 4.2.1.1) of the certificates in the issuer
// JWT header x5c chain of an SD-JWT VC (or JWT VC) wire value. It lets the
// wallet evaluate DCQL aki trusted_authorities queries (OID4VP 1.0 Section
// 6.1.1.1), which HAIP 1.0 section 5 requires.
func AuthorityKeyIdentifiersFromCredential(rawCredential string) []string {
	issuerJWT := rawCredential
	if separator := strings.IndexByte(issuerJWT, '~'); separator >= 0 {
		issuerJWT = issuerJWT[:separator]
	}
	certificates, err := commonX509.DecodeX5CFromJWTHeader(issuerJWT)
	if err != nil {
		return nil
	}
	identifiers := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		if len(certificate.AuthorityKeyId) == 0 {
			continue
		}
		identifiers = append(identifiers, base64.RawURLEncoding.EncodeToString(certificate.AuthorityKeyId))
	}
	return identifiers
}
func (b *requestBuilder) Build() (*CredentialPresentationRequest, error) {
	if b.errValidation != nil {
		return nil, b.errValidation
	}
	if err := b.validateResponseEncryptionMetadata(); err != nil {
		// The Verifier asked for an encrypted response and left nothing to
		// encrypt it to, so even the refusal is not sent in the clear.
		b.errorResponseAllowed = false
		return nil, err
	}
	if err := b.enforceHAIPProfile(); err != nil {
		return nil, err
	}
	return b.req, nil
}
