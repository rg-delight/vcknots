package oid4vp

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet/profile"
)

type Oid4vpPresenter struct {
	HTTPClient *http.Client
	// AllowHTTP permits HTTP response endpoints for a local test verifier.
	AllowHTTP           bool
	X509TrustChainRoots *x509.CertPool
	// RequestObjectValidation selects explicit trust, time and signing policy
	// for Final. X509TrustChainRoots remains available for existing consumers.
	RequestObjectValidation *RequestObjectValidationOptions
	// InsecureSkipX509Verify skips certificate verification for testing purposes.
	// WARNING: This should NEVER be set to true in production environments.
	// This is only for conformance testing with self-signed or non-standard certificates.
	InsecureSkipX509Verify bool
	// Profile selects the OpenID4VP protocol policy. The zero value normalizes to
	// profile.Final, which applies no HAIP constraints. Set it to profile.HAIP to
	// enforce HAIP 1.0 on the Final path; the Draft24 entrypoints ignore it.
	Profile profile.Profile
	// WalletMetadata, when non-nil, is serialized as the wallet_metadata form
	// parameter of a Final request_uri POST (OID4VP 1.0 §5.10). When nil the
	// parameter is omitted.
	WalletMetadata map[string]any
	// RequestURINonce generates the wallet_nonce sent with a Final request_uri
	// POST. A nil value uses 32 random bytes, base64url-encoded without padding.
	RequestURINonce func() (string, error)
	// SupportedTransactionDataTypes lists the transaction_data "type" values the
	// wallet can process. A nil or empty list means the wallet supports no
	// transaction_data type, so any request carrying transaction_data is
	// rejected with invalid_transaction_data (OID4VP 1.0 §5.1, §8.4).
	SupportedTransactionDataTypes []string
	// PreRegisteredClients is the wallet's registry of Verifiers registered out
	// of band, keyed by Client Identifier. OID4VP 1.0 §5.9.2: a Client
	// Identifier without a ":" references a pre-registered client, and "the
	// Client Identifier needs to be known to the Wallet in advance of the
	// Authorization Request". A Final request whose client_id resolves neither
	// here nor through ResolvePreRegisteredClient is rejected with
	// ErrPreRegisteredClientUnknown. The Draft24 entrypoints keep refusing
	// every pre-registered Client Identifier.
	PreRegisteredClients map[string]PreRegisteredClient
	// ResolvePreRegisteredClient is consulted when PreRegisteredClients holds no
	// entry for the Client Identifier, so a wallet can keep its registry in a
	// database instead of a map. A nil resolver means the map is the whole
	// registry.
	ResolvePreRegisteredClient PreRegisteredClientResolver
}

var _ profile.Carrier = (*Oid4vpPresenter)(nil)

func (p *Oid4vpPresenter) httpClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// ProtocolProfile reports the normalized OpenID4VP profile this presenter
// enforces.
func (p *Oid4vpPresenter) ProtocolProfile() profile.Profile {
	normalized, err := p.Profile.Normalize()
	if err != nil {
		return p.Profile
	}
	return normalized
}

// SetProtocolProfile is used by the wallet root to propagate its profile to the
// default presenter plugin it constructs itself.
func (p *Oid4vpPresenter) SetProtocolProfile(value profile.Profile) {
	p.Profile = value
}

// SetSupportedTransactionDataTypes is used by the wallet root to propagate its
// supported transaction_data types to the default presenter plugin.
func (p *Oid4vpPresenter) SetSupportedTransactionDataTypes(types []string) {
	p.SupportedTransactionDataTypes = types
}

// ParsePresentationRequest parses the presentation request URI and returns a CredentialPresentationRequest,
// following the flow defined in the OID4VP specification and RFC9101 (OAuth 2.0 with JAR).
//
// Verifier may provide an Authorization Request using either of three options:
// 1. request_uri (preferred): A URI that points to a JWT-encoded Authorization Request.
// 2. request: A JWT-encoded Authorization Request directly in the query parameter.
// 3. Query parameters: Individual parameters in the query string.
//
// This function detect which option is used and passes that to the proper handlers to obtain the CredentialPresentationRequest.
func (p *Oid4vpPresenter) ParsePresentationRequest(uriString string) (*CredentialPresentationRequest, error) {
	return p.parsePresentationRequest(uriString, false)
}

// ParseDraft24PresentationRequest accepts the existing Draft24 Presentation Exchange and DCQL request forms.
// New Final integrations must use ParsePresentationRequest.
func (p *Oid4vpPresenter) ParseDraft24PresentationRequest(uriString string) (*CredentialPresentationRequest, error) {
	return p.parsePresentationRequest(uriString, true)
}
func (p *Oid4vpPresenter) parsePresentationRequest(uriString string, draft24 bool) (*CredentialPresentationRequest, error) {
	// Normalize the profile once per parse so an unknown value fails closed
	// before any network access and every checkpoint reads a validated value.
	normalizedProfile, err := p.Profile.Normalize()
	if err != nil {
		return nil, fmt.Errorf("invalid OID4VP profile: %w", err)
	}
	if !draft24 && normalizedProfile.IsHAIP() && (p.AllowHTTP || p.InsecureSkipX509Verify) {
		// HAIP §5: the profile requires TLS verifier endpoints and verified
		// X.509 request signing; the test-only escapes must not weaken it. The
		// Draft24 entrypoints are exempt from the HAIP policy.
		return nil, newAuthorizationRequestError(InvalidRequestError, "HAIP profile does not permit AllowHTTP or InsecureSkipX509Verify")
	}

	parsedURL, err := url.Parse(uriString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}
	queryParams := parsedURL.Query()
	// Reject malformed outer identifiers before dereferencing request_uri.
	if clientID := strings.TrimSpace(queryParams.Get("client_id")); clientID != "" {
		if _, err := parseOID4VPClientID(clientID); err != nil {
			return nil, fmt.Errorf("invalid client_id in initial request: %w", err)
		}
	}

	builder, err := NewRequestBuilderForProfile(normalizedProfile)
	if err != nil {
		return nil, err
	}
	builder.draft24 = draft24
	builder.httpClient = p.httpClient()
	builder.allowHTTP = p.AllowHTTP
	builder.x509TrustChainRoots = p.X509TrustChainRoots
	builder.insecureSkipX509Verify = p.InsecureSkipX509Verify
	builder.expectedClientID = strings.TrimSpace(queryParams.Get("client_id"))
	builder.walletMetadata = p.WalletMetadata
	builder.requestURINonce = p.RequestURINonce
	builder.supportedTransactionDataTypes = p.SupportedTransactionDataTypes
	builder.preRegisteredClients = p.PreRegisteredClients
	builder.resolvePreRegisteredClient = p.ResolvePreRegisteredClient
	if p.RequestObjectValidation != nil {
		builder.WithRequestObjectValidation(*p.RequestObjectValidation)
	}

	requestURI := queryParams.Get("request_uri")
	requestObj := queryParams.Get("request")
	requestURIMethod := queryParams.Get("request_uri_method")
	if !draft24 {
		// RFC 9101 §5: "If this parameter is present in the authorization
		// request, request_uri MUST NOT be present." The reciprocal sentence
		// applies to request_uri. OID4VP 1.0 §5.10.2 requires terminating.
		if requestURI != "" && requestObj != "" {
			return nil, newAuthorizationRequestError(InvalidRequestError, "request and request_uri must not both be present in the same request")
		}
	}

	// Request Object by Reference
	if requestURI != "" {
		method := RequestURIMethodGET // Default to GET if not specified
		if requestURIMethod != "" {
			if draft24 {
				switch strings.ToLower(requestURIMethod) {
				case "get":
					method = RequestURIMethodGET
				case "post":
					method = RequestURIMethodPOST
				default:
					return nil, fmt.Errorf("unsupported request_uri_method: %s", requestURIMethod)
				}
			} else {
				// OID4VP 1.0 §5.1: the two valid values are case-sensitive
				// get and post; anything else is invalid_request_uri_method
				// (OID4VP 1.0 §8.5).
				switch requestURIMethod {
				case "get":
					method = RequestURIMethodGET
				case "post":
					method = RequestURIMethodPOST
				default:
					return nil, newAuthorizationRequestError(InvalidRequestURIMethodError, "request_uri_method must be 'get' or 'post' (case-sensitive), got %q", requestURIMethod)
				}
			}
		}
		builder = builder.WithRequestObjectURI(requestURI, method)
	} else if requestObj != "" {
		builder = builder.WithRequestObject(requestObj)
	} else {
		builder = builder.WithQueryParams(queryParams)
	}

	req, err := builder.Build()
	if err != nil {
		// OID4VP: when the Authorization Request is rejected with an OAuth
		// error code and response_mode=direct_post, deliver the error
		// authorization response to the Verifier's response_uri. Requests
		// received as Request Objects are excluded: their validation fails
		// before the signature is verified, so the response_uri is not yet
		// trustworthy (see requestBuilder.errorResponseAllowed).
		var authzErr *AuthorizationRequestError
		if errors.As(err, &authzErr) && builder.errorResponseAllowed {
			if sendErr := p.sendAuthorizationErrorResponse(builder.req, authzErr); sendErr != nil {
				return nil, fmt.Errorf("failed to build CredentialPresentationRequest: %w (also failed to send error authorization response: %v)", err, sendErr)
			}
		}
		return nil, fmt.Errorf("failed to build CredentialPresentationRequest: %w", err)
	}

	return req, nil
}
