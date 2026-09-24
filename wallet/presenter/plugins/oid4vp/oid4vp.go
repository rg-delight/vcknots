package oid4vp

import (
	"context"
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
	// PreRegisteredClients is the registry of Verifiers registered out of
	// band, keyed by Client Identifier (OID4VP 1.0 §5.9.2). A Final request
	// whose client_id has no ":" and resolves neither here nor through
	// ResolvePreRegisteredClient is refused with ErrPreRegisteredClientUnknown.
	// The Draft24 entry points refuse every pre-registered Client Identifier.
	PreRegisteredClients map[string]PreRegisteredClient
	// ResolvePreRegisteredClient is consulted when PreRegisteredClients holds no
	// entry for the Client Identifier, so a wallet can keep its registry in a
	// database instead of a map. A nil resolver means the map is the whole
	// registry.
	ResolvePreRegisteredClient PreRegisteredClientResolver
	// SendParseErrorResponses posts the error authorization response of a
	// parse-time refusal whose AuthorizationRequestError names a ResponseURI,
	// with this presenter's client. The zero value posts nothing: the endpoint
	// is chosen by an unauthenticated request, and a caller that wants to
	// answer it calls AuthorizationRequestError.SendErrorResponse itself.
	SendParseErrorResponses bool
	// RequireClientMetadataJWKKeyIDs refuses a client_metadata.jwks member
	// without a kid (ErrClientMetadataJWKKeyIDMissing) or with a duplicate kid
	// (ErrClientMetadataJWKKeyIDDuplicate), as OID4VP 1.0 §5.1 requires. The
	// zero value accepts them: the Wallet selects the encryption key by use
	// and alg, and Verifiers in the field omit kid.
	RequireClientMetadataJWKKeyIDs bool
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

// ParsePresentationRequest parses and authenticates an OpenID4VP 1.0
// Authorization Request URI. The request arrives as a Request Object by
// reference (request_uri), by value (request), or as plain query parameters
// (OID4VP 1.0 §5, RFC 9101).
func (p *Oid4vpPresenter) ParsePresentationRequest(uriString string) (*CredentialPresentationRequest, error) {
	return p.parsePresentationRequest(uriString, false)
}

// ParseDraft24PresentationRequest accepts the existing Draft24 Presentation Exchange and DCQL request forms.
// New Final integrations must use ParsePresentationRequest.
func (p *Oid4vpPresenter) ParseDraft24PresentationRequest(uriString string) (*CredentialPresentationRequest, error) {
	return p.parsePresentationRequest(uriString, true)
}

// ParseRequestObject authenticates an OpenID4VP 1.0 Request Object the caller
// already holds, with the same checks and typed errors as a Request Object
// ParsePresentationRequest fetched. expectedClientID is the Authorization
// Request client_id the Request Object's claim must equal (OID4VP 1.0
// §5.10.1, ErrRequestObjectClientIDMismatch); pass "" only when there is no
// outer client_id. A caller that fetched the object through request_uri
// states so with RequestObjectValidationOptions.DeliveredByReference and
// WalletNonce. DC API invocations use ParseDCAPIRequest.
func (p *Oid4vpPresenter) ParseRequestObject(requestObject string, expectedClientID string) (*CredentialPresentationRequest, error) {
	return p.parseRequestObject(requestObject, expectedClientID, false)
}

// ParseDraft24RequestObject is ParseRequestObject for the existing Draft24 wire
// contract, the by-value counterpart of ParseDraft24PresentationRequest. New
// Final integrations must use ParseRequestObject.
func (p *Oid4vpPresenter) ParseDraft24RequestObject(requestObject string, expectedClientID string) (*CredentialPresentationRequest, error) {
	return p.parseRequestObject(requestObject, expectedClientID, true)
}
func (p *Oid4vpPresenter) parsePresentationRequest(uriString string, draft24 bool) (*CredentialPresentationRequest, error) {
	builder, err := p.newParseBuilder(draft24)
	if err != nil {
		return nil, err
	}

	parsedURL, err := url.Parse(uriString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}
	queryParams := parsedURL.Query()
	// Reject malformed outer identifiers before dereferencing request_uri.
	clientID := strings.TrimSpace(queryParams.Get("client_id"))
	if clientID != "" {
		if _, err := parseClientIDForWire(clientID, draft24); err != nil {
			return nil, fmt.Errorf("invalid client_id in initial request: %w", err)
		}
	}
	builder.expectedClientID = clientID

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

	return p.buildParsedRequest(builder)
}

// parseRequestObject is the by-value counterpart of parsePresentationRequest;
// both share newParseBuilder and buildParsedRequest.
func (p *Oid4vpPresenter) parseRequestObject(requestObject string, expectedClientID string, draft24 bool) (*CredentialPresentationRequest, error) {
	builder, err := p.newParseBuilder(draft24)
	if err != nil {
		return nil, err
	}

	clientID := strings.TrimSpace(expectedClientID)
	if clientID != "" {
		if _, err := parseClientIDForWire(clientID, draft24); err != nil {
			return nil, fmt.Errorf("invalid client_id in initial request: %w", err)
		}
	}
	builder.expectedClientID = clientID
	builder.expectedClientIDAbsent = clientID == ""

	return p.buildParsedRequest(builder.WithRequestObject(requestObject))
}

// newParseBuilder creates the requestBuilder of one parse operation with the
// presenter's transport, trust and protocol policy.
func (p *Oid4vpPresenter) newParseBuilder(draft24 bool) (*requestBuilder, error) {
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

	builder, err := NewRequestBuilderForProfile(normalizedProfile)
	if err != nil {
		return nil, err
	}
	builder.draft24 = draft24
	builder.httpClient = p.httpClient()
	builder.allowHTTP = p.AllowHTTP
	builder.x509TrustChainRoots = p.X509TrustChainRoots
	builder.insecureSkipX509Verify = p.InsecureSkipX509Verify
	builder.walletMetadata = p.WalletMetadata
	builder.requestURINonce = p.RequestURINonce
	builder.supportedTransactionDataTypes = p.SupportedTransactionDataTypes
	builder.preRegisteredClients = p.PreRegisteredClients
	builder.resolvePreRegisteredClient = p.ResolvePreRegisteredClient
	builder.requireClientMetadataJWKKeyIDs = p.RequireClientMetadataJWKKeyIDs
	if p.RequestObjectValidation != nil {
		builder.WithRequestObjectValidation(*p.RequestObjectValidation)
	}
	return builder, nil
}

// buildParsedRequest finalizes one parse operation. A refusal records where an
// error authorization response may go, and is posted there only when the
// presenter opted in with SendParseErrorResponses.
func (p *Oid4vpPresenter) buildParsedRequest(builder *requestBuilder) (*CredentialPresentationRequest, error) {
	req, err := builder.Build()
	if err != nil {
		builder.attachErrorResponseTarget(err)
		var authzErr *AuthorizationRequestError
		if p.SendParseErrorResponses && errors.As(err, &authzErr) && authzErr.ResponseURI() != "" {
			if sendErr := authzErr.SendErrorResponse(context.Background(), p.httpClient()); sendErr != nil {
				return nil, fmt.Errorf("failed to build CredentialPresentationRequest: %w (also %v)", err, sendErr)
			}
		}
		return nil, fmt.Errorf("failed to build CredentialPresentationRequest: %w", err)
	}

	return req, nil
}
