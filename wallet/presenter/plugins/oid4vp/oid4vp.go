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
	// RequireClientMetadataJWKKeyIDs refuses, while the request is parsed, an
	// Authorization Request whose client_metadata parameter carries a jwks
	// member without a kid (ErrClientMetadataJWKKeyIDMissing) or two members
	// with the same kid (ErrClientMetadataJWKKeyIDDuplicate). OpenID4VP 1.0
	// Section 5.1 makes a unique kid on every such key a MUST; Draft24 has no
	// such rule, and the setting applies to its entrypoints too when a caller
	// chooses it.
	//
	// The zero value accepts such keys. The Wallet does not need the kid to
	// answer (it picks the response encryption key by use and alg), and
	// Verifiers in the field omit it, so enforcing it is the integrator's
	// policy choice rather than a default. HAIP adds no rule on kid and does
	// not turn this on.
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

// ParseRequestObject authenticates an OpenID4VP 1.0 Request Object the caller
// already holds, with no Authorization Request URI to read it out of: a JWT the
// application fetched from request_uri itself, or one that reached it over a
// transport this library does not drive.
//
// It runs the authentication ParsePresentationRequest runs for a Request Object
// it fetched, and returns the same typed errors: the compact JWS shape and the
// typ header, the x5c signature and certificate chain, the Client Identifier
// Prefix binding to the signing certificate and to the response endpoint, aud,
// exp / nbf and the profile's lifetime policy. Every Authorization Request
// parameter is taken from the signed claims.
//
// expectedClientID is the client_id of the Authorization Request this Request
// Object belongs to. The Request Object's own client_id claim must equal it
// (OpenID4VP 1.0 Section 5.10.1, RFC 9101 Section 6.1); a mismatch is reported
// with ErrRequestObjectClientIDMismatch. Pass "" only when the caller holds the
// Request Object alone and has no Authorization Request parameter to compare it
// against: the client_id claim is still authenticated against the certificate
// that signed the Request Object, and only the comparison against an outer
// parameter that does not exist is skipped.
//
// What this entry point cannot receive is what belongs to the Authorization
// Request rather than to the Request Object. There is no request_uri_method and
// no wallet_nonce echo, because the fetch already happened outside this call;
// an application that did fetch through request_uri records that with
// RequestObjectValidationOptions.DeliveredByReference so the HAIP Section 5.1
// delivery requirement is still met. A Digital Credentials API invocation is
// not a Request Object delivery at all: it carries a platform-authenticated
// Origin and is parsed by ParseDCAPIRequest.
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

// parseRequestObject is the by-value counterpart of parsePresentationRequest:
// the Authorization Request parameters arrive as the Request Object itself
// instead of as a URI to read it out of. Both load the same builder through
// newParseBuilder and finish through buildParsedRequest, so the Request Object
// reaches exactly the same WithRequestObject authentication either way.
func (p *Oid4vpPresenter) parseRequestObject(requestObject string, expectedClientID string, draft24 bool) (*CredentialPresentationRequest, error) {
	builder, err := p.newParseBuilder(draft24)
	if err != nil {
		return nil, err
	}

	// The caller's Authorization Request client_id is checked the same way the
	// URI forms check the one they read from the query string, so a malformed
	// identifier is refused before the Request Object is authenticated against
	// it.
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

// newParseBuilder creates the requestBuilder one parse operation runs on and
// copies the presenter's transport, trust and protocol policy onto it. Every
// entry point that parses an Authorization Request starts here, so the URI
// forms and the by-value Request Object forms cannot drift apart in the policy
// they apply.
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
