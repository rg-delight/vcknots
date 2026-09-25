// Package oid4vp implements the OpenID for Verifiable Presentations wallet
// side: it parses and validates Authorization Requests and sends
// Authorization Responses to the Verifier.
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

	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// Oid4vpPresenter is the OpenID4VP presenter plugin. Its fields configure the
// HTTP client, trust and protocol policy applied to requests and responses.
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
	// Profile is the OpenID4VP 1.0 profile whose Options the presenter
	// applies. The zero value is profile.Final(), which adds no constraint;
	// profile.HAIP() enforces HAIP 1.0 on the 1.0 path. The Draft24
	// entrypoints do not apply it. A draft profile is refused
	// (profile.ErrDraftProfile).
	Profile profile.Profile
	// WalletMetadata, when non-nil, is serialized as the wallet_metadata form
	// parameter of a request_uri POST (OID4VP 1.0 §5.10, Draft 24 §5.10).
	// When nil the parameter is omitted.
	WalletMetadata map[string]any
	// RequestURINonce generates the wallet_nonce sent with a request_uri POST.
	// A nil value uses 32 random bytes, base64url-encoded without padding.
	RequestURINonce func() (string, error)
	// SupportedTransactionDataTypes lists the transaction_data "type" values the
	// wallet can process. A nil or empty list means the wallet supports no
	// transaction_data type, so any request carrying transaction_data is
	// rejected with invalid_transaction_data (OID4VP 1.0 §5.1, §8.4; Draft 24
	// §5.1).
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

// ProtocolProfile reports the OpenID4VP 1.0 profile this presenter enforces.
func (p *Oid4vpPresenter) ProtocolProfile() profile.Profile {
	return p.Profile
}

var (
	_ types.RequestParser      = (*Oid4vpPresenter)(nil)
	_ types.DCAPIRequestParser = (*Oid4vpPresenter)(nil)
	_ types.Responder          = (*Oid4vpPresenter)(nil)
)

// ParsePresentationRequest parses and authenticates an OpenID4VP 1.0
// Authorization Request URI. The request arrives as a Request Object by
// reference (request_uri), by value (request), or as plain query parameters
// (OID4VP 1.0 §5, RFC 9101). ParseRequest returns the same request as a
// handle that can be answered.
func (p *Oid4vpPresenter) ParsePresentationRequest(uriString string) (*CredentialPresentationRequest, error) {
	handle, err := p.parseRequestURI(context.Background(), uriString)
	if err != nil {
		return nil, err
	}
	return handle.req, nil
}

// ParseRequest parses and admits an OpenID4VP 1.0 Authorization Request URI,
// dereferencing its request_uri when present. The result is an
// *AdmittedRequest.
func (p *Oid4vpPresenter) ParseRequest(ctx context.Context, uri string) (types.AdmittedRequest, error) {
	return asAdmitted(p.parseRequestURI(ctx, uri))
}

// ParseRequestObject authenticates an OpenID4VP 1.0 Request Object the caller
// already holds, as a Request Object passed by value (RFC 9101 §5.1).
// src.ClientID is the Authorization Request client_id the Request Object's
// claim must equal (OID4VP 1.0 §5.10.1, ErrRequestObjectClientIDMismatch); it
// is empty only when there is no outer client_id. A profile with
// RequireSignedRequestByReference (HAIP 1.0 §5.1) refuses every Request Object
// passed by value with ErrHAIPRequestURIRequired: only ParseRequest, which
// fetches request_uri itself, observes delivery by reference. The result is an
// *AdmittedRequest.
func (p *Oid4vpPresenter) ParseRequestObject(ctx context.Context, requestObject string, src types.RequestObjectSource) (types.AdmittedRequest, error) {
	return asAdmitted(p.parseRequestObject(ctx, requestObject, src))
}

func (p *Oid4vpPresenter) parseRequestURI(ctx context.Context, uriString string) (*AdmittedRequest, error) {
	builder, err := p.newRequestBuilder(ctx)
	if err != nil {
		return nil, err
	}
	queryParams, err := authorizationRequestQuery(uriString)
	if err != nil {
		return nil, err
	}
	// Reject malformed outer identifiers before dereferencing request_uri.
	clientID := strings.TrimSpace(queryParams.Get("client_id"))
	if clientID != "" {
		if _, err := parseOID4VPClientID(clientID); err != nil {
			return nil, fmt.Errorf("invalid client_id in initial request: %w", err)
		}
	}
	builder.expectedClientID = clientID

	requestURI := queryParams.Get("request_uri")
	requestObj := queryParams.Get("request")
	requestURIMethod := queryParams.Get("request_uri_method")
	// RFC 9101 §5: "If this parameter is present in the authorization request,
	// request_uri MUST NOT be present." OID4VP 1.0 §5.10.2 requires
	// terminating.
	if requestURI != "" && requestObj != "" {
		return nil, newAuthorizationRequestError(InvalidRequestError, "request and request_uri must not both be present in the same request")
	}

	switch {
	case requestURI != "":
		method := RequestURIMethodGET
		// OID4VP 1.0 §5.1: the two valid values are case-sensitive get and
		// post; anything else is invalid_request_uri_method (§8.5).
		switch requestURIMethod {
		case "", "get":
		case "post":
			method = RequestURIMethodPOST
		default:
			return nil, newAuthorizationRequestError(InvalidRequestURIMethodError, "request_uri_method must be 'get' or 'post' (case-sensitive), got %q", requestURIMethod)
		}
		builder.WithRequestObjectURI(requestURI, method)
	case requestObj != "":
		if builder.options.RequireSignedRequestByReference {
			return nil, errHAIPRequestURIRequired()
		}
		builder.WithRequestObject(requestObj)
	default:
		builder.WithQueryParams(queryParams)
	}
	return p.finishParse(&builder.requestCore, builder.Build, wireOpenID4VP1)
}

// parseRequestObject is the by-value counterpart of parseRequestURI.
func (p *Oid4vpPresenter) parseRequestObject(ctx context.Context, requestObject string, src types.RequestObjectSource) (*AdmittedRequest, error) {
	builder, err := p.newRequestBuilder(ctx)
	if err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(src.ClientID)
	if clientID != "" {
		if _, err := parseOID4VPClientID(clientID); err != nil {
			return nil, fmt.Errorf("invalid client_id in initial request: %w", err)
		}
	}
	if builder.options.RequireSignedRequestByReference {
		// HAIP 1.0 §5.1: the Request Object must come from request_uri, which
		// only a fetch by this library can establish.
		return nil, errHAIPRequestURIRequired()
	}
	builder.applySource(clientID)
	builder.WithRequestObject(requestObject)
	return p.finishParse(&builder.requestCore, builder.Build, wireOpenID4VP1)
}

// authorizationRequestQuery returns the query parameters of an Authorization
// Request URI.
func authorizationRequestQuery(uriString string) (url.Values, error) {
	parsedURL, err := url.Parse(uriString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}
	return parsedURL.Query(), nil
}

// profileOptions returns the Options of the presenter's profile, failing
// closed on a draft profile before any network access.
func (p *Oid4vpPresenter) profileOptions() (profile.Options, error) {
	if err := p.Profile.RequireFinalVersion(); err != nil {
		return profile.Options{}, fmt.Errorf("invalid OID4VP profile: %w", err)
	}
	return p.Profile.Options(), nil
}

// configureCore copies the presenter's transport and trust policy into the
// state of one parse.
func (p *Oid4vpPresenter) configureCore(ctx context.Context, core *requestCore) {
	core.ctx = ctx
	core.httpClient = p.httpClient()
	core.allowHTTP = p.AllowHTTP
	core.x509TrustChainRoots = p.X509TrustChainRoots
	core.insecureSkipX509Verify = p.InsecureSkipX509Verify
	core.requireClientMetadataJWKKeyIDs = p.RequireClientMetadataJWKKeyIDs
	if p.RequestObjectValidation != nil {
		core.setRequestObjectValidation(*p.RequestObjectValidation)
	}
}

// newRequestBuilder creates the builder of one OpenID4VP 1.0 parse with the
// presenter's transport, trust and protocol policy.
func (p *Oid4vpPresenter) newRequestBuilder(ctx context.Context) (*requestBuilder, error) {
	options, err := p.profileOptions()
	if err != nil {
		return nil, err
	}
	if options.ForbidInsecureTransports && (p.AllowHTTP || p.InsecureSkipX509Verify) {
		// HAIP §5: the profile requires TLS verifier endpoints and verified
		// X.509 request signing; the test-only escapes must not weaken it.
		return nil, newAuthorizationRequestError(InvalidRequestError, "HAIP profile does not permit AllowHTTP or InsecureSkipX509Verify")
	}
	builder := NewRequestBuilder()
	builder.options = options
	p.configureCore(ctx, &builder.requestCore)
	builder.policy = &builderPolicy{
		walletMetadata:                p.WalletMetadata,
		requestURINonce:               p.RequestURINonce,
		supportedTransactionDataTypes: p.SupportedTransactionDataTypes,
		preRegisteredClients:          p.PreRegisteredClients,
		resolvePreRegisteredClient:    p.ResolvePreRegisteredClient,
	}
	return builder, nil
}

// finishParse runs build and admits the result. On a refusal it records where
// an error authorization response may go; it is posted there only when the
// presenter opted in with SendParseErrorResponses.
func (p *Oid4vpPresenter) finishParse(core *requestCore, build func() (*CredentialPresentationRequest, error), wire wireContract) (*AdmittedRequest, error) {
	req, err := build()
	if err != nil {
		core.attachErrorResponseTarget(err)
		var authzErr *AuthorizationRequestError
		if p.SendParseErrorResponses && errors.As(err, &authzErr) && authzErr.ResponseURI() != "" {
			if sendErr := authzErr.SendErrorResponse(core.context(), p.httpClient()); sendErr != nil {
				return nil, fmt.Errorf("failed to build CredentialPresentationRequest: %w (also %v)", err, sendErr)
			}
		}
		return nil, fmt.Errorf("failed to build CredentialPresentationRequest: %w", err)
	}
	return p.admit(req, wire, core.requestObject)
}
