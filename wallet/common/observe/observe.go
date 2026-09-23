// Package observe lets an integrator watch the outbound HTTP exchanges the
// wallet library performs on its behalf, each one labelled with the protocol
// role the library sent it for.
//
// The library labels every request it builds (the Credential Issuer Metadata
// fetch, the Pushed Authorization Request, the Token Request, the Credential
// Request, the Request Object fetch, the Authorization Response POST, ...) on
// the request context. An integrator that wants to know what went over the wire
// wraps the transport of the *http.Client it injects into the library with
// Transport, and receives one Exchange per round trip. It never has to
// re-derive a request's role from its URL.
//
// An Exchange carries no header value, no body and no error text: only the
// role, the method, the URL as sent, the timing, the status and the few
// booleans a protocol report needs (a DPoP proof or a client attestation was
// sent, the request or response was a JWT, the Authorization Response was
// encrypted). What the integrator keeps, and where it keeps the URL, is its own
// decision.
package observe

import (
	"context"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Endpoint is the protocol role of one outbound request. The vocabulary is
// closed: a request the library did not label (a Credential Offer fetched by
// reference, a CRL or OCSP download, a request an integrator sends through the
// same client) is EndpointOther.
type Endpoint string

const (
	// EndpointIssuerMetadata is the Credential Issuer Metadata request
	// (OpenID4VCI 1.0 Section 12.2.2, Draft 13 Section 11.2.2).
	EndpointIssuerMetadata Endpoint = "issuer_metadata"
	// EndpointAuthorizationServerMetadata is the RFC 8414 metadata request.
	EndpointAuthorizationServerMetadata Endpoint = "authorization_server_metadata"
	// EndpointAuthorization is the Authorization Endpoint request the wallet
	// follows itself (OpenID4VCI 1.0 Section 5.1).
	EndpointAuthorization Endpoint = "authorization"
	// EndpointAttestationChallenge is the OAuth Client Attestation challenge
	// request.
	EndpointAttestationChallenge Endpoint = "attestation_challenge"
	// EndpointPushedAuthorization is the RFC 9126 Pushed Authorization Request.
	EndpointPushedAuthorization Endpoint = "pushed_authorization"
	// EndpointToken is the Token Request (OpenID4VCI 1.0 Section 6).
	EndpointToken Endpoint = "token"
	// EndpointNonce is the Nonce Request (OpenID4VCI 1.0 Section 7).
	EndpointNonce Endpoint = "nonce"
	// EndpointCredential is the Credential Request (OpenID4VCI 1.0 Section 8).
	EndpointCredential Endpoint = "credential"
	// EndpointDeferredCredential is the Deferred Credential Request
	// (OpenID4VCI 1.0 Section 9).
	EndpointDeferredCredential Endpoint = "deferred_credential"
	// EndpointNotification is the Notification Request (OpenID4VCI 1.0
	// Section 11).
	EndpointNotification Endpoint = "notification"
	// EndpointJWKS is a JWK Set fetch.
	EndpointJWKS Endpoint = "jwks"
	// EndpointRequestObject is the request_uri fetch of an Authorization
	// Request (OpenID4VP 1.0 Section 5.10, RFC 9101).
	EndpointRequestObject Endpoint = "request_object"
	// EndpointResponse is the Authorization Response or error response POST to
	// the verifier's Response Endpoint (OpenID4VP 1.0 Section 8.2).
	EndpointResponse Endpoint = "response_endpoint"
	// EndpointFederationEntityConfiguration is an OpenID Federation Entity
	// Configuration fetch at /.well-known/openid-federation (OpenID
	// Federation 1.0 Section 9).
	EndpointFederationEntityConfiguration Endpoint = "federation_entity_configuration"
	// EndpointFederationSubordinateStatement is a Subordinate Statement fetch
	// from a superior's federation_fetch_endpoint (OpenID Federation 1.0
	// Section 8.1).
	EndpointFederationSubordinateStatement Endpoint = "federation_subordinate_statement"
	// EndpointStatusList is a Status List Token fetch
	// (draft-ietf-oauth-status-list Section 8).
	EndpointStatusList Endpoint = "status_list"
	// EndpointIssuerKeyMaterial is a fetch the credential issuer key ladder
	// makes: JWT VC Issuer Metadata and the jwks_uri it names, a did:web DID
	// document, or a DID Configuration.
	EndpointIssuerKeyMaterial Endpoint = "issuer_key_material"
	// EndpointOther is every request the library did not label.
	EndpointOther Endpoint = "other"
)

type endpointKey struct{}

type responseEncryptionKey struct{}

// WithEndpoint labels the requests built from ctx with their protocol role. The
// library calls it where it sends a request; an inner label replaces an outer
// one, so a Nonce Request issued while a Credential Request is being prepared
// is still labelled EndpointNonce.
func WithEndpoint(ctx context.Context, endpoint Endpoint) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, endpointKey{}, endpoint)
}

// EndpointOf reports the role ctx was labelled with, or EndpointOther.
func EndpointOf(ctx context.Context) Endpoint {
	if ctx == nil {
		return EndpointOther
	}
	if endpoint, ok := ctx.Value(endpointKey{}).(Endpoint); ok && endpoint != "" {
		return endpoint
	}
	return EndpointOther
}

// WithResponseEncryption records on ctx whether the OpenID4VP Authorization
// Response sent with it is encrypted (a JWE in the `response` parameter). The
// wire cannot show this: both forms are application/x-www-form-urlencoded.
func WithResponseEncryption(ctx context.Context, encrypted bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, responseEncryptionKey{}, encrypted)
}

// ResponseEncryptionOf reports the annotation WithResponseEncryption left on
// ctx, and whether there was one.
func ResponseEncryptionOf(ctx context.Context) (encrypted bool, ok bool) {
	if ctx == nil {
		return false, false
	}
	encrypted, ok = ctx.Value(responseEncryptionKey{}).(bool)
	return encrypted, ok
}

// Inherit copies the labels of src onto dst. A transport that re-parents a
// request on a context of its own (to bind it to an operation's cancellation or
// trace, say) calls it so a transport further down still sees the role.
func Inherit(dst, src context.Context) context.Context {
	if src == nil {
		return dst
	}
	if endpoint, ok := src.Value(endpointKey{}).(Endpoint); ok {
		dst = WithEndpoint(dst, endpoint)
	}
	if encrypted, ok := ResponseEncryptionOf(src); ok {
		dst = WithResponseEncryption(dst, encrypted)
	}
	return dst
}

// Exchange is one outbound request and the response headers it received.
type Exchange struct {
	Endpoint Endpoint
	// Method is the request method as sent.
	Method string
	// URL is the request URL as sent, without userinfo and fragment. It is a
	// copy the observer may keep.
	URL *url.URL
	// StartedAt is when the request was handed to the transport; Duration runs
	// to the response headers, so a large body streams after it.
	StartedAt time.Time
	Duration  time.Duration
	// StatusCode is 0 when the transport failed before a response arrived.
	StatusCode int
	// DPoP and ClientAttestation report that the request carried a DPoP proof
	// (RFC 9449) or an OAuth-Client-Attestation header. The values are never
	// exposed.
	DPoP              bool
	ClientAttestation bool
	// RequestJWT and ResponseJWT report an application/jwt Content-Type, which
	// is how an encrypted Credential Request or Response travels (OpenID4VCI
	// 1.0 Sections 8.2 and 8.3).
	RequestJWT  bool
	ResponseJWT bool
	// ResponseEncrypted is the WithResponseEncryption annotation of the
	// request, nil when the library made no claim.
	ResponseEncrypted *bool
}

// Observer receives the exchanges of the transport it was given to. It is
// called after the response headers arrived or the transport failed, on the
// goroutine that sent the request, so an implementation shared between
// concurrent requests has to be safe for concurrent use. It must not block.
type Observer interface {
	ObserveExchange(Exchange)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(Exchange)

// ObserveExchange calls f.
func (f ObserverFunc) ObserveExchange(exchange Exchange) { f(exchange) }

// Transport returns a RoundTripper that sends through base (http.DefaultTransport
// when nil) and reports every round trip to observer. A nil observer returns
// base unchanged. Observation never changes the result of the round trip.
func Transport(base http.RoundTripper, observer Observer) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if observer == nil {
		return base
	}
	return &observingTransport{base: base, observer: observer}
}

type observingTransport struct {
	base     http.RoundTripper
	observer Observer
}

func (t *observingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	startedAt := time.Now()
	response, err := t.base.RoundTrip(request)
	t.observer.ObserveExchange(exchangeOf(request, startedAt, time.Since(startedAt), response))
	return response, err
}

func exchangeOf(request *http.Request, startedAt time.Time, duration time.Duration, response *http.Response) Exchange {
	exchange := Exchange{
		Endpoint:          EndpointOf(request.Context()),
		Method:            request.Method,
		URL:               sentURL(request.URL),
		StartedAt:         startedAt,
		Duration:          duration,
		DPoP:              request.Header.Get("DPoP") != "",
		ClientAttestation: request.Header.Get("OAuth-Client-Attestation") != "",
		RequestJWT:        isJWTMediaType(request.Header.Get("Content-Type")),
	}
	if encrypted, ok := ResponseEncryptionOf(request.Context()); ok {
		exchange.ResponseEncrypted = &encrypted
	}
	if response != nil {
		exchange.StatusCode = response.StatusCode
		exchange.ResponseJWT = isJWTMediaType(response.Header.Get("Content-Type"))
	}
	return exchange
}

// sentURL copies the URL minus the fragment (never transmitted) and the
// userinfo (a credential).
func sentURL(endpoint *url.URL) *url.URL {
	if endpoint == nil {
		return nil
	}
	projected := *endpoint
	projected.User = nil
	projected.Fragment = ""
	projected.RawFragment = ""
	return &projected
}

// isJWTMediaType reports whether a Content-Type header names application/jwt.
// Parameters are ignored, and a header the media type parser rejects still has
// its type/subtype compared, so a slightly malformed issuer header does not
// hide an encrypted exchange.
func isJWTMediaType(contentType string) bool {
	trimmed := strings.TrimSpace(contentType)
	if trimmed == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(trimmed)
	if err != nil {
		mediaType, _, _ = strings.Cut(trimmed, ";")
	}
	return strings.EqualFold(strings.TrimSpace(mediaType), "application/jwt")
}

// Recorder is an Observer that keeps the first exchanges it receives, up to a
// limit, and remembers that it dropped later ones. It is safe for concurrent
// use and every method is safe on a nil receiver.
type Recorder struct {
	mu        sync.Mutex
	limit     int
	exchanges []Exchange
	truncated bool
}

// NewRecorder returns a Recorder that keeps at most limit exchanges; a limit
// below one keeps none and reports every exchange as truncated.
func NewRecorder(limit int) *Recorder {
	return &Recorder{limit: limit}
}

// ObserveExchange keeps exchange unless the limit was reached.
func (r *Recorder) ObserveExchange(exchange Exchange) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.exchanges) >= r.limit {
		r.truncated = true
		return
	}
	r.exchanges = append(r.exchanges, exchange)
}

// Exchanges returns a copy of the kept exchanges in the order they completed.
// It is never nil.
func (r *Recorder) Exchanges() []Exchange {
	if r == nil {
		return []Exchange{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	exchanges := make([]Exchange, len(r.exchanges))
	copy(exchanges, r.exchanges)
	return exchanges
}

// Truncated reports whether an exchange was dropped at the limit.
func (r *Recorder) Truncated() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.truncated
}
