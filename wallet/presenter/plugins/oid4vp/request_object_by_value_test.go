package oid4vp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/trustknots/vcknots/wallet/profile"
)

// TestParseRequestObjectMatchesTheURIDelivery is the contract of the by-value
// entry point: the same signed Request Object authenticated with
// ParseRequestObject and with the request= Authorization Request parameter
// yields the same CredentialPresentationRequest, including the authentication
// evidence, because both run the same builder.
func TestParseRequestObjectMatchesTheURIDelivery(t *testing.T) {
	f := newRequestObjectFixture(t)
	requestObject := f.sign(t, f.claims(), nil)

	uri := "openid4vp://authorize?" + url.Values{
		"client_id": {f.clientID()},
		"request":   {requestObject},
	}.Encode()
	fromURI, err := f.presenter().ParsePresentationRequest(uri)
	if err != nil {
		t.Fatalf("the URI delivery must be accepted: %v", err)
	}
	fromValue, err := f.presenter().ParseRequestObject(requestObject, f.clientID())
	if err != nil {
		t.Fatalf("the by-value delivery must be accepted: %v", err)
	}
	if !reflect.DeepEqual(fromURI, fromValue) {
		t.Fatalf("by-value and by-URI results differ:\n%+v\n%+v", fromValue, fromURI)
	}
	if fromValue.RequestObjectVerification == nil ||
		fromValue.RequestObjectVerification.Delivery != "value" ||
		fromValue.RequestObjectVerification.ClientID != f.clientID() {
		t.Fatalf("missing authentication evidence: %+v", fromValue.RequestObjectVerification)
	}
}

// TestParseDraft24RequestObjectMatchesTheURIDelivery repeats the parity check
// for the Presentation Exchange wire contract, whose by-value entry point
// authenticates an X.509 Request Object through the same shared path.
func TestParseDraft24RequestObjectMatchesTheURIDelivery(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["response_mode"] = "direct_post"
	delete(claims, "dcql_query")
	claims["presentation_definition"] = map[string]any{"id": "pid-definition"}
	requestObject := f.sign(t, claims, nil)

	uri := "openid4vp://authorize?" + url.Values{
		"client_id": {f.clientID()},
		"request":   {requestObject},
	}.Encode()
	fromURI, err := f.presenter().ParseDraft24PresentationRequest(uri)
	if err != nil {
		t.Fatalf("the Draft24 URI delivery must be accepted: %v", err)
	}
	fromValue, err := f.presenter().ParseDraft24RequestObject(requestObject, f.clientID())
	if err != nil {
		t.Fatalf("the Draft24 by-value delivery must be accepted: %v", err)
	}
	if !reflect.DeepEqual(fromURI, fromValue) {
		t.Fatalf("by-value and by-URI Draft24 results differ:\n%+v\n%+v", fromValue, fromURI)
	}
}

// TestParseRequestObjectRejectsClientIDMismatch keeps the OpenID4VP 1.0
// Section 5.10.1 cross-check available to a caller that holds the
// Authorization Request client_id, with the typed error the URI path returns.
func TestParseRequestObjectRejectsClientIDMismatch(t *testing.T) {
	f := newRequestObjectFixture(t)
	requestObject := f.sign(t, f.claims(), nil)

	_, err := f.presenter().ParseRequestObject(requestObject, "x509_hash:another")
	if !errors.Is(err, ErrRequestObjectClientIDMismatch) {
		t.Fatalf("want ErrRequestObjectClientIDMismatch, got %v", err)
	}
	if _, err := f.presenter().ParseRequestObject(requestObject, "not a client identifier:"); err == nil ||
		!strings.Contains(err.Error(), "invalid client_id in initial request") {
		t.Fatalf("want a malformed client_id refused before authentication, got %v", err)
	}
}

// TestParseRequestObjectWithoutExpectedClientID covers the caller that holds
// the Request Object alone: there is no outer parameter to compare against, so
// the comparison is skipped, but the client_id claim is still bound to the
// certificate that signed the Request Object.
func TestParseRequestObjectWithoutExpectedClientID(t *testing.T) {
	f := newRequestObjectFixture(t)
	request, err := f.presenter().ParseRequestObject(f.sign(t, f.claims(), nil), "")
	if err != nil {
		t.Fatalf("a Request Object without an outer client_id must be accepted: %v", err)
	}
	if request.RequestObjectVerification == nil || request.ClientID != f.clientID() {
		t.Fatalf("the client_id must stay bound to the signing certificate: %+v", request.RequestObjectVerification)
	}

	other := newRequestObjectFixture(t)
	claims := f.claims()
	claims["client_id"] = other.clientID()
	if _, err := f.presenter().ParseRequestObject(f.sign(t, claims, nil), ""); !errors.Is(err, ErrX509HashMismatch) {
		t.Fatalf("want ErrX509HashMismatch for a client_id the signer cannot speak for, got %v", err)
	}
}

// TestParseRequestObjectRefusesUnsignedRequests keeps the by-value entry point
// a Request Object entry point: the Final profile authenticates the request
// through its signature, so an alg=none JWT and a bare parameter document are
// both refused instead of being read as Authorization Request parameters.
func TestParseRequestObjectRefusesUnsignedRequests(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(map[string]any{"alg": "none", "typ": "oauth-authz-req+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "."

	if _, err := f.presenter().ParseRequestObject(unsigned, f.clientID()); !errors.Is(err, ErrRequestObjectSignatureInvalid) {
		t.Fatalf("want ErrRequestObjectSignatureInvalid for an alg=none request object, got %v", err)
	}
	if _, err := f.presenter().ParseRequestObject(string(payload), f.clientID()); err == nil ||
		!strings.Contains(err.Error(), "bounded compact signed JWT") {
		t.Fatalf("want a non-JWT request refused, got %v", err)
	}
	if _, err := f.presenter().ParseDraft24RequestObject(unsigned, f.clientID()); !errors.Is(err, ErrRequestObjectSignatureInvalid) {
		t.Fatalf("want the Draft24 entry point to refuse an alg=none request object, got %v", err)
	}
}

// TestParseRequestObjectHAIPDeliveryPolicy keeps the HAIP Section 5.1 delivery
// rule on the by-value entry point: a Request Object the library did not fetch
// through request_uri is refused unless the caller attests the fetch with
// DeliveredByReference, exactly as the request= parameter is.
func TestParseRequestObjectHAIPDeliveryPolicy(t *testing.T) {
	f := newRequestObjectFixture(t)
	requestObject := f.sign(t, f.claims(), nil)

	if _, err := f.haipPresenter(false).ParseRequestObject(requestObject, f.clientID()); !errors.Is(err, ErrHAIPRequestURIRequired) {
		t.Fatalf("want ErrHAIPRequestURIRequired without a delivery attestation, got %v", err)
	}
	request, err := f.haipPresenter(true).ParseRequestObject(requestObject, f.clientID())
	if err != nil {
		t.Fatalf("an attested delivery must be accepted under HAIP: %v", err)
	}
	if proof := request.RequestObjectVerification; proof == nil || !proof.DeliveryAttested || proof.Delivery != "value" {
		t.Fatalf("the attested delivery must be recorded: %+v", proof)
	}
}

// TestParseRequestObjectIsNotTheDCAPIEntryPoint records what a by-value caller
// cannot supply here: a Digital Credentials API invocation carries a
// platform-authenticated Origin and is parsed by ParseDCAPIRequest, so a DC API
// Response Mode reaching this entry point is refused the same way it is when it
// arrives as an Authorization Request parameter.
func TestParseRequestObjectIsNotTheDCAPIEntryPoint(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["response_mode"] = "dc_api.jwt"
	delete(claims, "response_uri")
	requestObject := f.sign(t, claims, nil)

	_, valueErr := f.haipPresenter(true).ParseRequestObject(requestObject, f.clientID())
	if valueErr == nil || !strings.Contains(valueErr.Error(), "dc_api.jwt is not implemented") {
		t.Fatalf("want a DC API response mode refused by value, got %v", valueErr)
	}
	uri := "openid4vp://authorize?" + url.Values{
		"client_id": {f.clientID()},
		"request":   {requestObject},
	}.Encode()
	_, uriErr := f.haipPresenter(true).ParsePresentationRequest(uri)
	if uriErr == nil || uriErr.Error() != valueErr.Error() {
		t.Fatalf("the two deliveries must refuse a DC API response mode alike: %v vs %v", valueErr, uriErr)
	}
}

// haipPresenter builds a HAIP presenter whose validation options optionally
// carry the caller's DeliveredByReference attestation.
func (f *requestObjectFixture) haipPresenter(deliveredByReference bool) *Oid4vpPresenter {
	validation := RequestObjectValidationOptions{
		TrustAnchors:         []*x509.Certificate{f.root},
		Now:                  func() time.Time { return f.now },
		DeliveredByReference: deliveredByReference,
	}
	return &Oid4vpPresenter{
		HTTPClient:              f.server.Client(),
		RequestObjectValidation: &validation,
		Profile:                 profile.HAIP,
	}
}
