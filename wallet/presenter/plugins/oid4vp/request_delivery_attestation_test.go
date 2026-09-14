package oid4vp

import (
	"net/url"
	"strings"
	"testing"

	"github.com/trustknots/vcknots/wallet/profile"
)

func presenterWithDeliveryAttestation(f *requestObjectFixture, p profile.Profile, attested bool) *Oid4vpPresenter {
	options := f.options()
	options.DeliveredByReference = attested
	return &Oid4vpPresenter{
		HTTPClient:              f.server.Client(),
		RequestObjectValidation: &options,
		Profile:                 p,
	}
}

func parseRequestByValue(t *testing.T, f *requestObjectFixture, p profile.Profile, attested bool) (*CredentialPresentationRequest, error) {
	t.Helper()
	uri := "openid4vp://authorize?" + url.Values{
		"client_id": {f.clientID()},
		"request":   {f.signWithRoot(t, f.claims(), false)},
	}.Encode()
	return presenterWithDeliveryAttestation(f, p, attested).ParsePresentationRequest(uri)
}

func parseRequestByReference(t *testing.T, f *requestObjectFixture, p profile.Profile, attested bool) (*CredentialPresentationRequest, error) {
	t.Helper()
	f.mu.Lock()
	f.requestObject = []byte(f.signWithRoot(t, f.claims(), false))
	f.mu.Unlock()
	uri := "openid4vp://authorize?" + url.Values{
		"client_id":   {f.clientID()},
		"request_uri": {f.server.URL + "/request-object"},
	}.Encode()
	return presenterWithDeliveryAttestation(f, p, attested).ParsePresentationRequest(uri)
}

// TestHAIPRequestDeliveryAttestation covers the caller attestation that lets an
// application re-submit a stored request_uri Request Object with request= while
// satisfying the HAIP §5.1 delivery-by-reference requirement.
func TestHAIPRequestDeliveryAttestation(t *testing.T) {
	t.Run("request= with attestation is accepted and recorded", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		req, err := parseRequestByValue(t, f, profile.HAIP, true)
		if err != nil {
			t.Fatalf("HAIP with DeliveredByReference must accept request=: %v", err)
		}
		proof := req.RequestObjectVerification
		if proof == nil {
			t.Fatal("missing RequestObjectVerification")
		}
		if !proof.DeliveryAttested {
			t.Errorf("DeliveryAttested = false, want true")
		}
		if proof.Delivery != "value" {
			t.Errorf("Delivery = %q, want value", proof.Delivery)
		}
	})

	t.Run("request= without attestation is rejected", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		_, err := parseRequestByValue(t, f, profile.HAIP, false)
		if err == nil || !strings.Contains(err.Error(), "request_uri") {
			t.Fatalf("HAIP must reject request= without attestation: %v", err)
		}
	})

	t.Run("real request_uri never marks the attestation used", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		req, err := parseRequestByReference(t, f, profile.HAIP, true)
		if err != nil {
			t.Fatalf("HAIP request_uri must be accepted: %v", err)
		}
		proof := req.RequestObjectVerification
		if proof == nil {
			t.Fatal("missing RequestObjectVerification")
		}
		if proof.DeliveryAttested {
			t.Errorf("DeliveryAttested = true for request_uri, want false")
		}
		if proof.Delivery != "reference" {
			t.Errorf("Delivery = %q, want reference", proof.Delivery)
		}
	})

	t.Run("Final ignores the attestation", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		if _, err := parseRequestByValue(t, f, profile.Final, false); err != nil {
			t.Fatalf("Final must accept request= without attestation: %v", err)
		}
		req, err := parseRequestByValue(t, f, profile.Final, true)
		if err != nil {
			t.Fatalf("Final must accept request= with attestation: %v", err)
		}
		proof := req.RequestObjectVerification
		if proof == nil {
			t.Fatal("missing RequestObjectVerification")
		}
		if proof.Delivery != "value" {
			t.Errorf("Delivery = %q, want value", proof.Delivery)
		}
		if proof.DeliveryAttested {
			t.Errorf("Final must not mark the HAIP-only attestation as used: %+v", proof)
		}
	})
}

// TestDeliveryAttestationDoesNotSuppressWalletNonceMismatch proves the
// attestation is scoped to the HAIP delivery check: it never stands in for the
// wallet_nonce echo bound to an actual request_uri POST in this process.
func TestDeliveryAttestationDoesNotSuppressWalletNonceMismatch(t *testing.T) {
	f := newRequestObjectFixture(t)
	captured := &capturedRequestURIForm{}
	f.echoNonceHandler(t, captured, func(string) string { return "wrong-nonce" })

	options := f.options()
	options.DeliveredByReference = true
	p := &Oid4vpPresenter{
		HTTPClient:              f.server.Client(),
		RequestObjectValidation: &options,
		Profile:                 profile.HAIP,
		RequestURINonce:         func() (string, error) { return "expected-nonce", nil },
	}

	_, err := f.parseRequestURIPost(t, p)
	if err == nil || !strings.Contains(err.Error(), "Request Object wallet_nonce does not match") {
		t.Fatalf("attestation must not suppress wallet_nonce mismatch: %v", err)
	}
}
