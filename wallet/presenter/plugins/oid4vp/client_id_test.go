package oid4vp

import (
	"errors"
	"testing"
)

// TestParseOID4VPClientIDExported pins the exported Client Identifier parse an
// application reads a Client Identifier Prefix with, including the two prefixes
// only the Wallet itself may mint.
func TestParseOID4VPClientIDExported(t *testing.T) {
	testCases := []struct {
		name       string
		clientID   string
		wantPrefix OID4VPClientIDPrefix
		wantOrigin string
		wantX509   bool
	}{
		{name: "x509 san dns", clientID: "x509_san_dns:verifier.example", wantPrefix: OID4VPClientIDPrefixX509SanDNS, wantOrigin: "verifier.example", wantX509: true},
		{name: "x509 hash", clientID: "x509_hash:abcd", wantPrefix: OID4VPClientIDPrefixX509Hash, wantOrigin: "abcd", wantX509: true},
		{name: "redirect uri", clientID: "redirect_uri:https://verifier.example/cb", wantPrefix: OID4VPClientIDPrefixRedirectURI, wantOrigin: "https://verifier.example/cb"},
		{name: "federation", clientID: "openid_federation:https://verifier.example", wantPrefix: OID4VPClientIDPrefixOIDFederation, wantOrigin: "https://verifier.example"},
		{name: "pre registered", clientID: "known-verifier", wantPrefix: OID4VPClientIDPrefixPreRegistered, wantOrigin: "known-verifier"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			parsed, err := ParseOID4VPClientID(testCase.clientID)
			if err != nil {
				t.Fatalf("ParseOID4VPClientID(%q) failed: %v", testCase.clientID, err)
			}
			if parsed.Prefix() != testCase.wantPrefix {
				t.Fatalf("prefix = %q, want %q", parsed.Prefix(), testCase.wantPrefix)
			}
			if parsed.Original() != testCase.wantOrigin {
				t.Fatalf("original = %q, want %q", parsed.Original(), testCase.wantOrigin)
			}
			if parsed.RequiresRequestObjectSignature() != testCase.wantX509 {
				t.Fatalf("RequiresRequestObjectSignature() = %v, want %v", parsed.RequiresRequestObjectSignature(), testCase.wantX509)
			}
		})
	}
}

// TestParseOID4VPClientIDReservedPrefixes keeps the two Wallet-only prefixes
// refused with a code a caller can branch on.
func TestParseOID4VPClientIDReservedPrefixes(t *testing.T) {
	for _, clientID := range []string{"origin:https://verifier.example", "web-origin:https://verifier.example"} {
		if _, err := ParseOID4VPClientID(clientID); !errors.Is(err, ErrClientIDPrefixReserved) {
			t.Fatalf("ParseOID4VPClientID(%q) error = %v, want ErrClientIDPrefixReserved", clientID, err)
		}
	}
}

// TestParseOID4VPClientIDUnknownPrefix keeps an unknown prefix a plain syntax
// error rather than the reserved-prefix verdict.
func TestParseOID4VPClientIDUnknownPrefix(t *testing.T) {
	_, err := ParseOID4VPClientID("made_up:value")
	if err == nil {
		t.Fatal("expected an error for an unsupported Client Identifier Prefix")
	}
	if errors.Is(err, ErrClientIDPrefixReserved) {
		t.Fatalf("unsupported prefix reported as reserved: %v", err)
	}
}

// TestDraft24QueryParamX509ClientIDRefused is the Draft24 half of the OID4VP
// 1.0 §5.9.3 rule the Final parser already applied: an X.509 Client Identifier
// carried in plain query parameters has no signature to authenticate it.
func TestDraft24QueryParamX509ClientIDRefused(t *testing.T) {
	presenter := &Oid4vpPresenter{}
	for _, clientID := range []string{"x509_san_dns:verifier.example", "x509_hash:YWJj"} {
		request := "openid4vp://?response_type=vp_token&client_id=" + clientID +
			"&response_mode=direct_post&response_uri=https://verifier.example/response&nonce=n"
		_, err := presenter.ParseDraft24PresentationRequest(request)
		if !errors.Is(err, ErrRequestObjectSignatureRequired) {
			t.Fatalf("ParseDraft24PresentationRequest(%q) error = %v, want ErrRequestObjectSignatureRequired", clientID, err)
		}
	}
}

// TestFinalQueryParamX509ClientIDRefused keeps the Final parser reporting the
// same condition with the same code.
func TestFinalQueryParamX509ClientIDRefused(t *testing.T) {
	presenter := &Oid4vpPresenter{}
	request := "openid4vp://?response_type=vp_token&client_id=x509_san_dns:verifier.example" +
		"&response_mode=direct_post&response_uri=https://verifier.example/response&nonce=n"
	_, err := presenter.ParsePresentationRequest(request)
	if !errors.Is(err, ErrRequestObjectSignatureRequired) {
		t.Fatalf("ParsePresentationRequest error = %v, want ErrRequestObjectSignatureRequired", err)
	}
}
