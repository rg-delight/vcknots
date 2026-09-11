package oid4vp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
)

func TestFinalRequestObjectAuthenticatesHashWithoutDNSAndChecksCRL(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["iss"] = map[string]any{"ignored": true}
	claims["client_metadata"] = map[string]any{"jwks": map[string]any{"keys": []any{}}}
	req, err := f.parse(t, claims)
	if err != nil {
		t.Fatal(err)
	}
	proof := req.RequestObjectVerification
	if proof == nil || proof.ClientID != f.clientID() || len(proof.CertificateSHA256) != 2 || proof.RevocationChecked != 1 || proof.RevocationUnadvertised != 0 {
		t.Fatalf("missing authentication evidence: %+v", proof)
	}
	if len(f.leaf.DNSNames) != 0 {
		t.Fatal("fixture must have no DNS SAN")
	}
	f.setCRL(t, true)
	_, err = f.parse(t, claims)
	var crlErr *commonX509.CRLCheckError
	if !errors.As(err, &crlErr) || crlErr.Kind != commonX509.CRLErrorRevoked {
		t.Fatalf("revoked signer must be rejected on the next operation: %v", err)
	}
}

func TestFinalRequestObjectClaims(t *testing.T) {
	f := newRequestObjectFixture(t)
	tests := []struct {
		name      string
		mutate    func(map[string]any)
		wantError bool
	}{
		{"optional dates absent", func(c map[string]any) {}, false},
		{"expired", func(c map[string]any) { c["exp"] = f.now.Add(-time.Second).Unix() }, true},
		{"expiration boundary", func(c map[string]any) { c["exp"] = f.now.Unix() }, true},
		{"future nbf", func(c map[string]any) { c["nbf"] = f.now.Add(time.Second).Unix() }, true},
		{"nbf boundary", func(c map[string]any) { c["nbf"] = f.now.Unix() }, false},
		{"fractional expiration", func(c map[string]any) { c["exp"] = float64(f.now.Unix()) + 0.5 }, false},
		{"fractional nbf", func(c map[string]any) { c["nbf"] = float64(f.now.Unix()) + 0.5 }, true},
		{"iat is not max age policy", func(c map[string]any) { c["iat"] = f.now.Add(time.Hour).Unix() }, false},
		{"string exp", func(c map[string]any) { c["exp"] = "2000000000" }, true},
		{"null nbf", func(c map[string]any) { c["nbf"] = nil }, true},
		{"string iat", func(c map[string]any) { c["iat"] = "yesterday" }, true},
		{"missing audience", func(c map[string]any) { delete(c, "aud") }, true},
		{"wrong audience", func(c map[string]any) { c["aud"] = "another-wallet" }, true},
		{"audience array", func(c map[string]any) { c["aud"] = []string{"another-wallet", "https://self-issued.me/v2"} }, false},
		{"invalid audience array member", func(c map[string]any) { c["aud"] = []any{1, "https://self-issued.me/v2"} }, true},
		{"outer client mismatch", func(c map[string]any) { c["client_id"] = "x509_hash:another" }, true},
		{"nonstring nonce", func(c map[string]any) { c["nonce"] = 42 }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := f.claims()
			tt.mutate(claims)
			_, err := f.parse(t, claims)
			if (err != nil) != tt.wantError {
				t.Fatalf("want error=%v, got %v", tt.wantError, err)
			}
		})
	}
}

func TestFinalRequestObjectExplicitAudienceClockAndAlgorithms(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["aud"] = "https://wallet.example"
	claims["exp"] = f.now.Add(-time.Second).Unix()
	options := f.options()
	options.WalletAudience = []string{"https://wallet.example"}
	options.ClockSkew = 2 * time.Second
	p := f.presenter()
	p.RequestObjectValidation = &options
	uri := "openid4vp://authorize?" + url.Values{"client_id": []string{f.clientID()}, "request": []string{f.sign(t, claims, nil)}}.Encode()
	if _, err := p.ParsePresentationRequest(uri); err != nil {
		t.Fatal(err)
	}
	options.SigningAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
	if _, err := p.ParsePresentationRequest(uri); err == nil {
		t.Fatal("algorithm outside caller allowlist was accepted")
	}
	options.SigningAlgorithms = nil
	options.ClockSkew = -time.Second
	if _, err := p.ParsePresentationRequest(uri); err == nil {
		t.Fatal("negative clock skew accepted")
	}
}

func TestFinalRequestObjectRejectsUntrustedOrUnprovenAuthentication(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	uri := "openid4vp://authorize?" + url.Values{"client_id": []string{f.clientID()}, "request": []string{f.sign(t, claims, nil)}}.Encode()
	for _, insecure := range []bool{false, true} {
		p := &Oid4vpPresenter{HTTPClient: f.server.Client(), InsecureSkipX509Verify: insecure}
		if _, err := p.ParsePresentationRequest(uri); err == nil {
			t.Fatalf("untrusted leaf accepted with insecure=%v", insecure)
		}
	}
	other := newRequestObjectFixture(t)
	opts := other.options()
	p := f.presenter()
	p.RequestObjectValidation = &opts
	if _, err := p.ParsePresentationRequest(uri); err == nil {
		t.Fatal("unrelated root accepted")
	}
	for _, prefix := range []string{"x509_hash:any", "x509_san_dns:verifier.example"} {
		unsigned := "openid4vp://authorize?" + url.Values{
			"client_id": []string{prefix}, "response_type": []string{"vp_token"}, "response_mode": []string{"direct_post"},
			"response_uri": []string{f.server.URL + "/unexpected-post"}, "nonce": []string{"n"}, "dcql_query": []string{`{"credentials":[{"id":"q","format":"jwt_vc_json"}]}`},
		}.Encode()
		if _, err := f.presenter().ParsePresentationRequest(unsigned); err == nil {
			t.Fatal("unsigned X.509 client accepted")
		}
	}
	claims["client_id"] = "redirect_uri:https://verifier.example/response"
	claims["client_metadata"] = map[string]any{"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, Algorithm: "ES256"}}}}
	token := f.sign(t, claims, (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt"))
	uri = "openid4vp://authorize?" + url.Values{
		"client_id": []string{"redirect_uri:https://verifier.example/response"},
		"request":   []string{token},
	}.Encode()
	_, err := f.presenter().ParsePresentationRequest(uri)
	if err == nil || !strings.Contains(err.Error(), "no configured authentication method") {
		t.Fatalf("self-asserted metadata signing key accepted: %v", err)
	}
}

func TestFinalRequestObjectDNSBindingUsesResponseURIForBothPostModes(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	for _, mode := range []string{"direct_post", "direct_post.jwt", "fragment"} {
		t.Run(mode, func(t *testing.T) {
			claims := f.claims()
			claims["client_id"] = "x509_san_dns:verifier.example"
			claims["response_mode"] = mode
			bound := "response_uri"
			if mode == "fragment" {
				delete(claims, "response_uri")
				bound = "redirect_uri"
			}
			claims[bound] = "https://verifier.example/response"
			parse := func() error {
				uri := "openid4vp://authorize?" + url.Values{
					"client_id": []string{"x509_san_dns:verifier.example"},
					"request":   []string{f.sign(t, claims, nil)},
				}.Encode()
				_, err := f.presenter().ParsePresentationRequest(uri)
				return err
			}
			if err := parse(); err != nil {
				t.Fatal(err)
			}
			claims[bound] = "https://other.example/response"
			if err := parse(); err == nil {
				t.Fatal("endpoint host mismatch accepted")
			}
		})
	}
}

func TestFinalRequestObjectTypAndSignature(t *testing.T) {
	f := newRequestObjectFixture(t)
	for _, typ := range []string{"", "JWT", "oauth-authz-req+jwt"} {
		opts := (&jose.SignerOptions{}).WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
		if typ != "" {
			opts.WithType(jose.ContentType(typ))
		}
		token := f.sign(t, f.claims(), opts)
		uri := "openid4vp://authorize?" + url.Values{"client_id": []string{f.clientID()}, "request": []string{token}}.Encode()
		_, err := f.presenter().ParsePresentationRequest(uri)
		if (err != nil) != (typ != "oauth-authz-req+jwt") {
			t.Fatalf("typ=%q err=%v", typ, err)
		}
	}
	token := f.sign(t, f.claims(), nil)
	parts := strings.Split(token, ".")
	tampered := f.claims()
	tampered["nonce"] = "changed-after-signing"
	raw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(raw)
	tamperedURI := "openid4vp://authorize?" + url.Values{"client_id": []string{f.clientID()}, "request": []string{strings.Join(parts, ".")}}.Encode()
	if _, err := f.presenter().ParsePresentationRequest(tamperedURI); err == nil {
		t.Fatal("tampered Request Object accepted")
	}
}

func TestFinalRequestObjectByReference(t *testing.T) {
	f := newRequestObjectFixture(t)
	token := f.sign(t, f.claims(), nil)
	for _, method := range []string{"get", "post"} {
		t.Run(method, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.ToLower(r.Method) != method {
					t.Errorf("wrong request URI method: %s", r.Method)
				}
				body := token
				if method == "post" {
					// OID4VP 1.0 §5.10.1: the Request Object must echo the
					// wallet_nonce the Wallet sent in the POST body.
					if err := r.ParseForm(); err != nil {
						t.Errorf("failed to parse POST form: %v", err)
					}
					claims := f.claims()
					claims["wallet_nonce"] = r.Form.Get("wallet_nonce")
					body = f.sign(t, claims, nil)
				}
				w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			uri := "openid4vp://authorize?" + url.Values{
				"client_id": []string{f.clientID()}, "request_uri": []string{server.URL}, "request_uri_method": []string{method},
			}.Encode()
			req, err := f.presenter().ParsePresentationRequest(uri)
			if err != nil {
				t.Fatal(err)
			}
			if req.RequestObjectVerification == nil || req.RequestObjectVerification.RevocationChecked != 1 {
				t.Fatalf("request URI returned without authentication: %+v", req)
			}
		})
	}
}

func TestFinalRequestObjectRequiresOuterClientID(t *testing.T) {
	f := newRequestObjectFixture(t)
	uri := "openid4vp://authorize?request=" + url.QueryEscape(f.sign(t, f.claims(), nil))
	_, err := f.presenter().ParsePresentationRequest(uri)
	if err == nil || !strings.Contains(err.Error(), "client_id Authorization Request parameter is required with a Request Object") {
		t.Fatalf("missing outer client_id must be rejected: %v", err)
	}
}

func TestFinalRequestObjectRejectsOuterClientIDMismatch(t *testing.T) {
	f := newRequestObjectFixture(t)
	uri := "openid4vp://authorize?" + url.Values{
		"client_id": []string{"x509_hash:not-the-object-client-id"},
		"request":   []string{f.sign(t, f.claims(), nil)},
	}.Encode()
	_, err := f.presenter().ParsePresentationRequest(uri)
	if err == nil || !strings.Contains(err.Error(), "outer client_id does not match request object client_id") {
		t.Fatalf("mismatched outer client_id must be rejected: %v", err)
	}
}

func TestFinalRequestObjectDNSBindingIsCaseInsensitive(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example.test")
	claims := f.claims()
	claims["client_id"] = "x509_san_dns:Verifier.Example.TEST"
	claims["response_mode"] = "direct_post"
	claims["response_uri"] = "https://VERIFIER.example.test/response"
	uri := "openid4vp://authorize?" + url.Values{
		"client_id": []string{"x509_san_dns:Verifier.Example.TEST"},
		"request":   []string{f.sign(t, claims, nil)},
	}.Encode()
	if _, err := f.presenter().ParsePresentationRequest(uri); err != nil {
		t.Fatalf("case-insensitive DNS binding rejected: %v", err)
	}
}

func TestFinalRequestObjectRejectsEmbeddedRequestParameters(t *testing.T) {
	f := newRequestObjectFixture(t)
	for _, key := range []string{"request", "request_uri"} {
		t.Run(key, func(t *testing.T) {
			claims := f.claims()
			claims[key] = "https://verifier.example/request"
			uri := "openid4vp://authorize?" + url.Values{
				"client_id": []string{f.clientID()},
				"request":   []string{f.sign(t, claims, nil)},
			}.Encode()
			_, err := f.presenter().ParsePresentationRequest(uri)
			if err == nil || !strings.Contains(err.Error(), "request object must not contain request or request_uri") {
				t.Fatalf("embedded %s must be rejected: %v", key, err)
			}
		})
	}
}

func TestFinalRequestObjectURIResponseIsBounded(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write(bytes.Repeat([]byte("a"), 1<<20+10))
	}))
	defer server.Close()
	f := newRequestObjectFixture(t)
	p := f.presenter()
	p.HTTPClient = server.Client()
	uri := "openid4vp://authorize?" + url.Values{
		"client_id":   []string{f.clientID()},
		"request_uri": []string{server.URL},
	}.Encode()
	_, err := p.ParsePresentationRequest(uri)
	if err == nil || !strings.Contains(err.Error(), "request_uri response exceeds 1 MiB") {
		t.Fatalf("oversized request_uri response must be rejected: %v", err)
	}
}
