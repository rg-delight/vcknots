package issuerkeys

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/credential/statuslist"
	"github.com/trustknots/vcknots/wallet/profile"
)

// The adapter is handed to the checker's hook; this fails to compile if the
// two drift.
var _ statuslist.ResolveIssuerKeysFunc = (&Resolver{}).StatusListKeyFunc(Request{}, nil)

// statusListFixture is an issuer that signs Status List Tokens under an https
// identifier, with a CA that certifies its signing key, and a key of its own
// that no mechanism publishes. Its resolver enables every mechanism and makes
// no network request.
type statusListFixture struct {
	issuer   string
	ca       testCertificate
	leaf     testCertificate
	metadata testKey
	resolver *Resolver
	network  *failingTransport
}

func newStatusListFixture(t *testing.T) *statusListFixture {
	t.Helper()
	ca := newTestCA(t, "status list root")
	network := &failingTransport{}
	return &statusListFixture{
		issuer:   "https://issuer.example.test",
		ca:       ca,
		leaf:     newTestLeaf(t, ca, "issuer.example.test"),
		metadata: newES256Key(t, "metadata-key"),
		network:  network,
		resolver: &Resolver{
			HTTPClient: &http.Client{Transport: network},
			Mechanisms: allMechanisms(),
			Now:        fixedNow,
		},
	}
}

func (f *statusListFixture) template(format string) Request {
	return Request{
		CredentialFormat: format,
		CredentialIssuer: f.issuer,
	}
}

func (f *statusListFixture) trust(anchors ...*x509.Certificate) *X5CTrust {
	return &X5CTrust{TrustAnchors: anchors, AllowUnadvertisedRevocation: true}
}

func statusListHeader(chain ...testCertificate) map[string]any {
	header := map[string]any{"alg": "ES256", "typ": "statuslist+jwt"}
	if len(chain) > 0 {
		values := make([]any, 0, len(chain))
		for _, value := range x5cOf(chain...) {
			values = append(values, value)
		}
		header["x5c"] = values
	}
	return header
}

func keyRequest(issuer string, header map[string]any) statuslist.KeyRequest {
	return statuslist.KeyRequest{Issuer: issuer, Header: header}
}

// TestStatusListKeysX5C covers an https issuer whose token carries x5c: the
// chain is the only key source (SD-JWT VC -19 Section 2.5 and 7.3, ADR-0093),
// and a chain that is not trusted is refused rather than replaced by another
// mechanism.
func TestStatusListKeysX5C(t *testing.T) {
	t.Parallel()

	t.Run("a trusted chain bound to the issuer host is the only candidate", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		keys, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(FormatSDJWTVC), f.trust(f.ca.certificate),
			keyRequest(f.issuer, statusListHeader(f.leaf)))
		if err != nil {
			t.Fatalf("StatusListKeys failed: %v", err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismX5CTrustedChain}) || len(keys) != 1 {
			t.Fatalf("mechanisms = %v, keys = %d", got, len(keys))
		}
		trusted, ok := resolution.CandidateFor(jose.JSONWebKey{Key: f.leaf.certificate.PublicKey})
		if !ok || trusted.Issuer != f.issuer || len(trusted.CertificateSHA256) != 2 || !keys[0].IsPublic() {
			t.Errorf("trusted candidate = %+v, %v", trusted, ok)
		}
		if resolution.IssuerDNSName != "issuer.example.test" || f.network.count() != 0 {
			t.Errorf("IssuerDNSName = %q, requests = %d", resolution.IssuerDNSName, f.network.count())
		}
	})

	// Each of these used to fall through to the ladder's candidates (here the
	// Credential Issuer Metadata `jwks`); an x5c that is present and not
	// trusted now ends the resolution.
	untrusted := []struct {
		name    string
		arrange func(t *testing.T, f *statusListFixture) (*X5CTrust, map[string]any)
		failure string
		cause   error
	}{
		{
			name: "a chain reaching no configured anchor",
			arrange: func(t *testing.T, f *statusListFixture) (*X5CTrust, map[string]any) {
				return f.trust(newTestCA(t, "other root").certificate), statusListHeader(f.leaf)
			},
			failure: failureChainUntrusted,
			cause:   commonX509.ErrNoTrustAnchor,
		},
		{
			name: "no trust anchor configured",
			arrange: func(t *testing.T, f *statusListFixture) (*X5CTrust, map[string]any) {
				return f.trust(), statusListHeader(f.leaf)
			},
			failure: failureChainUntrusted,
		},
		{
			name: "no x5c trust at all",
			arrange: func(t *testing.T, f *statusListFixture) (*X5CTrust, map[string]any) {
				return nil, statusListHeader(f.leaf)
			},
			failure: failureChainUntrusted,
		},
		{
			name: "a leaf that does not name the issuer host",
			arrange: func(t *testing.T, f *statusListFixture) (*X5CTrust, map[string]any) {
				return f.trust(f.ca.certificate), statusListHeader(newTestLeaf(t, f.ca, "other.example.test"))
			},
			failure: "certificate does not name the issuer host",
		},
		{
			name: "a malformed chain",
			arrange: func(t *testing.T, f *statusListFixture) (*X5CTrust, map[string]any) {
				header := statusListHeader()
				header["x5c"] = []any{"not base64 DER"}
				return f.trust(f.ca.certificate), header
			},
			failure: "certificate chain is malformed",
			cause:   commonX509.ErrX5CInvalid,
		},
	}
	for _, test := range untrusted {
		t.Run(test.name+" is refused without falling back", func(t *testing.T) {
			t.Parallel()
			f := newStatusListFixture(t)
			trust, header := test.arrange(t, f)
			keys, _, err := f.resolver.StatusListKeys(context.Background(), f.template(FormatJWTVCJSON), trust, keyRequest(f.issuer, header))
			var unresolved *UnresolvedError
			if keys != nil || !errors.As(err, &unresolved) {
				t.Fatalf("StatusListKeys = %v, %v; want *UnresolvedError", keys, err)
			}
			if test.cause != nil && !errors.Is(err, test.cause) {
				t.Errorf("err = %v, want it to wrap %v", err, test.cause)
			}
			if got := diagnosticFor(t, unresolved.Diagnostics, RungX5C).Failure; got != test.failure {
				t.Errorf("x5c failure = %q, want %q", got, test.failure)
			}
		})
	}

	t.Run("the x5c mechanism switched off refuses a token carrying x5c", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		f.resolver.Mechanisms.X5C = false
		_, _, err := f.resolver.StatusListKeys(context.Background(), f.template(FormatSDJWTVC), f.trust(f.ca.certificate), keyRequest(f.issuer, statusListHeader(f.leaf)))
		var unresolved *UnresolvedError
		if !errors.As(err, &unresolved) {
			t.Fatalf("err = %v", err)
		}
		if diagnostic := diagnosticFor(t, unresolved.Diagnostics, RungX5C); !slices.Equal(diagnostic.DisabledBy, []string{SwitchX5C}) {
			t.Errorf("x5c diagnostic = %+v", diagnostic)
		}
	})

	t.Run("a revocation status that cannot be established ends the verification", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		trust := f.trust(f.ca.certificate)
		trust.AllowUnadvertisedRevocation = false
		keys, _, err := f.resolver.StatusListKeys(context.Background(), f.template(FormatSDJWTVC), trust, keyRequest(f.issuer, statusListHeader(f.leaf)))
		if err == nil || keys != nil || errors.Is(err, ErrNoIssuerKeyResolved) {
			t.Fatalf("StatusListKeys = %v, %v; want the chain refusal", keys, err)
		}
		if code, _ := common.CodeOf(err); code != "x509_chain_revocation_unknown" {
			t.Errorf("code = %q, want x509_chain_revocation_unknown", code)
		}
	})
}

// TestStatusListKeysHAIPRules covers HAIP 1.0 Section 6.1 as the checker hands
// it to the hook in KeyRequest.X5C.
func TestStatusListKeysHAIPRules(t *testing.T) {
	t.Parallel()
	haip := profile.HAIPOptions().StatusListTokenX5C

	t.Run("a chain without the anchor is accepted", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		request := keyRequest(f.issuer, statusListHeader(f.leaf))
		request.X5C = haip
		if _, _, err := f.resolver.StatusListKeys(context.Background(), f.template(FormatSDJWTVC), f.trust(f.ca.certificate), request); err != nil {
			t.Fatal(err)
		}
	})

	for _, test := range []struct {
		name    string
		arrange func(t *testing.T, f *statusListFixture) (*X5CTrust, statuslist.KeyRequest)
	}{
		{
			name: "a chain carrying the trust anchor",
			arrange: func(t *testing.T, f *statusListFixture) (*X5CTrust, statuslist.KeyRequest) {
				return f.trust(f.ca.certificate), keyRequest(f.issuer, statusListHeader(f.leaf, f.ca))
			},
		},
		{
			name: "a self-signed leaf",
			arrange: func(t *testing.T, f *statusListFixture) (*X5CTrust, statuslist.KeyRequest) {
				// Trusted as an anchor itself, so only the rule refuses it.
				root := newTestCA(t, "self-signed signer")
				return f.trust(root.certificate), keyRequest(f.issuer, statusListHeader(root))
			},
		},
		{
			name: "an https issuer without x5c",
			arrange: func(t *testing.T, f *statusListFixture) (*X5CTrust, statuslist.KeyRequest) {
				return f.trust(f.ca.certificate), keyRequest(f.issuer, statusListHeader())
			},
		},
		{
			name: "a DID issuer",
			arrange: func(t *testing.T, f *statusListFixture) (*X5CTrust, statuslist.KeyRequest) {
				didValue := didJWK(t, f.metadata.public)
				return f.trust(f.ca.certificate), keyRequest(didValue, map[string]any{"alg": "ES256", "kid": didValue + "#0"})
			},
		},
	} {
		t.Run(test.name+" is rejected", func(t *testing.T) {
			t.Parallel()
			f := newStatusListFixture(t)
			trust, request := test.arrange(t, f)
			request.X5C = haip
			keys, _, err := f.resolver.StatusListKeys(context.Background(), f.template(FormatSDJWTVC), trust, request)
			if keys != nil || !errors.Is(err, statuslist.ErrStatusListCertificateRejected) {
				t.Fatalf("StatusListKeys = %v, %v; want ErrStatusListCertificateRejected", keys, err)
			}
		})
	}
}

// TestStatusListKeysWebResolution covers an https issuer whose token carries
// no x5c: the keys come from the web-based resolution of the Referenced Token
// (draft-ietf-oauth-status-list-21 Section 11.3), JWT VC Issuer Metadata for
// the SD-JWT VC family, and never from the Credential Issuer Metadata `jwks`.
func TestStatusListKeysWebResolution(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T) (*testOrigin, *Resolver, Request, testKey) {
		origin := newTestOrigin(t)
		signer := newES256Key(t, "status-key")
		template := Request{
			CredentialFormat: FormatSDJWTVC,
			CredentialIssuer: origin.url() + "/tenant",
		}
		return origin, origin.resolver(allMechanisms()), template, signer
	}

	t.Run("JWT VC Issuer Metadata supplies the keys of an SD-JWT VC issuer", func(t *testing.T) {
		t.Parallel()
		origin, resolver, template, signer := setup(t)
		issuer := template.CredentialIssuer
		origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{"issuer": issuer, "jwks": jwksObject(t, signer.public)})
		keys, resolution, err := resolver.StatusListKeys(context.Background(), template, nil,
			keyRequest(issuer, map[string]any{"alg": "ES256", "kid": "status-key"}))
		if err != nil {
			t.Fatal(err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismJWTVCIssuerMetadata}) || len(keys) != 1 || keys[0].KeyID != "status-key" {
			t.Fatalf("mechanisms = %v, keys = %+v", got, keys)
		}
	})

	t.Run("a W3C JWT VC https issuer has no web-based key source", func(t *testing.T) {
		t.Parallel()
		_, resolver, template, _ := setup(t)
		template.CredentialFormat = FormatJWTVCJSON
		_, _, err := resolver.StatusListKeys(context.Background(), template, nil,
			keyRequest(template.CredentialIssuer, map[string]any{"alg": "ES256", "kid": "metadata-key"}))
		var unresolved *UnresolvedError
		if !errors.As(err, &unresolved) {
			t.Fatalf("err = %v, want *UnresolvedError", err)
		}
		if got := diagnosticFor(t, unresolved.Diagnostics, RungJWTVCIssuerMetadata).Failure; got != "not applicable for this credential format" {
			t.Errorf("jwt-vc-issuer failure = %q", got)
		}
	})

	t.Run("an identifier that is neither https nor a DID is not resolved", func(t *testing.T) {
		t.Parallel()
		_, resolver, template, _ := setup(t)
		_, _, err := resolver.StatusListKeys(context.Background(), template, nil, keyRequest("urn:example:issuer", map[string]any{"alg": "ES256"}))
		if !errors.Is(err, ErrNoIssuerKeyResolved) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestStatusListKeysDID covers a DID issuer: its keys count only once a DIF
// Well Known DID Configuration served by the Credential Issuer's origin binds
// the DID, whatever the credential's format - an ldp_vc included, whose Status
// List Token used to be refused as DID-only (audit item M3).
func TestStatusListKeysDID(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T, format string, linked bool) (*Resolver, Request, statuslist.KeyRequest) {
		origin := newTestOrigin(t)
		signer := newES256Key(t, "")
		didValue := didJWK(t, signer.public)
		if linked {
			header, claims := domainLinkage(didValue, didValue+"#0", origin.url())
			origin.json(t, didConfigurationPath, map[string]any{
				"@context":    "https://identity.foundation/.well-known/did-configuration/v1",
				"linked_dids": []any{signJWT(t, signer, header, claims)},
			})
		}
		template := Request{
			CredentialFormat: format,
			CredentialIssuer: origin.url(),
		}
		return origin.resolver(allMechanisms()), template, keyRequest(didValue, map[string]any{"alg": "ES256", "kid": didValue + "#0"})
	}

	for _, format := range []string{FormatLDPVC, FormatJWTVCJSON, FormatSDJWTVC} {
		t.Run("a DID Configuration binds the DID for "+format, func(t *testing.T) {
			t.Parallel()
			resolver, template, request := setup(t, format, true)
			keys, resolution, err := resolver.StatusListKeys(context.Background(), template, nil, request)
			if err != nil {
				t.Fatal(err)
			}
			if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismDIDConfigurationBinding}) || len(keys) != 1 {
				t.Fatalf("mechanisms = %v", got)
			}
			if candidate := resolution.Candidates[0]; candidate.Issuer != request.Issuer || candidate.DID != request.Issuer {
				t.Errorf("candidate = %+v", candidate)
			}
		})
	}

	t.Run("an unbound DID is DID-only trust", func(t *testing.T) {
		t.Parallel()
		resolver, template, request := setup(t, FormatJWTVCJSON, false)
		_, _, err := resolver.StatusListKeys(context.Background(), template, nil, request)
		var didOnly *DIDOnlyTrustError
		if !errors.As(err, &didOnly) {
			t.Fatalf("err = %v, want *DIDOnlyTrustError", err)
		}
	})

	t.Run("the DID Configuration switched off leaves the DID unbound", func(t *testing.T) {
		t.Parallel()
		resolver, template, request := setup(t, FormatLDPVC, true)
		resolver.Mechanisms.DIDConfiguration = false
		_, _, err := resolver.StatusListKeys(context.Background(), template, nil, request)
		var didOnly *DIDOnlyTrustError
		if !errors.As(err, &didOnly) {
			t.Fatalf("err = %v, want *DIDOnlyTrustError", err)
		}
		if diagnostic := diagnosticFor(t, didOnly.Diagnostics, RungDID); !slices.Equal(diagnostic.DisabledBy, []string{SwitchDIDConfiguration}) {
			t.Errorf("DID diagnostic = %+v", diagnostic)
		}
	})

	t.Run("a kid naming another DID is not resolved", func(t *testing.T) {
		t.Parallel()
		resolver, template, request := setup(t, FormatLDPVC, true)
		request.Header = map[string]any{"alg": "ES256", "kid": "did:example:other#0"}
		_, _, err := resolver.StatusListKeys(context.Background(), template, nil, request)
		if !errors.Is(err, ErrNoIssuerKeyResolved) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestStatusListKeysWithoutIssuer covers a credential without `iss`, whose
// Issuer is the subject of its x5c leaf (SD-JWT VC -19 Section 2.5): the
// Status List Token must carry a trusted chain whose leaf has that subject.
func TestStatusListKeysWithoutIssuer(t *testing.T) {
	t.Parallel()

	t.Run("a trusted leaf with the credential issuer's subject is the candidate", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		trust := f.trust(f.ca.certificate)
		trust.IssuerCertificate = newTestLeaf(t, f.ca, "credential.example.test").certificate
		keys, resolution, err := f.resolver.StatusListKeys(context.Background(), f.template(FormatSDJWTVC), trust, keyRequest("", statusListHeader(f.leaf)))
		if err != nil {
			t.Fatal(err)
		}
		if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismX5CTrustedChain}) || len(keys) != 1 {
			t.Fatalf("mechanisms = %v", got)
		}
	})

	for _, test := range []struct {
		name    string
		issuer  func(t *testing.T, f *statusListFixture) *x509.Certificate
		failure string
	}{
		{name: "another subject", issuer: func(t *testing.T, f *statusListFixture) *x509.Certificate {
			other := newTestCA(t, "another issuer")
			return other.certificate
		}, failure: "certificate subject is not the credential issuer"},
		{name: "no issuer certificate", issuer: func(*testing.T, *statusListFixture) *x509.Certificate { return nil }, failure: "credential issuer certificate is not configured"},
	} {
		t.Run(test.name+" is not resolved", func(t *testing.T) {
			t.Parallel()
			f := newStatusListFixture(t)
			trust := f.trust(f.ca.certificate)
			trust.IssuerCertificate = test.issuer(t, f)
			_, _, err := f.resolver.StatusListKeys(context.Background(), f.template(FormatSDJWTVC), trust, keyRequest("", statusListHeader(f.leaf)))
			var unresolved *UnresolvedError
			if !errors.As(err, &unresolved) {
				t.Fatalf("err = %v", err)
			}
			if got := diagnosticFor(t, unresolved.Diagnostics, RungX5C).Failure; got != test.failure {
				t.Errorf("x5c failure = %q, want %q", got, test.failure)
			}
		})
	}

	t.Run("a token without x5c is not resolved", func(t *testing.T) {
		t.Parallel()
		f := newStatusListFixture(t)
		_, _, err := f.resolver.StatusListKeys(context.Background(), f.template(FormatSDJWTVC), f.trust(f.ca.certificate), keyRequest("", statusListHeader()))
		if !errors.Is(err, ErrNoIssuerKeyResolved) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestStatusListKeyFuncWithTheChecker runs the adapter under a HAIP checker,
// end to end: the checker hands its x5c rules to the hook, and the hook's
// anchor refusal reaches the caller as a certificate rejection.
func TestStatusListKeyFuncWithTheChecker(t *testing.T) {
	t.Parallel()
	f := newStatusListFixture(t)
	signer := testKey{private: f.leaf.key, public: jose.JSONWebKey{Key: f.leaf.certificate.PublicKey}, alg: jose.ES256}

	check := func(t *testing.T, chain ...testCertificate) error {
		var token string
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/statuslist+jwt")
			_, _ = w.Write([]byte(token))
		}))
		t.Cleanup(server.Close)
		uri := server.URL + "/status"
		header := map[string]any{"typ": "statuslist+jwt", "x5c": x5cOf(chain...)}
		token = signJWT(t, signer, header, map[string]any{
			"sub": uri, "iat": testNow.Add(-time.Minute).Unix(),
			"status_list": map[string]any{"bits": 1, "lst": "eNrbuRgAAhcBXQ"},
		})
		checker := &statuslist.Checker{
			HTTPClient:        server.Client(),
			Now:               fixedNow,
			Profile:           profile.HAIP(),
			ResolveIssuerKeys: f.resolver.StatusListKeyFunc(f.template(FormatSDJWTVC), f.trust(f.ca.certificate)),
		}
		_, err := checker.Check(context.Background(), f.issuer, map[string]any{"status_list": map[string]any{"uri": uri, "idx": 0}})
		return err
	}

	if err := check(t, f.leaf); err != nil {
		t.Fatalf("a chain without the anchor: %v", err)
	}
	if err := check(t, f.leaf, f.ca); !errors.Is(err, statuslist.ErrStatusListCertificateRejected) {
		t.Fatalf("a chain with the anchor: err = %v, want ErrStatusListCertificateRejected", err)
	}
	if code, _ := common.CodeOf(check(t, f.leaf, f.ca)); code != "status_list_certificate_rejected" {
		t.Fatalf("code = %q", code)
	}
}
