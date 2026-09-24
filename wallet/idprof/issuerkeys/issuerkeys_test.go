package issuerkeys

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
)

// ladderFixture is the world one ladder case runs in: an https origin that
// hosts the issuer, the DID documents and the well-known documents, and the
// keys an issuer might sign with.
type ladderFixture struct {
	origin *testOrigin
	// signer is the issuer's signing key, `kid` "issuer-key-1".
	signer testKey
	// decoy is a key nobody signed with.
	decoy testKey
	// issuer is an Issuer identifier with a path, hosted by origin.
	issuer string
	// credentialIssuer is the Credential Issuer identifier of the issuance,
	// the same identifier as issuer.
	credentialIssuer string
}

func newLadderFixture(t *testing.T) *ladderFixture {
	t.Helper()
	origin := newTestOrigin(t)
	return &ladderFixture{
		origin:           origin,
		signer:           newES256Key(t, "issuer-key-1"),
		decoy:            newES256Key(t, "decoy-key"),
		issuer:           origin.url() + "/tenant",
		credentialIssuer: origin.url() + "/tenant",
	}
}

// sdJWTRequest is an SD-JWT VC signed by f.signer under f.issuer.
func (f *ladderFixture) sdJWTRequest() Request {
	return Request{
		Issuer:           f.issuer,
		KeyID:            "issuer-key-1",
		Algorithm:        "ES256",
		CredentialFormat: FormatSDJWTVC,
		CredentialIssuer: f.credentialIssuer,
	}
}

// jwtVCRequest is a W3C JWT VC signed by f.signer under the DID didValue.
func (f *ladderFixture) jwtVCRequest(didValue, kid string) Request {
	return Request{
		Issuer:           didValue,
		KeyID:            kid,
		Algorithm:        "ES256",
		CredentialFormat: FormatJWTVCJSON,
		CredentialIssuer: f.credentialIssuer,
		Payload:          map[string]any{"iss": didValue, "vc": map[string]any{"issuer": didValue}},
	}
}

// originString is the RFC 6454 serialization of the fixture origin.
func (f *ladderFixture) originString() string { return f.origin.url() }

// didWebDocument is a DID document for didValue whose assertionMethod refers
// to the verification method fragment with key.
func didWebDocument(t *testing.T, didValue, fragment string, key jose.JSONWebKey) map[string]any {
	t.Helper()
	id := didValue + "#" + fragment
	return map[string]any{
		"id": didValue,
		"verificationMethod": []any{map[string]any{
			"id": id, "type": "JsonWebKey2020", "controller": didValue, "publicKeyJwk": jwkMap(t, key),
		}},
		"assertionMethod": []any{id},
	}
}

type wantDiagnostic struct {
	attempted  bool
	count      int
	failure    string
	disabledBy []string
}

type ladderCase struct {
	name       string
	mechanisms func(*Mechanisms)
	maxBytes   int64
	arrange    func(t *testing.T, f *ladderFixture) Request
	// wantErr is the sentinel the error must match, nil for a resolution.
	wantErr        error
	wantMechanisms []Mechanism
	wantKeyIDs     []string
	wantDNSName    string
	diagnostics    map[string]wantDiagnostic
	check          func(t *testing.T, f *ladderFixture, resolution *Resolution, err error)
}

func runLadderCases(t *testing.T, cases []ladderCase) {
	t.Helper()
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newLadderFixture(t)
			mechanisms := allMechanisms()
			if test.mechanisms != nil {
				test.mechanisms(&mechanisms)
			}
			resolver := f.origin.resolver(mechanisms)
			resolver.MaxDocumentBytes = test.maxBytes
			request := test.arrange(t, f)

			resolution, err := resolver.Resolve(context.Background(), request)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("Resolve error = %v, want %v", err, test.wantErr)
				}
			} else if err != nil {
				t.Fatalf("Resolve failed: %v", err)
			}
			if test.wantErr == nil {
				if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, test.wantMechanisms) {
					t.Errorf("candidate mechanisms = %v, want %v", got, test.wantMechanisms)
				}
				if test.wantKeyIDs != nil {
					var got []string
					for _, candidate := range resolution.Candidates {
						got = append(got, candidate.Key.KeyID)
					}
					if !slices.Equal(got, test.wantKeyIDs) {
						t.Errorf("candidate key IDs = %v, want %v", got, test.wantKeyIDs)
					}
				}
				if resolution.IssuerDNSName != test.wantDNSName {
					t.Errorf("IssuerDNSName = %q, want %q", resolution.IssuerDNSName, test.wantDNSName)
				}
			}
			diagnostics := diagnosticsOf(t, resolution, err)
			for rung, want := range test.diagnostics {
				got := diagnosticFor(t, diagnostics, rung)
				if got.Attempted != want.attempted || got.CandidateCount != want.count || got.Failure != want.failure || !slices.Equal(got.DisabledBy, want.disabledBy) {
					t.Errorf("%s diagnostic = %+v, want %+v", rung, got, want)
				}
			}
			assertDiagnosticsCarryNoSecrets(t, f, diagnostics, err)
			if test.check != nil {
				test.check(t, f, resolution, err)
			}
		})
	}
}

// assertDiagnosticsCarryNoSecrets checks that nothing the ladder reports names
// the origin or carries key material: a diagnostic is rendered and logged.
func assertDiagnosticsCarryNoSecrets(t *testing.T, f *ladderFixture, diagnostics []MechanismDiagnostic, err error) {
	t.Helper()
	coordinates := jwkMap(t, f.signer.public)["x"].(string)
	texts := []string{}
	for _, diagnostic := range diagnostics {
		texts = append(texts, diagnostic.Failure)
	}
	if err != nil {
		texts = append(texts, err.Error())
	}
	for _, text := range texts {
		if strings.Contains(text, f.origin.hostPort()) || strings.Contains(text, coordinates) ||
			strings.Contains(text, "did:jwk:") || strings.Contains(text, "did:key:") || strings.Contains(text, "%3A") {
			t.Errorf("diagnostic text %q carries a URL, a DID or key material", text)
		}
	}
}

func TestJWTVCIssuerMetadataRung(t *testing.T) {
	t.Parallel()
	runLadderCases(t, []ladderCase{
		{
			name: "a path-suffixed Issuer identifier reads the path-suffixed well-known document",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer, "jwks": jwksObject(t, f.signer.public),
				})
				return f.sdJWTRequest()
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata},
			wantKeyIDs:     []string{"issuer-key-1"},
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, count: 1},
				RungIssuerMetadataJWKS:  {failure: "issuer metadata carries no signing key"},
			},
			check: func(t *testing.T, f *ladderFixture, resolution *Resolution, _ error) {
				if f.origin.requested("/.well-known/jwt-vc-issuer/tenant") != 1 {
					t.Errorf("path-suffixed document was not requested")
				}
				if got := resolution.Candidates[0].Issuer; got != f.issuer {
					t.Errorf("candidate issuer = %q, want %q", got, f.issuer)
				}
			},
		},
		{
			name: "a host-only Issuer identifier reads the bare well-known document",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.Issuer = f.origin.url()
				f.origin.json(t, "/.well-known/jwt-vc-issuer", map[string]any{
					"issuer": request.Issuer, "jwks": jwksObject(t, f.signer.public),
				})
				return request
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata},
		},
		{
			name: "jwks_uri is followed when remote key sets are enabled",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer, "jwks_uri": f.origin.url() + "/jwks.json",
				})
				f.origin.json(t, "/jwks.json", jwksObject(t, f.signer.public))
				return f.sdJWTRequest()
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata},
		},
		{
			name:       "jwks_uri is not followed when remote key sets are disabled, and the switch is named",
			mechanisms: func(m *Mechanisms) { m.RemoteJWKS = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer, "jwks_uri": f.origin.url() + "/jwks.json",
				})
				f.origin.json(t, "/jwks.json", jwksObject(t, f.signer.public))
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "jwt-vc-issuer metadata carries no inline jwks", disabledBy: []string{SwitchRemoteJWKS}},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requested("/jwks.json") != 0 {
					t.Errorf("jwks_uri was requested although RemoteJWKS is off")
				}
			},
		},
		{
			name: "an issuer member that is not exactly the credential iss is refused",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer + "/", "jwks": jwksObject(t, f.signer.public),
				})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "jwt-vc-issuer metadata names another issuer"},
			},
		},
		{
			name: "a redirect is refused and its target never requested",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.set("/.well-known/jwt-vc-issuer/tenant", testRoute{
					status: 302, headers: map[string]string{"Location": f.origin.url() + "/elsewhere"},
				})
				f.origin.json(t, "/elsewhere", map[string]any{"issuer": f.issuer, "jwks": jwksObject(t, f.signer.public)})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "redirects are not allowed"},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requested("/elsewhere") != 0 {
					t.Errorf("redirect target was requested")
				}
			},
		},
		{
			name: "a response not labelled as JSON is refused",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.set("/.well-known/jwt-vc-issuer/tenant", testRoute{contentType: "text/plain", body: []byte(`{}`)})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "response is not labelled as JSON"},
			},
		},
		{
			name: "a media type that merely contains application/json is refused",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.set("/.well-known/jwt-vc-issuer/tenant", testRoute{contentType: "application/jsonx", body: []byte(`{}`)})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "response is not labelled as JSON"},
			},
		},
		{
			name: "a jwks_uri served as a JWK Set media type is read",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer, "jwks_uri": f.origin.url() + "/jwks.json",
				})
				body, err := json.Marshal(jwksObject(t, f.signer.public))
				if err != nil {
					t.Fatal(err)
				}
				f.origin.set("/jwks.json", testRoute{contentType: "application/jwk-set+json", body: body})
				return f.sdJWTRequest()
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata},
		},
		{
			name: "an error status is reported with its code only",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "fetch failed: HTTP 404"},
			},
		},
		{
			name:     "a declared oversized document is refused before it is read",
			maxBytes: 512,
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.set("/.well-known/jwt-vc-issuer/tenant", testRoute{
					contentType: "application/json", body: []byte(`{}`),
					headers: map[string]string{"Content-Length": "513"},
				})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "response is too large"},
			},
		},
		{
			name:     "an undeclared oversized document is cut off while it is read",
			maxBytes: 512,
			arrange: func(t *testing.T, f *ladderFixture) Request {
				body := `{"issuer":"` + f.issuer + `","padding":"` + strings.Repeat("a", 2048) + `"}`
				f.origin.set("/.well-known/jwt-vc-issuer/tenant", testRoute{contentType: "application/json", body: []byte(body), chunked: true})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "response is too large"},
			},
		},
		{
			name: "a document whose key set holds no key is not usable",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{"issuer": f.issuer, "jwks": map[string]any{"keys": []any{}}})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "jwks carries no readable public key"},
			},
		},
		{
			name: "every key stays a candidate after a stale kid match, the named key first",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer,
					"jwks":   jwksObject(t, f.signer.withKeyID("rotated-key", ""), f.decoy.withKeyID("issuer-key-1", "")),
				})
				return f.sdJWTRequest()
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata, MechanismJWTVCIssuerMetadata},
			wantKeyIDs:     []string{"issuer-key-1", "rotated-key"},
		},
		{
			name: "a key that states another algorithm is dropped",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				ed := newEd25519Key(t, "ed-key")
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer,
					"jwks":   jwksObject(t, ed.withKeyID("ed-key", "EdDSA"), f.signer.withKeyID("issuer-key-1", "ES256")),
				})
				return f.sdJWTRequest()
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata},
			wantKeyIDs:     []string{"issuer-key-1"},
		},
		{
			name: "the rung does not apply to W3C JWT VC, and nothing is requested",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.CredentialFormat = FormatJWTVCJSON
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {failure: "not applicable for this credential format"},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("requests were made: %d", f.origin.requestCount())
				}
			},
		},
		{
			name:       "a switched-off rung names its switch and requests nothing",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {failure: failureDisabled, disabledBy: []string{SwitchJWTVCIssuerMetadata}},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("requests were made: %d", f.origin.requestCount())
				}
			},
		},
		{
			name: "an http Issuer identifier is refused without AllowHTTP",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.Issuer = "http://" + f.origin.hostPort() + "/tenant"
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "issuer identifier is not https"},
			},
		},
		{
			name: "an Issuer identifier with a query is refused",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.Issuer = f.issuer + "?tenant=a"
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "issuer identifier carries a query or fragment"},
			},
		},
		{
			name: "a jwks_uri with a fragment is refused and not requested",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer, "jwks_uri": f.origin.url() + "/jwks.json#keys",
				})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "issuer identifier carries a query or fragment"},
			},
		},
	})
}

func TestJWTVCIssuerMetadataOverPlainHTTP(t *testing.T) {
	t.Parallel()
	origin := newPlainTestOrigin(t)
	signer := newES256Key(t, "issuer-key-1")
	issuer := origin.url() + "/tenant"
	origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{"issuer": issuer, "jwks": jwksObject(t, signer.public)})
	request := Request{Issuer: issuer, Algorithm: "ES256", CredentialFormat: FormatSDJWTVCDraft, CredentialIssuer: issuer}

	refusing := &Resolver{HTTPClient: origin.server.Client(), Mechanisms: allMechanisms()}
	if _, err := refusing.Resolve(context.Background(), request); !errors.Is(err, ErrNoIssuerKeyResolved) {
		t.Fatalf("Resolve without AllowHTTP = %v, want ErrNoIssuerKeyResolved", err)
	}
	if origin.requestCount() != 0 {
		t.Fatalf("an http origin was requested without AllowHTTP")
	}

	allowing := &Resolver{HTTPClient: origin.server.Client(), Mechanisms: allMechanisms(), AllowHTTP: true}
	resolution, err := allowing.Resolve(context.Background(), request)
	if err != nil {
		t.Fatalf("Resolve with AllowHTTP failed: %v", err)
	}
	if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismJWTVCIssuerMetadata}) {
		t.Fatalf("candidate mechanisms = %v", got)
	}
}

func TestX5CRung(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, "root")
	leaf := newTestLeaf(t, ca, "127.0.0.1")
	runLadderCases(t, []ladderCase{
		{
			name: "an SD-JWT VC chain reports the Issuer identifier host",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			wantDNSName:    "127.0.0.1",
			diagnostics: map[string]wantDiagnostic{
				RungX5C: {attempted: true, count: 1},
			},
		},
		{
			name:       "a switched-off x5c rung names its switch",
			mechanisms: func(m *Mechanisms) { m.X5C = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungX5C: {failure: failureDisabled, disabledBy: []string{SwitchX5C}},
			},
		},
		{
			name: "no x5c header is reported as not present",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungX5C: {failure: "not present"},
			},
		},
		{
			name: "a chain longer than sixteen certificates is treated as absent",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				for range 17 {
					request.X5C = append(request.X5C, x5cOf(leaf)...)
				}
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungX5C: {failure: "not present"},
			},
		},
		{
			name: "a W3C JWT VC signer must claim to be the Credential Issuer",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.CredentialFormat = FormatJWTVCJSON
				request.Issuer = f.origin.url() + "/other"
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungX5C:                {failure: "issuer must match credential issuer metadata"},
				RungIssuerMetadataJWKS: {failure: "issuer is not the credential issuer"},
			},
		},
		{
			name: "a W3C JWT VC signed as the Credential Issuer reports its host",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.CredentialFormat = FormatJWTVCJSON
				request.Issuer = f.credentialIssuer
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			wantDNSName:    "127.0.0.1",
		},
		{
			name: "no rung applies to a Data Integrity credential",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.CredentialFormat = FormatLDPVC
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungX5C:                 {failure: "not applicable for this credential format"},
				RungJWTVCIssuerMetadata: {failure: "not applicable for this credential format"},
			},
		},
		{
			name: "an http Issuer identifier reports no DNS name without AllowHTTP",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.Issuer = "http://issuer.example.test/tenant"
				request.CredentialIssuer = request.Issuer
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			mechanisms:     func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungX5C: {failure: "issuer identifier is not https"},
			},
		},
	})
}

func TestIssuerMetadataRung(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, "root")
	leaf := newTestLeaf(t, ca, "127.0.0.1")
	runLadderCases(t, []ladderCase{
		{
			name:       "every metadata key is tried after a stale kid match, the named key first",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.IssuerMetadataJWKS = keySet(f.signer.withKeyID("rotated-key", ""), f.decoy.withKeyID("issuer-key-1", ""))
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS, MechanismCredentialIssuerMetadataJWKS},
			wantKeyIDs:     []string{"issuer-key-1", "rotated-key"},
			diagnostics: map[string]wantDiagnostic{
				RungIssuerMetadataJWKS: {attempted: true, count: 2},
			},
			check: func(t *testing.T, f *ladderFixture, resolution *Resolution, _ error) {
				for _, candidate := range resolution.Candidates {
					if candidate.Issuer != f.credentialIssuer {
						t.Errorf("metadata candidate issuer = %q, want the Credential Issuer", candidate.Issuer)
					}
				}
			},
		},
		{
			name: "a switched-off metadata rung is not resurrected and names its switch",
			mechanisms: func(m *Mechanisms) {
				m.JWTVCIssuerMetadata = false
				m.IssuerMetadataJWKS = false
			},
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.signer.public, leafJWK(leaf, "leaf"))
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {failure: failureDisabled, disabledBy: []string{SwitchJWTVCIssuerMetadata}},
				RungIssuerMetadataJWKS:  {failure: failureDisabled, disabledBy: []string{SwitchIssuerMetadataJWKS}},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("requests were made: %d", f.origin.requestCount())
				}
			},
		},
		{
			name:       "metadata keys for another algorithm only are reported as such",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.IssuerMetadataJWKS = keySet(f.signer.withKeyID("issuer-key-1", "ES384"))
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungIssuerMetadataJWKS: {failure: "no issuer metadata key matches the credential algorithm"},
			},
		},
		{
			name:       "an x5c leaf the metadata names comes before the metadata keys, whatever the kid",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.CredentialFormat = FormatJWTVCJSON
				request.KeyID = "stale-key"
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.decoy.withKeyID("stale-key", ""), leafJWK(leaf, "issuer-key-1"))
				return request
			},
			wantMechanisms: []Mechanism{MechanismX5CMetadataJWKSBinding, MechanismCredentialIssuerMetadataJWKS, MechanismCredentialIssuerMetadataJWKS},
			wantKeyIDs:     []string{"", "stale-key", "issuer-key-1"},
			wantDNSName:    "127.0.0.1",
			diagnostics: map[string]wantDiagnostic{
				RungIssuerMetadataJWKS: {attempted: true, count: 3},
			},
		},
		{
			name: "an x5c leaf binds through the metadata even with the x5c rung switched off",
			mechanisms: func(m *Mechanisms) {
				m.JWTVCIssuerMetadata = false
				m.X5C = false
			},
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(leafJWK(leaf, "issuer-key-1"))
				return request
			},
			wantMechanisms: []Mechanism{MechanismX5CMetadataJWKSBinding, MechanismCredentialIssuerMetadataJWKS},
		},
		{
			name:       "an x5c leaf the metadata does not name adds nothing",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.X5C = x5cOf(leaf)
				request.IssuerMetadataJWKS = keySet(f.decoy.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			wantDNSName:    "127.0.0.1",
		},
		{
			name:       "metadata keys are not attributed to an issuer other than the Credential Issuer",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.Issuer = f.origin.url() + "/other"
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungIssuerMetadataJWKS: {failure: "issuer is not the credential issuer"},
			},
		},
		{
			name:       "an encryption key is never a signature candidate",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				encryption := f.signer.withKeyID("enc-key", "")
				encryption.Use = "enc"
				signing := f.decoy.withKeyID("sig-key", "")
				signing.Use = "sig"
				request.IssuerMetadataJWKS = keySet(encryption, signing)
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			wantKeyIDs:     []string{"sig-key"},
		},
		{
			name:       "a metadata set holding only encryption keys offers nothing",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				encryption := f.signer.withKeyID("enc-key", "")
				encryption.Use = "enc"
				request.IssuerMetadataJWKS = keySet(encryption)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungIssuerMetadataJWKS: {failure: "no issuer metadata key matches the credential algorithm"},
			},
		},
		{
			name:       "a private metadata key is offered as its public half",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.IssuerMetadataJWKS = keySet(jose.JSONWebKey{Key: f.signer.private, KeyID: "issuer-key-1"})
				return request
			},
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			check: func(t *testing.T, _ *ladderFixture, resolution *Resolution, _ error) {
				if !resolution.Candidates[0].Key.IsPublic() {
					t.Errorf("candidate key is not public")
				}
			},
		},
	})
}

func TestDIDRungMethods(t *testing.T) {
	t.Parallel()
	runLadderCases(t, []ladderCase{
		{
			name: "a did:key bound by the issuer metadata",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didKey(t, f.signer.public)
				request := f.jwtVCRequest(didValue, didValue+"#"+strings.TrimPrefix(didValue, "did:key:"))
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, count: 1},
			},
			check: func(t *testing.T, f *ladderFixture, resolution *Resolution, _ error) {
				didValue := didKey(t, f.signer.public)
				if got := resolution.Candidates[0]; got.Issuer != didValue || got.DID != didValue {
					t.Errorf("DID candidate = issuer %q did %q, want %q", got.Issuer, got.DID, didValue)
				}
			},
		},
		{
			name: "a did:key the metadata does not name is DID-only trust",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didKey(t, f.signer.public)
				request := f.jwtVCRequest(didValue, didValue)
				request.IssuerMetadataJWKS = keySet(f.decoy.public)
				request.Payload = nil
				return request
			},
			mechanisms: func(m *Mechanisms) { m.DIDConfiguration = false },
			wantErr:    ErrDIDOnlyTrustUnsupported,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID-only trust not accepted without metadata/config binding", disabledBy: []string{SwitchDIDConfiguration}},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, err error) {
				var didOnly *DIDOnlyTrustError
				if !errors.As(err, &didOnly) || len(didOnly.Diagnostics) != 3 {
					t.Fatalf("DID-only error = %#v, want three diagnostics ending at the DID rung", err)
				}
				if code, _ := common.CodeOf(err); code != "issuer_keys_did_only_trust_unsupported" {
					t.Errorf("code = %q", code)
				}
			},
		},
		{
			name: "a did:jwk with a relative kid bound by the issuer metadata",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				request := f.jwtVCRequest(didValue, "#0")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
		},
		{
			name: "an Ed25519 did:jwk bound by the signed vc.issuer.credential_issuer",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				ed := newEd25519Key(t, "")
				didValue := didJWK(t, ed.public)
				request := f.jwtVCRequest(didValue, didValue+"#0")
				request.Algorithm = "EdDSA"
				request.Payload["vc"] = map[string]any{"issuer": map[string]any{"id": didValue, "credential_issuer": f.credentialIssuer}}
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDCredentialIssuerBinding},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("the credential_issuer binding made %d requests", f.origin.requestCount())
				}
			},
		},
		{
			name: "the credential_issuer binding switched off leaves the DID unbound",
			mechanisms: func(m *Mechanisms) {
				m.CredentialIssuerBinding = false
				m.DIDConfiguration = false
			},
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				request := f.jwtVCRequest(didValue, didValue+"#0")
				request.Payload["vc"] = map[string]any{"issuer": map[string]any{"id": didValue, "credential_issuer": f.credentialIssuer}}
				return request
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID-only trust not accepted without metadata/config binding", disabledBy: []string{SwitchCredentialIssuerBinding, SwitchDIDConfiguration}},
			},
		},
		{
			name:       "a credential_issuer naming another Credential Issuer does not bind",
			mechanisms: func(m *Mechanisms) { m.DIDConfiguration = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				request := f.jwtVCRequest(didValue, didValue+"#0")
				request.Payload["vc"] = map[string]any{"issuer": map[string]any{"id": didValue, "credential_issuer": "https://other.example.test/issuer"}}
				return request
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name:       "the credential_issuer binding does not apply to SD-JWT VC",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				request := f.jwtVCRequest(didValue, didValue+"#0")
				request.CredentialFormat = FormatSDJWTVC
				request.Payload["vc"] = map[string]any{"issuer": map[string]any{"id": didValue, "credential_issuer": f.credentialIssuer}}
				return request
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID-only trust not accepted without metadata/config binding"},
			},
		},
		{
			name:       "a switched-off DID method names its switch and is not DID-only trust",
			mechanisms: func(m *Mechanisms) { m.DIDJWK = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				request := f.jwtVCRequest(didValue, didValue+"#0")
				request.Payload["vc"] = map[string]any{"issuer": map[string]any{"id": didValue, "credential_issuer": f.credentialIssuer}}
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {failure: failureDisabled, disabledBy: []string{SwitchDIDJWK}},
			},
		},
		{
			name: "a DID method this package does not resolve is reported as unsupported",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return f.jwtVCRequest("did:example:issuer", "did:example:issuer#key-1")
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {failure: "DID method is not supported"},
			},
		},
		{
			name: "a kid that is not a DID with a URL issuer",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			mechanisms:     func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungDID: {failure: "issuer is not a DID"},
			},
		},
		{
			name: "no kid and a URL issuer",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.KeyID = ""
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			mechanisms:     func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungDID: {failure: "issuer is not a DID"},
			},
		},
		{
			name: "a kid naming a DID under a URL issuer is not attributed to the issuer",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				request := f.sdJWTRequest()
				request.CredentialFormat = FormatJWTVCJSON
				request.KeyID = didValue + "#0"
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {failure: "kid names a DID but the issuer is not that DID"},
			},
		},
		{
			name: "a kid naming another DID than the issuer yields no DID key",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.jwtVCRequest(didJWK(t, f.decoy.public), didJWK(t, f.signer.public)+"#0")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID:                {failure: "kid names a DID other than the issuer"},
				RungIssuerMetadataJWKS: {failure: "issuer is not the credential issuer"},
			},
		},
	})
}

func TestDIDRungDIDWeb(t *testing.T) {
	t.Parallel()
	runLadderCases(t, []ladderCase{
		{
			name: "a did:web document key bound by the issuer metadata",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.json(t, "/bank/did.json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
			check: func(t *testing.T, f *ladderFixture, resolution *Resolution, _ error) {
				if got := f.origin.accept("/bank/did.json"); got != "application/did+json, application/json" {
					t.Errorf("Accept = %q", got)
				}
				if got, want := resolution.Candidates[0].Key.KeyID, f.origin.didWeb("bank")+"#issuer-key-1"; got != want {
					t.Errorf("DID candidate KeyID = %q, want the verification method id %q", got, want)
				}
			},
		},
		{
			name: "a bare kid narrows the document to its verification method",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				document := didWebDocument(t, didValue, "issuer-key-1", f.signer.public)
				document["assertionMethod"] = append(document["assertionMethod"].([]any), map[string]any{
					"id": didValue + "#decoy", "type": "JsonWebKey2020", "controller": didValue, "publicKeyJwk": jwkMap(t, f.decoy.public),
				})
				f.origin.json(t, "/bank/did.json", document)
				request := f.jwtVCRequest(didValue, "issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public, f.decoy.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, count: 1},
			},
		},
		{
			name: "a relative fragment kid narrows the document to its verification method",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.json(t, "/bank/did.json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, "#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
		},
		{
			name: "a kid naming no verification method of the document yields no DID key",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.json(t, "/bank/did.json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, "#rotated")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID resolved to no verification key"},
			},
		},
		{
			name: "an embedded assertionMethod key",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.json(t, "/bank/did.json", map[string]any{
					"id": didValue,
					"assertionMethod": []any{map[string]any{
						"id": didValue + "#issuer-key-1", "type": "JsonWebKey2020", "controller": didValue, "publicKeyJwk": jwkMap(t, f.signer.public),
					}},
				})
				request := f.jwtVCRequest(didValue, "#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
		},
		{
			name: "the JSON-LD DID document media type is accepted",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.jsonAs(t, "/bank/did.json", "application/did+ld+json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, "#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
		},
		{
			name:       "an authentication-only verification method is never an issuer key",
			mechanisms: func(m *Mechanisms) { m.DIDConfiguration = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				document := didWebDocument(t, didValue, "issuer-key-1", f.signer.public)
				document["authentication"] = document["assertionMethod"]
				delete(document, "assertionMethod")
				f.origin.json(t, "/bank/did.json", document)
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.Payload["vc"] = map[string]any{"issuer": map[string]any{"id": didValue, "credential_issuer": f.credentialIssuer}}
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID resolved to no verification key"},
			},
		},
		{
			name: "a did:web host other than the Credential Issuer's is refused before any request",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := "did:web:other.example.test:bank"
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "did:web host is not the credential issuer host"},
			},
		},
		{
			name: "a did:web on the Credential Issuer's host but another port is refused before any request",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := "did:web:127.0.0.1%3A1:bank"
				f.origin.json(t, "/bank/did.json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "did:web host is not the credential issuer host"},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("requests were made: %d", f.origin.requestCount())
				}
			},
		},
		{
			name: "a did:web document that cannot be fetched yields no DID key",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID resolved to no verification key"},
			},
		},
		{
			name: "a did:web document that is not labelled as JSON yields no DID key",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.set("/bank/did.json", testRoute{contentType: "text/plain", body: []byte(`{}`)})
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID resolved to no verification key"},
			},
		},
		{
			name:     "an oversized did:web document yields no DID key",
			maxBytes: 512,
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.set("/bank/did.json", testRoute{contentType: "application/did+json", body: []byte(`{}`), headers: map[string]string{"Content-Length": "513"}})
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID resolved to no verification key"},
			},
		},
		{
			name: "a did:web redirect is refused and its target never requested",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.set("/bank/did.json", testRoute{status: 302, headers: map[string]string{"Location": f.origin.url() + "/moved/did.json"}})
				f.origin.json(t, "/moved/did.json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requested("/moved/did.json") != 0 {
					t.Errorf("redirect target was requested")
				}
			},
		},
		{
			name: "a did:web document naming another DID yields no DID key",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				document := didWebDocument(t, didValue, "issuer-key-1", f.signer.public)
				document["id"] = f.origin.didWeb("other")
				f.origin.json(t, "/bank/did.json", document)
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
		},
	})
}

func TestDIDRungDIDConfiguration(t *testing.T) {
	t.Parallel()
	const configurationPath = "/.well-known/did-configuration.json"
	// linkage publishes a DID Configuration for the fixture's did:jwk signer,
	// after adjust has changed the Domain Linkage Credential.
	linkage := func(t *testing.T, f *ladderFixture, adjust func(didValue string, header, claims map[string]any) testKey) Request {
		didValue := didJWK(t, f.signer.public)
		header, claims := domainLinkage(didValue, didValue+"#0", f.originString())
		key := f.signer
		if adjust != nil {
			if replacement := adjust(didValue, header, claims); replacement.private != nil {
				key = replacement
			}
		}
		f.origin.json(t, configurationPath, map[string]any{
			"@context":    "https://identity.foundation/.well-known/did-configuration/v1",
			"linked_dids": []any{signJWT(t, key, header, claims)},
		})
		return f.jwtVCRequest(didValue, didValue+"#0")
	}
	didOnly := map[string]wantDiagnostic{
		RungDID: {attempted: true, failure: "DID-only trust not accepted without metadata/config binding"},
	}
	runLadderCases(t, []ladderCase{
		{
			name: "a Domain Linkage Credential from the Credential Issuer's origin binds the DID",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, nil)
			},
			wantMechanisms: []Mechanism{MechanismDIDConfigurationBinding},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requested(configurationPath) != 1 {
					t.Errorf("DID Configuration requested %d times", f.origin.requested(configurationPath))
				}
			},
		},
		{
			name:       "the DID Configuration switched off is never requested",
			mechanisms: func(m *Mechanisms) { m.DIDConfiguration = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, nil)
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID-only trust not accepted without metadata/config binding", disabledBy: []string{SwitchDIDConfiguration}},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("requests were made: %d", f.origin.requestCount())
				}
			},
		},
		{
			name: "a linkage to another origin does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["credentialSubject"].(map[string]any)["origin"] = "https://other.example.test"
					return testKey{}
				})
			},
			wantErr:     ErrDIDOnlyTrustUnsupported,
			diagnostics: didOnly,
		},
		{
			name: "a linkage to the same host on another scheme does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["credentialSubject"].(map[string]any)["origin"] = "http://" + f.origin.hostPort()
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage for another DID does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["credentialSubject"].(map[string]any)["id"] = "did:example:other"
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage whose iss is another DID does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["iss"] = "did:example:other"
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage with a typ header does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, header, _ map[string]any) testKey {
					header["typ"] = "JWT"
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage without a kid does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, header, _ map[string]any) testKey {
					delete(header, "kid")
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "an expired linkage JWT does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["exp"] = testNow.Add(-time.Minute).Unix()
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage JWT whose exp is not a NumericDate does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["exp"] = "2999-01-01"
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage whose expirationDate has passed does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["expirationDate"] = testNow.Add(-time.Minute).Format(time.RFC3339)
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage whose issuanceDate is a bare past date binds",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["issuanceDate"] = "2026-01-01"
					return testKey{}
				})
			},
			wantMechanisms: []Mechanism{MechanismDIDConfigurationBinding},
		},
		{
			name: "a linkage with an unreadable issuanceDate does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["issuanceDate"] = "yesterday"
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage that does not declare DomainLinkageCredential does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, claims map[string]any) testKey {
					claims["vc"].(map[string]any)["type"] = []any{"VerifiableCredential"}
					return testKey{}
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage signed by a key of another DID does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				other := newES256Key(t, "")
				return linkage(t, f, func(_ string, header, _ map[string]any) testKey {
					header["kid"] = didJWK(t, other.public) + "#0"
					return other
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name: "a linkage whose signature does not verify does not bind",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return linkage(t, f, func(_ string, _, _ map[string]any) testKey {
					return f.decoy
				})
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name:       "the DID Configuration does not apply to SD-JWT VC",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := linkage(t, f, nil)
				request.CredentialFormat = FormatSDJWTVC
				return request
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("requests were made: %d", f.origin.requestCount())
				}
			},
		},
		{
			name: "the metadata binding answers before the DID Configuration is requested",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := linkage(t, f, nil)
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requested(configurationPath) != 0 {
					t.Errorf("the DID Configuration was requested although the metadata bound the key")
				}
			},
		},
	})
}

func TestEveryMechanismSwitchedOff(t *testing.T) {
	t.Parallel()
	f := newLadderFixture(t)
	ca := newTestCA(t, "root")
	leaf := newTestLeaf(t, ca, "127.0.0.1")
	didValue := f.origin.didWeb("bank")
	request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
	request.CredentialFormat = FormatSDJWTVC
	request.X5C = x5cOf(leaf)
	request.IssuerMetadataJWKS = keySet(f.signer.public)

	// Only the x5c rung left standing: an X.509-only issuer policy.
	resolver := f.origin.resolver(Mechanisms{X5C: true})
	_, err := resolver.Resolve(context.Background(), request)
	if !errors.Is(err, ErrNoIssuerKeyResolved) {
		t.Fatalf("Resolve error = %v, want ErrNoIssuerKeyResolved", err)
	}
	if f.origin.requestCount() != 0 {
		t.Fatalf("requests were made with every networked mechanism off: %d", f.origin.requestCount())
	}
	diagnostics := diagnosticsOf(t, nil, err)
	want := map[string][]string{
		RungX5C:                 nil,
		RungJWTVCIssuerMetadata: {SwitchJWTVCIssuerMetadata},
		RungDID:                 {SwitchDIDWeb},
		RungIssuerMetadataJWKS:  {SwitchIssuerMetadataJWKS},
	}
	for rung, disabledBy := range want {
		if got := diagnosticFor(t, diagnostics, rung).DisabledBy; !slices.Equal(got, disabledBy) {
			t.Errorf("%s DisabledBy = %v, want %v", rung, got, disabledBy)
		}
	}
	if code, _ := common.CodeOf(err); code != "issuer_keys_unresolved" {
		t.Errorf("code = %q", code)
	}
}

func TestResolveHonoursContext(t *testing.T) {
	t.Parallel()
	f := newLadderFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.origin.resolver(allMechanisms()).Resolve(ctx, f.sdJWTRequest())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve error = %v, want context.Canceled", err)
	}
}

func TestInjectedDIDResolverReceivesTheDID(t *testing.T) {
	t.Parallel()
	signer := newES256Key(t, "")
	var resolved []string
	resolver := &Resolver{
		Mechanisms: allMechanisms(),
		DID: didResolverFunc(func(_ context.Context, didValue string) (*jose.JSONWebKeySet, error) {
			resolved = append(resolved, didValue)
			return keySet(signer.withKeyID(didValue+"#0", "")), nil
		}),
	}
	didValue := "did:key:zDnaeFake"
	resolution, err := resolver.Resolve(context.Background(), Request{
		Issuer: didValue, KeyID: didValue + "#0", Algorithm: "ES256",
		CredentialFormat: FormatJWTVCJSON, CredentialIssuer: "https://issuer.example.test",
		IssuerMetadataJWKS: keySet(signer.public),
	})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !slices.Equal(resolved, []string{didValue}) {
		t.Errorf("resolved DIDs = %v", resolved)
	}
	if resolution.Candidates[0].Mechanism != MechanismDIDMetadataBinding {
		t.Errorf("first candidate = %v", resolution.Candidates[0].Mechanism)
	}
}

type didResolverFunc func(context.Context, string) (*jose.JSONWebKeySet, error)

func (f didResolverFunc) Resolve(ctx context.Context, didValue string) (*jose.JSONWebKeySet, error) {
	return f(ctx, didValue)
}

func TestJWTVCIssuerMetadataURL(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"https://issuer.example.test":             "https://issuer.example.test/.well-known/jwt-vc-issuer",
		"https://issuer.example.test/":            "https://issuer.example.test/.well-known/jwt-vc-issuer",
		"https://issuer.example.test/tenant":      "https://issuer.example.test/.well-known/jwt-vc-issuer/tenant",
		"https://issuer.example.test/a/b/":        "https://issuer.example.test/.well-known/jwt-vc-issuer/a/b",
		"https://issuer.example.test:8443/tenant": "https://issuer.example.test:8443/.well-known/jwt-vc-issuer/tenant",
	}
	for issuer, want := range tests {
		parsed, err := url.Parse(issuer)
		if err != nil {
			t.Fatal(err)
		}
		if got := jwtVCIssuerMetadataURL(parsed).String(); got != want {
			t.Errorf("jwtVCIssuerMetadataURL(%q) = %q, want %q", issuer, got, want)
		}
	}
}

func TestOriginAuthority(t *testing.T) {
	t.Parallel()
	tests := []struct{ left, right string }{
		{"https://Issuer.Example.test/a", "https://issuer.example.test:443/b"},
		{"http://issuer.example.test:80/a", "http://issuer.example.test"},
	}
	for _, test := range tests {
		left, _ := url.Parse(test.left)
		right, _ := url.Parse(test.right)
		if originAuthority(left) != originAuthority(right) {
			t.Errorf("originAuthority(%q) != originAuthority(%q)", test.left, test.right)
		}
	}
	left, _ := url.Parse("https://issuer.example.test:8443")
	right, _ := url.Parse("https://issuer.example.test")
	if originAuthority(left) == originAuthority(right) {
		t.Errorf("a non-default port must be part of the authority")
	}
}

func TestVerificationMethodID(t *testing.T) {
	t.Parallel()
	const didValue = "did:web:issuer.example.test"
	tests := map[string]string{
		"":                              "",
		didValue + "#key-1":             didValue + "#key-1",
		"#key-1":                        didValue + "#key-1",
		"key-1":                         didValue + "#key-1",
		"did:web:other.example.test#k":  "",
		"https://issuer.example.test/k": "",
		`a\b`:                           "",
	}
	for kid, want := range tests {
		if got := verificationMethodID(didValue, kid); got != want {
			t.Errorf("verificationMethodID(%q) = %q, want %q", kid, got, want)
		}
	}
}
