package profile

import "strings"

// Options are the constraints a profile adds to OpenID4VCI 1.0 and OpenID4VP
// 1.0. Each field is one requirement of HAIP 1.0, named by the section that
// states it, and can be applied on its own through Profile.With. The zero
// value adds no constraint: it is OpenID4VCI 1.0 / OpenID4VP 1.0 Final.
//
// Options is comparable, so a Profile is comparable too.
type Options struct {
	// ForbidInsecureTransports refuses the test-only transport escapes of the
	// protocol plugins: Config.Experimental.Transport and the OpenID4VCI
	// receiver's Experimental (package experimental), and AllowHTTP and
	// InsecureSkipX509Verify on the OpenID4VP presenter.
	// HAIP 1.0 §4 (FAPI 2.0 TLS) and §5 (x509_hash Verifier authentication).
	ForbidInsecureTransports bool
	// AllowedCredentialFormats restricts the Credential Format Identifiers a
	// Credential Configuration (OpenID4VCI) or a DCQL Credential Query
	// (OpenID4VP) may use. The zero value restricts nothing.
	// HAIP 1.0 §3, §4 and §5: SD-JWT VC (dc+sd-jwt) or ISO mdoc (mso_mdoc).
	AllowedCredentialFormats CredentialFormats
	// IssuerX5C applies to the issuer signature of an SD-JWT VC being
	// accepted: Require makes a validated x5c chain the only way to
	// authenticate the issuer, ExcludeAnchor refuses a chain carrying a trust
	// anchor, RejectSelfSigned a self-signed leaf.
	// HAIP 1.0 §6.1.1 (Issuer identification and key resolution).
	IssuerX5C X5CRules
	// StatusListTokenX5C applies to the signature of a Status List Token.
	// It is not enforced yet: the status list client does not consult it.
	// HAIP 1.0 §6.1 (IETF SD-JWT VC Profile).
	StatusListTokenX5C X5CRules

	// RequirePAR refuses an authorization server without a Pushed
	// Authorization Request endpoint.
	// HAIP 1.0 §4 (FAPI 2.0 PAR).
	RequirePAR bool
	// RequireDPoP requires a DPoP key and DPoP-bound access tokens.
	// HAIP 1.0 §4 (sender-constrained access tokens, RFC 9449).
	RequireDPoP bool
	// RequireAuthorizationResponseIss requires the iss parameter in the
	// Authorization Response, advertised or not.
	// HAIP 1.0 §4 (FAPI 2.0, RFC 9207).
	RequireAuthorizationResponseIss bool
	// RequireScopeAuthorization requests the credential by scope only, never
	// by authorization_details.
	// HAIP 1.0 §4.2 (Credential Offer) and §4.3 (Authorization Endpoint).
	RequireScopeAuthorization bool
	// RequireIssuerMetadataScopes refuses a Credential Configuration without
	// a scope.
	// HAIP 1.0 §4.1 (Issuer Metadata).
	RequireIssuerMetadataScopes bool
	// RequireNonceEndpointForKeyBinding refuses Credential Issuer Metadata
	// that advertises cryptographic_binding_methods_supported, or a request
	// with a key attestation, without a nonce_endpoint.
	// HAIP 1.0 §4.1 (Issuer Metadata).
	RequireNonceEndpointForKeyBinding bool
	// RequestSignedIssuerMetadata asks for signed Credential Issuer Metadata
	// when the receiver configures no IssuerMetadataSigning of its own.
	// HAIP 1.0 §4.1 (signed Issuer Metadata MUST be supported).
	RequestSignedIssuerMetadata bool
	// SignedMetadataX5C applies to the x5c header of signed Credential Issuer
	// Metadata. The signer is always resolved from x5c; ExcludeAnchor and
	// RejectSelfSigned add the HAIP certificate rules.
	// HAIP 1.0 §4.1 (Issuer Metadata).
	SignedMetadataX5C X5CRules
	// RequireClientAuthentication requires an OAuth 2.0 client
	// authentication mechanism (Wallet Attestation or private_key_jwt) at the
	// PAR and token endpoints, and a client_id on a pre-authorized_code
	// token request.
	// HAIP 1.0 §4.4.1 (Wallet Attestation).
	RequireClientAuthentication bool
	// AttestationX5C applies to Wallet Attestations and key attestations
	// (OpenID4VCI 1.0 Appendices E and D). It is added to the rules of
	// Config.Attestation.Trust.
	// HAIP 1.0 §4.4.1 (Wallet Attestation) and §4.5.1 (Key Attestation).
	AttestationX5C X5CRules

	// RequireSignedRequestByReference requires a redirect-based
	// Authorization Request to be a signed Request Object passed by
	// request_uri (or by value with the caller's DeliveredByReference
	// statement).
	// HAIP 1.0 §5.1 (OpenID4VP via redirects).
	RequireSignedRequestByReference bool
	// RequireDirectPostJWT requires the response mode direct_post.jwt on a
	// redirect-based request.
	// HAIP 1.0 §5.1 (OpenID4VP via redirects).
	RequireDirectPostJWT bool
	// RequireDCAPIJWT requires the response mode dc_api.jwt on a Digital
	// Credentials API request.
	// HAIP 1.0 §5.2 (OpenID4VP via the W3C Digital Credentials API).
	RequireDCAPIJWT bool
	// AllowedClientIDPrefixes restricts the Client Identifier Prefix of every
	// request that names a Verifier, which is every request except an
	// unsigned Digital Credentials API one. The zero value restricts nothing.
	// HAIP 1.0 §5 (x509_hash for signed requests).
	AllowedClientIDPrefixes ClientIDPrefixes
	// RequestObjectX5C applies to a signed Request Object: Require accepts
	// only an x509_san_dns or x509_hash Client Identifier, whose Request
	// Object carries x5c; ExcludeAnchor and RejectSelfSigned add the HAIP
	// certificate rules.
	// HAIP 1.0 §5 (signed requests).
	RequestObjectX5C X5CRules
	// ResponseEncryption restricts the encryption of an Authorization
	// Response.
	// HAIP 1.0 §5 (response encryption per OpenID4VP 1.0 §8.3).
	ResponseEncryption ResponseEncryptionRules
	// AlwaysKeyBindingWhenConfirmed presents an SD-JWT VC that carries a cnf
	// claim with a KB-JWT, even when the Verifier did not require holder
	// binding.
	// HAIP 1.0 §6.1.1.1 (Cryptographic Holder Binding between VC and VP).
	AlwaysKeyBindingWhenConfirmed bool
}

// HAIPOptions returns every constraint HAIP 1.0 adds to OpenID4VCI 1.0 and
// OpenID4VP 1.0: all options on, credential formats restricted to dc+sd-jwt
// and mso_mdoc, and signed requests to the x509_hash Client Identifier
// Prefix.
func HAIPOptions() Options {
	all := X5CRules{Require: true, ExcludeAnchor: true, RejectSelfSigned: true}
	return Options{
		ForbidInsecureTransports: true,
		AllowedCredentialFormats: FormatSDJWTVC | FormatMsoMdoc,
		IssuerX5C:                all,
		StatusListTokenX5C:       all,

		RequirePAR:                        true,
		RequireDPoP:                       true,
		RequireAuthorizationResponseIss:   true,
		RequireScopeAuthorization:         true,
		RequireIssuerMetadataScopes:       true,
		RequireNonceEndpointForKeyBinding: true,
		RequestSignedIssuerMetadata:       true,
		SignedMetadataX5C:                 all,
		RequireClientAuthentication:       true,
		AttestationX5C:                    all,

		RequireSignedRequestByReference: true,
		RequireDirectPostJWT:            true,
		RequireDCAPIJWT:                 true,
		AllowedClientIDPrefixes:         ClientIDPrefixX509Hash,
		RequestObjectX5C:                all,
		ResponseEncryption: ResponseEncryptionRules{
			ECDHESOnly:             true,
			P256Only:               true,
			GCMOnly:                true,
			RequireJWKAlg:          true,
			RequireVerifierGCMBoth: true,
		},
		AlwaysKeyBindingWhenConfirmed: true,
	}
}

// ValidatesCredentialConfigurations reports whether o constrains a
// Credential Configuration, which the OpenID4VCI receiver then validates.
func (o Options) ValidatesCredentialConfigurations() bool {
	return o.RequireIssuerMetadataScopes || o.AllowedCredentialFormats != 0
}

// weakened names the options of floor that o does not keep at least as
// strict.
func (o Options) weakened(floor Options) []string {
	var names []string
	flag := func(name string, got, want bool) {
		if want && !got {
			names = append(names, name)
		}
	}
	rules := func(name string, got, want X5CRules) {
		flag(name+".Require", got.Require, want.Require)
		flag(name+".ExcludeAnchor", got.ExcludeAnchor, want.ExcludeAnchor)
		flag(name+".RejectSelfSigned", got.RejectSelfSigned, want.RejectSelfSigned)
	}
	flag("ForbidInsecureTransports", o.ForbidInsecureTransports, floor.ForbidInsecureTransports)
	if !o.AllowedCredentialFormats.within(floor.AllowedCredentialFormats) {
		names = append(names, "AllowedCredentialFormats")
	}
	rules("IssuerX5C", o.IssuerX5C, floor.IssuerX5C)
	rules("StatusListTokenX5C", o.StatusListTokenX5C, floor.StatusListTokenX5C)
	flag("RequirePAR", o.RequirePAR, floor.RequirePAR)
	flag("RequireDPoP", o.RequireDPoP, floor.RequireDPoP)
	flag("RequireAuthorizationResponseIss", o.RequireAuthorizationResponseIss, floor.RequireAuthorizationResponseIss)
	flag("RequireScopeAuthorization", o.RequireScopeAuthorization, floor.RequireScopeAuthorization)
	flag("RequireIssuerMetadataScopes", o.RequireIssuerMetadataScopes, floor.RequireIssuerMetadataScopes)
	flag("RequireNonceEndpointForKeyBinding", o.RequireNonceEndpointForKeyBinding, floor.RequireNonceEndpointForKeyBinding)
	flag("RequestSignedIssuerMetadata", o.RequestSignedIssuerMetadata, floor.RequestSignedIssuerMetadata)
	rules("SignedMetadataX5C", o.SignedMetadataX5C, floor.SignedMetadataX5C)
	flag("RequireClientAuthentication", o.RequireClientAuthentication, floor.RequireClientAuthentication)
	rules("AttestationX5C", o.AttestationX5C, floor.AttestationX5C)
	flag("RequireSignedRequestByReference", o.RequireSignedRequestByReference, floor.RequireSignedRequestByReference)
	flag("RequireDirectPostJWT", o.RequireDirectPostJWT, floor.RequireDirectPostJWT)
	flag("RequireDCAPIJWT", o.RequireDCAPIJWT, floor.RequireDCAPIJWT)
	if !o.AllowedClientIDPrefixes.within(floor.AllowedClientIDPrefixes) {
		names = append(names, "AllowedClientIDPrefixes")
	}
	rules("RequestObjectX5C", o.RequestObjectX5C, floor.RequestObjectX5C)
	enc, floorEnc := o.ResponseEncryption, floor.ResponseEncryption
	flag("ResponseEncryption.ECDHESOnly", enc.ECDHESOnly, floorEnc.ECDHESOnly)
	flag("ResponseEncryption.P256Only", enc.P256Only, floorEnc.P256Only)
	flag("ResponseEncryption.GCMOnly", enc.GCMOnly, floorEnc.GCMOnly)
	flag("ResponseEncryption.RequireJWKAlg", enc.RequireJWKAlg, floorEnc.RequireJWKAlg)
	flag("ResponseEncryption.RequireVerifierGCMBoth", enc.RequireVerifierGCMBoth, floorEnc.RequireVerifierGCMBoth)
	flag("AlwaysKeyBindingWhenConfirmed", o.AlwaysKeyBindingWhenConfirmed, floor.AlwaysKeyBindingWhenConfirmed)
	return names
}

// X5CRules are the certificate rules HAIP 1.0 states for every x5c-signed
// artifact it profiles.
type X5CRules struct {
	// Require makes the x5c JOSE header the only way to resolve the signing
	// key.
	Require bool
	// ExcludeAnchor refuses an x5c chain that includes the trust anchor
	// certificate.
	ExcludeAnchor bool
	// RejectSelfSigned refuses a self-signed signing certificate.
	RejectSelfSigned bool
}

// Union returns the rules that r or s turns on.
func (r X5CRules) Union(s X5CRules) X5CRules {
	return X5CRules{
		Require:          r.Require || s.Require,
		ExcludeAnchor:    r.ExcludeAnchor || s.ExcludeAnchor,
		RejectSelfSigned: r.RejectSelfSigned || s.RejectSelfSigned,
	}
}

// ResponseEncryptionRules restrict the JWE of an encrypted Authorization
// Response (OpenID4VP 1.0 §8.3). The zero value is OpenID4VP 1.0: ECDH-ES
// family key agreement on P-256, P-384 or P-521, any content encryption the
// library supports, and a JWK without alg accepted when the Verifier names
// the draft-era authorization_encrypted_response_alg.
type ResponseEncryptionRules struct {
	// ECDHESOnly accepts only the key agreement alg ECDH-ES.
	ECDHESOnly bool
	// P256Only accepts only Verifier keys on P-256.
	P256Only bool
	// GCMOnly accepts only the content encryption A128GCM and A256GCM.
	GCMOnly bool
	// RequireJWKAlg refuses a Verifier key without alg, as OpenID4VP 1.0
	// §8.3 states.
	RequireJWKAlg bool
	// RequireVerifierGCMBoth refuses Verifier metadata whose
	// encrypted_response_enc_values_supported does not list both A128GCM and
	// A256GCM.
	RequireVerifierGCMBoth bool
}

// CredentialFormats is a set of Credential Format Identifiers. The zero value
// is no restriction.
type CredentialFormats uint8

// Credential Format Identifiers of OpenID4VCI 1.0 Appendix A and OpenID4VP
// 1.0 Appendix B.
const (
	// FormatSDJWTVC is dc+sd-jwt (IETF SD-JWT VC).
	FormatSDJWTVC CredentialFormats = 1 << iota
	// FormatMsoMdoc is mso_mdoc (ISO mdoc).
	FormatMsoMdoc
	// FormatJWTVCJSON is jwt_vc_json (W3C VCDM secured with JOSE).
	FormatJWTVCJSON
	// FormatLDPVC is ldp_vc (W3C VCDM secured with Data Integrity).
	FormatLDPVC
	// FormatJWTVCJSONLD is jwt_vc_json-ld.
	FormatJWTVCJSONLD
)

var credentialFormatIdentifiers = map[string]CredentialFormats{
	"dc+sd-jwt":      FormatSDJWTVC,
	"mso_mdoc":       FormatMsoMdoc,
	"jwt_vc_json":    FormatJWTVCJSON,
	"ldp_vc":         FormatLDPVC,
	"jwt_vc_json-ld": FormatJWTVCJSONLD,
}

// Allows reports whether identifier is in s. An empty set allows every
// identifier; a non-empty one allows only its members, compared exactly.
func (s CredentialFormats) Allows(identifier string) bool {
	if s == 0 {
		return true
	}
	member, ok := credentialFormatIdentifiers[identifier]
	return ok && s&member != 0
}

// String lists the identifiers in s, or "any" for the empty set.
func (s CredentialFormats) String() string {
	return setString(uint16(s), credentialFormatNames)
}

var credentialFormatNames = []string{"dc+sd-jwt", "mso_mdoc", "jwt_vc_json", "ldp_vc", "jwt_vc_json-ld"}

// within reports whether s allows no more than floor.
func (s CredentialFormats) within(floor CredentialFormats) bool {
	return floor == 0 || (s != 0 && s&^floor == 0)
}

// ClientIDPrefixes is a set of OpenID4VP 1.0 §5.9.3 Client Identifier
// Prefixes. The zero value is no restriction.
type ClientIDPrefixes uint16

// Client Identifier Prefixes of OpenID4VP 1.0 §5.9.3 and Appendix A.2.
const (
	// ClientIDPrefixPreRegistered is a Client Identifier without a prefix
	// (§5.9.2).
	ClientIDPrefixPreRegistered ClientIDPrefixes = 1 << iota
	ClientIDPrefixRedirectURI
	ClientIDPrefixOpenIDFederation
	ClientIDPrefixDecentralizedIdentifier
	ClientIDPrefixVerifierAttestation
	ClientIDPrefixX509SanDNS
	ClientIDPrefixX509Hash
	ClientIDPrefixOrigin
)

var clientIDPrefixNames = []string{
	"pre-registered", "redirect_uri", "openid_federation", "decentralized_identifier",
	"verifier_attestation", "x509_san_dns", "x509_hash", "origin",
}

// Allows reports whether the Client Identifier Prefix named prefix is in s,
// with "pre-registered" naming a Client Identifier without a prefix. An empty
// set allows every prefix.
func (s ClientIDPrefixes) Allows(prefix string) bool {
	if s == 0 {
		return true
	}
	for index, name := range clientIDPrefixNames {
		if name == prefix {
			return s&(1<<index) != 0
		}
	}
	return false
}

// String lists the prefixes in s, or "any" for the empty set.
func (s ClientIDPrefixes) String() string {
	return setString(uint16(s), clientIDPrefixNames)
}

// within reports whether s allows no more than floor.
func (s ClientIDPrefixes) within(floor ClientIDPrefixes) bool {
	return floor == 0 || (s != 0 && s&^floor == 0)
}

func setString(bits uint16, names []string) string {
	if bits == 0 {
		return "any"
	}
	var members []string
	for index, name := range names {
		if bits&(1<<index) != 0 {
			members = append(members, name)
		}
	}
	return strings.Join(members, ",")
}
