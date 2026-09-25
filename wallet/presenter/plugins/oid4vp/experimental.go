package oid4vp

// ExperimentalOptions are relaxations of OpenID4VP that no specification
// allows. They exist for local test verifiers and conformance experiments
// only, and each one makes the presenter accept requests a conforming Wallet
// refuses. A presenter applies none of them unless the caller passes them to
// SetExperimentalOptions; they cannot be set in an Oid4vpPresenter literal. A
// profile with ForbidInsecureTransports (HAIP) refuses a presenter with
// AllowHTTP or InsecureSkipX509Verify.
type ExperimentalOptions struct {
	// AllowHTTP accepts http for request_uri and for the Response URI or
	// Redirect URI of a local test verifier. Not conforming: OpenID4VP 1.0
	// §5.10 and Draft 24 §5.11 require https for a request_uri POST, and HAIP
	// 1.0 §5 requires TLS.
	AllowHTTP bool
	// InsecureSkipX509Verify authenticates a Draft 24 x509_san_dns Request
	// Object by its binding and signature only, without verifying the
	// certificate chain; the request is admitted without a
	// RequestObjectVerification. Not conforming: Draft 24 §5.10.4 has the
	// Wallet "validate the signature and the trust chain of the X.509
	// certificate". The OpenID4VP 1.0 entry points refuse every signed
	// Request Object while it is set.
	InsecureSkipX509Verify bool
	// AcceptClientMetadataJWKsWithoutKeyID accepts a client_metadata.jwks
	// member without a kid, or with a kid another member repeats, on the
	// OpenID4VP 1.0 entry points. Not conforming: OpenID4VP 1.0 §5.1 states
	// "Each JWK in the set MUST have a kid (Key ID) parameter that uniquely
	// identifies the key within the context of the request". Draft 24 has no
	// such rule, and its entry points never check kid.
	AcceptClientMetadataJWKsWithoutKeyID bool
}

// SetExperimentalOptions applies options to every parse and response of p
// from now on. It is the only way to relax p beyond OpenID4VP; see
// ExperimentalOptions for what each option breaks.
func (p *Oid4vpPresenter) SetExperimentalOptions(options ExperimentalOptions) {
	p.experimental = options
}

// ExperimentalOptions reports the relaxations SetExperimentalOptions applied
// to p, the zero value when none was.
func (p *Oid4vpPresenter) ExperimentalOptions() ExperimentalOptions {
	return p.experimental
}
