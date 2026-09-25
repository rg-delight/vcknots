// Package experimental holds every setting of the wallet library that departs
// from the OpenID4VC specifications. They exist to test a peer — a local
// issuer or verifier without TLS, or how an issuer or verifier handles a
// malformed message — and are not for production use.
//
// Design. The rest of the library conforms to the specifications and has no
// switch that turns a MUST off. A departure is reachable only through a type
// this package defines, carried by a field named Experimental:
//
//   - wallet.Config.Experimental (Options) for the wallet and the plugins it
//     builds;
//   - oid4vci.Oid4vciReceiver.Experimental (Transport) for an injected
//     OpenID4VCI receiver.
//
// Code that relaxes a rule therefore imports this package, which makes the
// departure visible in review and searchable. The rules are:
//
//   - The zero value of every type here is the conforming behavior.
//   - Nothing here is read from the environment or from global state; a
//     setting takes effect only where a caller sets it.
//   - A profile that forbids a departure refuses it rather than ignoring it:
//     profile.Options.ForbidInsecureTransports (HAIP) refuses Transport, and
//     Hooks, which rewrite draft protocol messages, are refused unless a draft
//     profile is enabled.
//   - A new departure is added as a field of one of these types (or a new
//     type in this package), never as a field of a stable configuration type.
//     The OpenID4VP presenter's transport escapes (AllowHTTP,
//     InsecureSkipX509Verify) follow the same pattern: a Transport-like type
//     here, taken by an Experimental field of oid4vp.Oid4vpPresenter.
//
// This package imports no other wallet package except presenter/types, so any
// wallet package can depend on it.
package experimental

import (
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

// Options are the departures a wallet.Config can carry. Not
// specification-conforming; for testing only.
type Options struct {
	// Transport relaxes transport security for the protocol plugins the
	// wallet builds. A wallet refuses it when an injected Receiver or
	// Presenter would not receive it; set Oid4vciReceiver.Experimental on an
	// injected receiver instead.
	Transport Transport
	// Hooks rewrite draft protocol messages the library built.
	Hooks Hooks
}

// Transport relaxes transport security. Not specification-conforming; for
// testing only.
type Transport struct {
	// AllowHTTP accepts plain http endpoints and identifiers, for a local test
	// issuer or verifier. OpenID4VCI 1.0 Section 12.2.1 requires the https
	// scheme for a Credential Issuer Identifier and Section 12.2.2 TLS for
	// metadata; OpenID4VP 1.0 and HAIP 1.0 require TLS throughout. A profile
	// with ForbidInsecureTransports (HAIP) refuses it. A client assertion is
	// still sent over plain http only to a loopback host.
	AllowHTTP bool
}

// Hooks rewrite messages after the library built them, so a tester can see
// how an issuer or verifier handles a malformed one. A nil hook leaves its
// message unchanged. They rewrite draft protocol messages only, so a wallet
// refuses them (wallet.ErrProfileForbidsDraft) unless Config.Profiles enables
// a draft profile, which never happens under HAIP. Not
// specification-conforming; for testing only.
type Hooks struct {
	// KeyProof rewrites Draft 13 key proofs.
	KeyProof ProofTransform
	// PresentationExchangeResponse rewrites Draft 24 Presentation Exchange
	// responses.
	PresentationExchangeResponse Draft24ResponseTransform
}

// Set reports whether any hook is set.
func (h Hooks) Set() bool {
	return h.KeyProof.Content != nil || h.KeyProof.Serialized != nil || h.PresentationExchangeResponse != nil
}

// ProofJWTContent is the header and claims of a key proof before it is
// signed. Both maps are copies a transform may change. Header never carries
// "alg": the algorithm belongs to the signing key.
type ProofJWTContent struct {
	Header map[string]any
	Claims map[string]any
}

// ProofTransform rewrites a Draft 13 key proof, for testing how an issuer
// handles a malformed one. Content runs before signing, so the result is
// still correctly signed; Serialized runs on the compact JWS. A nil member is
// not called, so the zero value leaves the proof unchanged. An error aborts
// the issuance with wallet.ErrDraft13ProofTransformFailed.
type ProofTransform struct {
	Content    func(ProofJWTContent) (ProofJWTContent, error)
	Serialized func(string) (string, error)
}

// Draft24ResponseTransform rewrites a Presentation Exchange response after
// the library built and signed it and before it is sent, so a tester can see
// how a Verifier handles a malformed one. A rewrite can break the proof. An
// error stops the presentation and is reported wrapped in
// wallet.ErrDraft24ResponseTransformFailed.
type Draft24ResponseTransform func(vpToken []byte, submission presenterTypes.PresentationSubmission) ([]byte, presenterTypes.PresentationSubmission, error)
