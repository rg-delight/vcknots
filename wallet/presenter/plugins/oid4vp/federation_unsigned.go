package oid4vp

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
)

// authenticateUnsignedFederationRequest authenticates an openid_federation
// Verifier whose Authorization Request arrived in plain parameters. OpenID4VP
// 1.0 Section 5.9.3: "The Authorization Request MAY also contain a
// `trust_chain` parameter. The final Verifier metadata is obtained from the
// Trust Chain after applying the policies ... The `client_metadata` parameter,
// if present in the Authorization Request, MUST be ignored when this Client
// Identifier Prefix is used."
//
// Nothing signs such a request, so what the Trust Chain authenticates is the
// Verifier's metadata and, through its redirect_uris, the only endpoints the
// response may reach. The request is accepted only when its response endpoint
// is one of them, which is what keeps an unsigned request from sending a
// presentation anywhere but to the Verifier it names.
func (b *requestBuilder) authenticateUnsignedFederationRequest(params map[string]any) error {
	clientID, err := b.parseClientID(b.req.ClientID)
	if err != nil || clientID.prefix != OID4VPClientIDPrefixOIDFederation {
		return nil
	}
	options, err := b.requestObjectValidationOptions()
	if err != nil {
		return err
	}
	if options.Federation == nil || len(options.Federation.TrustAnchors) == 0 {
		return fmt.Errorf("%w: no OpenID Federation trust anchor is configured", federation.ErrTrustAnchorNotConfigured)
	}
	var carried []string
	if raw, present := params["trust_chain"]; present && raw != nil && raw != "" {
		carried, err = federation.ParseTrustChainParameter(raw)
		if err != nil {
			return err
		}
	}
	trust, err := b.federationResolver(options).ResolveVerifierTrust(
		options.resolveContext(),
		clientID.original,
		carried,
		options.Federation.PreferredLocales,
	)
	if err != nil {
		return err
	}
	if err := federation.AssertResponseURIAllowed(trust.Metadata, b.req.responseEndpoint()); err != nil {
		return err
	}
	if err := b.adoptFederationVerifierMetadata(trust.Metadata); err != nil {
		return err
	}
	b.req.VerifierFederation = newFederationEvidence(trust)
	return nil
}
