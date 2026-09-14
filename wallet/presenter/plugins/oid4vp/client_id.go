package oid4vp

import (
	"fmt"
	"strings"
)

type OID4VPClientID struct {
	original string
	prefix   OID4VPClientIDPrefix
}
type OID4VPClientIDPrefix string

const (
	OID4VPClientIDPrefixRedirectURI         OID4VPClientIDPrefix = "redirect_uri"
	OID4VPClientIDPrefixOIDFederation       OID4VPClientIDPrefix = "openid_federation"
	OID4VPClientIDPrefixDID                 OID4VPClientIDPrefix = "decentralized_identifier"
	OID4VPClientIDPrefixVerifierAttestation OID4VPClientIDPrefix = "verifier_attestation"
	OID4VPClientIDPrefixX509SanDNS          OID4VPClientIDPrefix = "x509_san_dns"
	OID4VPClientIDPrefixX509Hash            OID4VPClientIDPrefix = "x509_hash"
	OID4VPClientIDPrefixOriginal            OID4VPClientIDPrefix = "origin"
	// OID4VPClientIDPrefixPreRegistered is the pseudo-prefix used when the
	// client_id contains no ":" character (OID4VP 1.0 §5.9.2).
	OID4VPClientIDPrefixPreRegistered OID4VPClientIDPrefix = "pre-registered"
)

// parseOID4VPClientID parses and validates a client_id that arrived over the
// wire, from any delivery: query parameters, a request= Request Object, a
// request_uri Request Object, a signed DC API request or the Draft24 paths. It
// never accepts a Client Identifier Prefix that only the Wallet itself is
// allowed to mint, so the prefixes "origin" and "web-origin" are both refused
// here. Use (*requestBuilder).parseClientID to parse a Client Identifier while
// building a request, which adds back the single exception the unsigned
// Digital Credentials API path needs.
func parseOID4VPClientID(clientID string) (*OID4VPClientID, error) {
	return parseOID4VPClientIDAllowingWebOrigin(clientID, false)
}

// parseClientID parses a client_id in the context of the delivery this builder
// is processing. It is parseOID4VPClientID with one exception: while parsing an
// unsigned Digital Credentials API request the Wallet-synthesised
// "web-origin:<origin>" effective identifier is accepted, because
// parseDCAPIUnsigned put it there itself after discarding whatever the request
// carried.
//
// OID4VP 1.0 Appendix A.2: "The `client_id` parameter MUST be omitted in
// unsigned requests defined in (#unsigned_request). The Wallet MUST ignore any
// `client_id` parameter that is present in an unsigned request." Every other
// requestSource therefore reaches the strict parse, so a "web-origin" prefix
// read off the wire is rejected exactly like the reserved "origin" prefix of
// OID4VP 1.0 Section 5.9.3: "This reserved Client Identifier Prefix is defined
// in (#dc_api_request). The Wallet MUST NOT accept this Client Identifier
// Prefix in requests."
func (b *requestBuilder) parseClientID(clientID string) (*OID4VPClientID, error) {
	return parseOID4VPClientIDAllowingWebOrigin(clientID, b.requestSource == "dcapi-unsigned")
}

// parseOID4VPClientIDAllowingWebOrigin implements the OID4VP 1.0 Section 5.9.2
// Client Identifier syntax. allowWebOrigin is true only on the one internal
// path that synthesises the identifier itself; see parseClientID.
func parseOID4VPClientIDAllowingWebOrigin(clientID string, allowWebOrigin bool) (*OID4VPClientID, error) {
	// Syntax: <client_id_prefix>:<orig_client_id>

	// Trim whitespace from client_id
	clientID = strings.TrimSpace(clientID)

	parts := strings.SplitN(clientID, ":", 2)
	if len(parts) != 2 {
		// OID4VP 1.0 §5.9.2: "If a `:` character is not present in the Client
		// Identifier, the Wallet MUST treat the Client Identifier as
		// referencing a pre-registered client."
		if clientID == "" {
			return nil, fmt.Errorf("invalid client_id format")
		}
		return &OID4VPClientID{original: clientID, prefix: OID4VPClientIDPrefixPreRegistered}, nil
	}

	prefix := parts[0]
	origin := strings.TrimSpace(parts[1])

	// Detect duplicate prefix (e.g., "x509_san_dns:x509_san_dns:...")
	if strings.HasPrefix(origin, prefix+":") {
		return nil, fmt.Errorf("invalid client_id: duplicate prefix detected")
	}

	switch OID4VPClientIDPrefix(prefix) {
	case OID4VPClientIDPrefixRedirectURI,
		OID4VPClientIDPrefixOIDFederation,
		OID4VPClientIDPrefixDID,
		OID4VPClientIDPrefixVerifierAttestation,
		OID4VPClientIDPrefixX509SanDNS,
		OID4VPClientIDPrefixX509Hash:
		return &OID4VPClientID{
			original: origin,
			prefix:   OID4VPClientIDPrefix(prefix),
		}, nil
	case OID4VPClientIDPrefixWebOrigin:
		// OID4VP 1.0 Appendix A.2: "The `client_id` parameter MUST be omitted
		// in unsigned requests defined in (#unsigned_request). The Wallet MUST
		// ignore any `client_id` parameter that is present in an unsigned
		// request." web-origin is the effective identifier the Wallet derives
		// from the platform-authenticated Origin, so accepting it from a
		// request would let a Verifier name itself and derive no response
		// endpoint binding, which is what Section 5.9.3 forbids for the
		// companion "origin" prefix.
		if !allowWebOrigin {
			return nil, fmt.Errorf("client_id prefix 'web-origin' is reserved for the Wallet's own unsigned Digital Credentials API identifier and is not allowed in requests")
		}
		return &OID4VPClientID{
			original: origin,
			prefix:   OID4VPClientIDPrefixWebOrigin,
		}, nil
	case OID4VPClientIDPrefixOriginal:
		// OID4VP 1.0 Section 5.9.3: "This reserved Client Identifier Prefix is
		// defined in (#dc_api_request). The Wallet MUST NOT accept this Client
		// Identifier Prefix in requests."
		return nil, fmt.Errorf("client_id prefix 'origin' is not allowed")
	default:
		// OID4VP 1.0 Section 5.9.2 defines the syntax as
		// "<client_id_prefix>:<orig_client_id>" over a closed set of prefixes,
		// so name the token that was parsed as the prefix rather than implying
		// the Wallet merely does not implement it yet.
		return nil, fmt.Errorf("client_id prefix %q is not a supported Client Identifier Prefix", prefix)
	}
}
