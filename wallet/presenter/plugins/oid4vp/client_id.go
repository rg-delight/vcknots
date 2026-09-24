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

// ParseOID4VPClientID parses and validates a client_id that arrived over the
// wire, from any delivery: query parameters, a request= Request Object, a
// request_uri Request Object, a signed DC API request or the Draft24 paths. It
// is the same parse every entry point of this package applies, exported so an
// application that has to know which Client Identifier Prefix it is talking to
// - to render it, or to decide what evidence the prefix demands - reads it from
// the Client Identifier syntax of OID4VP 1.0 Section 5.9.2 rather than from a
// second copy of the rules.
//
// A Client Identifier with no ":" is a pre-registered client and reports
// OID4VPClientIDPrefixPreRegistered. A Client Identifier Prefix that only the
// Wallet itself is allowed to mint is refused with ErrClientIDPrefixReserved:
// "origin" (Section 5.9.3) and "web-origin" (Appendix A.2). Every other
// unknown prefix is refused as a plain syntax error.
func ParseOID4VPClientID(clientID string) (*OID4VPClientID, error) {
	return parseOID4VPClientIDAllowingWebOrigin(clientID, false)
}

// Prefix reports the Client Identifier Prefix this Client Identifier carries,
// or OID4VPClientIDPrefixPreRegistered when it carries none.
func (c *OID4VPClientID) Prefix() OID4VPClientIDPrefix {
	return c.prefix
}

// Original reports the <orig_client_id> part of the Client Identifier: the
// value after the prefix, or the whole identifier for a pre-registered client.
func (c *OID4VPClientID) Original() string {
	return c.original
}

// RequiresRequestObjectSignature reports whether this Client Identifier can
// only be authenticated by the signature over a Request Object: the X.509
// certificate that signed it (OID4VP 1.0 Section 5.9.3 "x509_san_dns" and
// "x509_hash"), or the key a Verifier Attestation confirms
// ("verifier_attestation": "the Verifier MUST sign the request object with the
// private key corresponding to the public key in the `cnf` claim"). A request
// carrying such an identifier in plain query parameters authenticates nothing,
// and the parse entry points refuse it with ErrRequestObjectSignatureRequired.
func (c *OID4VPClientID) RequiresRequestObjectSignature() bool {
	return c.prefix == OID4VPClientIDPrefixX509SanDNS ||
		c.prefix == OID4VPClientIDPrefixX509Hash ||
		c.prefix == OID4VPClientIDPrefixVerifierAttestation
}

// parseOID4VPClientID is the package-internal spelling of ParseOID4VPClientID.
func parseOID4VPClientID(clientID string) (*OID4VPClientID, error) {
	return ParseOID4VPClientID(clientID)
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
	if b.draft24 {
		return parseDraft24ClientID(clientID)
	}
	return parseOID4VPClientIDAllowingWebOrigin(clientID, b.requestSource == sourceDCAPIUnsigned)
}

// ParseDraft24OID4VPClientID is ParseOID4VPClientID for a client_id that
// arrived over the Draft24 wire contract, whose "https" Client Identifier
// Scheme names an OpenID Federation Entity Identifier (see
// parseDraft24ClientID). An application that routes a request to the Draft24
// parser reads the Client Identifier Prefix through this function, so it
// treats a Draft24 Federation Verifier exactly as the parser does.
func ParseDraft24OID4VPClientID(clientID string) (*OID4VPClientID, error) {
	return parseDraft24ClientID(clientID)
}

// parseDraft24ClientID is the Client Identifier syntax of the Draft24 wire
// contract. It differs from OpenID4VP 1.0 in one prefix only: Draft24 Section
// 5.10.1 names an OpenID Federation Entity Identifier with the "https" Client
// Identifier Scheme, so the whole https URL is both the Client Identifier and
// the Entity Identifier, where OpenID4VP 1.0 spells the same Verifier
// "openid_federation:<entity id>". The Draft24 identifier is reported with the
// Final prefix so both wire contracts reach the one federation authentication.
func parseDraft24ClientID(clientID string) (*OID4VPClientID, error) {
	trimmed := strings.TrimSpace(clientID)
	if strings.HasPrefix(trimmed, "https://") {
		return &OID4VPClientID{original: trimmed, prefix: OID4VPClientIDPrefixOIDFederation}, nil
	}
	return parseOID4VPClientID(trimmed)
}

// parseClientIDForWire parses the outer Authorization Request client_id with
// the syntax of the wire contract being parsed.
func parseClientIDForWire(clientID string, draft24 bool) (*OID4VPClientID, error) {
	if draft24 {
		return parseDraft24ClientID(clientID)
	}
	return parseOID4VPClientID(clientID)
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
			return nil, fmt.Errorf("client_id prefix 'web-origin' is reserved for the Wallet's own unsigned Digital Credentials API identifier and is not allowed in requests: %w", ErrClientIDPrefixReserved)
		}
		return &OID4VPClientID{
			original: origin,
			prefix:   OID4VPClientIDPrefixWebOrigin,
		}, nil
	case OID4VPClientIDPrefixOriginal:
		// OID4VP 1.0 Section 5.9.3: "This reserved Client Identifier Prefix is
		// defined in (#dc_api_request). The Wallet MUST NOT accept this Client
		// Identifier Prefix in requests."
		return nil, fmt.Errorf("client_id prefix 'origin' is not allowed: %w", ErrClientIDPrefixReserved)
	default:
		// OID4VP 1.0 Section 5.9.2 defines the syntax as
		// "<client_id_prefix>:<orig_client_id>" over a closed set of prefixes,
		// so name the token that was parsed as the prefix rather than implying
		// the Wallet merely does not implement it yet.
		return nil, fmt.Errorf("client_id prefix %q is not a supported Client Identifier Prefix", prefix)
	}
}
