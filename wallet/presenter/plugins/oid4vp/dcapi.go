package oid4vp

// OID4VPClientIDPrefixWebOrigin is the effective Client Identifier Prefix the
// Wallet assigns to an unsigned DC API request. OID4VP 1.0 Appendix A.2: "The
// client_id parameter MUST be omitted in unsigned requests". The Wallet uses
// the platform-authenticated Origin as the effective identifier.
const OID4VPClientIDPrefixWebOrigin OID4VPClientIDPrefix = "web-origin"
