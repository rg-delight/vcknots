package x509

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// maxX5CCertificates bounds a JOSE x5c chain. It is the bound
// VerifySigningCertificateChain already enforces, so a chain accepted by this
// decoder is never rejected for its length further along the trust path.
const maxX5CCertificates = 16

// DecodeX5CChain decodes a JOSE x5c header value into its certificate chain,
// leaf first. raw is the value as it appears in a decoded JOSE header: either
// a []string read into a typed header, or the []any of strings encoding/json
// produces for a map[string]any header.
//
// Each entry is "a base64-encoded (Section 4 of [RFC4648] -- not
// base64url-encoded) DER [ITU.X690.2008] PKIX certificate value"
// (RFC 7515 Section 4.1.6). base64url input is reported as invalid rather than
// repaired, because a wallet that repairs it accepts chains no conforming
// verifier would. The chain must hold between 1 and 16 certificates.
//
// Decoding is not authentication: the returned chain is still untrusted input
// until VerifySigningCertificateChain accepts it against configured anchors.
func DecodeX5CChain(raw any) ([]*x509.Certificate, error) {
	encoded, err := x5cHeaderEntries(raw)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > maxX5CCertificates {
		return nil, fmt.Errorf("x5c header must contain between 1 and %d certificates", maxX5CCertificates)
	}
	chain := make([]*x509.Certificate, 0, len(encoded))
	for index, entry := range encoded {
		der, err := base64.StdEncoding.DecodeString(entry)
		if err != nil {
			return nil, fmt.Errorf("x5c certificate %d is not valid base64 DER: %w", index, err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("x5c certificate %d is not valid base64 DER: %w", index, err)
		}
		chain = append(chain, certificate)
	}
	return chain, nil
}

// DecodeX5CFromJWTHeader decodes the x5c chain carried by the protected header
// of a compact JWS or JWT. Only the header is read; obj's signature is not
// verified here, because the key that would verify it is the leaf this call
// returns. The header member is decoded by DecodeX5CChain and inherits its
// encoding and length rules.
func DecodeX5CFromJWTHeader(obj string) ([]*x509.Certificate, error) {
	parts := strings.Split(obj, ".")
	if len(parts) < 2 {
		return nil, errors.New("x5c source is not a compact JWS")
	}
	// Trim padding a non-conforming producer may have added: the protected
	// header is base64url without padding (RFC 7515 Section 2).
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "="))
	if err != nil {
		return nil, fmt.Errorf("JWS protected header is not valid base64url: %w", err)
	}
	header := map[string]any{}
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, fmt.Errorf("JWS protected header is not valid JSON: %w", err)
	}
	value, present := header["x5c"]
	if !present {
		return nil, errors.New("x5c header is required")
	}
	return DecodeX5CChain(value)
}

// IsSelfSigned reports whether cert is self-issued and carries its own
// signature. Subject and issuer are compared as raw DER rather than as their
// string rendering, and the signature is verified with the certificate's own
// public key: a certificate that merely repeats a subject DN in its issuer
// field, as a re-keyed CA of the same name does, is not self-signed.
func IsSelfSigned(cert *x509.Certificate) bool {
	if cert == nil || len(cert.Raw) == 0 || !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// RequireNonSelfSignedLeaf enforces "The X.509 certificate signing the request
// MUST NOT be self-signed" (HAIP Sections 5 and 6.1.1) on a decoded chain.
// label names the signed artifact in the error, for example "wallet
// attestation" or "key attestation".
func RequireNonSelfSignedLeaf(chain []*x509.Certificate, label string) error {
	if len(chain) == 0 {
		return fmt.Errorf("%s must include an x5c header chain", label)
	}
	if chain[0] == nil || len(chain[0].Raw) == 0 {
		return fmt.Errorf("%s x5c leaf certificate is empty", label)
	}
	if IsSelfSigned(chain[0]) {
		return fmt.Errorf("%s x5c leaf certificate must not be self-signed", label)
	}
	return nil
}

// x5cHeaderEntries normalises the two shapes an x5c member reaches this
// package in without copying the string values.
func x5cHeaderEntries(raw any) ([]string, error) {
	switch value := raw.(type) {
	case []string:
		return value, nil
	case []any:
		entries := make([]string, 0, len(value))
		for index, item := range value {
			entry, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("x5c certificate %d is not a string", index)
			}
			entries = append(entries, entry)
		}
		return entries, nil
	case nil:
		return nil, errors.New("x5c header is required")
	default:
		return nil, errors.New("x5c header must be an array of base64-encoded certificates")
	}
}
