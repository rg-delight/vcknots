package oid4vp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
)

// withDraft24RequestObject authenticates a Draft24 Request Object. It uses the
// provided JWT string as the request object to populate the
// CredentialPresentationRequest, validating its claims and signature as per
// OID4VP and RFC 9101.
//
// The Draft24 wire contract (the client_id_scheme parameter and
// presentation_definition) is preserved here, but an X.509 signed Request
// Object is authenticated by the same shared path Final uses whenever the
// caller configured RequestObjectValidationOptions. A caller that configured
// only the legacy X509TrustChainRoots pool, or the InsecureSkipX509Verify test
// escape, keeps the original Draft24 behaviour.
func (b *requestBuilder) withDraft24RequestObject(obj string) *requestBuilder {
	if b.errValidation != nil {
		return b
	}

	options, err := b.requestObjectValidationOptions()
	if err != nil {
		b.errValidation = err
		return b
	}

	parsedJWT, err := jwt.ParseSigned(obj, resolveRequestObjectAlgorithms(options))
	if err != nil {
		b.errValidation = fmt.Errorf("failed to parse request object JWT: %w: %w", err, ErrRequestObjectSignatureInvalid)
		return b
	}

	// Validate 'typ' header as per OID4VP specification
	// Request Objects MUST include typ Header Parameter with value "oauth-authz-req+jwt"
	if len(parsedJWT.Headers) == 0 {
		b.errValidation = fmt.Errorf("request object JWT must have headers: %w", ErrRequestObjectTypInvalid)
		return b
	}

	typHeader, exists := parsedJWT.Headers[0].ExtraHeaders["typ"]
	if !exists {
		b.errValidation = fmt.Errorf("request object JWT must include 'typ' header parameter: %w", ErrRequestObjectTypInvalid)
		return b
	}

	typStr, ok := typHeader.(string)
	if !ok || typStr != "oauth-authz-req+jwt" {
		b.errValidation = fmt.Errorf("request object JWT 'typ' header must be 'oauth-authz-req+jwt', got: %v: %w", typHeader, ErrRequestObjectTypInvalid)
		return b
	}

	// extract claims without verification for initial processing
	claims := make(commonJOSE.Claims)
	if err := parsedJWT.UnsafeClaimsWithoutVerification(&claims); err != nil {
		b.errValidation = fmt.Errorf("failed to get JWT claims: %w", err)
		return b
	}

	b.setParamsWithAnyMap(claims)

	if err := b.validate(); err != nil {
		b.errValidation = err
		return b
	}

	clientID, clientIDErr := parseOID4VPClientID(b.req.ClientID)
	isX509ClientID := clientIDErr == nil &&
		(clientID.prefix == OID4VPClientIDPrefixX509Hash || clientID.prefix == OID4VPClientIDPrefixX509SanDNS)

	// A configured RequestObjectValidationOptions is the caller's request for
	// the shared authentication path: trust anchors or a root pool, the CRL
	// policy, the wallet audience, the clock skew and the signature algorithms
	// all apply to Draft24 exactly as they do to Final.
	if isX509ClientID && b.requestObjectValidation != nil && !b.insecureSkipX509Verify {
		if err := b.authenticateX509RequestObject(obj, parsedJWT, options); err != nil {
			b.errValidation = err
		}
		return b
	}

	// x509_hash, legacy configuration: the Client Identifier is the leaf
	// certificate thumbprint, so no chain is verified.
	if clientIDErr == nil && clientID.prefix == OID4VPClientIDPrefixX509Hash {
		certificates, err := commonX509.DecodeX5CFromJWTHeader(obj)
		if err != nil {
			b.errValidation = err
			return b
		}
		thumbprint := sha256.Sum256(certificates[0].Raw)
		actualHash := base64.RawURLEncoding.EncodeToString(thumbprint[:])
		if actualHash != clientID.original {
			b.errValidation = fmt.Errorf("x509_hash client_id mismatch: expected %s, got %s: %w", clientID.original, actualHash, ErrX509HashMismatch)
			return b
		}

		claims := jwt.Claims{}
		if err := parsedJWT.Claims(certificates[0].PublicKey, &claims); err != nil {
			b.errValidation = fmt.Errorf("failed to verify request object with x5c certificate: %w: %w", err, ErrRequestObjectSignatureInvalid)
			return b
		}
		return b
	}

	// x509_san_dns, legacy configuration: the chain is verified against the
	// X509TrustChainRoots pool with the legacy revocation check.
	if clientIDErr == nil && clientID.prefix == OID4VPClientIDPrefixX509SanDNS {
		var certificates []*x509.Certificate

		if b.insecureSkipX509Verify {
			// For testing: parse the certificates from x5c WITHOUT calling
			// x509.Verify(), which in Go 1.20+ performs strict standards
			// compliance checks that reject non-compliant certificates (for
			// example "OIDF Test" from conformance test suites).
			certificates, err = commonX509.DecodeX5CFromJWTHeader(obj)
			if err != nil {
				b.errValidation = err
				return b
			}
		} else {
			// Production: verify certificate chain
			certificateChains, err := parsedJWT.Headers[0].Certificates(x509.VerifyOptions{
				Roots: b.x509TrustChainRoots,
			})
			if err != nil {
				b.errValidation = err
				return b
			}

			for _, chain := range certificateChains {
				err = commonX509.CheckIfCertsRevoked(chain)
				if err == nil {
					b.errValidation = nil
					certificates = chain
					break
				} else {
					b.errValidation = err
				}
			}
			if certificates == nil {
				return b
			}
		}

		// Request object must be verified with the leaf certificate in the x5c array (RFC 7515).
		claims := jwt.Claims{}
		if err := parsedJWT.Claims(certificates[0].PublicKey, &claims); err != nil {
			b.errValidation = fmt.Errorf("failed to verify request object with x5c certificate: %w: %w", err, ErrRequestObjectSignatureInvalid)
			return b
		}

		// ClientID should contain DNS name which is same as the SAN of the leaf certificate in the x5c array (OID4VP x509_san_dns). #106
		matched := false
		for _, n := range certificates[0].DNSNames {
			if clientID.original == n {
				matched = true
				break
			}
		}
		if !matched {
			b.errValidation = fmt.Errorf("SAN of the certificate and client_id did not match: %w", ErrRequestObjectClientIDMismatch)
			return b
		}

		// response_uri / redirect_uri check #107
		var uri *url.URL
		if b.req.ResponseMode == "direct_post" {
			uri, err = url.Parse(b.req.ResponseURI)
			if err != nil {
				b.errValidation = fmt.Errorf("response_uri must be URI: %w", err)
				return b
			}
		} else {
			uri, err = url.Parse(b.req.RedirectURI)
			if err != nil {
				b.errValidation = fmt.Errorf("redirect_uri must be URI: %w", err)
				return b
			}
		}
		if hostname := uri.Hostname(); hostname != clientID.original {
			b.errValidation = fmt.Errorf("redirect_uri/response_uri and client_id (origin) must be same: %w", ErrRequestObjectClientIDMismatch)
			return b
		}

		return b
	}

	// JWT signature verification is mandatory for JWT request objects as per RFC9101
	if b.req.ClientMetadata == nil {
		b.errValidation = fmt.Errorf("client_metadata is required for JWT request object verification")
		return b
	}

	// fetch the public key for signature verification
	k, err := b.req.ClientMetadata.FetchKeyWithKID(parsedJWT.Headers[0].KeyID)
	if err != nil {
		b.errValidation = fmt.Errorf("failed to fetch public key for JWT verification: %w", err)
		return b
	}

	// verify the JWT signature and extract standard claims for validation
	standardClaims := jwt.Claims{}
	if err := parsedJWT.Claims(&k, &standardClaims); err != nil {
		b.errValidation = fmt.Errorf("failed to verify JWT signature: %w: %w", err, ErrRequestObjectSignatureInvalid)
		return b
	}

	// validate standard JWT claims as per RFC9101 and OID4VP requirements
	if err := standardClaims.Validate(jwt.Expected{
		Time: time.Now(), // validates exp, iat, nbf claims
	}); err != nil {
		b.errValidation = fmt.Errorf("JWT standard claims validation failed: %w", err)
		return b
	}

	// extract all verified claims for parameter processing
	verifiedClaims := make(commonJOSE.Claims)
	if err := parsedJWT.Claims(&k, &verifiedClaims); err != nil {
		b.errValidation = fmt.Errorf("failed to extract verified claims: %w", err)
		return b
	}

	// re-set parameters from verified claims to ensure integrity
	b.setParamsWithAnyMap(verifiedClaims)

	if err := b.validate(); err != nil {
		b.errValidation = err
		return b
	}

	return b
}
