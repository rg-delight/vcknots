package oid4vp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
)

// withDraft24RequestObject retains the legacy Draft24 authentication contract.
// It uses the provided JWT string as the request object
// to populate the CredentialPresentationRequest,
// validating its claims and signature as per OID4VP and RFC9101.
func (b *requestBuilder) withDraft24RequestObject(obj string) *requestBuilder {
	if b.errValidation != nil {
		return b
	}

	// Parse the JWT
	allowedAlgs := []jose.SignatureAlgorithm{jose.ES256, jose.RS256}
	parsedJWT, err := jwt.ParseSigned(obj, allowedAlgs)
	if err != nil {
		b.errValidation = fmt.Errorf("failed to parse request object JWT: %w", err)
		return b
	}

	// Validate 'typ' header as per OID4VP specification
	// Request Objects MUST include typ Header Parameter with value "oauth-authz-req+jwt"
	if len(parsedJWT.Headers) == 0 {
		b.errValidation = fmt.Errorf("request object JWT must have headers")
		return b
	}

	typHeader, exists := parsedJWT.Headers[0].ExtraHeaders["typ"]
	if !exists {
		b.errValidation = fmt.Errorf("request object JWT must include 'typ' header parameter")
		return b
	}

	typStr, ok := typHeader.(string)
	if !ok || typStr != "oauth-authz-req+jwt" {
		b.errValidation = fmt.Errorf("request object JWT 'typ' header must be 'oauth-authz-req+jwt', got: %v", typHeader)
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

	// x509_san_dns
	clientID, err := parseOID4VPClientID(b.req.ClientID)
	if err == nil && clientID.prefix == OID4VPClientIDPrefixX509Hash {
		certificates, err := parseX5CCertificatesFromJWT(obj)
		if err != nil {
			b.errValidation = err
			return b
		}
		if len(certificates) == 0 {
			b.errValidation = fmt.Errorf("x5c header is empty")
			return b
		}
		thumbprint := sha256.Sum256(certificates[0].Raw)
		actualHash := base64.RawURLEncoding.EncodeToString(thumbprint[:])
		if actualHash != clientID.original {
			b.errValidation = fmt.Errorf("x509_hash client_id mismatch: expected %s, got %s", clientID.original, actualHash)
			return b
		}

		claims := jwt.Claims{}
		if err := parsedJWT.Claims(certificates[0].PublicKey, &claims); err != nil {
			b.errValidation = fmt.Errorf("failed to verify request object with x5c certificate: %v", err)
			return b
		}
		return b
	}

	if err == nil && clientID.prefix == OID4VPClientIDPrefixX509SanDNS {
		var certificates *[]*x509.Certificate = nil

		if b.insecureSkipX509Verify {
			// For testing: Parse certificates from x5c WITHOUT calling x509.Verify(),
			// which in Go 1.20+ performs strict standards compliance checks that reject
			// non-compliant certificates (e.g., "OIDF Test" from conformance test suites).
			// We manually parse the x5c chain and use the certificates directly.

			// Split JWT to get header part
			parts := strings.Split(obj, ".")
			if len(parts) < 2 {
				b.errValidation = fmt.Errorf("invalid JWT format")
				return b
			}

			// Decode header (JWT uses base64url encoding without padding)
			headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				b.errValidation = fmt.Errorf("failed to decode JWT header: %w", err)
				return b
			}

			var header struct {
				X5C []string `json:"x5c"`
			}
			if err := json.Unmarshal(headerJSON, &header); err != nil {
				b.errValidation = fmt.Errorf("failed to parse JWT header: %w", err)
				return b
			}

			if len(header.X5C) == 0 {
				b.errValidation = fmt.Errorf("x5c header is empty")
				return b
			}

			// Parse all certificates in the x5c chain
			// x5c contains standard base64 encoded (not base64url) DER certificates
			var certChain []*x509.Certificate
			for i, certB64 := range header.X5C {
				certDER, err := base64.StdEncoding.DecodeString(certB64)
				if err != nil {
					b.errValidation = fmt.Errorf("failed to decode x5c certificate at index %d: %w", i, err)
					return b
				}
				cert, err := x509.ParseCertificate(certDER)
				if err != nil {
					b.errValidation = fmt.Errorf("failed to parse x5c certificate at index %d: %w", i, err)
					return b
				}
				certChain = append(certChain, cert)
			}

			certificates = &certChain
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
					certificates = &chain
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
		verifyKey := (*certificates)[0].PublicKey
		if err := parsedJWT.Claims(verifyKey, &claims); err != nil {
			b.errValidation = fmt.Errorf("failed to verify request object with x5c certificate: %v", err)
			return b
		}

		// ClientID should contain DNS name which is same as the SAN of the leaf certificate in the x5c array (OID4VP x509_san_dns). #106
		matched := false
		for _, n := range (*certificates)[0].DNSNames {
			if clientID.original == n {
				matched = true
				break
			}
		}
		if !matched {
			b.errValidation = fmt.Errorf("SAN of the certificate and client_id did not match")
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
			b.errValidation = fmt.Errorf("redirect_uri/response_uri and client_id (origin) must be same")
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
		b.errValidation = fmt.Errorf("failed to verify JWT signature: %w", err)
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
