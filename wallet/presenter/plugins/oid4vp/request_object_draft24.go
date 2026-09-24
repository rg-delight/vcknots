package oid4vp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/go-jose/go-jose/v4/jwt"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
)

// withDraft24RequestObject authenticates a Draft24 Request Object and loads
// its claims. X.509 Request Objects go through authenticateX509RequestObject,
// except x509_san_dns with only X509TrustChainRoots configured and the
// InsecureSkipX509Verify test escape.
func (b *requestBuilder) withDraft24RequestObject(obj string) *requestBuilder {
	if b.errValidation != nil {
		return b
	}

	options, err := b.requestObjectValidationOptions()
	if err != nil {
		b.errValidation = err
		return b
	}
	b.adoptCallerWalletNonce(options)

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

	clientID, clientIDErr := b.parseClientID(b.req.ClientID)
	isX509ClientID := clientIDErr == nil &&
		(clientID.prefix == OID4VPClientIDPrefixX509Hash || clientID.prefix == OID4VPClientIDPrefixX509SanDNS)

	// A Verifier identified by an attestation or by an OpenID Federation
	// Entity Identifier is authenticated exactly as on the Final wire: the
	// Draft24 text defines the same two schemes, and the keys that may sign
	// their Request Objects come from the attestation or the Trust Chain,
	// never from client_metadata.
	if clientIDErr == nil && (clientID.prefix == OID4VPClientIDPrefixVerifierAttestation || clientID.prefix == OID4VPClientIDPrefixOIDFederation) {
		if b.requestObjectValidation == nil {
			b.errValidation = fmt.Errorf("%w: %q", ErrRequestObjectClientAuthUnsupported, clientID.prefix)
			return b
		}
		if err := b.authenticateRequestObjectByClientIdentifier(obj, parsedJWT, options); err != nil {
			b.errValidation = err
		}
		return b
	}

	// The shared X.509 path applies when the caller configured
	// RequestObjectValidationOptions, and always to x509_hash, whose thumbprint
	// names a certificate without saying it is trusted. Only x509_san_dns
	// without options keeps the X509TrustChainRoots check below.
	useShared := b.requestObjectValidation != nil || (clientIDErr == nil && clientID.prefix == OID4VPClientIDPrefixX509Hash)
	if isX509ClientID && useShared && !b.insecureSkipX509Verify {
		if err := b.authenticateX509RequestObject(obj, parsedJWT, options); err != nil {
			b.errValidation = err
		}
		return b
	}

	// x509_hash under InsecureSkipX509Verify: the thumbprint and signature are
	// checked, the chain is not.
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

	// verify the JWT signature and extract the verified claims
	verifiedClaims := make(commonJOSE.Claims)
	if err := parsedJWT.Claims(&k, &verifiedClaims); err != nil {
		b.errValidation = fmt.Errorf("failed to verify JWT signature: %w: %w", err, ErrRequestObjectSignatureInvalid)
		return b
	}

	// The registered claims (RFC 9101 Section 10.2, RFC 7519 Section 4.1)
	// are judged by the same policy as every other Request Object: at the
	// caller's verification time (RequestObjectValidationOptions.Now) with
	// the caller's ClockSkew. A wallet that re-authenticates at consent the
	// Request Object it admitted earlier names the admission instant, so a
	// Request Object whose exp falls between the two is not refused at
	// consent. This path never read aud, and keeps not reading it.
	policy := b.resolveClaimPolicy(options, requestObjectNow(options))
	policy.Audiences = nil
	policy.AudienceOptional = true
	if err := validateRequestObjectClaims(verifiedClaims, policy); err != nil {
		b.errValidation = fmt.Errorf("JWT standard claims validation failed: %w", err)
		return b
	}
	// This path has always refused a Request Object issued in the future;
	// it keeps doing so, against the same instant and skew.
	if err := validateDraft24IssuedAt(verifiedClaims, policy); err != nil {
		b.errValidation = fmt.Errorf("JWT standard claims validation failed: %w", err)
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

// validateDraft24IssuedAt refuses an iat later than the verification time plus
// the clock skew (RFC 7519 Section 4.1.6 leaves the check to the recipient).
func validateDraft24IssuedAt(claims commonJOSE.Claims, policy requestObjectClaimPolicy) error {
	issuedAt, err := requestObjectNumericDate(claims, "iat")
	if err != nil || issuedAt == nil {
		return err
	}
	if requestObjectInstant(policy.Now.Add(policy.ClockSkew)).Cmp(issuedAt) < 0 {
		return fmt.Errorf("request object is issued in the future: %w", ErrRequestObjectExpired)
	}
	return nil
}
