package oid4vp

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/profile"
)

// OID4VPClientIDPrefixWebOrigin is the effective Client Identifier Prefix the
// Wallet assigns to an unsigned DC API request. OID4VP 1.0 Appendix A.2: "The
// client_id parameter MUST be omitted in unsigned requests". The Wallet uses
// the platform-authenticated Origin as the effective identifier.
const OID4VPClientIDPrefixWebOrigin OID4VPClientIDPrefix = "web-origin"

// dcapiSignatureVerifier verifies one DC API request object signature with the
// authenticated leaf certificate's public key and returns the signed claims.
type dcapiSignatureVerifier func(publicKey any) (map[string]any, error)

// newDCAPIRequestBuilder wires the presenter's trust and profile policy into a
// requestBuilder used by the DC API paths.
func (p *Oid4vpPresenter) newDCAPIRequestBuilder(normalizedProfile profile.Profile) *requestBuilder {
	b := NewRequestBuilder()
	b.profile = normalizedProfile
	b.httpClient = p.httpClient()
	b.allowHTTP = p.AllowHTTP
	b.x509TrustChainRoots = p.X509TrustChainRoots
	b.insecureSkipX509Verify = p.InsecureSkipX509Verify
	b.errorResponseAllowed = false
	if p.RequestObjectValidation != nil {
		b.WithRequestObjectValidation(*p.RequestObjectValidation)
	}
	return b
}

// ParseDCAPIRequest authenticates and parses one platform DC API invocation
// (OID4VP 1.0 Appendix A.3). The Origin is supplied by the platform and is
// never read from the request. Unsigned requests are accepted without a
// signature using web-origin:<origin> as the effective identifier; signed and
// multi-signed requests are authenticated exactly like a signed Request Object.
func (p *Oid4vpPresenter) ParseDCAPIRequest(invocation DCAPIInvocation) (*CredentialPresentationRequest, error) {
	normalizedProfile, err := p.Profile.Normalize()
	if err != nil {
		return nil, fmt.Errorf("invalid OID4VP profile: %w", err)
	}
	origin := strings.TrimSpace(invocation.Origin)
	if origin == "" {
		return nil, newAuthorizationRequestError(InvalidRequestError, "the platform Origin is required for a DC API request")
	}

	var request *CredentialPresentationRequest
	switch invocation.Request.Protocol {
	case DCAPIProtocolUnsigned:
		request, err = p.parseDCAPIUnsigned(invocation, origin, normalizedProfile)
	case DCAPIProtocolSigned:
		request, err = p.parseDCAPISigned(invocation, origin, normalizedProfile)
	case DCAPIProtocolMultiSigned:
		request, err = p.parseDCAPIMultiSigned(invocation, origin, normalizedProfile)
	default:
		return nil, newAuthorizationRequestError(InvalidRequestError, "unsupported DC API protocol %q", invocation.Request.Protocol)
	}
	if err != nil {
		return nil, err
	}
	// OID4VP 1.0 Appendix A.4: "The audience for the response (for example, the
	// aud value in a Key Binding JWT) MUST be the Origin, prefixed with
	// origin:". This is the case even for signed requests.
	request.ResponseAudience = dcapiOriginAudience(origin)
	request.DCAPIProtocol = invocation.Request.Protocol
	return request, nil
}

// parseDCAPIUnsigned handles Appendix A.3.1. The Wallet MUST ignore any
// client_id and expected_origins delivered in an unsigned request (A.2).
func (p *Oid4vpPresenter) parseDCAPIUnsigned(invocation DCAPIInvocation, origin string, normalizedProfile profile.Profile) (*CredentialPresentationRequest, error) {
	if len(invocation.Request.Data) == 0 || string(invocation.Request.Data) == "null" {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API unsigned request data is required")
	}
	var params map[string]any
	if err := json.Unmarshal(invocation.Request.Data, &params); err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API unsigned request data must be a JSON object: %v", err)
	}
	// A.2: "The client_id parameter MUST be omitted in unsigned requests
	// defined in Appendix A.3.1. The Wallet MUST ignore any client_id parameter
	// that is present in an unsigned request." The same applies to
	// expected_origins: "This parameter is not for use in unsigned requests and
	// therefore a Wallet MUST ignore this parameter if it is present in an
	// unsigned request."
	delete(params, "client_id")
	delete(params, "expected_origins")
	params["client_id"] = dcapiWebOriginClientID(origin)

	b := p.newDCAPIRequestBuilder(normalizedProfile)
	b.requestSource = "dcapi-unsigned"
	b.setParamsWithAnyMap(params)
	if b.errValidation != nil {
		return nil, b.errValidation
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	if err := b.enforceHAIPProfile(); err != nil {
		return nil, err
	}
	return b.req, nil
}

// parseDCAPISigned handles Appendix A.3.2.1: data.request is a compact JWS
// whose protected header or payload carries client_id.
func (p *Oid4vpPresenter) parseDCAPISigned(invocation DCAPIInvocation, origin string, normalizedProfile profile.Profile) (*CredentialPresentationRequest, error) {
	var data map[string]json.RawMessage
	if err := json.Unmarshal(invocation.Request.Data, &data); err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API signed request data must be a JSON object: %v", err)
	}
	rawRequest, ok := data["request"]
	if !ok {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API signed request must carry a request member")
	}
	var obj string
	if err := json.Unmarshal(rawRequest, &obj); err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API signed request member must be a compact JWS string")
	}
	if strings.Count(obj, ".") != 2 || len(obj) > 1<<20 {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API signed request must be a bounded compact signed JWT")
	}

	b := p.newDCAPIRequestBuilder(normalizedProfile)
	options, err := b.requestObjectValidationOptions()
	if err != nil {
		return nil, err
	}
	algs := options.SigningAlgorithms
	if len(algs) == 0 {
		algs = []jose.SignatureAlgorithm{jose.ES256, jose.RS256}
	}
	parsed, err := jwt.ParseSigned(obj, algs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DC API request object JWT: %w", err)
	}
	if len(parsed.Headers) != 1 {
		return nil, errors.New("DC API request object JWT must have one protected header")
	}
	typ, _ := parsed.Headers[0].ExtraHeaders["typ"].(string)
	if typ != "oauth-authz-req+jwt" {
		return nil, errors.New("DC API request object JWT 'typ' header must be 'oauth-authz-req+jwt'")
	}
	header, err := decodeDCAPIProtectedHeader(compactProtectedSegment(obj))
	if err != nil {
		return nil, fmt.Errorf("failed to decode DC API request object protected header: %w", err)
	}
	claims := map[string]any{}
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode DC API request object claims: %w", err)
	}
	clientID := dcapiClientIDFromHeaderOrPayload(header, claims)
	if clientID == "" {
		return nil, newAuthorizationRequestError(InvalidRequestError, "signed DC API request must carry client_id")
	}
	certificates, err := parseX5CCertificatesFromJWT(obj)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if options.Now != nil {
		now = options.Now()
	}
	chainResult, err := b.verifyRequestObjectCertificateChain(certificates, options, now)
	if err != nil {
		return nil, fmt.Errorf("DC API request object certificate chain is not trusted: %w", err)
	}
	verify := func(publicKey any) (map[string]any, error) {
		verified := commonJOSE.Claims{}
		if err := parsed.Claims(publicKey, &verified); err != nil {
			return nil, fmt.Errorf("failed to verify DC API request object signature: %w", err)
		}
		return map[string]any(verified), nil
	}
	b.requestSource = "dcapi-signed"
	return b.finishDCAPIRequestObject(certificates, options, chainResult, clientID, verify, origin)
}

// parseDCAPIMultiSigned handles Appendix A.3.2.2. Each entry in the JWS JSON
// Serialization signatures array carries its own client_id in the protected
// header; the Wallet authenticates the first signature whose x509_hash client
// identifier it can verify and MUST verify at least one.
func (p *Oid4vpPresenter) parseDCAPIMultiSigned(invocation DCAPIInvocation, origin string, normalizedProfile profile.Profile) (*CredentialPresentationRequest, error) {
	var data map[string]json.RawMessage
	if err := json.Unmarshal(invocation.Request.Data, &data); err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API multi-signed request data must be a JSON object: %v", err)
	}
	rawRequest, ok := data["request"]
	if !ok {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API multi-signed request must carry a request member")
	}
	var multi struct {
		Payload    string `json:"payload"`
		Signatures []struct {
			Protected string `json:"protected"`
			Signature string `json:"signature"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(rawRequest, &multi); err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API multi-signed request must be a JWS JSON Serialization object")
	}
	if multi.Payload == "" || len(multi.Signatures) == 0 {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API multi-signed request requires payload and signatures")
	}
	initialBuilder := p.newDCAPIRequestBuilder(normalizedProfile)
	options, err := initialBuilder.requestObjectValidationOptions()
	if err != nil {
		return nil, err
	}
	algs := options.SigningAlgorithms
	if len(algs) == 0 {
		algs = []jose.SignatureAlgorithm{jose.ES256, jose.RS256}
	}
	parsed, err := jose.ParseSigned(string(rawRequest), algs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DC API multi-signed request: %w", err)
	}
	if len(parsed.Signatures) != len(multi.Signatures) {
		return nil, errors.New("DC API multi-signed request signatures could not be parsed")
	}

	var lastErr error
	for index := range multi.Signatures {
		header, headerErr := decodeDCAPIProtectedHeader(multi.Signatures[index].Protected)
		if headerErr != nil {
			lastErr = headerErr
			continue
		}
		clientID, _ := header["client_id"].(string)
		if clientID == "" {
			lastErr = errors.New("DC API multi-signed signature is missing client_id")
			continue
		}
		clientIDValue, parseErr := parseOID4VPClientID(clientID)
		if parseErr != nil {
			lastErr = parseErr
			continue
		}
		if clientIDValue.prefix != OID4VPClientIDPrefixX509Hash && clientIDValue.prefix != OID4VPClientIDPrefixX509SanDNS {
			lastErr = errors.New("DC API multi-signed client identifier has no configured authentication method")
			continue
		}
		certificates, certErr := parseX5CCertificatesFromHeader(header)
		if certErr != nil {
			lastErr = certErr
			continue
		}
		b := p.newDCAPIRequestBuilder(normalizedProfile)
		now := time.Now()
		if options.Now != nil {
			now = options.Now()
		}
		chainResult, chainErr := b.verifyRequestObjectCertificateChain(certificates, options, now)
		if chainErr != nil {
			lastErr = chainErr
			continue
		}
		verify := func(publicKey any) (map[string]any, error) {
			verifiedIndex, _, payload, verifyErr := parsed.VerifyMulti(publicKey)
			if verifyErr != nil {
				return nil, fmt.Errorf("failed to verify DC API multi-signed request: %w", verifyErr)
			}
			if verifiedIndex != index {
				return nil, errors.New("verified DC API signature does not match the authenticated Client Identifier")
			}
			claims := map[string]any{}
			if unmarshalErr := json.Unmarshal(payload, &claims); unmarshalErr != nil {
				return nil, fmt.Errorf("failed to decode DC API multi-signed payload: %w", unmarshalErr)
			}
			return claims, nil
		}
		b.requestSource = "dcapi-signed"
		request, finishErr := b.finishDCAPIRequestObject(certificates, options, chainResult, clientID, verify, origin)
		if finishErr != nil {
			lastErr = finishErr
			continue
		}
		return request, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no authenticatable signature")
	}
	return nil, fmt.Errorf("no trusted DC API multi-signed request signature: %w", lastErr)
}

// finishDCAPIRequestObject completes a signed DC API request: it verifies the
// selected signature, enforces the DC API and profile constraints, validates
// the standard claims and records the authentication result.
func (b *requestBuilder) finishDCAPIRequestObject(certificates []*x509.Certificate, options RequestObjectValidationOptions, chainResult *commonX509.SigningChainResult, clientID string, verify dcapiSignatureVerifier, origin string) (*CredentialPresentationRequest, error) {
	if len(certificates) == 0 || len(certificates) > 16 {
		return nil, errors.New("x5c header must contain between 1 and 16 certificates")
	}
	verified, err := verify(certificates[0].PublicKey)
	if err != nil {
		return nil, err
	}
	if payloadClientID, ok := verified["client_id"].(string); ok && payloadClientID != "" && payloadClientID != clientID {
		return nil, newAuthorizationRequestError(InvalidRequestError, "DC API signature client_id does not match the request object client_id")
	}
	verified["client_id"] = clientID
	parsedClientID, err := parseOID4VPClientID(clientID)
	if err != nil {
		return nil, err
	}
	if parsedClientID.prefix != OID4VPClientIDPrefixX509Hash && parsedClientID.prefix != OID4VPClientIDPrefixX509SanDNS {
		return nil, errors.New("signed DC API request client identifier has no configured authentication method")
	}
	if b.profile.IsHAIP() {
		// HAIP §5: "The X.509 certificate of the trust anchor MUST NOT be
		// included in the x5c JOSE header of the signed request."
		for _, certificate := range certificates {
			for _, anchor := range options.TrustAnchors {
				if anchor != nil && bytes.Equal(certificate.Raw, anchor.Raw) {
					return nil, errors.New("HAIP profile does not permit the trust anchor certificate in the x5c header")
				}
			}
		}
	}
	if err := bindDCAPIX509ClientID(parsedClientID, certificates[0]); err != nil {
		return nil, err
	}
	if err := validateDCAPIExpectedOrigins(verified, origin); err != nil {
		return nil, err
	}
	now := time.Now()
	if options.Now != nil {
		now = options.Now()
	}
	if err := validateRequestObjectClaims(commonJOSE.Claims(verified), options.WalletAudience, now, options.ClockSkew); err != nil {
		return nil, fmt.Errorf("JWT standard claims validation failed: %w", err)
	}
	b.setParamsWithAnyMap(verified)
	if b.errValidation != nil {
		return nil, b.errValidation
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	if err := b.enforceHAIPProfile(); err != nil {
		return nil, err
	}
	b.req.RequestObjectVerification = &RequestObjectVerification{
		ClientID: b.req.ClientID, CertificateSHA256: chainResult.Fingerprints,
		RevocationChecked:      chainResult.Revocation.CheckedCertificates,
		RevocationUnadvertised: chainResult.Revocation.NoMechanismCertificates,
	}
	return b.req, nil
}

// BuildDCAPIResponse builds the object returned to the platform for an already
// parsed DC API request (OID4VP 1.0 Appendix A.4). dc_api returns the plaintext
// vp_token object; dc_api.jwt encrypts the Authorization Response exactly like
// direct_post.jwt (§8.3) and returns it as the response member.
func (p *Oid4vpPresenter) BuildDCAPIResponse(request *CredentialPresentationRequest, vpToken map[string][]string) (*DCAPIResponse, error) {
	if request == nil {
		return nil, errors.New("DC API response requires a parsed request")
	}
	if len(vpToken) == 0 {
		return nil, errors.New("DC API response requires a non-empty vp_token")
	}
	protocol := request.DCAPIProtocol
	if protocol == "" {
		return nil, errors.New("DC API response requires the request protocol")
	}
	switch request.ResponseMode {
	case OAuthAuthzReqResponseModeDCAPI:
		return &DCAPIResponse{Protocol: protocol, Data: map[string]any{"vp_token": vpToken}}, nil
	case OAuthAuthzReqResponseModeDCAPIJWT:
		if request.ClientMetadata == nil {
			return nil, errors.New("dc_api.jwt response requires verifier client_metadata with an encryption key")
		}
		payload := map[string]any{"vp_token": vpToken}
		encrypted, err := p.CreateEncryptedAuthorizationResponse(payload, request.ClientMetadata)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt DC API response: %w", err)
		}
		return &DCAPIResponse{Protocol: protocol, Data: map[string]any{"response": encrypted}}, nil
	default:
		return nil, fmt.Errorf("response_mode %q is not a DC API mode", request.ResponseMode)
	}
}

// bindDCAPIX509ClientID binds an x509_hash or x509_san_dns Client Identifier to
// the selected leaf certificate. Over the DC API there is no redirect_uri or
// response_uri, so only the certificate binding is checked; the platform Origin
// is validated separately against expected_origins.
func bindDCAPIX509ClientID(clientID *OID4VPClientID, leaf *x509.Certificate) error {
	switch clientID.prefix {
	case OID4VPClientIDPrefixX509Hash:
		digest := sha256.Sum256(leaf.Raw)
		if base64.RawURLEncoding.EncodeToString(digest[:]) != clientID.original {
			return errors.New("x509_hash client_id mismatch")
		}
		return nil
	case OID4VPClientIDPrefixX509SanDNS:
		for _, name := range leaf.DNSNames {
			if strings.EqualFold(name, clientID.original) {
				return nil
			}
		}
		return errors.New("SAN of the certificate and client_id did not match")
	default:
		return fmt.Errorf("unsupported DC API client_id prefix: %s", clientID.prefix)
	}
}

// validateDCAPIExpectedOrigins enforces Appendix A.2: expected_origins is
// REQUIRED for signed requests and the platform Origin MUST match one entry,
// otherwise the Wallet MUST return an error.
func validateDCAPIExpectedOrigins(claims map[string]any, origin string) error {
	raw, present := claims["expected_origins"]
	if !present {
		return newAuthorizationRequestError(InvalidRequestError, "expected_origins is required for signed DC API requests")
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return newAuthorizationRequestError(InvalidRequestError, "expected_origins must be a non-empty array of origins")
	}
	for _, value := range list {
		candidate, ok := value.(string)
		if !ok {
			return newAuthorizationRequestError(InvalidRequestError, "expected_origins must contain only strings")
		}
		if candidate == origin || strings.TrimRight(candidate, "/") == strings.TrimRight(origin, "/") {
			return nil
		}
	}
	return newAuthorizationRequestError(InvalidRequestError, "the platform Origin does not match any expected_origins entry")
}

// dcapiClientIDFromHeaderOrPayload returns client_id from the protected header
// when present, otherwise from the signed payload (Appendix A.3.2).
func dcapiClientIDFromHeaderOrPayload(header, claims map[string]any) string {
	if clientID, ok := header["client_id"].(string); ok && clientID != "" {
		return clientID
	}
	clientID, _ := claims["client_id"].(string)
	return clientID
}

func compactProtectedSegment(obj string) string {
	if index := strings.IndexByte(obj, '.'); index >= 0 {
		return obj[:index]
	}
	return ""
}

func decodeDCAPIProtectedHeader(encoded string) (map[string]any, error) {
	if encoded == "" {
		return nil, errors.New("protected header is empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	header := map[string]any{}
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, err
	}
	return header, nil
}

// parseX5CCertificatesFromHeader decodes the x5c member of a decoded JWS
// protected header (used by the multi-signed path).
func parseX5CCertificatesFromHeader(header map[string]any) ([]*x509.Certificate, error) {
	raw, present := header["x5c"]
	if !present {
		return nil, errors.New("x5c header is required")
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil, errors.New("x5c header is empty")
	}
	certificates := make([]*x509.Certificate, 0, len(list))
	for index, value := range list {
		encoded, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("x5c certificate at index %d is not a string", index)
		}
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("failed to decode x5c certificate at index %d: %w", index, err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x5c certificate at index %d: %w", index, err)
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

func dcapiWebOriginClientID(origin string) string {
	return string(OID4VPClientIDPrefixWebOrigin) + ":" + origin
}

func dcapiOriginAudience(origin string) string {
	return string(OID4VPClientIDPrefixOriginal) + ":" + origin
}
