package oid4vci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver/oid4vcisign"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// Oid4vciReceiver is the bundled OpenID4VCI receiver plugin. It implements the
// Draft 13 types.Receiver contract, the Final 1.0 / HAIP
// types.OID4VCIFinalTransport contract and, through the embedded
// oid4vcisign.Default, the types.OID4VCIFinalSigner contract.
type Oid4vciReceiver struct {
	// Default supplies the OpenID4VCI 1.0 Final signing primitives (DPoP proof,
	// jwt key proof, client attestation JWTs) so this plugin satisfies
	// types.OID4VCIFinalSigner as well as types.OID4VCIFinalTransport. A wallet
	// that signs elsewhere configures its own signer and uses this plugin only
	// as a transport.
	oid4vcisign.Default

	HTTPClient *http.Client
	// AllowHTTP permits HTTP endpoints for a local test issuer. The zero value requires HTTPS.
	AllowHTTP bool
	// Profile selects the OpenID4VCI Final/HAIP policy. The zero value normalizes
	// to profile.Final, which applies no HAIP constraints. Set it to profile.HAIP
	// to enforce HAIP 1.0 on the Final path.
	Profile profile.Profile
	// IssuerMetadataSigning configures OpenID4VCI 1.0 Section 12.2.3 signed
	// Credential Issuer Metadata. A nil value requests signed metadata under
	// HAIP and accepts an unsigned application/json document in every profile;
	// see IssuerMetadataSigningOptions for the defaults each field takes.
	IssuerMetadataSigning *IssuerMetadataSigningOptions

	// dpopNonceMu guards dpopNonces. The map is created on first use because
	// every caller builds this struct as a literal, so there is no constructor
	// that could allocate it. A zero Oid4vciReceiver is therefore usable and,
	// once in use, must not be copied.
	dpopNonceMu sync.Mutex
	// dpopNonces is the RFC 9449 Section 8.2 per-server nonce store: "The DPoP
	// nonce ... is provided by the server to the client in the DPoP-Nonce HTTP
	// header ... Clients should expect that a server will use the same nonce
	// for all requests to that server". It is keyed by the endpoint's scheme
	// and authority, because that is the granularity RFC 9449 Section 8.2
	// assigns a nonce to, and it holds the most recent value the wallet has
	// seen from that server on any endpoint.
	dpopNonces map[string]string
}

var (
	_ types.OID4VCIFinalTransport = (*Oid4vciReceiver)(nil)
	_ types.OID4VCIFinalSigner    = (*Oid4vciReceiver)(nil)
	_ profile.Carrier             = (*Oid4vciReceiver)(nil)
)

// ProtocolProfile reports the normalized OID4VCI profile this receiver enforces.
func (o *Oid4vciReceiver) ProtocolProfile() profile.Profile {
	normalized, err := o.Profile.Normalize()
	if err != nil {
		return o.Profile
	}
	return normalized
}

// SetProtocolProfile is used by the wallet root to propagate its profile to the
// default receiver plugin it constructs itself.
func (o *Oid4vciReceiver) SetProtocolProfile(p profile.Profile) {
	o.Profile = p
}

// normalizedProfile normalizes the configured profile once. Unknown values fail
// closed before any network access so every checkpoint reads a validated value.
func (o *Oid4vciReceiver) normalizedProfile() (profile.Profile, error) {
	normalized, err := o.Profile.Normalize()
	if err != nil {
		return "", fmt.Errorf("invalid OID4VCI profile: %w", err)
	}
	return normalized, nil
}

// requireHAIPTransport rejects the test-only HTTP escape when HAIP is selected.
// HAIP §4 requires TLS for issuer and authorization server endpoints.
func (o *Oid4vciReceiver) requireHAIPTransport(normalized profile.Profile) error {
	if normalized.IsHAIP() && o.AllowHTTP {
		return fmt.Errorf("HAIP profile does not permit AllowHTTP")
	}
	return nil
}

// httpClient returns the client every OpenID4VCI request is sent through. The
// caller's client is wrapped rather than mutated, and the wrapper is rebuilt per
// call because a caller may replace HTTPClient between requests; the wrapper
// shares the caller's Transport, so connection pooling is unaffected.
func (o *Oid4vciReceiver) httpClient() *http.Client {
	return NoRedirectClient(o.HTTPClient)
}

var oid4vciHTTPClient = &http.Client{Timeout: 15 * time.Second, CheckRedirect: rejectOID4VCIRedirect}

// ErrHTTPRedirectNotAllowed reports that an OpenID4VCI endpoint answered with a
// redirect. No OpenID4VCI endpoint is defined to redirect, and following one is
// never safe: a 307 or 308 replays the request body together with the
// Authorization, DPoP and OAuth-Client-Attestation headers against an origin the
// response chose, and a redirected metadata document substitutes the Credential
// Issuer's identity for another. The root wallet package cannot be imported from
// a plugin, so it declares its own alias of this sentinel.
var ErrHTTPRedirectNotAllowed = common.NewCodedError("http_redirect_not_allowed", "OID4VCI endpoint redirected; redirects are not followed")

// rejectOID4VCIRedirect refuses to follow a redirect on any OpenID4VCI request,
// metadata retrieval included. Credential Issuer Metadata is fetched from the
// path Section 12.2.2 fixes inside the Credential Issuer Identifier, so a
// redirect can only move the document to an origin the identifier does not name.
func rejectOID4VCIRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("OID4VCI endpoint redirected to %s: %w", req.URL.Redacted(), ErrHTTPRedirectNotAllowed)
}

// NoRedirectClient returns a shallow copy of client whose CheckRedirect refuses
// every 3xx with ErrHTTPRedirectNotAllowed. The caller's *http.Client is never
// mutated: its Transport, Timeout, Jar and every other field are carried over to
// the copy, which shares the same Transport. A nil client yields this package's
// default client, which already refuses redirects.
func NoRedirectClient(client *http.Client) *http.Client {
	if client == nil {
		return oid4vciHTTPClient
	}
	noRedirect := *client
	noRedirect.CheckRedirect = rejectOID4VCIRedirect
	return &noRedirect
}

// OID4VCICredentialFormatToSerializationFlavor maps OID4VCI credential format identifiers
// to wallet serialization flavors.
func OID4VCICredentialFormatToSerializationFlavor(format string) (credential.SupportedSerializationFlavor, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "jwt_vc_json", "jwt_vc", string(credential.JwtVc):
		return credential.JwtVc, nil
	case "dc+sd-jwt", string(credential.SDJwtVC):
		return credential.SDJwtVC, nil
	default:
		return "", fmt.Errorf("unsupported credential format: %q", format)
	}
}

// doRequest performs an HTTP request and unmarshals the JSON response into target.
// It handles common patterns: URL construction, status checking, body reading, and JSON parsing.
// ctx bounds the request.
func (o *Oid4vciReceiver) doRequest(ctx context.Context, method string, endpoint common.URIField, path string, body io.Reader, target interface{}) error {
	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	if path == "/.well-known/oauth-authorization-server" {
		// Special handling for metadata discovery as per RFC 8414 §3
		// The well-known string MUST be inserted between the host component and the path component.
		// RFC 8414 §3.1 excludes the trailing slash from the AS path component.
		originalPath := strings.TrimSuffix(endpointURL.Path, "/")
		if !strings.HasPrefix(originalPath, path) {
			endpointURL.Path = path + originalPath
		}
	} else {
		// OID4VCI Draft 13 (ID1) §11.2.2, etc...
		if !strings.HasSuffix(endpointURL.Path, path) {
			endpointURL = *endpointURL.JoinPath(path)
		}
	}

	return o.doRequestURL(ctx, method, endpointURL, body, target)
}

func (o *Oid4vciReceiver) doRequestURL(ctx context.Context, method string, endpointURL url.URL, body io.Reader, target interface{}) error {
	if method != http.MethodGet && method != http.MethodPost {
		return fmt.Errorf("unsupported HTTP method: %s", method)
	}
	if method == "POST" && body == nil {
		return fmt.Errorf("POST request requires a body")
	}
	req, err := http.NewRequestWithContext(ctx, method, endpointURL.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return &httpStatusError{statusCode: resp.StatusCode, body: string(bodyBytes)}
	}

	if len(bodyBytes) == 0 {
		return fmt.Errorf("empty response body")
	}
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	return nil
}

// doFinalRequest performs one OpenID4VCI 1.0 Final request and decodes a JSON
// body into target, discarding the response headers. ctx bounds the request.
func (o *Oid4vciReceiver) doFinalRequest(ctx context.Context, method string, endpoint common.URIField, body io.Reader, contentType string, headers map[string]string, target any) error {
	_, err := o.doFinalRequestWithResponseHeader(ctx, method, endpoint, body, contentType, headers, target)
	return err
}

// doFinalRequestWithResponseHeader is doFinalRequest, returning the response
// header as well. Some OpenID4VCI responses carry protocol state outside the
// body: the Section 7.2 Nonce Response may carry an RFC 9449 Section 8.2
// DPoP-Nonce the wallet has to use on the next request. The header is returned
// non-nil whenever a response was received, so a caller may read it without a
// nil check; on a transport error it is nil and the error is returned.
func (o *Oid4vciReceiver) doFinalRequestWithResponseHeader(ctx context.Context, method string, endpoint common.URIField, body io.Reader, contentType string, headers map[string]string, target any) (http.Header, error) {
	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpointURL.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for key, value := range headers {
		if value != "" {
			req.Header.Set(key, value)
		}
	}

	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	o.rememberDPoPNonce(endpointURL, resp.Header.Get("DPoP-Nonce"))

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.Header, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.Header, &httpStatusError{statusCode: resp.StatusCode, body: string(bodyBytes)}
	}
	if target == nil || len(bodyBytes) == 0 {
		return resp.Header, nil
	}
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return resp.Header, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return resp.Header, nil
}

// ReceiveCredential performs a Draft 13 credential request. It is a legacy
// types.Receiver method and therefore carries no context; it binds its request
// to context.Background().
func (o *Oid4vciReceiver) ReceiveCredential(
	receivingTypes types.SupportedReceivingTypes,
	endpoint common.URIField,
	credentialConfigurationID string,
	credentialIdentifier *string,
	accessToken types.CredentialIssuanceAccessToken,
	credentialDefinition *types.CredentialDefinition,
	jwtProof *string,
	options ...*types.CredentialRequestOptions,
) (*string, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}

	endpointURL := url.URL(endpoint)
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}

	// Prepare credential request body
	reqBody := map[string]interface{}{}
	if credentialIdentifier != nil && *credentialIdentifier != "" {
		reqBody["credential_identifier"] = *credentialIdentifier
	} else {
		reqBody["credential_configuration_id"] = credentialConfigurationID
	}

	if jwtProof != nil {
		reqBody["proofs"] = map[string]interface{}{
			"jwt": []string{*jwtProof},
		}
	}

	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(context.Background(), "POST", endpointURL.String(), bytes.NewReader(reqBodyBytes))
	if err != nil {
		return nil, err
	}

	requestOptions := firstCredentialRequestOptions(options)

	// Set headers
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	tokenType := authorizationScheme(accessToken.TokenType)
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken.Token))
	if strings.EqualFold(accessToken.TokenType, "DPoP") {
		if requestOptions == nil || requestOptions.DPoPProofJWT == nil || *requestOptions.DPoPProofJWT == "" {
			return nil, fmt.Errorf("DPoP proof JWT is required for DPoP access token")
		}
		req.Header.Set("DPoP", *requestOptions.DPoPProofJWT)
	}
	req.Header.Set("Accept", "application/json")
	req.ContentLength = int64(len(reqBodyBytes))

	// Execute request
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	o.rememberDPoPNonce(endpointURL, resp.Header.Get("DPoP-Nonce"))

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		if isUseDPoPNonceResponse(resp, bodyBytes) {
			return nil, fmt.Errorf(
				"%w; status: %d; endpoint: %s; response: %s",
				types.NewDPoPNonceError(resp.Header.Get("DPoP-Nonce"), types.ErrUseDPoPNonce),
				resp.StatusCode,
				endpointURL.String(),
				string(bodyBytes),
			)
		}
		return nil, fmt.Errorf("failed to receive credential; status: %d; endpoint: %s; response: %s", resp.StatusCode, endpointURL.String(), string(bodyBytes))
	}

	if len(bodyBytes) == 0 {
		return nil, fmt.Errorf("credential response is empty")
	}

	// Extract credential from response
	var credentialResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &credentialResponse); err != nil {
		return nil, err
	}

	var credential interface{}

	credentialsRaw, hasCredentials := credentialResponse["credentials"]
	if hasCredentials {
		credentials, ok := credentialsRaw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("credentials response has invalid type")
		}
		if len(credentials) != 1 {
			return nil, fmt.Errorf("credentials response must contain exactly one credential, got %d", len(credentials))
		}
		credentialWrapper, ok := credentials[0].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("first credential entry has invalid format")
		}
		var found bool
		credential, found = credentialWrapper["credential"]
		if !found {
			return nil, fmt.Errorf("credential field missing in first credentials entry")
		}
	} else {
		var ok bool
		credential, ok = credentialResponse["credential"]
		if !ok {
			return nil, fmt.Errorf("no credential found in response")
		}
	}

	credentialStr, ok := credential.(string)
	if !ok {
		// If credential is not a string, marshal it back to JSON
		credentialBytes, err := json.Marshal(credential)
		if err != nil {
			return nil, err
		}
		credentialStr = string(credentialBytes)
	}

	return &credentialStr, nil
}
