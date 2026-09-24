package oid4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
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

// ErrHTTPRedirectNotAllowed reports that an OpenID4VCI endpoint answered with a
// redirect. No OpenID4VCI endpoint is defined to redirect, and following one is
// never safe: a 307 or 308 replays the request body together with the
// Authorization, DPoP and OAuth-Client-Attestation headers against an origin the
// response chose, and a redirected metadata document substitutes the Credential
// Issuer's identity for another. The root wallet package cannot be imported from
// a plugin, so it declares its own alias of this sentinel.
var ErrHTTPRedirectNotAllowed = common.NewCodedError("http_redirect_not_allowed", "OID4VCI endpoint redirected; redirects are not followed")

func rejectOID4VCIRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("OID4VCI endpoint redirected to %s: %w", req.URL.Redacted(), ErrHTTPRedirectNotAllowed)
}

// NoRedirectClient returns a shallow copy of client whose CheckRedirect refuses
// every 3xx with ErrHTTPRedirectNotAllowed. The caller's *http.Client is not
// mutated. A nil client yields a client with a 15 second timeout.
func NoRedirectClient(client *http.Client) *http.Client {
	if client == nil {
		return &http.Client{Timeout: 15 * time.Second, CheckRedirect: rejectOID4VCIRedirect}
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

	requestOptions := firstCredentialRequestOptions(options)
	var dpopProof string
	if strings.EqualFold(accessToken.TokenType, dpopAuthorizationScheme) {
		if requestOptions == nil || requestOptions.DPoPProofJWT == nil || *requestOptions.DPoPProofJWT == "" {
			return nil, fmt.Errorf("DPoP proof JWT is required for DPoP access token")
		}
		dpopProof = *requestOptions.DPoPProofJWT
	}
	response, err := o.do(observe.WithEndpoint(context.Background(), observe.EndpointCredential), exchange{
		method:      http.MethodPost,
		url:         endpointURL,
		contentType: "application/json; charset=utf-8",
		body:        func() ([]byte, error) { return reqBodyBytes, nil },
		header: func(header http.Header) error {
			if dpopProof != "" {
				header.Set("DPoP", dpopProof)
			}
			return nil
		},
		accessToken: &accessToken,
		limit:       httpfetch.CredentialBodyLimit,
	})
	if err != nil {
		return nil, err
	}
	bodyBytes := response.body
	if response.statusCode != http.StatusOK {
		if isUseDPoPNonce(response) {
			return nil, fmt.Errorf(
				"%w; status: %d; endpoint: %s",
				types.NewDPoPNonceError(response.header.Get("DPoP-Nonce"), types.ErrUseDPoPNonce),
				response.statusCode,
				endpointURL.String(),
			)
		}
		return nil, fmt.Errorf("failed to receive credential from %s: %w", endpointURL.String(), response.statusError())
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
