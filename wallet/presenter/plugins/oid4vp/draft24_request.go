package oid4vp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"strings"
)

// draft24RequestBuilder parses and authenticates one OpenID4VP Draft 24
// Authorization Request, which carries a Presentation Exchange
// presentation_definition or a Draft 24 dcql_query. Draft 24 is outside every
// protocol profile, so HAIP never applies here.
type draft24RequestBuilder struct {
	requestCore
}

func newDraft24RequestBuilder() *draft24RequestBuilder {
	core := newRequestCore()
	// Draft 24 authenticated an X.509 Request Object without reading aud; a
	// caller opts into the check by naming its WalletAudience.
	core.audienceOptional = true
	return &draft24RequestBuilder{requestCore: core}
}

// parseDraft24ClientID is the Client Identifier syntax of the Draft 24 wire
// contract. It differs from OpenID4VP 1.0 in one prefix only: Draft 24
// Section 5.10.1 names an OpenID Federation Entity Identifier with the "https"
// Client Identifier Scheme, which is reported with the 1.0 prefix so both wire
// contracts reach the one federation authentication.
func parseDraft24ClientID(clientID string) (*OID4VPClientID, error) {
	trimmed := strings.TrimSpace(clientID)
	if strings.HasPrefix(trimmed, "https://") {
		return &OID4VPClientID{original: trimmed, prefix: OID4VPClientIDPrefixOIDFederation}, nil
	}
	return parseOID4VPClientID(trimmed)
}

// ParseDraft24OID4VPClientID is ParseOID4VPClientID for a client_id that
// arrived over the Draft 24 wire contract, where an "https" Client Identifier
// names an OpenID Federation Entity Identifier.
func ParseDraft24OID4VPClientID(clientID string) (*OID4VPClientID, error) {
	return parseDraft24ClientID(clientID)
}

func (b *draft24RequestBuilder) parseClientID(clientID string) (*OID4VPClientID, error) {
	return parseDraft24ClientID(clientID)
}

func (b *draft24RequestBuilder) validate() error {
	if b.errValidation != nil {
		return b.errValidation
	}
	// Draft 24 Section 5.1 names three ways to express the Presentation
	// Definition - by value, by reference in presentation_definition_uri, or
	// through a scope the Wallet maps to one - besides DCQL. Resolving a
	// reference or a scope is the Wallet's own step after admission, so their
	// presence is what is required here.
	hasDefinition := b.req.PresentationDefinition != nil && b.req.PresentationDefinition.ID != ""
	hasDefinitionReference := b.req.PresentationDefinitionURI != "" || b.req.Scope != ""
	if !hasDefinition && !hasDefinitionReference && (b.req.DcqlQuery == nil || len(b.req.DcqlQuery.Credentials) == 0) {
		return newAuthorizationRequestError(InvalidRequestError, "presentation_definition, presentation_definition_uri, scope or dcql_query is required for Draft24")
	}
	if b.req.ResponseType == "" {
		return newAuthorizationRequestError(InvalidRequestError, "response_type is required")
	}
	if b.req.ClientID == "" {
		return newAuthorizationRequestError(InvalidRequestError, "client_id is required")
	}
	dcAPIMode := isDCAPIMode(b.req.ResponseMode)
	if dcAPIMode {
		return newAuthorizationRequestError(InvalidRequestError, "response_mode %s is only valid over the Digital Credentials API", b.req.ResponseMode)
	}
	if !isDirectPostMode(b.req.ResponseMode) && b.req.RedirectURI == "" {
		return newAuthorizationRequestError(InvalidRequestError, "redirect_uri is required")
	}
	if b.req.Nonce == "" {
		return newAuthorizationRequestError(InvalidRequestError, "%w", ErrNonceRequired)
	}
	if isDirectPostMode(b.req.ResponseMode) {
		if _, err := parseResponseURI(b.req.ResponseURI, b.allowHTTP); err != nil {
			return newAuthorizationRequestError(InvalidRequestError, "%v", err)
		}
	}
	return nil
}

// WithQueryParams populates the request from URL query parameters.
func (b *draft24RequestBuilder) WithQueryParams(params map[string][]string) *draft24RequestBuilder {
	if b.errValidation != nil {
		return b
	}
	b.requestSource = sourceQuery

	singleParams := make(map[string]any)
	for key, values := range params {
		if len(values) > 1 {
			b.errValidation = fmt.Errorf("multiple values provided for parameter: %s", key)
			return b
		}
		singleParams[key] = values[0]
	}

	if value, isString := singleParams["client_id"].(string); isString {
		parsed, err := b.parseClientID(strings.TrimSpace(value))
		if err == nil && parsed.RequiresRequestObjectSignature() {
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%w", ErrRequestObjectSignatureRequired)
			return b
		}
		b.errorResponseAllowed = err == nil && parsed.prefix == OID4VPClientIDPrefixRedirectURI
	}

	b.setParams(singleParams)

	if err := b.validate(); err != nil {
		b.errValidation = err
		return b
	}
	if err := b.authenticateUnsignedFederationRequest(b.parseClientID, singleParams); err != nil {
		b.errValidation = err
		return b
	}
	return b
}

// WithRequestObjectURI fetches the Request Object from request_uri and
// authenticates it. A POST carries an empty wallet_metadata object and no
// wallet_nonce.
func (b *draft24RequestBuilder) WithRequestObjectURI(uri string, method RequestURIMethod) *draft24RequestBuilder {
	if b.errValidation != nil {
		return b
	}
	form := url.Values{}
	if method == RequestURIMethodPOST {
		form.Set("wallet_metadata", "{}")
	}
	body, err := b.fetchRequestObject(uri, method, form, "application/oauth-authz-req+jwt, application/jwt, text/plain, */*")
	if err != nil {
		b.errValidation = err
		return b
	}
	b.requestSource = sourceReference
	return b.withRequestObject(string(body))
}

// WithRequestObject authenticates a Request Object passed by value.
func (b *draft24RequestBuilder) WithRequestObject(obj string) *draft24RequestBuilder {
	b.requestSource = sourceValue
	return b.withRequestObject(obj)
}

// Build returns the admitted request, or the first refusal.
func (b *draft24RequestBuilder) Build() (*CredentialPresentationRequest, error) {
	if b.errValidation != nil {
		return nil, b.errValidation
	}
	if err := b.validateResponseEncryptionMetadata(); err != nil {
		b.errorResponseAllowed = false
		return nil, err
	}
	if b.req.RequestObjectVerification != nil {
		b.req.RequestObjectVerification.Delivery = b.requestSource.delivery()
	}
	if b.req.ClientMetadata != nil {
		b.req.ClientMetadata.encryptionPolicy = encryptionPolicyFinal
	}
	return b.req, nil
}

// setParams sets the request fields from the Draft 24 Authorization Request
// parameters, recording the first refusal in b.errValidation. Draft 24
// tolerates non-string values and keeps the redirect URI the Client
// Identifier implies.
func (b *draft24RequestBuilder) setParams(params map[string]any) {
	if b.errValidation != nil {
		return
	}
	params = withoutIssuerClaim(params)

	missing := []string{}
	getParam := func(key string, required bool) string {
		if val, exists := params[key]; exists {
			if strVal, ok := val.(string); ok {
				return strVal
			}
			return fmt.Sprintf("%v", val)
		}
		if required {
			missing = append(missing, key)
		}
		return ""
	}

	b.req.ResponseType = getParam("response_type", true)
	b.req.ClientID = strings.TrimSpace(getParam("client_id", true))
	if b.expectedClientID != "" && b.req.ClientID != b.expectedClientID {
		b.errValidation = fmt.Errorf("outer client_id does not match request object client_id: %s != %s: %w", b.expectedClientID, b.req.ClientID, ErrRequestObjectClientIDMismatch)
		return
	}

	redirectURIFromParam := getParam("redirect_uri", false)
	redirectURIFromClientID := ""
	if cid := b.req.ClientID; cid != "" {
		parsedCID, err := b.parseClientID(cid)
		if err != nil {
			b.errValidation = fmt.Errorf("invalid client_id: %w", err)
			return
		}
		switch parsedCID.prefix {
		case OID4VPClientIDPrefixRedirectURI, OID4VPClientIDPrefixX509SanDNS:
			redirectURIFromClientID = parsedCID.original
		case OID4VPClientIDPrefixX509Hash, OID4VPClientIDPrefixOIDFederation, OID4VPClientIDPrefixVerifierAttestation:
		case OID4VPClientIDPrefixPreRegistered:
			// Draft 24 has no pre-registered Client Identifier.
			b.errValidation = fmt.Errorf("invalid client_id format")
			return
		default:
			b.errValidation = fmt.Errorf("unsupported client_id prefix: %s", parsedCID.prefix)
		}
	}

	if redirectURIFromParam != "" && redirectURIFromClientID != "" && redirectURIFromParam != redirectURIFromClientID {
		b.errValidation = fmt.Errorf("redirect_uri mismatch between parameter and one derived from client_id")
		return
	}

	b.req.RedirectURI = redirectURIFromClientID
	b.req.State = getParam("state", false)
	b.req.Nonce = getParam("nonce", true)
	b.req.Scope = getParam("scope", false)
	b.req.ResponseMode = OAuthAuthzReqResponseMode(getParam("response_mode", true))

	responseURIFromParam := getParam("response_uri", isDirectPostMode(b.req.ResponseMode))
	if isDirectPostMode(b.req.ResponseMode) {
		if err := validateRedirectAndResponseURIExclusivity(redirectURIFromParam, responseURIFromParam); err != nil {
			b.errValidation = err
			return
		}
	}
	b.req.ResponseURI = responseURIFromParam
	if err := bindDraft24RedirectURIResponseURI(params, b.req.ClientID, redirectURIFromClientID, responseURIFromParam, b.req.ResponseMode); err != nil {
		// The refused response_uri is not the Verifier's, so the error
		// authorization response goes to the URI the Client Identifier
		// authenticates.
		b.req.ResponseURI = redirectURIFromClientID
		b.errValidation = err
		return
	}

	b.req.PresentationDefinitionURI = getParam("presentation_definition_uri", false)
	if raw, exists := params["presentation_definition"]; exists {
		var data []byte
		var err error
		if value, ok := raw.(string); ok {
			data = []byte(value)
		} else {
			data, err = json.Marshal(raw)
		}
		var definition PresentationDefinition
		if err == nil {
			err = json.Unmarshal(data, &definition)
		}
		if err != nil {
			b.errValidation = fmt.Errorf("invalid presentation_definition: %w", err)
			return
		}
		b.req.PresentationDefinition = &definition
		// PresentationDefinition keeps only the id; the wire value is kept
		// for a caller that renders or forwards the whole definition.
		b.req.RawPresentationDefinition = json.RawMessage(bytes.Clone(data))
	}

	if cm, exists := params["client_metadata"]; exists && cm != nil {
		metadata, err := parseClientMetadataParam(cm, b.requireClientMetadataJWKKeyIDs)
		if err != nil {
			b.errValidation = err
			return
		}
		b.req.ClientMetadata = metadata
	}

	if rawDcqlQuery, exists := params["dcql_query"]; exists {
		dcqlQuery, err := parseDraft24DcqlQuery(rawDcqlQuery)
		if err != nil {
			b.errValidation = err
			return
		}
		b.req.DcqlQuery = dcqlQuery
	}

	if len(missing) == 1 && missing[0] == "nonce" {
		b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%w", ErrNonceRequired)
	} else if len(missing) > 0 {
		b.errValidation = newAuthorizationRequestError(InvalidRequestError, "missing required parameters: %s", strings.Join(missing, ", "))
	}

	if td, exists := params["transaction_data"]; exists && td != nil {
		switch v := td.(type) {
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					b.req.TransactionData = append(b.req.TransactionData, str)
				}
			}
		case []string:
			b.req.TransactionData = v
		}
	}
	b.req.TransactionDataHashesAlg = getParam("transaction_data_hashes_alg", false)
}

// parseDraft24DcqlQuery decodes a Draft 24 dcql_query without the 1.0
// validation. Credential matching still decides which formats can be
// presented.
func parseDraft24DcqlQuery(raw any) (*DcqlQuery, error) {
	queryMap, err := decodeDcqlQueryObject(raw)
	if err != nil {
		return nil, err
	}
	// require_cryptographic_holder_binding and trusted_authorities are 1.0
	// members the Draft 24 decoder ignores; the input is not mutated.
	if credentials, ok := queryMap["credentials"].([]any); ok {
		queryMap = maps.Clone(queryMap)
		filtered := make([]any, len(credentials))
		for i, item := range credentials {
			filtered[i] = item
			if query, ok := item.(map[string]any); ok {
				query = maps.Clone(query)
				delete(query, "require_cryptographic_holder_binding")
				delete(query, "trusted_authorities")
				filtered[i] = query
			}
		}
		queryMap["credentials"] = filtered
	}
	return dcqlQueryFromObject(queryMap)
}
