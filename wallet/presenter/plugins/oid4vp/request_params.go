package oid4vp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// validateRedirectAndResponseURIExclusivity returns an error when the
// redirect_uri and response_uri request parameters are both set. Per OID4VP
// 1.0 §5.1/§8.2 they are mutually exclusive when response_mode is direct_post
// (or direct_post.jwt); the Wallet MUST return an invalid_request Authorization
// Response error. Callers scope this check to the direct_post modes.
func validateRedirectAndResponseURIExclusivity(redirectURIFromParam, responseURIFromParam string) error {
	if redirectURIFromParam != "" && responseURIFromParam != "" {
		return newAuthorizationRequestError(InvalidRequestError, "redirect_uri and response_uri must not both be present in the same request")
	}
	return nil
}

// setParamsWithInterfaceMap sets the CredentialPresentationRequest fields from a map of any parameters,
// tracking any missing required parameters.
// Missing required parameters are recorded in b.errValidation and set as empty strings.
func (b *requestBuilder) setParamsWithAnyMap(params map[string]any) {
	if b.errValidation != nil {
		return
	}

	// OID4VP specification: MUST ignore 'iss' claim if present in Request Object
	// Remove 'iss' claim from params to ensure it's not processed
	if _, exists := params["iss"]; exists {
		// Create a copy of params without 'iss' claim
		filteredParams := make(map[string]any)
		for k, v := range params {
			if k != "iss" {
				filteredParams[k] = v
			}
		}
		params = filteredParams
	}

	missing := []string{}

	getParam := func(key string, required bool) string {
		if val, exists := params[key]; exists {
			if strVal, ok := val.(string); ok {
				return strVal
			}
			if !b.draft24 {
				b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%s must be a string", key)
				return ""
			}
			// Convert non-string values to string representation if possible
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

	redirectURIFromParam := getParam("redirect_uri", false) // redirect_uri may be emitted
	redirectURIFromClientID := ""
	if cid := b.req.ClientID; cid != "" {
		// The builder-scoped parse: only the unsigned DC API path may carry the
		// Wallet-synthesised web-origin identifier (Appendix A.2).
		if parsedCID, err := b.parseClientID(cid); err == nil {
			switch parsedCID.prefix {
			case OID4VPClientIDPrefixRedirectURI:
				redirectURIFromClientID = parsedCID.original
			case OID4VPClientIDPrefixX509SanDNS:
				if b.draft24 {
					redirectURIFromClientID = parsedCID.original
				}
			case OID4VPClientIDPrefixX509Hash:
				// x509_hash binds the request object to an x5c certificate hash,
				// so it does not derive a redirect URI from client_id.
			case OID4VPClientIDPrefixWebOrigin:
				// The DC API effective client identifier uses the platform
				// Origin; no redirect URI is derived (OID4VP 1.0 Appendix A.2).
			case OID4VPClientIDPrefixOIDFederation, OID4VPClientIDPrefixVerifierAttestation:
				// OID4VP 1.0 §5.9.3: both prefixes name a Verifier whose
				// response endpoints are constrained by what authenticated it
				// (the Trust Chain metadata, or the attestation's
				// redirect_uris), never derived from the Client Identifier.
				// The request is authenticated by
				// authenticateRequestObjectByClientIdentifier.
			case OID4VPClientIDPrefixPreRegistered:
				// OID4VP 1.0 §5.9.2: "If a `:` character is not present in the
				// Client Identifier, the Wallet MUST treat the Client Identifier
				// as referencing a pre-registered client", and "the Client
				// Identifier needs to be known to the Wallet in advance of the
				// Authorization Request". The wallet's registry is therefore the
				// only source of Verifier metadata and request-signature keys
				// for this prefix; an unregistered identifier is refused instead
				// of accepted unauthenticated.
				if b.draft24 {
					b.errValidation = fmt.Errorf("invalid client_id format")
					return
				}
				registered, lookupErr := b.lookupPreRegisteredClient(parsedCID.original)
				if lookupErr != nil {
					b.errValidation = lookupErr
					return
				}
				b.preRegisteredClient = registered
			default: // unimplemented: other client_id prefixes
				b.errValidation = fmt.Errorf("unsupported client_id prefix: %s", parsedCID.prefix)
			}
		} else {
			b.errValidation = fmt.Errorf("invalid client_id: %w", err)
			return
		}
	}

	if redirectURIFromParam != "" && redirectURIFromClientID != "" && redirectURIFromParam != redirectURIFromClientID {
		b.errValidation = fmt.Errorf("redirect_uri mismatch between parameter and one derived from client_id")
		return
	}

	b.req.RedirectURI = redirectURIFromClientID
	if !b.draft24 && redirectURIFromParam != "" {
		b.req.RedirectURI = redirectURIFromParam
	}
	b.req.State = getParam("state", false)
	b.req.Nonce = getParam("nonce", true)
	if b.draft24 {
		b.req.Scope = getParam("scope", false)
	}

	b.req.ResponseMode = OAuthAuthzReqResponseMode(getParam("response_mode", true))

	// OID4VP 1.0 §5.9.3: with the redirect_uri Client Identifier Prefix "the
	// original Client Identifier part (without the prefix redirect_uri:) is the
	// Verifier's Redirect URI (or Response URI when Response Mode direct_post is
	// used)", and "The Verifier MAY omit the redirect_uri Authorization Request
	// parameter (or response_uri when Response Mode direct_post is used)". The
	// Client Identifier already carries the Response URI, so the parameter is
	// not required on the Final path.
	responseURIRequired := isDirectPostMode(b.req.ResponseMode)
	if !b.draft24 && redirectURIFromClientID != "" {
		responseURIRequired = false
	}
	responseURIFromParam := getParam("response_uri", responseURIRequired)

	// OID4VP 1.0 §8.2: redirect_uri and response_uri are mutually exclusive
	// when response_mode is direct_post (or direct_post.jwt).
	if isDirectPostMode(b.req.ResponseMode) {
		if err := validateRedirectAndResponseURIExclusivity(redirectURIFromParam, responseURIFromParam); err != nil {
			b.errValidation = err
			return
		}
	}

	b.req.ResponseURI = responseURIFromParam

	// OID4VP 1.0 §5.9.3 binds the Response URI to the redirect_uri Client
	// Identifier the same way it binds the Redirect URI: the value after the
	// prefix "is the Verifier's Redirect URI (or Response URI when Response Mode
	// direct_post is used)". Without this, a request carrying
	// client_id=redirect_uri:https://verifier.example/cb together with
	// response_mode=direct_post and a foreign response_uri would send the VP
	// Token to an endpoint the Client Identifier does not authenticate.
	if !b.draft24 && redirectURIFromClientID != "" && isDirectPostMode(b.req.ResponseMode) {
		if responseURIFromParam == "" {
			b.req.ResponseURI = redirectURIFromClientID
		} else if responseURIFromParam != redirectURIFromClientID {
			// The rejected response_uri is not the Verifier's, so the error
			// authorization response goes to the URI the Client Identifier
			// authenticates, never to the one the request chose.
			b.req.ResponseURI = redirectURIFromClientID
			b.errValidation = newAuthorizationRequestError(InvalidRequestError,
				"%w", ErrResponseURIClientIDMismatch)
			return
		}
		// §8.2: the response goes to the Response URI, so no Redirect URI is
		// used for this request.
		b.req.RedirectURI = ""
	}
	if b.draft24 {
		if err := bindDraft24RedirectURIResponseURI(params, b.req.ClientID, redirectURIFromClientID, responseURIFromParam, b.req.ResponseMode); err != nil {
			// As on the Final path, the refused response_uri is not the
			// Verifier's, so the error authorization response goes to the
			// URI the Client Identifier authenticates.
			b.req.ResponseURI = redirectURIFromClientID
			b.errValidation = err
			return
		}
	}

	// OID4VP 1.0 Appendix A.2: the response is returned through the DC API, so
	// response_uri and redirect_uri MUST be absent from the request. This is
	// enforced on the DC API delivery paths only; a request_uri-delivered
	// dc_api.jwt request is a different (rejected) delivery and keeps its own
	// profile error.
	if b.requestSource.isDCAPI() &&
		(b.req.ResponseMode == OAuthAuthzReqResponseModeDCAPI || b.req.ResponseMode == OAuthAuthzReqResponseModeDCAPIJWT) {
		if redirectURIFromParam != "" || responseURIFromParam != "" {
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "redirect_uri and response_uri must not be present with response_mode %s", b.req.ResponseMode)
			return
		}
		b.req.RedirectURI = ""
		b.req.ResponseURI = ""
	}

	if b.requestSource == sourceQuery && !b.draft24 {
		if _, hasMethod := params["request_uri_method"]; hasMethod {
			// OID4VP 1.0 §5.1: "request_uri_method parameter MUST NOT be
			// present if a request_uri parameter is not present." This path is
			// only reached when request_uri and request are both absent.
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "request_uri_method must not be present without request_uri")
			return
		}
	}

	if b.draft24 {
		b.req.PresentationDefinitionURI = getParam("presentation_definition_uri", false)
		raw, exists := params["presentation_definition"]
		if exists {
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
			// The library keeps only the definition id. A caller that has to
			// render or forward the Verifier's own Presentation Exchange
			// definition keeps the wire value instead of re-encoding a lossy
			// copy of it.
			b.req.RawPresentationDefinition = json.RawMessage(bytes.Clone(data))
		}
	} else {
		// Final uses DCQL. Keep Presentation Exchange behind the explicit Draft24 API.
		for _, unsupported := range []string{"presentation_definition", "presentation_definition_uri", "presentation_submission"} {
			if _, exists := params[unsupported]; exists {
				b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%s is not supported; use dcql_query instead", unsupported)
				return
			}
		}
	}

	// Requesting Credentials via the scope parameter is not supported by this wallet.
	if scope, exists := params["scope"]; exists && !b.draft24 {
		if scopeStr, ok := scope.(string); !ok || scopeStr != "" {
			b.errValidation = newAuthorizationRequestError(InvalidScopeError, "scope parameter is not supported; use dcql_query instead")
			return
		}
	}

	if cm, exists := params["client_metadata"]; exists && cm != nil {
		var rawMetadata []byte
		if cmMap, ok := cm.(map[string]any); ok {
			// Convert map to JSON and then unmarshal to struct
			jsonBytes, err := json.Marshal(cmMap)
			if err != nil {
				b.errValidation = fmt.Errorf("failed to marshal client_metadata: %w", err)
				return
			}
			rawMetadata = jsonBytes
		} else if cmStr, ok := cm.(string); ok {
			// Handle string format
			rawMetadata = []byte(cmStr)
		} else {
			b.errValidation = fmt.Errorf("client_metadata must be a string or map")
			return
		}
		var clientMeta VerifierMetadata
		if err := json.Unmarshal(rawMetadata, &clientMeta); err != nil {
			b.errValidation = fmt.Errorf("invalid client_metadata: %w", err)
			return
		}
		if b.requireClientMetadataJWKKeyIDs {
			if err := validateClientMetadataJWKKeyIDs(rawMetadata); err != nil {
				b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%w", err)
				return
			}
		}
		b.req.ClientMetadata = &clientMeta
	}

	// OID4VP 1.0 §5.9.2: a pre-registered Verifier's metadata "needs to be known
	// to the Wallet in advance of the Authorization Request", so the registered
	// metadata wins over a client_metadata parameter, which nothing
	// authenticates for this Client Identifier Prefix.
	if b.preRegisteredClient != nil && b.preRegisteredClient.Metadata != nil {
		registeredMetadata := *b.preRegisteredClient.Metadata
		b.req.ClientMetadata = &registeredMetadata
	}

	if rawDcqlQuery, exists := params["dcql_query"]; exists {
		var dcqlQuery *DcqlQuery
		var err error
		if b.draft24 {
			dcqlQuery, err = parseDraft24DcqlQuery(rawDcqlQuery)
		} else {
			// The HAIP format restriction is applied where the Final DCQL query
			// is validated (dcql.go), not by re-parsing after the fact.
			dcqlQuery, err = parseDcqlQueryWithHAIP(rawDcqlQuery, b.profile.IsHAIP())
		}
		if err != nil {
			b.errValidation = err
			return
		}
		b.req.DcqlQuery = dcqlQuery
	} else if !b.draft24 {
		missing = append(missing, "dcql_query")
	}

	if len(missing) == 1 && missing[0] == "nonce" {
		b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%w", ErrNonceRequired)
	} else if len(missing) > 0 {
		b.errValidation = newAuthorizationRequestError(InvalidRequestError, "missing required parameters: %s", strings.Join(missing, ", "))
	}

	if td, exists := params["transaction_data"]; exists && td != nil {
		if b.draft24 {
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
		} else {
			switch v := td.(type) {
			case []interface{}:
				for _, item := range v {
					str, ok := item.(string)
					if !ok {
						b.errValidation = newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data entries must be base64url strings")
						return
					}
					b.req.TransactionData = append(b.req.TransactionData, str)
				}
			case []string:
				b.req.TransactionData = v
			case string:
				// application/x-www-form-urlencoded transfers the array as a
				// JSON-serialized string.
				var entries []string
				if err := json.Unmarshal([]byte(v), &entries); err != nil {
					b.errValidation = newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data must be a JSON array of strings")
					return
				}
				b.req.TransactionData = entries
			default:
				b.errValidation = newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data must be an array of strings")
				return
			}
		}
	}

	if b.draft24 {
		b.req.TransactionDataHashesAlg = getParam("transaction_data_hashes_alg", false)
	}
	// The Final profile carries transaction_data_hashes_alg inside each
	// transaction_data object (OID4VP 1.0 Appendix B.3.3.1); it is resolved and
	// set by validateFinalTransactionData below. A top-level value is not
	// defined by the Final specification and is ignored.

	if !b.draft24 && b.errValidation == nil && len(b.req.TransactionData) > 0 {
		if err := b.validateFinalTransactionData(); err != nil {
			b.errValidation = err
			return
		}
	}
}

// validateFinalTransactionData enforces OID4VP 1.0 §5.1 and §8.4/§8.5 for the
// Final path: every transaction_data entry must be base64url-encoded JSON with
// a supported type and a non-empty credential_ids array referencing the DCQL
// queries. Any failure is invalid_transaction_data.
func (b *requestBuilder) validateFinalTransactionData() error {
	supported := make(map[string]bool, len(b.supportedTransactionDataTypes))
	for _, dataType := range b.supportedTransactionDataTypes {
		supported[dataType] = true
	}
	// queryIDs maps each Credential Query id to whether it requires
	// cryptographic holder binding.
	queryIDs := make(map[string]bool)
	if b.req.DcqlQuery != nil {
		for _, query := range b.req.DcqlQuery.Credentials {
			queryIDs[query.ID] = query.RequiresHolderBinding()
		}
	}
	resolvedAlg := ""
	for i, encoded := range b.req.TransactionData {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d] is not base64url-encoded JSON: %v", i, err)
		}
		var entry map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&entry); err != nil {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d] is not a JSON object: %v", i, err)
		}
		dataType, ok := entry["type"].(string)
		if !ok || dataType == "" {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].type is required and must be a string", i)
		}
		if !supported[dataType] {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].type %q: %w", i, dataType, ErrTransactionDataTypeUnsupported)
		}
		credentialIDs, ok := entry["credential_ids"].([]any)
		if !ok || len(credentialIDs) == 0 {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].credential_ids must be a non-empty array", i)
		}
		for _, rawID := range credentialIDs {
			id, ok := rawID.(string)
			bindingRequired, known := queryIDs[id]
			if !ok || !known {
				return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].credential_ids references an unknown credential query", i)
			}
			// OID4VP 1.0 Section 8.4 carries the transaction data hashes in
			// the Key Binding of the presentation, so a Credential Query that
			// waives cryptographic holder binding has nowhere to carry them
			// and cannot authorize the transaction.
			if !bindingRequired {
				return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].credential_ids references a credential query without cryptographic holder binding", i)
			}
		}
		// OID4VP 1.0 Appendix B.3.3.1 places transaction_data_hashes_alg in the
		// transaction_data object alongside type and credential_ids, not at the
		// Authorization Request top level. The Wallet picks the first algorithm
		// it supports from each object's array, defaulting to sha-256.
		entryAlg, err := selectTransactionDataHashesAlg(i, entry)
		if err != nil {
			return err
		}
		if resolvedAlg == "" {
			resolvedAlg = entryAlg
		} else if resolvedAlg != entryAlg {
			return newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data objects request conflicting transaction_data_hashes_alg values")
		}
	}
	b.req.TransactionDataHashesAlg = resolvedAlg
	return nil
}

// selectTransactionDataHashesAlg returns the first hash algorithm supported by
// this wallet from one transaction_data object's transaction_data_hashes_alg
// array, or sha-256 when the array is absent (OID4VP 1.0 Appendix B.3.3.1).
func selectTransactionDataHashesAlg(index int, entry map[string]any) (string, error) {
	rawAlg, exists := entry["transaction_data_hashes_alg"]
	if !exists || rawAlg == nil {
		return "sha-256", nil
	}
	algs, ok := rawAlg.([]any)
	if !ok || len(algs) == 0 {
		return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].transaction_data_hashes_alg must be a non-empty array of strings", index)
	}
	for _, rawName := range algs {
		name, ok := rawName.(string)
		if !ok || name == "" {
			return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].transaction_data_hashes_alg must contain only non-empty strings", index)
		}
		switch strings.ToLower(name) {
		case "sha-256", "sha-384", "sha-512":
			return strings.ToLower(name), nil
		}
	}
	return "", newAuthorizationRequestError(InvalidTransactionDataError, "transaction_data[%d].transaction_data_hashes_alg has no supported hash algorithm", index)
}
