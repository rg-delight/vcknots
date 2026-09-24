package oid4vp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// ParseDraft24PresentationRequest parses and authenticates an OpenID4VP Draft
// 24 Authorization Request URI (Presentation Exchange or Draft 24 DCQL).
func (p *Oid4vpPresenter) ParseDraft24PresentationRequest(uriString string) (*CredentialPresentationRequest, error) {
	return p.parseDraft24RequestURI(uriString)
}

// ParseDraft24RequestObject is ParseRequestObject for the Draft 24 wire
// contract.
func (p *Oid4vpPresenter) ParseDraft24RequestObject(requestObject string, expectedClientID string) (*CredentialPresentationRequest, error) {
	return p.parseDraft24RequestObject(requestObject, expectedClientID)
}

func (p *Oid4vpPresenter) parseDraft24RequestURI(uriString string) (*CredentialPresentationRequest, error) {
	builder, err := p.newDraft24RequestBuilder()
	if err != nil {
		return nil, err
	}
	queryParams, err := authorizationRequestQuery(uriString)
	if err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(queryParams.Get("client_id"))
	if clientID != "" {
		if _, err := parseDraft24ClientID(clientID); err != nil {
			return nil, fmt.Errorf("invalid client_id in initial request: %w", err)
		}
	}
	builder.expectedClientID = clientID

	requestURI := queryParams.Get("request_uri")
	requestObj := queryParams.Get("request")
	switch {
	case requestURI != "":
		method := RequestURIMethodGET
		switch requestURIMethod := queryParams.Get("request_uri_method"); strings.ToLower(requestURIMethod) {
		case "", "get":
		case "post":
			method = RequestURIMethodPOST
		default:
			return nil, fmt.Errorf("unsupported request_uri_method: %s", requestURIMethod)
		}
		builder.WithRequestObjectURI(requestURI, method)
	case requestObj != "":
		builder.WithRequestObject(requestObj)
	default:
		builder.WithQueryParams(queryParams)
	}
	return p.finishParse(&builder.requestCore, builder.Build)
}

func (p *Oid4vpPresenter) parseDraft24RequestObject(requestObject string, expectedClientID string) (*CredentialPresentationRequest, error) {
	builder, err := p.newDraft24RequestBuilder()
	if err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(expectedClientID)
	if clientID != "" {
		if _, err := parseDraft24ClientID(clientID); err != nil {
			return nil, fmt.Errorf("invalid client_id in initial request: %w", err)
		}
	}
	builder.expectedClientID = clientID
	builder.expectedClientIDAbsent = clientID == ""
	builder.WithRequestObject(requestObject)
	return p.finishParse(&builder.requestCore, builder.Build)
}

// newDraft24RequestBuilder creates the builder of one Draft 24 parse. The
// presenter's profile must be valid but does not apply.
func (p *Oid4vpPresenter) newDraft24RequestBuilder() (*draft24RequestBuilder, error) {
	if _, err := p.normalizedProfile(); err != nil {
		return nil, err
	}
	builder := newDraft24RequestBuilder()
	p.configureCore(&builder.requestCore)
	return builder, nil
}

// PresentDraft24 submits a Presentation Exchange response for existing Draft24 integrations.
// Final integrations use Present, whose vp_token is a DCQL response object.
func (p *Oid4vpPresenter) PresentDraft24(protocol types.SupportedPresentationProtocol, endpoint url.URL, serializedPresentation []byte, submission types.PresentationSubmission, request *types.PresentationRequest) (string, error) {
	if protocol != types.Oid4vp {
		return "", fmt.Errorf("plugin type mismatch")
	}
	submissionJSON, err := json.Marshal(submission)
	if err != nil {
		return "", fmt.Errorf("failed to marshal presentation_submission: %w", err)
	}
	form := url.Values{"vp_token": {string(serializedPresentation)}, "presentation_submission": {string(submissionJSON)}}
	if request != nil {
		if request.State != "" {
			form.Set("state", request.State)
		}
		metadata, _ := request.ClientMetadata.(*VerifierMetadata)
		switch {
		case request.ResponseMode == string(OAuthAuthzReqResponseModeDirectPostJWT):
			// OID4VP 1.0 Section 8.3: the JWE payload carries the response
			// parameters as top-level JSON members, so presentation_submission
			// is the object itself. A request that named direct_post.jwt is
			// never answered in plaintext, so a verifier without a usable
			// encryption key fails here instead of falling back.
			payload := map[string]interface{}{
				"vp_token":                string(serializedPresentation),
				"presentation_submission": json.RawMessage(submissionJSON),
			}
			if request.State != "" {
				payload["state"] = request.State
			}
			encrypted, err := p.CreateEncryptedAuthorizationResponse(payload, metadata)
			if err != nil {
				return "", fmt.Errorf("failed to create Draft24 encrypted authorization response: %w", err)
			}
			form = url.Values{"response": {encrypted}}
		case request.ResponseMode == "" && metadata != nil && metadata.AuthorizationEncryptedResponseAlg != "":
			// A caller that names no response mode and asks for encryption
			// through authorization_encrypted_response_alg gets the JARM shape,
			// with presentation_submission as a JSON string.
			payload := map[string]interface{}{"vp_token": string(serializedPresentation), "presentation_submission": string(submissionJSON)}
			if request.State != "" {
				payload["state"] = request.State
			}
			encrypted, err := p.encryptJARMPayload(payload, metadata.AuthorizationEncryptedResponseAlg, metadata.AuthorizationEncryptedResponseEnc, &metadata.Jwks)
			if err != nil {
				return "", fmt.Errorf("failed to create Draft24 JARM response: %w", err)
			}
			form = url.Values{"response": {encrypted}}
		}
	}
	body, err := p.postAuthorizationResponse(endpoint.String(), form)
	if err != nil {
		return "", fmt.Errorf("failed to send Draft24 presentation: %w", err)
	}
	var response struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if len(body) != 0 {
		_ = json.Unmarshal(body, &response)
	}
	return response.RedirectURI, nil
}
