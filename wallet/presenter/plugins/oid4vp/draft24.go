package oid4vp

import (
	"encoding/json"
	"fmt"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"net/url"
)

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
		if metadata, ok := request.ClientMetadata.(*VerifierMetadata); ok && metadata != nil && metadata.AuthorizationEncryptedResponseAlg != "" {
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
