package oid4vp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// The methods in this file answer a request the caller holds as a
// CredentialPresentationRequest, at an endpoint the caller names. They serve
// the wallet package's entry points that predate AdmittedRequest; new code
// answers an *AdmittedRequest with SubmitDCQLResponse,
// SubmitPresentationExchangeResponse or SubmitErrorResponse, which take the
// endpoint from the request.

// PresentDCQL sends one Authorization Response carrying every selected DCQL
// query to endpoint. request.ResponseMode selects plaintext (direct_post) or
// encryption (direct_post.jwt); "" encrypts when request.ClientMetadata asks
// for it.
func (p *Oid4vpPresenter) PresentDCQL(protocol types.SupportedPresentationProtocol, endpoint url.URL, vpToken map[string][]string, request *types.PresentationRequest) (string, error) {
	if protocol != types.Oid4vp {
		return "", fmt.Errorf("plugin type mismatch")
	}
	if request == nil {
		return "", fmt.Errorf("presentation request and vp_token are required")
	}
	metadata, _ := request.ClientMetadata.(*VerifierMetadata)
	redirectURI, _, err := p.postDCQLResponse(context.Background(), endpoint.String(), vpToken, request.State, request.ResponseMode, metadata)
	return redirectURI, err
}

// PresentDraft24 sends a Presentation Exchange response to endpoint.
func (p *Oid4vpPresenter) PresentDraft24(protocol types.SupportedPresentationProtocol, endpoint url.URL, serializedPresentation []byte, submission types.PresentationSubmission, request *types.PresentationRequest) (string, error) {
	if protocol != types.Oid4vp {
		return "", fmt.Errorf("plugin type mismatch")
	}
	var state, mode string
	var metadata *VerifierMetadata
	if request != nil {
		state, mode = request.State, request.ResponseMode
		metadata, _ = request.ClientMetadata.(*VerifierMetadata)
	}
	redirectURI, _, err := p.postPresentationExchangeResponse(context.Background(), endpoint.String(), serializedPresentation, submission, state, mode, metadata)
	return redirectURI, err
}

// SubmitEncryptedAuthorizationResponse encrypts authzResponse to metadata as a
// direct_post.jwt response (OID4VP 1.0 §8.3), posts it to endpoint and returns
// the Verifier's response body.
func (p *Oid4vpPresenter) SubmitEncryptedAuthorizationResponse(endpoint url.URL, authzResponse map[string]any, metadata *VerifierMetadata) (string, error) {
	if metadata == nil {
		return "", fmt.Errorf("verifier metadata is required for encrypted authorization response")
	}
	payload, err := json.Marshal(authzResponse)
	if err != nil {
		return "", fmt.Errorf("failed to marshal authorization response: %w", err)
	}
	token, err := p.encryptAuthorizationResponseJWE(payload, metadata)
	if err != nil {
		return "", err
	}
	body, err := postAuthorizationResponse(context.Background(), p.httpClient(), endpoint.String(), url.Values{"response": {token}})
	if err != nil {
		return "", fmt.Errorf("failed to submit encrypted authorization response: %w", err)
	}
	return string(body), nil
}
