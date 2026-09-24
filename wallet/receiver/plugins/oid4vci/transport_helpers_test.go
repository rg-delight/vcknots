package oid4vci

import (
	"context"
	"encoding/json"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// dpopAccessToken is a DPoP-bound Token Response carrying accessToken.
func dpopAccessToken(accessToken string) types.CredentialIssuanceAccessToken {
	return types.CredentialIssuanceAccessToken{Token: accessToken, TokenType: dpopAuthorizationScheme}
}

// fixedProof returns the same DPoP proof for every attempt.
func fixedProof(proof string) DPoPProofFactory {
	return func(string) (string, error) { return proof, nil }
}

// fixedAttestationHeaders returns the same client attestation headers for every attempt.
func fixedAttestationHeaders(headers types.OAuthClientAttestationHeaders) OAuthClientAttestationHeadersFactory {
	return func() (types.OAuthClientAttestationHeaders, error) { return headers, nil }
}

// postCredentialBody posts a pre-encoded body to a protected endpoint with a
// DPoP-bound access token and no c_nonce refresh.
func postCredentialBody(ctx context.Context, receiver *Oid4vciReceiver, endpoint common.URIField, accessToken string, body []byte, contentType string, proof DPoPProofFactory) (*CredentialEndpointHTTPResponse, error) {
	response, _, err := receiver.PostCredentialEndpointWithNonceRetryForToken(ctx, endpoint, dpopAccessToken(accessToken), nil, "", func(string) ([]byte, string, error) {
		return body, contentType, nil
	}, proof)
	return response, err
}

// requestCredentialJSON posts payload as JSON to a Credential or Deferred
// Credential Endpoint and decodes the plaintext response.
func requestCredentialJSON(ctx context.Context, receiver *Oid4vciReceiver, endpoint common.URIField, accessToken string, payload any, proof DPoPProofFactory) (*types.CredentialResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	response, err := postCredentialBody(ctx, receiver, endpoint, accessToken, body, "application/json", proof)
	if err != nil {
		return nil, err
	}
	return receiver.DecodeCredentialResponse(response.Body, response.ContentType, nil)
}
