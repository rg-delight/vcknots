package wallet

import (
	"fmt"
	"net/url"
	"sort"

	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

// OID4VPFinalAuthorizationResponse represents the JSON payload that is
// encrypted into a direct_post.jwt response for OID4VP Final DCQL requests.
type OID4VPFinalAuthorizationResponse map[string]any

// RedirectHandler is called when the verifier returns a redirect URI.
type RedirectHandler func(string) error

// PresentCredentialOptions configures presentation serialization and redirect handling.
type PresentCredentialOptions struct {
	SerializeOptions serializerTypes.SerializePresentationOptions
	OnRedirect       RedirectHandler
}

// PresentCredential orchestrates the credential presentation flow.
func (w *Wallet) PresentCredential(uriString string, key IKeyEntry, options serializerTypes.SerializePresentationOptions) (string, error) {
	return w.PresentCredentialWithOptions(uriString, key, &PresentCredentialOptions{SerializeOptions: options})
}

// PresentCredentialWithOptions orchestrates presentation and invokes redirect handler if provided.
func (w *Wallet) PresentCredentialWithOptions(uriString string, key IKeyEntry, options *PresentCredentialOptions) (string, error) {
	var serializeOptions serializerTypes.SerializePresentationOptions
	var onRedirect RedirectHandler
	if options != nil {
		serializeOptions = options.SerializeOptions
		onRedirect = options.OnRedirect
	}

	req, endpoint, err := w.parseAuthorizationRequest(uriString)
	if err != nil {
		return "", err
	}
	if err := validateTransactionDataHolderBinding(req); err != nil {
		return "", err
	}

	vpToken, err := w.buildDCQLVPToken(req, key, serializeOptions)
	if err != nil {
		return "", err
	}
	presentationRequest := &presenterTypes.PresentationRequest{
		State:          req.State,
		ResponseMode:   string(req.ResponseMode),
		ClientMetadata: req.ClientMetadata,
	}
	redirectURI, err := w.presenter.PresentDCQL(presenterTypes.Oid4vp, *endpoint, vpToken, presentationRequest)
	if err != nil {
		return "", err
	}
	if redirectURI != "" && onRedirect != nil {
		if err := onRedirect(redirectURI); err != nil {
			return redirectURI, err
		}
	}

	return redirectURI, nil
}

// PresentDCQLSelection submits an OID4VP authorization response built from
// credentials the caller already chose, for a request the caller already
// parsed. It exists because OID4VP 1.0 leaves two choices to the Wallet that
// belong to the person giving consent rather than to a library: which of a
// credential query's claim_sets to disclose (Section 6.3) and which option of a
// credential_set to answer (Section 6.2). PresentCredential and
// PresentCredentialWithOptions keep making both choices in the library.
//
// The selections are validated against the request before anything is
// serialized: a selection the request cannot accept fails with an error that
// wraps oid4vp.ErrDCQLSelectionUnsatisfied and nothing is sent. An empty
// selection is the Holder answering no credential query, and is sent as the
// empty vp_token object of OID4VP 1.0 Section 8.1. Transaction data assignment
// and response encryption are identical to PresentCredentialWithOptions.
//
// The returned value is the redirect_uri the Verifier answered with, if any.
func (w *Wallet) PresentDCQLSelection(req *oid4vp.CredentialPresentationRequest, endpoint url.URL, key IKeyEntry, selections []oid4vp.DCQLCredentialSelection, options serializerTypes.SerializePresentationOptions) (string, error) {
	if req == nil {
		return "", fmt.Errorf("authorization request is required to present a DCQL selection")
	}
	if err := validateTransactionDataHolderBinding(req); err != nil {
		return "", err
	}
	vpToken, err := w.buildDCQLVPTokenFromSelections(req, key, selections, options)
	if err != nil {
		return "", err
	}
	return w.presenter.PresentDCQL(presenterTypes.Oid4vp, endpoint, vpToken, &presenterTypes.PresentationRequest{
		State:          req.State,
		ResponseMode:   string(req.ResponseMode),
		ClientMetadata: req.ClientMetadata,
	})
}

// BuildOID4VPFinalAuthorizationResponse builds an OID4VP Final DCQL
// authorization response from credentials already stored in the wallet. The
// returned value is ready to encrypt with Oid4vpPresenter.CreateEncryptedAuthorizationResponse
// and submit as the direct_post.jwt "response" form field.
func (w *Wallet) BuildOID4VPFinalAuthorizationResponse(uriString string, key IKeyEntry) (OID4VPFinalAuthorizationResponse, error) {
	req, _, err := w.parseAuthorizationRequest(uriString)
	if err != nil {
		return nil, err
	}
	return w.buildOID4VPFinalAuthorizationResponse(req, key)
}

// SubmitOID4VPFinalAuthorizationResponse builds, encrypts, and submits an
// OID4VP Final direct_post.jwt authorization response for credentials already
// stored in the wallet. The returned body is the verifier response after posting
// the encrypted "response" form field to response_uri.
func (w *Wallet) SubmitOID4VPFinalAuthorizationResponse(uriString string, key IKeyEntry) (string, error) {
	req, endpoint, err := w.parseAuthorizationRequest(uriString)
	if err != nil {
		return "", err
	}
	return w.SubmitOID4VPFinalAuthorizationRequest(req, *endpoint, key)
}

// SubmitOID4VPFinalAuthorizationRequest builds, encrypts, and submits an
// already-parsed OID4VP Final direct_post.jwt authorization request. This keeps
// adapters from re-fetching one-time request_uri values when they need to inspect
// the request before handing control to the wallet API.
func (w *Wallet) SubmitOID4VPFinalAuthorizationRequest(req *oid4vp.CredentialPresentationRequest, endpoint url.URL, key IKeyEntry) (string, error) {
	if req.ResponseMode != oid4vp.OAuthAuthzReqResponseModeDirectPostJWT {
		return "", fmt.Errorf("response_mode must be direct_post.jwt for OID4VP Final encrypted submission")
	}
	if req.ClientMetadata == nil {
		return "", fmt.Errorf("client_metadata is required for OID4VP Final encrypted submission")
	}
	response, err := w.buildOID4VPFinalAuthorizationResponse(req, key)
	if err != nil {
		return "", err
	}
	return w.presenter.SubmitOID4VPFinalEncryptedAuthorizationResponse(endpoint, map[string]any(response), req.ClientMetadata)
}
func (w *Wallet) buildOID4VPFinalAuthorizationResponse(req *oid4vp.CredentialPresentationRequest, key IKeyEntry) (OID4VPFinalAuthorizationResponse, error) {
	if req.DcqlQuery == nil {
		return nil, fmt.Errorf("dcql_query is required for OID4VP Final authorization response")
	}
	if err := validateTransactionDataHolderBinding(req); err != nil {
		return nil, err
	}

	vpToken, err := w.buildDCQLVPToken(req, key, nil)
	if err != nil {
		return nil, err
	}

	response := OID4VPFinalAuthorizationResponse{
		"vp_token": vpToken,
	}
	if req.State != "" {
		response["state"] = req.State
	}
	return response, nil
}

// parseAuthorizationRequest parses the authorization request URI and determines the endpoint.
func (w *Wallet) parseAuthorizationRequest(uriString string) (*oid4vp.CredentialPresentationRequest, *url.URL, error) {
	req, err := w.presenter.ParseRequestURI(uriString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse request URI: %w", err)
	}

	if req.ResponseMode != oid4vp.OAuthAuthzReqResponseModeDirectPost && req.ResponseMode != oid4vp.OAuthAuthzReqResponseModeDirectPostJWT && req.RedirectURI == "" {
		return nil, nil, fmt.Errorf("redirect_uri is not specified")
	}

	var endpoint *url.URL
	if req.ResponseMode == oid4vp.OAuthAuthzReqResponseModeDirectPost || req.ResponseMode == oid4vp.OAuthAuthzReqResponseModeDirectPostJWT {
		if req.ResponseURI == "" {
			return nil, nil, fmt.Errorf("response_uri is not specified for response_mode=%s", req.ResponseMode)
		}
		endpoint, err = url.Parse(req.ResponseURI)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid response_uri: %w", err)
		}
	} else {
		endpoint, err = url.Parse(req.RedirectURI)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid redirect_uri: %w", err)
		}
	}

	if req.DcqlQuery == nil || len(req.DcqlQuery.Credentials) == 0 {
		return nil, nil, fmt.Errorf("dcql_query is not specified")
	}

	return req, endpoint, nil
}

// selectCredentialsForPresentation selects credentials matching the presentation definition.
func (w *Wallet) selectCredentialsForPresentation(req *oid4vp.CredentialPresentationRequest) ([]*SavedCredential, *credential.SupportedSerializationFlavor, error) {
	entries, _, err := w.GetCredentialEntries(GetCredentialEntriesRequest{
		Offset: 0,
		Limit:  nil,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get credential entries: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("no credentials available for presentation")
	}

	selectedCredentials := newestCredentials(entries, 1)

	// Validate that all selected credentials have the same serialization flavor
	serializationFlavor, err := w.validateSerializationFlavor(selectedCredentials)
	if err != nil {
		return nil, nil, err
	}

	return selectedCredentials, serializationFlavor, nil
}
func (w *Wallet) selectCredentialsForDCQL(query *oid4vp.DcqlQuery) (map[string]*SavedCredential, []oid4vp.DCQLCredentialSelection, error) {
	credentialsByID, candidates, err := w.dcqlCandidates()
	if err != nil {
		return nil, nil, err
	}

	selections, err := oid4vp.ResolveSatisfiableDCQLCredentials(query, candidates)
	if err != nil {
		// OID4VP 1.0 Section 8.5: the Wallet did not have the requested
		// Credentials to satisfy the Authorization Request.
		return nil, nil, newAccessDeniedError("%v", err)
	}
	if len(selections) == 0 {
		return nil, nil, newAccessDeniedError("dcql_query cannot be satisfied by stored credentials")
	}
	return credentialsByID, selections, nil
}

// newAccessDeniedError returns the typed OID4VP 1.0 Section 8.5 access_denied
// error so callers can send an authorization error response.
func newAccessDeniedError(format string, args ...any) *oid4vp.AuthorizationRequestError {
	return &oid4vp.AuthorizationRequestError{Code: oid4vp.AccessDeniedError, Err: fmt.Errorf(format, args...)}
}
func boolPointer(value bool) *bool {
	return &value
}

// credentialHasHolderBinding reports whether a stored credential carries a
// cryptographic holder binding key.
func credentialHasHolderBinding(flavor credential.SupportedSerializationFlavor, entry *SavedCredential) bool {
	if flavor == credential.SDJwtVC {
		return SDJWTCarriesConfirmation(entry.Entry.Raw)
	}
	if entry.Credential == nil || entry.Credential.Claims == nil {
		return false
	}
	_, present := (*entry.Credential.Claims)["cnf"]
	return present
}
func newestCredentials(entries []*SavedCredential, limit int) []*SavedCredential {
	if len(entries) == 0 || limit <= 0 {
		return nil
	}

	sorted := append([]*SavedCredential(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		left := sorted[i]
		right := sorted[j]

		if left == nil || left.Entry == nil {
			return false
		}
		if right == nil || right.Entry == nil {
			return true
		}

		return left.Entry.ReceivedAt.After(right.Entry.ReceivedAt)
	})

	if limit > len(sorted) {
		limit = len(sorted)
	}

	return sorted[:limit]
}

// validateSerializationFlavor ensures all credentials have the same serialization flavor.
func (w *Wallet) validateSerializationFlavor(credentials []*SavedCredential) (*credential.SupportedSerializationFlavor, error) {
	var serializationFlavor *credential.SupportedSerializationFlavor

	for _, cred := range credentials {
		sf, err := cred.Entry.SerializationFlavor()
		if err != nil {
			return nil, fmt.Errorf("credential entry has no serialization flavor information")
		}

		if serializationFlavor == nil {
			serializationFlavor = &sf
		} else if *serializationFlavor != sf {
			return nil, fmt.Errorf("credentials have different serialization flavors")
		}
	}

	if serializationFlavor == nil {
		return nil, fmt.Errorf("failed to detect serialization flavor")
	}

	return serializationFlavor, nil
}

// buildPresentation builds the credential presentation.
func (w *Wallet) buildPresentation(credentials []*SavedCredential, key IKeyEntry, req *oid4vp.CredentialPresentationRequest) (*credential.CredentialPresentation, error) {
	did, err := w.GenerateDID(DIDCreateOptions{
		TypeID:    "did:key",
		PublicKey: key.PublicKey(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate DID: %w", err)
	}

	var serializedCredentials [][]byte
	for _, entry := range credentials {
		serializedCredentials = append(serializedCredentials, entry.Entry.Raw)
	}

	presentation := &credential.CredentialPresentation{
		ID:          "urn:uuid:" + uuid.New().String(),
		Types:       []string{"VerifiablePresentation"},
		Credentials: serializedCredentials,
		Holder:      did.ID,
		Nonce:       &req.Nonce,
	}

	return presentation, nil
}
func applyOID4VPRequestOptions(req *oid4vp.CredentialPresentationRequest, options serializerTypes.SerializePresentationOptions) {
	if options == nil || req == nil || req.OAuthAuthzRequest == nil {
		return
	}
	options.SetAudience(req.ClientID)
	options.SetNonce(req.Nonce)
}
