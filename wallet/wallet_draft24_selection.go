package wallet

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/credential"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

// Draft24CredentialSelection is one credential the Holder chose for a DIF
// Presentation Exchange request, together with the input descriptors it
// answers. Which stored credential satisfies which input_descriptor is a
// consent decision, so it is named by the caller and never re-derived here.
type Draft24CredentialSelection struct {
	// CredentialID is the stored credential entry id.
	CredentialID string
	// Credential carries the credential by value instead of naming one in the
	// wallet store. It is required on a wallet built with Config.Storeless and
	// optional otherwise, where it takes precedence over the store lookup: the
	// Holder consented to this credential, so it is the one presented.
	Credential *credstoreTypes.CredentialEntry
	// InputDescriptorIDs are the presentation_definition input_descriptor ids
	// this credential answers. An empty list makes the library invent a
	// descriptor id, which only matches a Verifier that ignores it.
	InputDescriptorIDs []string
	// Key overrides the presentation key for this credential. A nil value uses
	// the key passed to PresentDraft24Selection.
	Key IKeyEntry
	// Options overrides the serialization options for this credential, which is
	// how a per-credential disclosure selection reaches the serializer. A nil
	// value uses the options passed to PresentDraft24Selection.
	Options serializerTypes.SerializePresentationOptions
}

// PresentDraft24Selection submits a DIF Presentation Exchange authorization
// response built from credentials the caller already chose, for a request the
// caller already parsed. It is the Draft24 counterpart of PresentDCQLSelection:
// PresentDraft24Credential keeps picking a single newest credential itself,
// while this entry point takes the Holder's per-input-descriptor choice, the
// per-credential holder key and the per-credential disclosure selection.
//
// The response is submitted plain or encrypted according to the request's own
// response_mode, falling back to the legacy client_metadata
// authorization_encrypted_response_alg; see Oid4vpPresenter.PresentDraft24.
//
// The returned value is the redirect_uri the Verifier answered with, if any.
func (w *Wallet) PresentDraft24Selection(
	req *oid4vp.CredentialPresentationRequest,
	endpoint url.URL,
	key IKeyEntry,
	selections []Draft24CredentialSelection,
	options serializerTypes.SerializePresentationOptions,
) (string, error) {
	if req == nil {
		return "", fmt.Errorf("authorization request is required to present a Draft24 selection")
	}
	if req.PresentationDefinition == nil || req.PresentationDefinition.ID == "" {
		return "", fmt.Errorf("presentation_definition is required to present a Draft24 selection")
	}
	// A Presentation Exchange vp_token is a Presentation, which cannot express
	// "no credential"; only the DCQL response object of OID4VP 1.0 Section 8.1
	// can. An empty selection is therefore a caller mistake here.
	if len(selections) == 0 {
		return "", fmt.Errorf("at least one credential selection is required to present a Draft24 request")
	}

	credentials, err := w.draft24SelectedCredentials(selections)
	if err != nil {
		return "", err
	}
	flavor, err := w.validateSerializationFlavor(credentials)
	if err != nil {
		return "", err
	}
	descriptorIDs := make([][]string, len(selections))
	for index, selection := range selections {
		descriptorIDs[index] = selection.InputDescriptorIDs
	}
	descriptorMap, err := w.buildDraft24DescriptorMap(credentials, flavor, descriptorIDs)
	if err != nil {
		return "", err
	}

	vpToken, err := w.serializeDraft24Selection(req, key, selections, credentials, flavor, options)
	if err != nil {
		return "", err
	}

	presentationRequest := &presenterTypes.PresentationRequest{
		State:          req.State,
		ResponseMode:   string(req.ResponseMode),
		ClientMetadata: req.ClientMetadata,
	}
	if req.ClientMetadata != nil {
		presentationRequest.AuthorizationEncryptedRespAlg = req.ClientMetadata.AuthorizationEncryptedResponseAlg
		presentationRequest.AuthorizationEncryptedRespEnc = req.ClientMetadata.AuthorizationEncryptedResponseEnc
	}
	submission := presenterTypes.PresentationSubmission{
		ID:            uuid.New().String(),
		DefinitionID:  req.PresentationDefinition.ID,
		DescriptorMap: descriptorMap,
	}
	return w.presenter.PresentDraft24(presenterTypes.Oid4vp, endpoint, vpToken, submission, presentationRequest)
}

// draft24SelectedCredentials resolves the caller's credential ids against the
// wallet store, keeping the caller's order so descriptor_map paths and the
// vp_token array agree.
func (w *Wallet) draft24SelectedCredentials(selections []Draft24CredentialSelection) ([]*SavedCredential, error) {
	stored := map[string]*SavedCredential{}
	// The store is only read when a selection needs it, so a wallet that
	// carries every credential by value never touches one (Config.Storeless).
	if draft24SelectionsNeedTheStore(selections) {
		entries, _, err := w.GetCredentialEntries(GetCredentialEntriesRequest{Offset: 0, Limit: nil})
		if err != nil {
			return nil, fmt.Errorf("failed to get credential entries: %w", err)
		}
		for _, entry := range entries {
			if entry != nil && entry.Entry != nil {
				stored[entry.Entry.Id] = entry
			}
		}
	}
	credentials := make([]*SavedCredential, 0, len(selections))
	for _, selection := range selections {
		if selection.Credential != nil {
			saved, err := w.convertEntryToSavedCredential(*selection.Credential)
			if err != nil {
				return nil, fmt.Errorf("selected credential %s cannot be presented: %w", selection.CredentialID, err)
			}
			credentials = append(credentials, saved)
			continue
		}
		saved, found := stored[selection.CredentialID]
		if !found {
			return nil, fmt.Errorf("selected credential %s is not stored in this wallet", selection.CredentialID)
		}
		credentials = append(credentials, saved)
	}
	return credentials, nil
}

// draft24SelectionsNeedTheStore reports whether any selection names a
// credential the wallet has to read out of its own store.
func draft24SelectionsNeedTheStore(selections []Draft24CredentialSelection) bool {
	for _, selection := range selections {
		if selection.Credential == nil {
			return true
		}
	}
	return false
}

// serializeDraft24Selection renders the vp_token of a Presentation Exchange
// response. SD-JWT VC carries one Presentation per credential, because an
// SD-JWT VC Presentation holds exactly one credential and each one needs its
// own Key Binding JWT; several of them travel as the JSON array the
// descriptor_map indexes with $[i]. Every other flavor keeps the single
// Presentation the legacy flow builds.
func (w *Wallet) serializeDraft24Selection(
	req *oid4vp.CredentialPresentationRequest,
	key IKeyEntry,
	selections []Draft24CredentialSelection,
	credentials []*SavedCredential,
	flavor *credential.SupportedSerializationFlavor,
	options serializerTypes.SerializePresentationOptions,
) ([]byte, error) {
	if *flavor != credential.SDJwtVC {
		resolved, err := w.draft24SerializeOptions(req, options, flavor)
		if err != nil {
			return nil, err
		}
		presentation, err := w.buildPresentation(credentials, key, req)
		if err != nil {
			return nil, err
		}
		serialized, _, err := w.serializer.SerializePresentation(*flavor, presentation, key, resolved)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize presentation: %w", err)
		}
		return serialized, nil
	}

	tokens := make([]string, 0, len(selections))
	for index, selection := range selections {
		selectionKey := key
		if selection.Key != nil {
			selectionKey = selection.Key
		}
		selectionOptions := options
		if selection.Options != nil {
			selectionOptions = selection.Options
		}
		resolved, err := w.draft24SerializeOptions(req, selectionOptions, flavor)
		if err != nil {
			return nil, err
		}
		presentation, err := w.buildPresentation([]*SavedCredential{credentials[index]}, selectionKey, req)
		if err != nil {
			return nil, err
		}
		serialized, _, err := w.serializer.SerializePresentation(*flavor, presentation, selectionKey, resolved)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize selected credential %s: %w", selection.CredentialID, err)
		}
		tokens = append(tokens, string(serialized))
	}
	if len(tokens) == 1 {
		return []byte(tokens[0]), nil
	}
	return json.Marshal(tokens)
}

// draft24SerializeOptions copies the caller's options so one credential's
// disclosure selection cannot leak into the next, fills in the serializer
// default when the caller passed none, and applies the request's audience and
// nonce.
func (w *Wallet) draft24SerializeOptions(
	req *oid4vp.CredentialPresentationRequest,
	options serializerTypes.SerializePresentationOptions,
	flavor *credential.SupportedSerializationFlavor,
) (serializerTypes.SerializePresentationOptions, error) {
	if sdOpts, ok := options.(*sdjwtvc.SdJwtVcPresentationOptions); ok {
		if sdOpts == nil {
			options = nil
		} else {
			clone := *sdOpts
			options = &clone
		}
	}
	if options == nil {
		defaultOptions, err := w.serializer.GetDefaultOption(*flavor)
		if err != nil {
			return nil, err
		}
		options = defaultOptions
	}
	applyOID4VPRequestOptions(req, options)
	return options, nil
}
