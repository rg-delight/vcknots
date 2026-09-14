package wallet

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
	"net/url"
)

// PresentDraft24Credential retains the legacy fork presentation flow for Draft24 callers.
// It preserves the legacy single-credential selection and descriptor generation;
// applications supplying their own selection use Oid4vpPresenter.PresentDraft24.
func (w *Wallet) PresentDraft24Credential(uriString string, key IKeyEntry, options serializerTypes.SerializePresentationOptions) error {
	req, endpoint, err := w.parseDraft24AuthorizationRequest(uriString)
	if err != nil {
		return err
	}

	credentials, flavor, err := w.selectCredentialsForPresentation(req)
	if err != nil {
		return err
	}

	if options == nil {
		options, err = w.serializer.GetDefaultOption(*flavor)
		if err != nil {
			return err
		}
	}
	applyOID4VPRequestOptions(req, options)

	descriptorMap, err := w.buildDraft24DescriptorMap(credentials, flavor)
	if err != nil {
		return err
	}

	presentation, err := w.buildPresentation(credentials, key, req)
	if err != nil {
		return err
	}

	return w.submitDraft24Presentation(presentation, flavor, endpoint, descriptorMap, req, key, options)
}

func (w *Wallet) parseDraft24AuthorizationRequest(uriString string) (*oid4vp.CredentialPresentationRequest, *url.URL, error) {
	req, err := w.presenter.ParseDraft24RequestURI(uriString)
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

	if req.PresentationDefinition == nil || req.PresentationDefinition.ID == "" {
		return nil, nil, fmt.Errorf("presentation_definition is not specified")
	}

	return req, endpoint, nil
}

func (w *Wallet) buildDraft24DescriptorMap(credentials []*SavedCredential, flavor *credential.SupportedSerializationFlavor) ([]presenterTypes.DescriptorMapItem, error) {
	vcFormat, vpFormat, err := flavor.OID4VPFormatIdentifier()
	if err != nil {
		return nil, fmt.Errorf("unsupported serialization format: %w", err)
	}

	var descriptorMap []presenterTypes.DescriptorMapItem
	for i := range credentials {
		descriptionItemID := uuid.New().String()
		descriptorPath := "$"
		if len(credentials) > 1 {
			descriptorPath = fmt.Sprintf("$[%d]", i)
		}
		// Temporary compatibility workaround:
		// the current verifier/request-object flow still requires
		// presentation_submission.descriptor_map, and dc+sd-jwt must point to the
		// combined vp_token itself with path "$" instead of JWT-VP style nested paths.
		// This format-specific branching does not belong in wallet core long term and
		// should be removed or moved once the verifier/request-object flow is
		// reorganized around DCQL.
		if vpFormat == "dc+sd-jwt" {
			descriptorMap = append(descriptorMap, presenterTypes.DescriptorMapItem{
				ID:     descriptionItemID,
				Format: vpFormat,
				Path:   descriptorPath,
			})
			continue
		}

		descriptorMap = append(descriptorMap, presenterTypes.DescriptorMapItem{
			ID:     descriptionItemID,
			Format: vpFormat,
			Path:   descriptorPath,
			PathNested: &presenterTypes.DescriptorMapItem{
				ID:     descriptionItemID,
				Format: vcFormat,
				Path:   fmt.Sprintf("$.verifiableCredential[%d]", i),
			},
		})
	}

	return descriptorMap, nil
}

func (w *Wallet) submitDraft24Presentation(presentation *credential.CredentialPresentation, flavor *credential.SupportedSerializationFlavor, endpoint *url.URL, descriptorMap []presenterTypes.DescriptorMapItem, req *oid4vp.CredentialPresentationRequest, key IKeyEntry, options serializerTypes.SerializePresentationOptions) error {
	if len(req.TransactionData) > 0 {
		if sdOpts, ok := options.(*sdjwtvc.SdJwtVcPresentationOptions); ok && sdOpts != nil {
			transactionDataHashesAlg := req.TransactionDataHashesAlg
			if transactionDataHashesAlg == "" {
				// OID4VP transaction_data_hashes_alg default when omitted.
				transactionDataHashesAlg = "sha-256"
			}

			sdOpts.TransactionData = req.TransactionData
			sdOpts.TransactionDataHashesAlg = transactionDataHashesAlg
		}
	}

	bytes, _, err := w.serializer.SerializePresentation(
		*flavor,
		presentation,
		key,
		options,
	)
	if err != nil {
		return fmt.Errorf("failed to serialize presentation: %w", err)
	}

	presentationSubmission := presenterTypes.PresentationSubmission{
		ID:            uuid.New().String(),
		DefinitionID:  req.PresentationDefinition.ID,
		DescriptorMap: descriptorMap,
	}

	presentationRequest := &presenterTypes.PresentationRequest{
		State:          req.State,
		ClientMetadata: req.ClientMetadata,
	}

	if req.ClientMetadata != nil {
		presentationRequest.AuthorizationEncryptedRespAlg = req.ClientMetadata.AuthorizationEncryptedResponseAlg
		presentationRequest.AuthorizationEncryptedRespEnc = req.ClientMetadata.AuthorizationEncryptedResponseEnc
	}

	_, err = w.presenter.PresentDraft24(presenterTypes.Oid4vp, *endpoint, bytes, presentationSubmission, presentationRequest)
	return err
}
