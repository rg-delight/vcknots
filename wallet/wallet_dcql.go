package wallet

import (
	"fmt"
	"slices"

	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

// buildDCQLVPToken finishes selection and serialization for every required
// query before the caller can submit any credential to the verifier.
func (w *Wallet) buildDCQLVPToken(req *oid4vp.CredentialPresentationRequest, key IKeyEntry, callerOptions serializerTypes.SerializePresentationOptions) (map[string][]string, error) {
	credentials, selections, err := w.selectCredentialsForDCQL(req.DcqlQuery)
	if err != nil {
		return nil, err
	}
	vpToken := make(map[string][]string, len(selections))
	for _, selection := range selections {
		saved := credentials[selection.CandidateID]
		flavor, err := saved.Entry.SerializationFlavor()
		if err != nil {
			return nil, fmt.Errorf("failed to detect selected credential format: %w", err)
		}
		options := callerOptions
		if sdOpts, ok := options.(*sdjwtvc.SdJwtVcPresentationOptions); ok {
			if sdOpts == nil {
				options = nil
			} else {
				copy := *sdOpts
				options = &copy
			}
		}
		if options == nil {
			options, err = w.serializer.GetDefaultOption(flavor)
			if err != nil {
				return nil, err
			}
		}
		applyOID4VPRequestOptions(req, options)
		if sdOpts, ok := options.(*sdjwtvc.SdJwtVcPresentationOptions); ok && sdOpts != nil {
			if sdOpts.LimitDisclosureToSelectedClaims || len(sdOpts.SelectedClaims) > 0 {
				for _, name := range selection.RequestedClaims {
					if !slices.Contains(sdOpts.SelectedClaims, name) {
						return nil, fmt.Errorf("requested claim %q is not allowed by caller disclosure selection", name)
					}
				}
			}
			sdOpts.SelectedClaims = slices.Clone(selection.RequestedClaims)
			sdOpts.LimitDisclosureToSelectedClaims = true
			sdOpts.RequireRootClaimMatch = true
			for _, query := range req.DcqlQuery.Credentials {
				if query.ID == selection.QueryID {
					sdOpts.RequireKeyBinding = sdOpts.RequireKeyBinding || query.RequiresHolderBinding()
					break
				}
			}
			sdOpts.TransactionData = req.TransactionData
			sdOpts.TransactionDataHashesAlg = req.TransactionDataHashesAlg
			if sdOpts.TransactionDataHashesAlg == "" {
				sdOpts.TransactionDataHashesAlg = "sha-256"
			}
		}
		presentation, err := w.buildPresentation([]*SavedCredential{saved}, key, req)
		if err != nil {
			return nil, err
		}
		serialized, _, err := w.serializer.SerializePresentation(flavor, presentation, key, options)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize selected credential %s: %w", selection.CandidateID, err)
		}
		vpToken[selection.QueryID] = append(vpToken[selection.QueryID], string(serialized))
	}
	return vpToken, nil
}
