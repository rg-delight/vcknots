package wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/trustknots/vcknots/wallet/credential"
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
	// OID4VP 1.0 Final Section 5.1: "If there is more than one element in the
	// array, the Wallet MUST use only one of the referenced Credentials for
	// transaction authorization." This pre-pass assigns every transaction_data
	// entry to one selected credential query, and rejects an entry that
	// references none of them, before any credential is serialized.
	transactionDataOwners, err := assignTransactionDataOwners(req.TransactionData, selections)
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
					// HAIP §6.1.1.1: "If the credential has cryptographic holder
					// binding, a KB-JWT ... MUST always be present". A credential
					// that carries cnf is holder-bound even when the verifier
					// waived the requirement, so HAIP forces the KB-JWT.
					if w.profile.IsHAIP() && flavor == credential.SDJwtVC && SDJWTCarriesConfirmation(saved.Entry.Raw) {
						sdOpts.RequireKeyBinding = true
					}
					break
				}
			}
			// Section 8.4: "The Wallet that received the transaction_data
			// parameter in the request MUST include a representation or
			// reference to the data in the respective Credential
			// presentation." Only the entries that reference this query
			// (Section 5.1) and that this query owns are hashed into its
			// Key Binding JWT; every other presentation stays free of them.
			referenced, err := transactionDataForQuery(req.TransactionData, selection.QueryID)
			if err != nil {
				return nil, err
			}
			sdOpts.TransactionData = nil
			for _, entry := range referenced {
				if transactionDataOwners[entry] == selection.QueryID {
					sdOpts.TransactionData = append(sdOpts.TransactionData, entry)
				}
			}
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

// SDJWTCarriesConfirmation reports whether the SD-JWT VC wire value's issuer
// JWT payload contains a cnf claim, i.e. the credential has cryptographic
// holder binding.
func SDJWTCarriesConfirmation(raw []byte) bool {
	issuerJWT := string(raw)
	if separator := strings.IndexByte(issuerJWT, '~'); separator >= 0 {
		issuerJWT = issuerJWT[:separator]
	}
	parts := strings.Split(issuerJWT, ".")
	if len(parts) != 3 {
		return false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false
	}
	_, present := payload["cnf"]
	return present
}
