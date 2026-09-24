package wallet

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/trustknots/vcknots/wallet/credential"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

// DCQLHolderSelection is one credential a Holder chose on a consent screen:
// the credential, the DCQL credential queries it answers, and the disclosure
// names the Holder kept. PresentDCQLHolderSelection translates it into the
// claims path vocabulary of oid4vp.DCQLCredentialSelection.
type DCQLHolderSelection struct {
	// QueryIDs are the ids of the credential queries this credential answers.
	// At least one is required, since the vp_token is keyed by credential query
	// id (OID4VP 1.0 Section 8.1).
	QueryIDs []string
	// Credential is the credential to present, carried by value so a wallet
	// built with Config.Storeless can present it. Its Id must be unique within
	// the selection.
	Credential credstoreTypes.CredentialEntry
	// DisclosedClaims are the disclosure names the Holder kept. Nil discloses
	// the Verifier's preferred claim set. Otherwise the first claim set, in the
	// Verifier's order, whose every claim the Holder kept is disclosed; if no
	// set is kept whole the selection is refused (Section 6.4.1).
	DisclosedClaims []string
}

// PresentDCQLHolderSelection submits an OID4VP Authorization Response for the
// credentials a Holder chose on a consent screen, without reading or writing a
// credential store.
//
// The vp_token contains exactly the chosen (query, credential) pairs. Before
// anything is serialized the choice is checked against the request; a
// credential a query cannot accept, a claim set not kept whole, a second
// credential for a query without multiple, or an unanswered required
// credential_set fails with an error wrapping oid4vp.ErrDCQLSelectionUnsatisfied.
// An empty selection against a request whose credential_sets are all optional
// is sent as the empty vp_token object of Section 8.1.
//
// Transaction data assignment, disclosure limits, key binding and submission
// are identical to PresentDCQLSelection. The returned value is the
// redirect_uri the Verifier answered with, if any.
func (w *Wallet) PresentDCQLHolderSelection(
	req *oid4vp.CredentialPresentationRequest,
	endpoint url.URL,
	key IKeyEntry,
	selections []DCQLHolderSelection,
	options serializerTypes.SerializePresentationOptions,
) (string, error) {
	if req == nil || req.DcqlQuery == nil {
		return "", fmt.Errorf("dcql_query is required to present a DCQL selection")
	}
	if err := validateTransactionDataHolderBinding(req); err != nil {
		return "", err
	}
	credentials, resolved, err := w.resolveDCQLHolderSelections(req.DcqlQuery, selections)
	if err != nil {
		return "", err
	}
	vpToken, err := w.serializeDCQLSelections(req, key, options, credentials, resolved)
	if err != nil {
		return "", err
	}
	return w.presentDCQLVPToken(req, endpoint, vpToken)
}

// resolveDCQLHolderSelections turns the Holder's answer into the library's
// selection vocabulary: one selection per (credential query, credential) pair
// the Holder chose and nothing else, each with the claim set the Holder's kept
// disclosure names select. The whole answer is then checked against the
// request's multiple and credential_sets rules.
func (w *Wallet) resolveDCQLHolderSelections(
	query *oid4vp.DCQLQuery,
	selections []DCQLHolderSelection,
) (map[string]*SavedCredential, []oid4vp.DCQLCredentialSelection, error) {
	credentials := make(map[string]*SavedCredential, len(selections))
	candidates := make([]oid4vp.DCQLCredentialCandidate, 0, len(selections))
	resolved := []oid4vp.DCQLCredentialSelection{}
	for _, selection := range selections {
		entry := selection.Credential
		if entry.Id == "" {
			return nil, nil, fmt.Errorf("every DCQL holder selection must identify its credential")
		}
		if _, duplicate := credentials[entry.Id]; duplicate {
			return nil, nil, fmt.Errorf("credential %q appears in more than one DCQL holder selection", entry.Id)
		}
		if len(selection.QueryIDs) == 0 {
			// The vp_token is keyed by credential query id (Section 8.1).
			return nil, nil, fmt.Errorf(
				"the DCQL holder selection for credential %q names no credential query", entry.Id)
		}
		saved, err := w.convertEntryToSavedCredential(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("selected credential %q cannot be presented: %w", entry.Id, err)
		}
		candidate, err := dcqlCandidateFromSavedCredential(saved)
		if err != nil {
			return nil, nil, err
		}
		credentials[entry.Id] = saved
		candidates = append(candidates, candidate)
		for _, queryID := range selection.QueryIDs {
			claimSets, err := oid4vp.ResolveDCQLClaimSets(query, queryID, candidate)
			if err != nil {
				return nil, nil, fmt.Errorf("the credential chosen for credential query %q cannot answer it: %w", queryID, err)
			}
			claims, ok := holderClaimSet(claimSets, selection.DisclosedClaims)
			if !ok {
				return nil, nil, fmt.Errorf(
					"%w: the claims kept for credential query %q do not cover any claim set it offers",
					oid4vp.ErrDCQLSelectionUnsatisfied, queryID)
			}
			resolved = append(resolved, oid4vp.DCQLCredentialSelection{
				QueryID:         queryID,
				CandidateID:     entry.Id,
				Format:          candidate.Format,
				VCT:             candidate.VCT,
				RequestedClaims: claims,
			})
		}
	}
	if err := oid4vp.ValidateDCQLCredentialSelections(query, candidates, resolved); err != nil {
		return nil, nil, err
	}
	return credentials, resolved, nil
}

// holderClaimSet picks the claim set to disclose. With no kept names it is the
// Verifier's preferred set; otherwise it is the first set, in the Verifier's
// order, whose every claim the Holder kept (OID4VP 1.0 Section 6.4.1 allows
// returning a set only whole).
func holderClaimSet(claimSets [][]string, kept []string) ([]string, bool) {
	if kept == nil {
		return claimSets[0], true
	}
	for _, claims := range claimSets {
		complete := true
		for _, claim := range claims {
			if !slices.Contains(kept, dcqlClaimDisclosureName(claim)) {
				complete = false
				break
			}
		}
		if complete {
			return claims, true
		}
	}
	return nil, false
}

// dcqlCandidateFromSavedCredential describes one credential the way the DCQL
// matcher reads it.
func dcqlCandidateFromSavedCredential(saved *SavedCredential) (oid4vp.DCQLCredentialCandidate, error) {
	flavor, err := saved.Entry.SerializationFlavor()
	if err != nil {
		return oid4vp.DCQLCredentialCandidate{}, fmt.Errorf("failed to detect the format of credential %q: %w", saved.Entry.Id, err)
	}
	vcFormat, _, err := flavor.OID4VPFormatIdentifier()
	if err != nil {
		return oid4vp.DCQLCredentialCandidate{}, fmt.Errorf("credential %q has no OID4VP format identifier: %w", saved.Entry.Id, err)
	}
	claimNames := []string{}
	claimValues := map[string]any{}
	claimObject := map[string]any{}
	if saved.Credential != nil && saved.Credential.Claims != nil {
		for name, value := range *saved.Credential.Claims {
			claimNames = append(claimNames, name)
			claimValues[name] = value
			claimObject[name] = value
		}
	}
	switch flavor {
	case credential.SDJwtVC:
		if reconstructed, reconstructErr := sdjwtvc.ReconstructClaimsObject(string(saved.Entry.Raw)); reconstructErr == nil {
			claimObject = reconstructed
		}
	case credential.JwtVc, credential.LdpVc:
		// OID4VP 1.0 Appendix B.1: a claims path pointer into a W3C
		// Verifiable Credential starts at the credential, not its subject.
		if root, ok := w3cCredentialObject(flavor, saved.Entry.Raw); ok {
			claimObject = root
		}
	}
	vct := ""
	var types []string
	if saved.Credential != nil && len(saved.Credential.Types) > 0 {
		vct = saved.Credential.Types[0]
		types = saved.Credential.Types
	}
	holderBound := credentialHasHolderBinding(flavor, saved)
	return oid4vp.DCQLCredentialCandidate{
		ID:              saved.Entry.Id,
		Format:          vcFormat,
		VCT:             vct,
		Types:           types,
		Claims:          claimNames,
		ClaimValues:     claimValues,
		ClaimObject:     claimObject,
		HolderBound:     &holderBound,
		AuthorityKeyIDs: oid4vp.AuthorityKeyIdentifiersFromCredential(string(saved.Entry.Raw)),
	}, nil
}

// dcqlClaimDisclosureName is the disclosure name an encoded DCQL claim path
// ends in: a bare name is its own, and a JSON array path yields its last string
// component, so ["nationalities",1] is named "nationalities". Anything else is
// returned unchanged so it matches no kept name.
func dcqlClaimDisclosureName(encoded string) string {
	if !strings.HasPrefix(encoded, "[") {
		return encoded
	}
	var path []any
	if err := json.Unmarshal([]byte(encoded), &path); err != nil {
		return encoded
	}
	for index := len(path) - 1; index >= 0; index-- {
		if name, ok := path[index].(string); ok {
			return name
		}
	}
	return encoded
}

// w3cCredentialObject decodes the Verifiable Credential a claims path pointer
// is applied to: the vc claim of a jwt_vc_json payload, or the ldp_vc
// document itself.
func w3cCredentialObject(flavor credential.SupportedSerializationFlavor, raw []byte) (map[string]any, bool) {
	document := raw
	if flavor == credential.JwtVc {
		parts := strings.Split(string(raw), ".")
		if len(parts) != 3 {
			return nil, false
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, false
		}
		document = payload
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, false
	}
	if flavor == credential.JwtVc {
		vc, ok := object["vc"].(map[string]any)
		return vc, ok
	}
	return object, true
}
