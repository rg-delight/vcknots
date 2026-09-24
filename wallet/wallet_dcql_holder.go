package wallet

import (
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

// DCQLHolderSelection is one credential a Holder chose on a consent screen, in
// the vocabulary that screen uses: the credential itself, the DCQL credential
// queries it answers, and the disclosure names the Holder agreed to share.
//
// It exists because the two sides name a claim differently. A DCQL claims query
// resolves to an encoded claim path - the bare name for a single-segment path,
// the JSON array for a deeper one, as encodeDCQLClaimPath produces - while a
// consent screen shows, and a Holder answers with, the disclosure names of the
// credential. oid4vp.DCQLCredentialSelection carries the library's vocabulary
// and is what oid4vp.ValidateDCQLCredentialSelections checks; this type carries
// the Holder's, and PresentDCQLHolderSelection translates between them so an
// application does not reimplement either the translation or the satisfiability
// rules of OID4VP 1.0 Sections 6.2 and 6.3.
type DCQLHolderSelection struct {
	// QueryIDs are the ids of the DCQL credential queries this credential
	// answers. At least one is required: without it the Wallet cannot say which
	// query the Holder consented to answer with this credential, and the
	// vp_token of OID4VP 1.0 Section 8.1 is keyed by credential query id.
	QueryIDs []string
	// Credential is the credential to present, carried by value so a wallet
	// built with Config.Storeless can present it. Its Id identifies it inside
	// this presentation only.
	Credential credstoreTypes.CredentialEntry
	// DisclosedClaims are the disclosure names the Holder kept. A nil list
	// discloses every claim of the claim set the credential query resolves to
	// (Section 6.3 leaves the choice between claim_sets to the Wallet, and the
	// library's own first-satisfiable choice stands). A non-nil list keeps only
	// the resolved claims whose own disclosure name it contains, so a claim the
	// Holder withheld is not disclosed and one the Holder kept stays exactly as
	// the query named it.
	DisclosedClaims []string
}

// PresentDCQLHolderSelection submits an OID4VP Authorization Response for the
// credentials a Holder chose on a consent screen. It is PresentDCQLSelection
// for an application that holds its credentials outside this wallet and names
// claims the way its consent screen does; nothing is read from, or written to,
// a credential store.
//
// The selection is validated against the request before anything is
// serialized, so the Holder's answer cannot disclose a credential the request
// did not ask for and cannot leave a required credential_set unanswered:
//
//   - a credential the request cannot accept for the query it was chosen for
//     fails with an error wrapping oid4vp.ErrDCQLSelectionUnsatisfied;
//   - an empty selection against a query with a required credential_set - or
//     with no credential_sets at all, where every credential query is required
//     (Section 6.4.2) - fails the same way;
//   - an empty selection against a query whose credential_sets are all optional
//     is the Holder answering no query, and is sent as the empty vp_token
//     object of Section 8.1.
//
// Transaction data assignment, disclosure limits, key binding and the plain or
// encrypted submission are identical to PresentDCQLSelection.
//
// The returned value is the redirect_uri the Verifier answered with, if any.
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

// resolveDCQLHolderSelections turns the Holder's answer into the library's own
// selection vocabulary, and refuses an answer the request cannot accept.
func (w *Wallet) resolveDCQLHolderSelections(
	query *oid4vp.DCQLQuery,
	selections []DCQLHolderSelection,
) (map[string]*SavedCredential, []oid4vp.DCQLCredentialSelection, error) {
	credentials, candidates, chosen, err := w.dcqlHolderCandidates(selections)
	if err != nil {
		return nil, nil, err
	}
	// The library chooses the claim set and the credential_set option, which is
	// also what decides whether an unanswered set makes the request
	// unsatisfiable: Section 6.2's `required` defaults to true
	// (CredentialSetQuery.IsRequired), so a Holder who answered nothing is
	// refused here unless every set is optional.
	resolved, err := oid4vp.ResolveSatisfiableDCQLCredentials(query, candidates)
	if err != nil {
		return nil, nil, err
	}
	satisfiable := map[string]map[string]bool{}
	for _, selection := range resolved {
		if satisfiable[selection.QueryID] == nil {
			satisfiable[selection.QueryID] = map[string]bool{}
		}
		satisfiable[selection.QueryID][selection.CandidateID] = true
	}
	for queryID, candidateIDs := range chosen {
		for candidateID := range candidateIDs {
			if satisfiable[queryID][candidateID] {
				continue
			}
			return nil, nil, fmt.Errorf(
				"%w: the credential chosen for credential query %q does not satisfy it",
				oid4vp.ErrDCQLSelectionUnsatisfied, queryID)
		}
	}
	disclosed := map[string][]string{}
	for _, selection := range selections {
		if selection.DisclosedClaims != nil {
			disclosed[selection.Credential.Id] = selection.DisclosedClaims
		}
	}
	for index := range resolved {
		if names, limited := disclosed[resolved[index].CandidateID]; limited {
			resolved[index].RequestedClaims = narrowToDisclosureNames(resolved[index].RequestedClaims, names)
		}
	}
	return credentials, resolved, nil
}

// dcqlHolderCandidates renders the Holder's credentials as DCQL matching
// candidates, the same view a stored credential gets in dcqlCandidates, and
// records which credential was chosen for which credential query.
func (w *Wallet) dcqlHolderCandidates(
	selections []DCQLHolderSelection,
) (map[string]*SavedCredential, []oid4vp.DCQLCredentialCandidate, map[string]map[string]bool, error) {
	credentials := make(map[string]*SavedCredential, len(selections))
	candidates := make([]oid4vp.DCQLCredentialCandidate, 0, len(selections))
	chosen := map[string]map[string]bool{}
	for _, selection := range selections {
		entry := selection.Credential
		if entry.Id == "" {
			return nil, nil, nil, fmt.Errorf("every DCQL holder selection must identify its credential")
		}
		if len(selection.QueryIDs) == 0 {
			// The vp_token is keyed by credential query id (Section 8.1), so a
			// credential the Holder did not attach to a query cannot be placed
			// in the response at all.
			return nil, nil, nil, fmt.Errorf(
				"the DCQL holder selection for credential %q names no credential query", entry.Id)
		}
		saved, err := w.convertEntryToSavedCredential(entry)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("selected credential %q cannot be presented: %w", entry.Id, err)
		}
		candidate, err := dcqlCandidateFromSavedCredential(saved)
		if err != nil {
			return nil, nil, nil, err
		}
		credentials[entry.Id] = saved
		candidates = append(candidates, candidate)
		for _, queryID := range selection.QueryIDs {
			if chosen[queryID] == nil {
				chosen[queryID] = map[string]bool{}
			}
			chosen[queryID][entry.Id] = true
		}
	}
	return credentials, candidates, chosen, nil
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
	if flavor == credential.SDJwtVC {
		if reconstructed, reconstructErr := sdjwtvc.ReconstructClaimsObject(string(saved.Entry.Raw)); reconstructErr == nil {
			claimObject = reconstructed
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

// narrowToDisclosureNames keeps the Holder's claim minimisation without leaving
// the claim vocabulary the DCQL query resolved to.
//
// Replacing the resolved claim paths with the Holder's disclosure names outright
// would make a multi-segment path fail its own claim-set check, so the resolved
// list is filtered by disclosure name instead: a claim the Holder withheld is
// dropped, and everything the Holder kept stays exactly as the query named it.
func narrowToDisclosureNames(resolved []string, disclosed []string) []string {
	kept := make([]string, 0, len(resolved))
	for _, claim := range resolved {
		if slices.Contains(disclosed, dcqlClaimDisclosureName(claim)) {
			kept = append(kept, claim)
		}
	}
	return kept
}

// dcqlClaimDisclosureName is the disclosure name an encoded DCQL claim path ends
// in: a bare name is its own, a JSON array path yields its last string element,
// and anything else is returned unchanged so it simply matches nothing.
func dcqlClaimDisclosureName(encoded string) string {
	if !strings.HasPrefix(encoded, "[") {
		return encoded
	}
	var path []any
	if err := json.Unmarshal([]byte(encoded), &path); err != nil || len(path) == 0 {
		return encoded
	}
	if name, ok := path[len(path)-1].(string); ok {
		return name
	}
	return encoded
}
