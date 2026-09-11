package wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
)

// This guard enforces OID4VP B.3.3 for the queries referenced by transaction
// data. Validation of supported transaction types is a separate policy.
func validateTransactionDataHolderBinding(req *oid4vp.CredentialPresentationRequest) error {
	if len(req.TransactionData) == 0 {
		return nil
	}
	if req.DcqlQuery == nil {
		return fmt.Errorf("transaction_data requires dcql_query")
	}
	queries := make(map[string]oid4vp.CredentialQuery, len(req.DcqlQuery.Credentials))
	for _, query := range req.DcqlQuery.Credentials {
		queries[query.ID] = query
	}
	for _, encoded := range req.TransactionData {
		credentialIDs, err := transactionDataCredentialIDs(encoded)
		if err != nil {
			return err
		}
		for _, id := range credentialIDs {
			query, known := queries[id]
			if !known {
				return fmt.Errorf("transaction_data references unknown credential query %q", id)
			}
			if query.Format == "dc+sd-jwt" && !query.RequiresHolderBinding() {
				return fmt.Errorf("transaction_data requires cryptographic holder binding for credential query %q", id)
			}
		}
	}
	return nil
}

// transactionDataCredentialIDs decodes the credential_ids array of one
// base64url-encoded transaction_data entry. OID4VP 1.0 Final Section 5.1
// defines it as "REQUIRED. Non-empty array of strings each referencing a
// Credential requested by the Verifier that can be used to authorize this
// transaction. The string matches the id field in the DCQL Credential Query."
func transactionDataCredentialIDs(encoded string) ([]string, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction_data encoding: %w", err)
	}
	var data struct {
		CredentialIDs []string `json:"credential_ids"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("invalid transaction_data object: %w", err)
	}
	if len(data.CredentialIDs) == 0 {
		return nil, fmt.Errorf("transaction_data.credential_ids must not be empty")
	}
	return data.CredentialIDs, nil
}

// transactionDataForQuery returns the encoded transaction_data entries whose
// credential_ids contain queryID, preserving request order. It applies the
// OID4VP 1.0 Final Section 5.1 reference filter only: an entry naming several
// credential queries is returned for each of them, so callers that present
// more than one credential must additionally honour the single-use rule with
// assignTransactionDataOwners.
func transactionDataForQuery(encoded []string, queryID string) ([]string, error) {
	var matched []string
	for index, entry := range encoded {
		credentialIDs, err := transactionDataCredentialIDs(entry)
		if err != nil {
			return nil, fmt.Errorf("transaction_data entry %d: %w", index, err)
		}
		if slices.Contains(credentialIDs, queryID) {
			matched = append(matched, entry)
		}
	}
	return matched, nil
}

// assignTransactionDataOwners maps every transaction_data entry to the single
// selected credential query that authorizes it, keyed by the encoded entry.
//
// OID4VP 1.0 Final Section 5.1 says of credential_ids: "If there is more than
// one element in the array, the Wallet MUST use only one of the referenced
// Credentials for transaction authorization." The wallet picks the first
// referenced query that the DCQL selection actually presents, so the entry is
// hashed into exactly one Key Binding JWT even when several of the referenced
// credentials are being presented.
//
// Section 8.4 requires the Wallet to "include a representation or reference to
// the data in the respective Credential presentation"; an entry whose
// credential_ids reference nothing the wallet is presenting cannot satisfy
// that, and the Error Response section lists exactly this case
// ("the credential_ids does not match, or the referenced Credential(s) are not
// available in the Wallet") under invalid_transaction_data. Such a request
// fails here, before any credential is serialized or disclosed.
func assignTransactionDataOwners(encoded []string, selections []oid4vp.DCQLCredentialSelection) (map[string]string, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	selected := make(map[string]bool, len(selections))
	for _, selection := range selections {
		selected[selection.QueryID] = true
	}
	owners := make(map[string]string, len(encoded))
	for index, entry := range encoded {
		if _, resolved := owners[entry]; resolved {
			continue
		}
		credentialIDs, err := transactionDataCredentialIDs(entry)
		if err != nil {
			return nil, fmt.Errorf("transaction_data entry %d: %w", index, err)
		}
		owner := ""
		for _, id := range credentialIDs {
			if selected[id] {
				owner = id
				break
			}
		}
		if owner == "" {
			return nil, fmt.Errorf("transaction_data entry %d references no selected credential (invalid_transaction_data)", index)
		}
		owners[entry] = owner
	}
	return owners, nil
}
