package wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

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
		raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("invalid transaction_data encoding: %w", err)
		}
		var data struct {
			CredentialIDs []string `json:"credential_ids"`
		}
		if err := json.Unmarshal(raw, &data); err != nil {
			return fmt.Errorf("invalid transaction_data object: %w", err)
		}
		if len(data.CredentialIDs) == 0 {
			return fmt.Errorf("transaction_data.credential_ids must not be empty")
		}
		for _, id := range data.CredentialIDs {
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
