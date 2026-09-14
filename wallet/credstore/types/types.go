package types

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/trustknots/vcknots/wallet/credential"

	"github.com/trustknots/vcknots/wallet/common"
)

// Sentinel errors for credential store operations
var (
	ErrCredentialNotFound     = common.NewCodedError("credstore_credential_not_found", "credential not found")
	ErrInvalidCredentialID    = common.NewCodedError("credstore_invalid_credential_id", "invalid credential ID")
	ErrCredentialExists       = common.NewCodedError("credstore_credential_exists", "credential already exists")
	ErrInvalidCredentialEntry = common.NewCodedError("credstore_invalid_credential_entry", "invalid credential entry")
	ErrStorageFailed          = common.NewCodedError("credstore_storage_failed", "storage operation failed")
	ErrRetrievalFailed        = common.NewCodedError("credstore_retrieval_failed", "credential retrieval failed")
	ErrSerializationFailed    = common.NewCodedError("credstore_serialization_failed", "credential serialization failed")
	ErrDeserializationFailed  = common.NewCodedError("credstore_deserialization_failed", "credential deserialization failed")
	ErrInvalidLocation        = common.NewCodedError("credstore_invalid_location", "invalid storage location")
	ErrInvalidMimeType        = common.NewCodedError("credstore_invalid_mime_type", "invalid or unsupported MIME type")
	ErrStorageCorrupted       = common.NewCodedError("credstore_storage_corrupted", "storage data corrupted")
	ErrPluginNotFound         = common.NewCodedError("credstore_plugin_not_found", "credential store plugin not found")
	ErrNilPlugin              = common.NewCodedError("credstore_nil_plugin", "credential store plugin cannot be nil")
)

// CredStoreError represents an error during credential store operations
type CredStoreError struct {
	Location SupportedCredStoreTypes `json:"location"`
	ID       string                  `json:"id,omitempty"`
	Op       string                  `json:"operation"`
	Err      error                   `json:"error"`
}

func (e *CredStoreError) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("credential store %v operation %s for ID %s: %v", e.Location, e.Op, e.ID, e.Err)
	}
	return fmt.Sprintf("credential store %v operation %s: %v", e.Location, e.Op, e.Err)
}

func (e *CredStoreError) Unwrap() error {
	return e.Err
}

// NewCredStoreError creates a new CredStoreError
func NewCredStoreError(location SupportedCredStoreTypes, id, op string, err error) *CredStoreError {
	return &CredStoreError{
		Location: location,
		ID:       id,
		Op:       op,
		Err:      err,
	}
}

type CredentialEntry struct {
	// TODO: Define the actual fields for credential entry
	Id         string
	ReceivedAt time.Time
	Raw        []byte
	MimeType   string
}

func (ce *CredentialEntry) Serialize() ([]byte, error) {
	return json.Marshal(ce)
}

func (ce *CredentialEntry) SerializationFlavor() (credential.SupportedSerializationFlavor, error) {
	switch ce.MimeType {
	case string(credential.JwtVc):
		return credential.JwtVc, nil
	case string(credential.SDJwtVC):
		return credential.SDJwtVC, nil
	case string(credential.MockFormat):
		return credential.MockFormat, nil
	default:
		return "", fmt.Errorf("unknown serialization flavor")
	}
}

type SupportedCredStoreTypes int

type CredStore interface {
	SaveCredentialEntry(credentialEntry CredentialEntry, location SupportedCredStoreTypes) error

	GetCredentialEntries(offset int, limit *int, location SupportedCredStoreTypes) (*GetCredentialEntriesResult, error)

	GetCredentialEntry(id string, location SupportedCredStoreTypes) (*CredentialEntry, error)
}

type GetCredentialEntriesResult struct {
	Entries    *[]CredentialEntry
	TotalCount *int
}

func ParseCredentialEntry(data []byte) (CredentialEntry, error) {
	var entry CredentialEntry
	err := json.Unmarshal(data, &entry)
	return entry, err
}
