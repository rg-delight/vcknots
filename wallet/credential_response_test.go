package wallet

import (
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// TestDecodeOID4VCIFinalCredentialResponse_AcceptsCredentialsArray is the
// positive shape case: the OpenID4VCI 1.0 §8.2 credentials array with one
// object element carrying a string credential is accepted and satisfies the
// exported validator.
func TestDecodeOID4VCIFinalCredentialResponse_AcceptsCredentialsArray(t *testing.T) {
	body := []byte(`{"credentials":[{"credential":"eyJ.abc.def"}]}`)
	response, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{})
	require.NoError(t, err)
	require.NoError(t, ValidateOID4VCIFinalCredentialResponse(response))
	require.Len(t, response.Credentials, 1)
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsRemovedSingularCredential
// pins that the draft-era top-level credential member is rejected: §8.2 removed
// it in favor of credentials, so accepting it would mask a nonconformant issuer.
func TestDecodeOID4VCIFinalCredentialResponse_RejectsRemovedSingularCredential(t *testing.T) {
	body := []byte(`{"credential":"eyJ.abc.def"}`)
	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{})
	require.ErrorContains(t, err, "singular credential member")
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsBareStringCredential pins
// that a credentials-array element which is a bare string is rejected: §8.2
// requires "The elements of the array MUST be objects."
func TestDecodeOID4VCIFinalCredentialResponse_RejectsBareStringCredential(t *testing.T) {
	body := []byte(`{"credentials":["eyJ.abc.def"]}`)
	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{})
	require.ErrorContains(t, err, "unsupported credential shape")
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsTransactionIDWithCredentials
// pins the §8.2 mutual exclusion: "It MUST NOT be used if the transaction_id
// parameter is present" and vice versa.
func TestDecodeOID4VCIFinalCredentialResponse_RejectsTransactionIDWithCredentials(t *testing.T) {
	body := []byte(`{"transaction_id":"tx-1","credentials":[{"credential":"eyJ.abc.def"}]}`)
	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{})
	require.ErrorContains(t, err, "transaction_id and credential content")
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsMultipleCredentials pins the
// single-credential contract this build receives: one proof is sent per request,
// so a credentials array with two elements is a contract violation.
func TestDecodeOID4VCIFinalCredentialResponse_RejectsMultipleCredentials(t *testing.T) {
	body := []byte(`{"credentials":[{"credential":"eyJ.abc.def"},{"credential":"eyJ.ghi.jkl"}]}`)
	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{})
	require.ErrorContains(t, err, "exactly one")
}

// TestDecodeOID4VCIFinalCredentialResponse_RequireEncryptionRejectsPlaintext
// pins the ADR-0062 strictness: a holder who requires an encrypted response is
// never served a plaintext one.
func TestDecodeOID4VCIFinalCredentialResponse_RequireEncryptionRejectsPlaintext(t *testing.T) {
	body := []byte(`{"credentials":[{"credential":"eyJ.abc.def"}]}`)
	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{RequireEncryption: true})
	require.ErrorContains(t, err, "unencrypted credential response")
}

// TestDecodeOID4VCIFinalCredentialResponse_DecryptionKeyRejectsPlaintext pins
// that a requested encryption is not silently downgraded: §8.2 "Credential
// Request encryption MUST be used if the credential_response_encryption
// parameter is included, to prevent it being substituted by an attacker."
func TestDecodeOID4VCIFinalCredentialResponse_DecryptionKeyRejectsPlaintext(t *testing.T) {
	key := newPrivateJWKForFinalVCITest(t, "response-enc-key-1")
	body := []byte(`{"credentials":[{"credential":"eyJ.abc.def"}]}`)
	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{DecryptionKey: &key})
	require.ErrorContains(t, err, "unencrypted credential response")
}

// TestDecodeOID4VCIFinalCredentialResponse_DecryptsEncryptedResponse is the
// positive encrypted case: an application/jwt §8.2 JWE is decrypted with the
// advertised key and the plaintext Final shape validates.
func TestDecodeOID4VCIFinalCredentialResponse_DecryptsEncryptedResponse(t *testing.T) {
	key := newPrivateJWKForFinalVCITest(t, "response-enc-key-1")
	key.Algorithm = "ECDH-ES"
	key.Use = "enc"
	body := encryptOID4VCIFinalCredentialResponseForTest(t, key, map[string]any{
		"credentials": []any{map[string]any{"credential": "eyJ.abc.def"}},
	})

	response, err := DecodeOID4VCIFinalCredentialResponse(body, "application/jwt", CredentialResponseDecodeOptions{
		RequireEncryption: true,
		DecryptionKey:     &key,
	})
	require.NoError(t, err)
	require.NoError(t, ValidateOID4VCIFinalCredentialResponse(response))
}

// TestValidateOID4VCIFinalCredentialResponse_AcceptsDeferredResponse pins that
// the §9 deferred shape (a transaction_id and no credentials) is accepted.
func TestValidateOID4VCIFinalCredentialResponse_AcceptsDeferredResponse(t *testing.T) {
	require.NoError(t, ValidateOID4VCIFinalCredentialResponse(&receiverTypes.CredentialResponse{TransactionID: "tx-1"}))
}

// TestValidateOID4VCIFinalCredentialResponse_RejectsNil pins the guard on the
// exported validator.
func TestValidateOID4VCIFinalCredentialResponse_RejectsNil(t *testing.T) {
	require.Error(t, ValidateOID4VCIFinalCredentialResponse(nil))
}

// encryptOID4VCIFinalCredentialResponseForTest wraps payload in an
// application/jwt §8.2 JWE addressed to key with ECDH-ES/A128GCM.
func encryptOID4VCIFinalCredentialResponseForTest(t *testing.T, key jose.JSONWebKey, payload any) []byte {
	t.Helper()
	plaintext, err := json.Marshal(payload)
	require.NoError(t, err)
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: key.Public().Key}, nil)
	require.NoError(t, err)
	jwe, err := encrypter.Encrypt(plaintext)
	require.NoError(t, err)
	serialized, err := jwe.CompactSerialize()
	require.NoError(t, err)
	return []byte(serialized)
}
