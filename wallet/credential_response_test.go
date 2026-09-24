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
	require.ErrorIs(t, err, ErrCredentialResponseShape)
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsBareStringCredential pins
// that a credentials-array element which is a bare string is rejected: §8.2
// requires "The elements of the array MUST be objects."
func TestDecodeOID4VCIFinalCredentialResponse_RejectsBareStringCredential(t *testing.T) {
	body := []byte(`{"credentials":["eyJ.abc.def"]}`)
	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{})
	require.ErrorContains(t, err, "unsupported credential shape")
	require.ErrorIs(t, err, ErrCredentialResponseShape)
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsTransactionIDWithCredentials
// pins the §8.2 mutual exclusion: "It MUST NOT be used if the transaction_id
// parameter is present" and vice versa.
func TestDecodeOID4VCIFinalCredentialResponse_RejectsTransactionIDWithCredentials(t *testing.T) {
	body := []byte(`{"transaction_id":"tx-1","credentials":[{"credential":"eyJ.abc.def"}]}`)
	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{})
	require.ErrorContains(t, err, "transaction_id and credential content")
	require.ErrorIs(t, err, ErrCredentialResponseShape)
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsMultipleCredentials pins the
// single-credential contract this build receives: one proof is sent per request,
// so a credentials array with two elements is a contract violation.
func TestDecodeOID4VCIFinalCredentialResponse_RejectsMultipleCredentials(t *testing.T) {
	body := []byte(`{"credentials":[{"credential":"eyJ.abc.def"},{"credential":"eyJ.ghi.jkl"}]}`)
	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{})
	require.ErrorContains(t, err, "asked for 1")
	require.ErrorIs(t, err, ErrCredentialResponseMultipleCredentials)
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsMissingCredentialsAndTransactionID
// pins that §8.2's two shapes are exhaustive for this path: a Credential
// Response carrying neither the credentials array nor a transaction_id holds
// nothing the wallet can act on and is rejected.
func TestDecodeOID4VCIFinalCredentialResponse_RejectsMissingCredentialsAndTransactionID(t *testing.T) {
	body := []byte(`{}`)
	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{})
	require.ErrorContains(t, err, "neither credentials nor a transaction_id")
	require.ErrorIs(t, err, ErrCredentialResponseShape)
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsEmptyCredentialsArray pins
// that §8.2 "credentials ... Contains an array of one or more issued
// Credentials": an empty array is the missing-content case, not a valid shape.
func TestDecodeOID4VCIFinalCredentialResponse_RejectsEmptyCredentialsArray(t *testing.T) {
	body := []byte(`{"credentials":[]}`)
	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{})
	require.ErrorContains(t, err, "neither credentials nor a transaction_id")
	require.ErrorIs(t, err, ErrCredentialResponseShape)
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsMalformedJSON pins that a
// body which is not a Credential Response object at all is a shape failure.
func TestDecodeOID4VCIFinalCredentialResponse_RejectsMalformedJSON(t *testing.T) {
	_, err := DecodeOID4VCIFinalCredentialResponse([]byte(`not json`), "application/json", CredentialResponseDecodeOptions{})
	require.ErrorIs(t, err, ErrCredentialResponseShape)
}

// TestDecodeOID4VCIFinalCredentialResponse_RequireEncryptionRejectsPlaintext
// pins the strictness: a holder who requires an encrypted response is
// never served a plaintext one.
func TestDecodeOID4VCIFinalCredentialResponse_RequireEncryptionRejectsPlaintext(t *testing.T) {
	body := []byte(`{"credentials":[{"credential":"eyJ.abc.def"}]}`)
	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/json", CredentialResponseDecodeOptions{RequireEncryption: true})
	require.ErrorContains(t, err, "unencrypted credential response")
	require.ErrorIs(t, err, ErrCredentialResponsePlaintext)
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
	require.ErrorIs(t, err, ErrCredentialResponsePlaintext)
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsEncryptedResponseWithoutKey
// pins that an application/jwt response is undecryptable when the caller holds
// no key, classified as ErrCredentialResponseDecrypt rather than as a plaintext
// downgrade.
func TestDecodeOID4VCIFinalCredentialResponse_RejectsEncryptedResponseWithoutKey(t *testing.T) {
	_, err := DecodeOID4VCIFinalCredentialResponse([]byte("eyJhbGciOiJFU0..."), "application/jwt", CredentialResponseDecodeOptions{})
	require.ErrorContains(t, err, "decryption key is required")
	require.ErrorIs(t, err, ErrCredentialResponseDecrypt)
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsMalformedJWE pins that an
// application/jwt body which is not a parseable JWE is ErrCredentialResponseDecrypt.
func TestDecodeOID4VCIFinalCredentialResponse_RejectsMalformedJWE(t *testing.T) {
	key := newPrivateJWKForFinalVCITest(t, "response-enc-key-1")
	_, err := DecodeOID4VCIFinalCredentialResponse([]byte("not-a-jwe"), "application/jwt", CredentialResponseDecodeOptions{DecryptionKey: &key})
	require.ErrorContains(t, err, "failed to parse credential response JWE")
	require.ErrorIs(t, err, ErrCredentialResponseDecrypt)
}

// TestDecodeOID4VCIFinalCredentialResponse_RejectsUndecryptableJWE pins that an
// application/jwt JWE addressed to another key cannot be decrypted and is
// classified as ErrCredentialResponseDecrypt.
func TestDecodeOID4VCIFinalCredentialResponse_RejectsUndecryptableJWE(t *testing.T) {
	addressee := newPrivateJWKForFinalVCITest(t, "response-enc-key-1")
	addressee.Algorithm = "ECDH-ES"
	addressee.Use = "enc"
	body := encryptOID4VCIFinalCredentialResponseForTest(t, addressee, map[string]any{
		"credentials": []any{map[string]any{"credential": "eyJ.abc.def"}},
	})
	otherKey := newPrivateJWKForFinalVCITest(t, "response-enc-key-2")

	_, err := DecodeOID4VCIFinalCredentialResponse(body, "application/jwt", CredentialResponseDecodeOptions{DecryptionKey: &otherKey})
	require.ErrorContains(t, err, "failed to decrypt credential response JWE")
	require.ErrorIs(t, err, ErrCredentialResponseDecrypt)
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

// §8.2: notification_id "MUST not be used if the credentials parameter is not
// present", and interval belongs to the deferred shape only.
func TestValidateOID4VCIFinalCredentialResponse_RejectsMembersOfTheOtherShape(t *testing.T) {
	err := ValidateOID4VCIFinalCredentialResponse(&receiverTypes.CredentialResponse{TransactionID: "tx-1", Interval: 5, NotificationID: "n-1"})
	require.ErrorIs(t, err, ErrCredentialResponseShape)
	require.ErrorContains(t, err, "notification_id")

	err = ValidateOID4VCIFinalCredentialResponse(&receiverTypes.CredentialResponse{
		Credentials: []any{map[string]any{"credential": "eyJ.abc.def"}},
		Interval:    5,
	})
	require.ErrorIs(t, err, ErrCredentialResponseShape)
	require.ErrorContains(t, err, "interval")
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
