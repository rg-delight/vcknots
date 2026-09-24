package wallet

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/internal/oid4vcijwe"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// CredentialResponseDecodeOptions tunes DecodeOID4VCIFinalCredentialResponse.
type CredentialResponseDecodeOptions struct {
	// RequireEncryption makes a plaintext Credential Response an error, even
	// when the exchange never asked for encryption.
	RequireEncryption bool
	// DecryptionKey is the private key whose public half the Credential Request
	// sent in credential_response_encryption.jwk. It decrypts an
	// application/jwt response, and its presence makes a plaintext response an
	// error: a requested encryption is never downgraded (§8.2).
	DecryptionKey *jose.JSONWebKey
	// AllowedKeyAlgorithms restricts the JWE "alg" values accepted while
	// decrypting. Empty accepts the ECDH-ES family and RSA-OAEP-256.
	AllowedKeyAlgorithms []jose.KeyAlgorithm
	// AllowedContentEncryptions restricts the JWE "enc" values accepted while
	// decrypting. Empty accepts the AES-GCM and AES-CBC-HMAC families.
	AllowedContentEncryptions []jose.ContentEncryption

	shape credentialResponseShape
}

// credentialResponseShape is what the issuance path expects of a Credential
// Response beyond the §8.2 rules that always apply.
type credentialResponseShape struct {
	// maxCredentials is the number of credentials the request asked for: one
	// per key proof (§8.2). Zero means one.
	maxCredentials int
	// allowDraft accepts the pre-Final shape: the singular credential member
	// and credentials elements that are bare strings.
	allowDraft bool
}

// ValidateOID4VCIFinalCredentialResponse checks the OpenID4VCI 1.0 §8.2 Credential
// Response shape for a request that carried one key proof. It rejects the
// removed singular credential member, credentials elements that are not objects
// with a credential member, transaction_id together with credentials, a
// notification_id without credentials, an interval with credentials, and a
// response carrying neither credentials nor a transaction_id; each wraps
// ErrCredentialResponseShape. More than one credential wraps
// ErrCredentialResponseMultipleCredentials. The issuance paths apply the same
// rules.
func ValidateOID4VCIFinalCredentialResponse(r *receiverTypes.CredentialResponse) error {
	return validateOID4VCIFinalCredentialResponse(r, credentialResponseShape{})
}

func validateOID4VCIFinalCredentialResponse(r *receiverTypes.CredentialResponse, shape credentialResponseShape) error {
	if r == nil {
		return fmt.Errorf("%w: credential response is nil", ErrCredentialResponseShape)
	}
	if r.Credential != nil && !shape.allowDraft {
		return fmt.Errorf("%w: credential response used the removed singular credential member; OpenID4VCI 1.0 §8.2 requires the credentials array", ErrCredentialResponseShape)
	}
	count := len(r.Credentials)
	if r.Credential != nil {
		count++
	}
	if r.TransactionID != "" && count > 0 {
		return fmt.Errorf("%w: credential response contained both transaction_id and credential content", ErrCredentialResponseShape)
	}
	if r.TransactionID == "" && count == 0 {
		return fmt.Errorf("%w: credential response contained neither credentials nor a transaction_id; OpenID4VCI 1.0 §8.2 issues one or the other", ErrCredentialResponseShape)
	}
	if r.NotificationID != "" && count == 0 {
		return fmt.Errorf("%w: credential response carried a notification_id without credentials", ErrCredentialResponseShape)
	}
	if r.Interval != 0 && count > 0 {
		return fmt.Errorf("%w: credential response carried an interval together with credentials", ErrCredentialResponseShape)
	}
	maxCredentials := max(shape.maxCredentials, 1)
	if count > maxCredentials {
		return fmt.Errorf("%w: credential response contained %d credentials, but the request asked for %d", ErrCredentialResponseMultipleCredentials, count, maxCredentials)
	}
	for index, value := range r.Credentials {
		object, ok := value.(map[string]any)
		if !ok {
			if _, isString := value.(string); isString && shape.allowDraft {
				continue
			}
			return fmt.Errorf("%w: credential response contained an unsupported credential shape at credentials[%d] (%T); §8.2 requires objects", ErrCredentialResponseShape, index, value)
		}
		if _, ok := object["credential"]; !ok {
			return fmt.Errorf("%w: credential response object at credentials[%d] does not contain a credential member", ErrCredentialResponseShape, index)
		}
	}
	return nil
}

// DecodeOID4VCIFinalCredentialResponse decodes an OpenID4VCI 1.0 Credential
// Response body and validates it as ValidateOID4VCIFinalCredentialResponse
// does. An application/jwt body is a §10 JWE decrypted with opts.DecryptionKey;
// anything else is read as plaintext JSON, which is refused when encryption was
// required or requested.
//
// Rejections wrap ErrCredentialResponsePlaintext, ErrCredentialResponseDecrypt,
// ErrCredentialResponseShape or ErrCredentialResponseMultipleCredentials.
func DecodeOID4VCIFinalCredentialResponse(body []byte, contentType string, opts CredentialResponseDecodeOptions) (*receiverTypes.CredentialResponse, error) {
	payload := body
	encrypted := httpfetch.MediaTypeIs(http.Header{"Content-Type": {contentType}}, "application/jwt")
	if !encrypted && (opts.RequireEncryption || opts.DecryptionKey != nil) {
		return nil, fmt.Errorf("%w: issuer returned an unencrypted credential response although response encryption was required", ErrCredentialResponsePlaintext)
	}
	if encrypted {
		if opts.DecryptionKey == nil {
			return nil, fmt.Errorf("%w: decryption key is required for encrypted credential response", ErrCredentialResponseDecrypt)
		}
		keyAlgorithms := opts.AllowedKeyAlgorithms
		if len(keyAlgorithms) == 0 {
			keyAlgorithms = oid4vcijwe.KeyAlgorithms()
		}
		contentEncryptions := opts.AllowedContentEncryptions
		if len(contentEncryptions) == 0 {
			contentEncryptions = oid4vcijwe.ContentEncryptions()
		}
		jwe, err := jose.ParseEncrypted(string(body), keyAlgorithms, contentEncryptions)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse credential response JWE: %w", ErrCredentialResponseDecrypt, err)
		}
		payload, err = jwe.Decrypt(opts.DecryptionKey.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decrypt credential response JWE: %w", ErrCredentialResponseDecrypt, err)
		}
	}
	var response receiverTypes.CredentialResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, fmt.Errorf("%w: failed to parse credential response JSON: %w", ErrCredentialResponseShape, err)
	}
	if err := validateOID4VCIFinalCredentialResponse(&response, opts.shape); err != nil {
		return nil, err
	}
	return &response, nil
}
