package wallet

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// CredentialResponseDecodeOptions tunes DecodeOID4VCIFinalCredentialResponse.
type CredentialResponseDecodeOptions struct {
	// RequireEncryption makes a plaintext Credential Response an error. It
	// carries the ADR-0062 strictness setting: a holder who requires an
	// encrypted response (OpenID4VCI 1.0 §8.2) is never served a plaintext one,
	// not even when the exchange never managed to ask for encryption.
	RequireEncryption bool
	// DecryptionKey is the private key the wallet advertised in the Credential
	// Request's credential_response_encryption.jwk. It is required to decrypt a
	// response whose media type is application/jwt, and its presence alone makes
	// a plaintext response an error: a requested encryption MUST NOT be silently
	// downgraded. §8.2: "Credential Request encryption MUST be used if the
	// credential_response_encryption parameter is included, to prevent it being
	// substituted by an attacker."
	DecryptionKey *jose.JSONWebKey
	// AllowedKeyAlgorithms restricts the JWE "alg" values accepted while
	// decrypting an application/jwt response. Empty uses the algorithms this
	// package supports (§10 and the §12.2.4 credential_response_encryption
	// metadata): ECDH-ES and its AES key-wrap variants, plus RSA-OAEP-256.
	AllowedKeyAlgorithms []jose.KeyAlgorithm
	// AllowedContentEncryptions restricts the JWE "enc" values accepted while
	// decrypting an application/jwt response. Empty uses the content encryption
	// algorithms this package supports.
	AllowedContentEncryptions []jose.ContentEncryption

	// allowLegacyCredentialShape restores the pre-Final shape the high-level
	// wallet path historically accepted: the draft singular credential member,
	// a credentials array of bare strings, and more than one credential, which
	// §14.6 batch issuance needs. It is unexported so an integrator always gets
	// the strict Final shape; only the package's own issuance path sets it.
	allowLegacyCredentialShape bool
}

// ValidateOID4VCIFinalCredentialResponse enforces the OpenID4VCI 1.0 Final
// Credential Response shape that a single-credential wallet accepts. It moves
// the ADR-0032 pre-merge hardening into the library wire so every consumer,
// not only the sidecar, fails closed on a nonconformant issuer.
//
// It rejects:
//
//   - the draft-era top-level singular credential member. §8.2 defines only the
//     credentials array (the member was removed in Final), so accepting it would
//     mask an issuer still emitting the draft shape.
//   - a credentials array whose element is a bare string. §8.2: "The elements of
//     the array MUST be objects."
//   - a response carrying both transaction_id and credentials. §8.2: "It MUST
//     NOT be used if the transaction_id parameter is present" and transaction_id
//     "MUST not be used if the credentials parameter is present".
//   - more than one credential. This build receives exactly one credential per
//     request (batch issuance is not enabled on this path).
//
// A response carrying only a transaction_id (and no credentials) is the §9
// deferred shape and is accepted.
func ValidateOID4VCIFinalCredentialResponse(r *receiverTypes.CredentialResponse) error {
	return validateOID4VCIFinalCredentialResponse(r, false)
}

// validateOID4VCIFinalCredentialResponse is the shared body of the validator.
// allowLegacyShape restores the pre-Final shape the high-level wallet path
// historically accepted (the singular credential member, a credentials array of
// bare strings, and more than one credential, which §14.6 batch issuance needs);
// the transaction_id/credentials exclusivity rule is enforced either way.
func validateOID4VCIFinalCredentialResponse(r *receiverTypes.CredentialResponse, allowLegacyShape bool) error {
	if r == nil {
		return fmt.Errorf("credential response is nil")
	}
	if r.TransactionID != "" && (r.Credential != nil || len(r.Credentials) > 0) {
		return fmt.Errorf("credential response contained both transaction_id and credential content")
	}
	if allowLegacyShape {
		return nil
	}
	if r.Credential != nil {
		return fmt.Errorf("credential response used the removed singular credential member; OpenID4VCI 1.0 §8.2 requires the credentials array")
	}
	if len(r.Credentials) > 1 {
		return fmt.Errorf("credential response contained %d credentials, but this build receives exactly one", len(r.Credentials))
	}
	for index, value := range r.Credentials {
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("credential response contained an unsupported credential shape at credentials[%d] (%T); §8.2 requires objects", index, value)
		}
		if _, ok := object["credential"]; !ok {
			return fmt.Errorf("credential response object at credentials[%d] does not contain a credential member", index)
		}
	}
	return nil
}

// DecodeOID4VCIFinalCredentialResponse decodes an OpenID4VCI 1.0 Final
// Credential Response body. When contentType names application/jwt the body is
// a §8.2 / §10 JWE and is decrypted with opts.DecryptionKey; otherwise it is
// plaintext JSON. It fails closed on a plaintext response when encryption was
// required or requested, so a response cannot be substituted above a TLS
// termination point.
//
// The returned response is shape-validated unless the options relax it for the
// package's own §14.6 batch path; an integrator receives the strict Final
// shape. Callers that need to validate an already-decoded response can call
// ValidateOID4VCIFinalCredentialResponse directly.
func DecodeOID4VCIFinalCredentialResponse(body []byte, contentType string, opts CredentialResponseDecodeOptions) (*receiverTypes.CredentialResponse, error) {
	payload := body
	encrypted := strings.Contains(strings.ToLower(contentType), "application/jwt")
	if !encrypted && (opts.RequireEncryption || opts.DecryptionKey != nil) {
		return nil, fmt.Errorf("issuer returned an unencrypted credential response although response encryption was required")
	}
	if encrypted {
		if opts.DecryptionKey == nil {
			return nil, fmt.Errorf("decryption key is required for encrypted credential response")
		}
		keyAlgorithms := opts.AllowedKeyAlgorithms
		if len(keyAlgorithms) == 0 {
			keyAlgorithms = oid4vciFinalJWEKeyAlgorithms()
		}
		contentEncryptions := opts.AllowedContentEncryptions
		if len(contentEncryptions) == 0 {
			contentEncryptions = oid4vciFinalJWEContentEncryptions()
		}
		jwe, err := jose.ParseEncrypted(string(body), keyAlgorithms, contentEncryptions)
		if err != nil {
			return nil, fmt.Errorf("failed to parse credential response JWE: %w", err)
		}
		payload, err = jwe.Decrypt(opts.DecryptionKey.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt credential response JWE: %w", err)
		}
	}
	var response receiverTypes.CredentialResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, fmt.Errorf("failed to parse credential response JSON: %w", err)
	}
	if err := validateOID4VCIFinalCredentialResponse(&response, opts.allowLegacyCredentialShape); err != nil {
		return nil, err
	}
	return &response, nil
}

// oid4vciFinalJWEKeyAlgorithms lists the JWE key management algorithms accepted
// while decrypting an encrypted Credential Response (§8.2 / §10). The wallet
// may advertise either an EC or an RSA response-encryption key, so both the
// §4.6 ECDH-ES family and §4.3 RSA-OAEP-256 are accepted. RSA1_5 is
// deliberately absent because RFC 8017 §7.2 RSAES-PKCS1-v1_5 is the
// Bleichenbacher-attackable scheme this library must never be talked into
// using.
func oid4vciFinalJWEKeyAlgorithms() []jose.KeyAlgorithm {
	return []jose.KeyAlgorithm{jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW, jose.RSA_OAEP_256}
}

// oid4vciFinalJWEContentEncryptions lists the JWE content encryption algorithms
// accepted while decrypting an encrypted Credential Response (§8.2 / §10).
func oid4vciFinalJWEContentEncryptions() []jose.ContentEncryption {
	return []jose.ContentEncryption{jose.A128GCM, jose.A192GCM, jose.A256GCM, jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512}
}
