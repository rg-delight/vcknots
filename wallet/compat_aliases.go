package wallet

// Temporary aliases for the credential acceptance API, which lives in
// wallet/acceptance. They keep the issuance code of this package compiling
// until it uses the sub-package directly, and are removed then. New code uses
// the sub-package.

import (
	"strings"

	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/credential"
)

type (
	CredentialAcceptancePolicy = acceptance.Policy
	CredentialVerification     = acceptance.Verification
	IssuerX509TrustOptions     = acceptance.IssuerX509TrustOptions
)

var (
	ErrCredentialParse                      = acceptance.ErrCredentialParse
	ErrCredentialTypInvalid                 = acceptance.ErrCredentialTypInvalid
	ErrCredentialAlgUnsupported             = acceptance.ErrCredentialAlgUnsupported
	ErrHolderBindingMissing                 = acceptance.ErrHolderBindingMissing
	ErrHolderBindingMismatch                = acceptance.ErrHolderBindingMismatch
	ErrHolderBindingConfirmationUnsupported = acceptance.ErrHolderBindingConfirmationUnsupported
	ErrIssuerKeyUnresolved                  = acceptance.ErrIssuerKeyUnresolved
	ErrIssuerSignatureInvalid               = acceptance.ErrIssuerSignatureInvalid
	ErrIssuerDNSBindingFailed               = acceptance.ErrIssuerDNSBindingFailed
	ErrCredentialExpired                    = acceptance.ErrCredentialExpired
	ErrCredentialNotYetValid                = acceptance.ErrCredentialNotYetValid
	ErrDisclosureIntegrity                  = acceptance.ErrDisclosureIntegrity
	ErrSDAlgUnsupported                     = acceptance.ErrSDAlgUnsupported
	ErrHAIPX5CRequired                      = acceptance.ErrHAIPX5CRequired
	ErrHAIPTrustAnchorInX5C                 = acceptance.ErrHAIPTrustAnchorInX5C
)

// issuerSignedJWT is the issuer-signed JWT of raw: for an SD-JWT VC, the part
// before the first "~".
func issuerSignedJWT(flavor credential.SupportedSerializationFlavor, raw []byte) string {
	if flavor == credential.SDJwtVC {
		if index := strings.IndexByte(string(raw), '~'); index >= 0 {
			return string(raw[:index])
		}
	}
	return string(raw)
}
