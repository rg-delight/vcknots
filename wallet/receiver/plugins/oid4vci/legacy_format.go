package oid4vci

import (
	"fmt"
	"strings"

	"github.com/trustknots/vcknots/wallet/credential"
)

// OID4VCICredentialFormatToSerializationFlavor maps a credential format
// identifier to the serialization flavor that decodes it.
//
// Deprecated: the staged wallet API resolves formats itself. This helper is
// kept only until the wallet package stops calling it.
func OID4VCICredentialFormatToSerializationFlavor(format string) (credential.SupportedSerializationFlavor, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "jwt_vc_json", "jwt_vc", string(credential.JwtVc):
		return credential.JwtVc, nil
	case "dc+sd-jwt", string(credential.SDJwtVC):
		return credential.SDJwtVC, nil
	default:
		return "", fmt.Errorf("unsupported credential format: %q", format)
	}
}
