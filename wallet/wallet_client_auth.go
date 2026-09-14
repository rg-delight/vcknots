package wallet

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	joseutil "github.com/trustknots/vcknots/wallet/common/jose"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// generateClientAssertion builds a signed JWT used as the client_assertion
// parameter for private_key_jwt client authentication (RFC 7523).
//
// The resulting JWT contains the following claims: iss, sub (both equal to the
// client_id), aud (the resolved authorization server audience), iat, nbf, exp,
// and jti. The header carries the signing key's kid and the given alg.
func (w *Wallet) generateClientAssertion(key IKeyEntry, clientID, audience string, alg jose.SignatureAlgorithm) (string, error) {
	if key == nil {
		return "", fmt.Errorf("client auth key is required")
	}
	if strings.TrimSpace(clientID) == "" {
		return "", fmt.Errorf("clientID is required for client assertion")
	}
	if strings.TrimSpace(audience) == "" {
		return "", fmt.Errorf("audience is required for client assertion aud")
	}
	if _, err := curveForSignatureAlgorithm(alg); err != nil {
		return "", err
	}

	signerAdapter, err := joseutil.NewJWKSigner(key, alg)
	if err != nil {
		return "", fmt.Errorf("failed to create client assertion signer adapter: %w", err)
	}

	signerOpts := (&jose.SignerOptions{}).WithType("JWT")
	if kid := key.PublicKey().KeyID; strings.TrimSpace(kid) != "" {
		signerOpts = signerOpts.WithHeader("kid", kid)
	}

	signingKey := jose.SigningKey{
		Algorithm: alg,
		Key:       signerAdapter,
	}

	signer, err := jose.NewSigner(signingKey, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create client assertion signer: %w", err)
	}

	now := time.Now()
	claims := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(clientAssertionLifetime).Unix(),
		"jti": uuid.NewString(),
	}

	assertion, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize client assertion: %w", err)
	}

	return assertion, nil
}

// clientAssertionLifetime is the validity window of a generated client_assertion.
const clientAssertionLifetime = 5 * time.Minute

// errNoUsableClientAuthMethod reports that neither anonymous access nor the
// configured client authentication method can be used at the token endpoint.
var errNoUsableClientAuthMethod = errors.New(
	"no usable client authentication method for the authorization server token endpoint; " +
		"the authorization server declares pre-authorized_grant_anonymous_access_supported as false, " +
		"or it does not support the configured client authentication method")

// resolveClientAuthMethod checks whether the configured client authentication
// method can be used at the authorization server token endpoint.
//
// An empty method defaults to anonymous authentication (None).
func resolveClientAuthMethod(clientAuth ClientAuthConfig, authMetadata *receiverTypes.AuthorizationServerMetadata) (receiverTypes.TokenEndpointAuthMethod, bool) {
	method := clientAuth.Method
	if method == "" {
		method = receiverTypes.None
	}
	return method, clientAuthMethodAvailable(method, clientAuth, authMetadata)
}

// clientAuthMethodAvailable reports whether the given method can be used against
// the authorization server described by authMetadata with the given config.
func clientAuthMethodAvailable(method receiverTypes.TokenEndpointAuthMethod, clientAuth ClientAuthConfig, authMetadata *receiverTypes.AuthorizationServerMetadata) bool {
	switch method {
	case receiverTypes.None:
		// pre-authorized_grant_anonymous_access_supported is an OPTIONAL
		// authorization server metadata parameter, so an absent value means
		// "unknown", not "unsupported". Issuers commonly omit it entirely — the
		// OpenID conformance suite among them — and treating that as a refusal
		// stops the pre-authorized code flow before a single token request goes
		// out. Only an explicit false states that the authorization server
		// rejects the grant without client authentication.
		if authMetadata == nil {
			return false
		}
		anonymousAccess := authMetadata.PreAuthorizedGrantAnonymousAccessSupported
		return anonymousAccess == nil || *anonymousAccess

	case receiverTypes.PrivateKeyJwt:
		if strings.TrimSpace(clientAuth.ClientID) == "" || clientAuth.Key == nil {
			return false
		}
		if !asMetadataSupportsAuthMethod(authMetadata, receiverTypes.PrivateKeyJwt) {
			return false
		}
		return asMetadataSupportsSigningAlg(authMetadata, clientAuth.signatureAlgorithm())
	}
	return false
}
func asMetadataSupportsAuthMethod(authMetadata *receiverTypes.AuthorizationServerMetadata, method receiverTypes.TokenEndpointAuthMethod) bool {
	if authMetadata == nil || authMetadata.TokenEndpointAuthMethodsSupported == nil {
		return false
	}
	for _, m := range *authMetadata.TokenEndpointAuthMethodsSupported {
		if m == method {
			return true
		}
	}
	return false
}

// asMetadataSupportsSigningAlg reports whether alg is explicitly advertised by
// the authorization server. RFC 8414 requires this metadata when JWT-based
// client authentication is supported and defines no default signing algorithm.
func asMetadataSupportsSigningAlg(authMetadata *receiverTypes.AuthorizationServerMetadata, alg jose.SignatureAlgorithm) bool {
	if authMetadata == nil || authMetadata.TokenEndpointAuthSigningAlgValuesSupported == nil ||
		len(*authMetadata.TokenEndpointAuthSigningAlgValuesSupported) == 0 {
		return false
	}
	for _, a := range *authMetadata.TokenEndpointAuthSigningAlgValuesSupported {
		if a == alg {
			return true
		}
	}
	return false
}

// resolveClientAssertionAudience returns the authorization server identifier
// used in the client_assertion aud claim. RFC 7523 requires this value to be
// agreed between the client and authorization server. Explicit configuration
// therefore takes precedence, followed by the metadata issuer. The token
// endpoint URL is a standards-compliant fallback.
func resolveClientAssertionAudience(clientAuth ClientAuthConfig, authMetadata *receiverTypes.AuthorizationServerMetadata, tokenEndpointURL string) string {
	if audience := strings.TrimSpace(clientAuth.AssertionAudience); audience != "" {
		return audience
	}
	if authMetadata != nil {
		issuerURL := url.URL(authMetadata.Issuer)
		if issuer := strings.TrimSpace(issuerURL.String()); issuer != "" {
			return issuer
		}
	}
	return tokenEndpointURL
}
