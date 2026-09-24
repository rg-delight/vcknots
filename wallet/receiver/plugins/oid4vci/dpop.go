package oid4vci

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver/types"

	"github.com/trustknots/vcknots/wallet/common"
)

// dpopNonceServerKey identifies the server an RFC 9449 Section 8.2 DPoP nonce
// belongs to. Section 8.2 scopes a nonce to the server ("Clients should expect
// that a server will use the same nonce for all requests to that server"), not
// to a single endpoint path, so the key is the scheme and authority only. Both
// are compared case insensitively, as RFC 3986 Section 6.2.2.1 requires.
func dpopNonceServerKey(endpointURL url.URL) string {
	return strings.ToLower(endpointURL.Scheme) + "://" + strings.ToLower(endpointURL.Host)
}

// maxDPoPNonceServers bounds the servers a receiver keeps a DPoP nonce for.
const maxDPoPNonceServers = 32

type dpopNonceEntry struct {
	nonce    string
	lastUsed uint64
}

// rememberDPoPNonce records the DPoP-Nonce a server sent (RFC 9449 Section
// 8.2) so the next proof for that server carries it. An empty value is
// ignored: a response without the header does not revoke a known nonce.
func (o *Oid4vciReceiver) rememberDPoPNonce(endpointURL url.URL, nonce string) {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return
	}
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	o.storeDPoPNonceLocked(dpopNonceServerKey(endpointURL), nonce)
}

// dpopNonceFor returns the latest DPoP nonce held for the server endpointURL
// addresses, or "" when none is held.
func (o *Oid4vciReceiver) dpopNonceFor(endpointURL url.URL) string {
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	server := dpopNonceServerKey(endpointURL)
	entry, found := o.dpopNonces[server]
	if !found {
		return ""
	}
	o.dpopNonceClock++
	entry.lastUsed = o.dpopNonceClock
	o.dpopNonces[server] = entry
	return entry.nonce
}

// storeDPoPNonceLocked stores a nonce as the most recently used entry and
// evicts the least recently used one beyond maxDPoPNonceServers.
func (o *Oid4vciReceiver) storeDPoPNonceLocked(server, nonce string) {
	if o.dpopNonces == nil {
		o.dpopNonces = make(map[string]dpopNonceEntry)
	}
	o.dpopNonceClock++
	o.dpopNonces[server] = dpopNonceEntry{nonce: nonce, lastUsed: o.dpopNonceClock}
	if len(o.dpopNonces) <= maxDPoPNonceServers {
		return
	}
	oldest := ""
	for candidate, entry := range o.dpopNonces {
		if oldest == "" || entry.lastUsed < o.dpopNonces[oldest].lastUsed {
			oldest = candidate
		}
	}
	delete(o.dpopNonces, oldest)
}

// requireDPoPTokenType applies HAIP Section 4 (sender-constrained access
// tokens): under HAIP a token_type other than DPoP is ErrDPoPRequired.
func requireDPoPTokenType(normalized profile.Profile, tokenType string) error {
	if normalized.IsHAIP() && !strings.EqualFold(strings.TrimSpace(tokenType), dpopAuthorizationScheme) {
		return fmt.Errorf(
			"%w: HAIP requires a DPoP-bound access token, the token endpoint issued token_type %q",
			ErrDPoPRequired, tokenType)
	}
	return nil
}

// RequireBearerTokenType accepts only a Bearer token_type (compared case
// insensitively, RFC 6749 Section 7.1). A DPoP token is ErrDPoPRequired: a
// client without a DPoP key cannot present it.
func RequireBearerTokenType(t *types.CredentialIssuanceAccessToken) error {
	if t == nil {
		return fmt.Errorf("token response is required")
	}
	switch {
	case strings.EqualFold(strings.TrimSpace(t.TokenType), "Bearer"):
		return nil
	case strings.EqualFold(strings.TrimSpace(t.TokenType), dpopAuthorizationScheme):
		return fmt.Errorf("%w: token endpoint issued a DPoP-bound access token, which the anonymous Pre-Authorized Code path cannot present", ErrDPoPRequired)
	default:
		return fmt.Errorf("token response returned unsupported token_type %q (Bearer required)", t.TokenType)
	}
}

// ErrDPoPRequired reports that a DPoP proof is required (RFC 9449) and the
// wallet cannot send one: a Bearer-token request answered with a DPoP
// challenge, a DPoP-bound token without a proof factory, or a non-DPoP token
// under HAIP.
var ErrDPoPRequired = common.NewCodedError("dpop_required", "credential endpoint requires DPoP")

// dpopAuthorizationScheme is the RFC 9449 Section 7.1 authentication scheme for
// a DPoP-bound access token.
const dpopAuthorizationScheme = "DPoP"

// authorizationScheme returns the Authorization scheme for token_type: DPoP
// (RFC 9449 Section 7.1) for a DPoP token, Bearer (RFC 6750) otherwise.
func authorizationScheme(tokenType string) string {
	if strings.EqualFold(strings.TrimSpace(tokenType), dpopAuthorizationScheme) {
		return dpopAuthorizationScheme
	}
	return "Bearer"
}
