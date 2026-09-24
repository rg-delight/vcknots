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

// ExportDPoPNonces returns a copy of the per-server DPoP nonces, keyed by
// scheme and authority, so a caller can carry them across an interruption.
func (o *Oid4vciReceiver) ExportDPoPNonces() map[string]string {
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	exported := make(map[string]string, len(o.dpopNonces))
	for server, entry := range o.dpopNonces {
		exported[server] = entry.nonce
	}
	return exported
}

// ImportDPoPNonces restores nonces ExportDPoPNonces produced. A server the
// receiver already holds a nonce for keeps it: that nonce was observed by this
// receiver, while an imported one may be stale or come from another flow.
// Blank values are ignored.
func (o *Oid4vciReceiver) ImportDPoPNonces(nonces map[string]string) {
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	for server, nonce := range nonces {
		nonce = strings.TrimSpace(nonce)
		if nonce == "" {
			continue
		}
		if _, known := o.dpopNonces[server]; known {
			continue
		}
		o.storeDPoPNonceLocked(server, nonce)
	}
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

// requireDPoPTokenType enforces HAIP §4 "Sender-constrained access token: MUST
// support DPoP" on a parsed token response. A token_type other than DPoP
// (case-insensitive) cannot bind the access token to the wallet's key, so it is
// reported as ErrDPoPRequired: under HAIP a plain RFC 6750 Bearer token is not
// a weaker token the wallet may still present, it is the absence of the
// sender-constraint the profile requires.
func requireDPoPTokenType(normalized profile.Profile, tokenType string) error {
	if normalized.IsHAIP() && !strings.EqualFold(strings.TrimSpace(tokenType), dpopAuthorizationScheme) {
		return fmt.Errorf(
			"%w: HAIP requires a DPoP-bound access token, the token endpoint issued token_type %q",
			ErrDPoPRequired, tokenType)
	}
	return nil
}

// RequireBearerTokenType enforces the Final 1.0 default for the anonymous
// Pre-Authorized Code path: the token response must carry a plain Bearer access
// token. OpenID4VCI 1.0 §6.1 makes token_type REQUIRED ("The type of the access
// token"), and RFC 6749 §7.1 defines it as case insensitive, so "Bearer",
// "bearer" and "BEARER" are the same value. A DPoP-bound token (RFC 9449 §7.1)
// is refused with ErrDPoPRequired because an anonymous client holds no key to
// build the proof that scheme requires; any other value is an unsupported
// token_type rather than a silent fallback to Bearer.
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

type DPoPProofFactory = types.DPoPProofFactory

// ErrDPoPRequired reports that a Credential, Deferred Credential or Notification
// response demanded a DPoP proof (an RFC 9449 §8 DPoP-Nonce header, or a
// WWW-Authenticate challenge naming the DPoP scheme of §7.1) while the access
// token was presented with a scheme that has no key-bound proof to offer. It is
// the fail-closed answer for a client that holds no DPoP key: continuing would
// either replay the request without the proof the resource server asked for or
// invent one the wallet cannot sign.
var ErrDPoPRequired = common.NewCodedError("dpop_required", "credential endpoint requires DPoP")

// dpopAuthorizationScheme is the RFC 9449 Section 7.1 authentication scheme for
// a DPoP-bound access token.
const dpopAuthorizationScheme = "DPoP"

// authorizationScheme maps a token response's token_type to the authentication
// scheme its access token is sent with. token_type is compared case
// insensitively, as RFC 6749 Section 7.1 defines it. Anything that is not DPoP
// takes the Bearer scheme of RFC 6750 Section 2.1: those are the only two
// schemes this wallet holds credentials for, so echoing back an unrecognised
// token_type would only build a header no issuer could act on.
func authorizationScheme(tokenType string) string {
	if strings.EqualFold(strings.TrimSpace(tokenType), dpopAuthorizationScheme) {
		return dpopAuthorizationScheme
	}
	return "Bearer"
}
