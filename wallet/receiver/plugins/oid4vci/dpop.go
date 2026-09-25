package oid4vci

import (
	"fmt"
	"strings"

	"github.com/trustknots/vcknots/wallet/profile"

	"github.com/trustknots/vcknots/wallet/common"
)

// dpopNonceKey identifies the nonces an RFC 9449 DPoP proof may carry: the
// server, its role and the proof key.
//
//   - Section 8.2 scopes a nonce to the server ("Clients should expect that a
//     server will use the same nonce for all requests to that server"), not to
//     an endpoint path, so the server is the scheme and authority, compared
//     case insensitively (RFC 3986 Section 6.2.2.1).
//   - Section 9: "the nonces provided by an authorization server and a
//     resource server are different and should not be confused with one
//     another", which holds even when both share an origin.
//   - A nonce is sent with one key only: a server that saw two keys answer the
//     same nonce could link them.
//
// An empty keyThumbprint marks an unattributed nonce: one a response carried
// before any key asked for it, such as the DPoP-Nonce of an OpenID4VCI 1.0
// Section 7.2 Nonce Response. The first key that asks the same server role
// claims it, and no other key sees it afterwards.
type dpopNonceKey struct {
	server         string
	resourceServer bool
	keyThumbprint  string
}

// dpopNonceKey is the key of the nonces ex's proofs carry. ok is false when ex
// has neither a keyed prover nor is a nonce source, so nothing is kept for it.
func (ex exchange) dpopNonceKey() (key dpopNonceKey, ok bool) {
	key = dpopNonceKey{
		server:         strings.ToLower(ex.url.Scheme) + "://" + strings.ToLower(ex.url.Host),
		resourceServer: ex.resourceServer,
	}
	if ex.dpop.Proof != nil && ex.dpop.KeyThumbprint != "" {
		key.keyThumbprint = ex.dpop.KeyThumbprint
		return key, true
	}
	return key, ex.dpopNonceSource
}

// maxDPoPNonceServers bounds the (server, role, key) entries a receiver keeps
// a DPoP nonce for.
const maxDPoPNonceServers = 32

type dpopNonceEntry struct {
	nonce    string
	lastUsed uint64
}

// dpopNonceCache holds the latest RFC 9449 Section 8.2 DPoP nonce of each
// dpopNonceKey, bounded to maxDPoPNonceServers entries (least recently used
// evicted).
type dpopNonceCache struct {
	entries map[dpopNonceKey]dpopNonceEntry
	clock   uint64
}

// rememberDPoPNonce records the DPoP-Nonce a response to ex carried (RFC 9449
// Section 8.2) so the next proof ex's key builds for the same server role
// carries it. An empty value is ignored: a response without the header does
// not revoke a known nonce. A response to an exchange without a keyed prover
// is kept only when the exchange is a nonce source, as an unattributed nonce.
func (o *Oid4vciReceiver) rememberDPoPNonce(ex exchange, nonce string) {
	nonce = strings.TrimSpace(nonce)
	key, ok := ex.dpopNonceKey()
	if nonce == "" || !ok {
		return
	}
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	o.storeDPoPNonceLocked(key, nonce)
}

// dpopNonceFor returns the latest DPoP nonce held for ex's key, or "" when
// none is held. Without a nonce of its own, the key claims the unattributed
// nonce of the same server role, which is then no longer offered to another
// key.
func (o *Oid4vciReceiver) dpopNonceFor(ex exchange) string {
	key, ok := ex.dpopNonceKey()
	if !ok || key.keyThumbprint == "" {
		return ""
	}
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	if o.dpopNonces == nil {
		return ""
	}
	cache := o.dpopNonces
	if entry, found := cache.entries[key]; found {
		cache.clock++
		entry.lastUsed = cache.clock
		cache.entries[key] = entry
		return entry.nonce
	}
	unattributed := key
	unattributed.keyThumbprint = ""
	entry, found := cache.entries[unattributed]
	if !found {
		return ""
	}
	delete(cache.entries, unattributed)
	o.storeDPoPNonceLocked(key, entry.nonce)
	return entry.nonce
}

// storeDPoPNonceLocked stores a nonce as the most recently used entry and
// evicts the least recently used one beyond maxDPoPNonceServers.
func (o *Oid4vciReceiver) storeDPoPNonceLocked(key dpopNonceKey, nonce string) {
	if o.dpopNonces == nil {
		o.dpopNonces = &dpopNonceCache{entries: make(map[dpopNonceKey]dpopNonceEntry)}
	}
	cache := o.dpopNonces
	cache.clock++
	cache.entries[key] = dpopNonceEntry{nonce: nonce, lastUsed: cache.clock}
	if len(cache.entries) <= maxDPoPNonceServers {
		return
	}
	var oldest dpopNonceKey
	found := false
	for candidate, entry := range cache.entries {
		if !found || entry.lastUsed < cache.entries[oldest].lastUsed {
			oldest, found = candidate, true
		}
	}
	delete(cache.entries, oldest)
}

// requireDPoPTokenType applies Options.RequireDPoP (HAIP Section 4,
// sender-constrained access tokens): a token_type other than DPoP is
// ErrDPoPRequired.
func requireDPoPTokenType(options profile.Options, tokenType string) error {
	if options.RequireDPoP && !strings.EqualFold(strings.TrimSpace(tokenType), dpopAuthorizationScheme) {
		return fmt.Errorf(
			"%w: HAIP requires a DPoP-bound access token, the token endpoint issued token_type %q",
			ErrDPoPRequired, tokenType)
	}
	return nil
}

// ErrDPoPRequired reports that a DPoP proof is required (RFC 9449) and the
// wallet cannot send one: a Bearer-token request answered with a DPoP
// challenge, a DPoP-bound token without a proof factory, or a non-DPoP token
// under Options.RequireDPoP.
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
