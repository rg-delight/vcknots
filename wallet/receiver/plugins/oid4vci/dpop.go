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

// rememberDPoPNonce records a DPoP-Nonce the wallet observed on any response
// from a server, so the next request to that same server can carry a proof that
// already satisfies it. RFC 9449 Section 8.2: "The DPoP-Nonce HTTP header field
// is used ... to provide the client with a nonce value to be used in a
// subsequent DPoP proof". An empty value is ignored: a response without the
// header does not revoke the nonce the wallet already holds.
func (o *Oid4vciReceiver) rememberDPoPNonce(endpointURL url.URL, nonce string) {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return
	}
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	if o.dpopNonces == nil {
		o.dpopNonces = make(map[string]string, 1)
	}
	o.dpopNonces[dpopNonceServerKey(endpointURL)] = nonce
}

// dpopNonceFor returns the latest DPoP nonce the wallet holds for the server
// endpointURL addresses, or the empty string when it holds none. Seeding the
// first proof of a request with it is what RFC 9449 Section 8.2 asks for:
// "Clients should expect that a server will use the same nonce for all requests
// to that server", which spares the wasted request that would otherwise be
// rejected with "use_dpop_nonce" only to be repeated.
func (o *Oid4vciReceiver) dpopNonceFor(endpointURL url.URL) string {
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	return o.dpopNonces[dpopNonceServerKey(endpointURL)]
}

// ExportDPoPNonces returns a snapshot of the RFC 9449 §8.2 per-server DPoP
// nonce store, keyed by dpopNonceServerKey. A copy is returned so a caller can
// carry the protocol state across an interruption (for example into an
// OID4VCIFinalTokenGrant.DPoPNonces and back out of it) without holding or
// mutating the receiver's map. An empty store exports an empty, non-nil map.
func (o *Oid4vciReceiver) ExportDPoPNonces() map[string]string {
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	exported := make(map[string]string, len(o.dpopNonces))
	for server, nonce := range o.dpopNonces {
		exported[server] = nonce
	}
	return exported
}

// ImportDPoPNonces restores the per-server nonces ExportDPoPNonces produced.
// Each value is remembered for its server, so the first DPoP proof built after
// a resume already carries the nonce that server last issued instead of paying
// the wasted challenge round trip RFC 9449 §8.2 exists to avoid. Blank values
// are ignored, matching rememberDPoPNonce.
func (o *Oid4vciReceiver) ImportDPoPNonces(nonces map[string]string) {
	if len(nonces) == 0 {
		return
	}
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	if o.dpopNonces == nil {
		o.dpopNonces = make(map[string]string, len(nonces))
	}
	for server, nonce := range nonces {
		if strings.TrimSpace(nonce) == "" {
			continue
		}
		o.dpopNonces[server] = nonce
	}
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
