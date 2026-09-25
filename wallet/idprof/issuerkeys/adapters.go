package issuerkeys

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"sync"

	"github.com/go-jose/go-jose/v4"
)

// This file adapts the ladder to the credential acceptor's issuer key
// resolution hook (acceptance.Policy.ResolveIssuerKeys). The hook receives the
// issuer and the protected header of a JWT that has not been verified yet, and
// wants the candidate public keys back; it has no room for the diagnostics or
// the evidence of which mechanism produced the key that verified, which is
// what the adapter keeps for the caller. The Token Status List checker's hook
// is adapted in statuslistkeys.go.

// KeyLookup adapts a Resolver to the credential acceptor's ResolveIssuerKeys
// hook for one credential, and remembers what the ladder said about it.
//
// The acceptor's hook takes no context, so the lookup carries the context of
// the acceptance call it was created for; it is meant to live exactly as long
// as that call. The hook is called once per credential, and a KeyLookup keeps
// the resolution of its most recent call.
//
// Keys returns the candidates the ladder produced whose Candidate.Issuer equals
// the JWT `iss`, in ladder order.
type KeyLookup struct {
	resolver *Resolver
	//nolint:containedctx // The acceptor's hook has no context parameter; see the type comment.
	ctx      context.Context
	template Request

	// callerVerifiesX5C records that the caller authenticates an x5c chain
	// itself and asks this lookup for keys only once a chain reached none of
	// its anchors; see CallerVerifiesX5C.
	callerVerifiesX5C bool

	mu         sync.Mutex
	resolution *Resolution
	err        error
}

// CallerVerifiesX5C tells the lookup that the caller walks an x5c chain itself
// - the credential acceptor does, against IssuerX509 - and asks for keys only
// when the credential carries none or its chain reached no configured anchor
// (acceptance.Policy.ResolveIssuerKeysWhenX5CUntrusted). A resolution
// for a credential that carries x5c then reports the x5c rung as "certificate
// chain is not trusted" instead of claiming the chain as usable. It returns l
// for chaining.
func (l *KeyLookup) CallerVerifiesX5C() *KeyLookup {
	l.callerVerifiesX5C = true
	return l
}

// NewKeyLookup returns a KeyLookup that resolves within ctx. template carries
// everything the ladder needs that the JWT header does not: CredentialFormat,
// CredentialIssuer, IssuerMetadataJWKS and, for the W3C `vc.issuer` binding,
// Payload. Keys fills Issuer, KeyID, Algorithm and X5C from its arguments,
// overwriting whatever the template held.
func (r *Resolver) NewKeyLookup(ctx context.Context, template Request) *KeyLookup {
	return &KeyLookup{resolver: r, ctx: ctx, template: template}
}

// Keys resolves the candidate public keys of a credential signed by issuer
// under header. Its signature is acceptance.Policy's
// ResolveIssuerKeys, so a caller passes the method value lookup.Keys.
func (l *KeyLookup) Keys(issuer string, header map[string]any) ([]jose.JSONWebKey, error) {
	return l.KeysFromClaims(issuer, header, l.template.Payload)
}

// KeysFromClaims is Keys for the acceptor's ResolveIssuerKeysFromClaims hook:
// claims are the credential's issuer-signed claims, which the W3C JWT VC
// `vc.issuer` binding (Mechanisms.CredentialIssuerBinding) reads. They replace
// the template's Payload.
func (l *KeyLookup) KeysFromClaims(issuer string, header map[string]any, claims map[string]any) ([]jose.JSONWebKey, error) {
	request := requestFromHeader(l.template, issuer, header)
	request.Payload = claims
	resolution, err := l.resolver.resolve(l.ctx, request)
	if l.callerVerifiesX5C && len(request.X5C) > 0 {
		if resolution != nil {
			markChainUntrusted(resolution)
		}
		var didOnly *DIDOnlyTrustError
		if errors.As(err, &didOnly) {
			markChainUntrusted(&Resolution{Diagnostics: didOnly.Diagnostics})
		}
	}
	if err == nil {
		resolution.Candidates = issuerCandidates(resolution.Candidates, issuer)
	}
	if err == nil && len(resolution.Candidates) == 0 {
		err = l.ctx.Err()
		if err == nil {
			err = &UnresolvedError{Diagnostics: resolution.Diagnostics}
		}
	}

	l.mu.Lock()
	l.resolution, l.err = resolution, err
	l.mu.Unlock()

	if err != nil {
		return nil, err
	}
	return candidateKeys(resolution.Candidates), nil
}

// Resolution returns what the ladder produced on the most recent Keys call:
// the candidates and, whether or not any key was found, the per-rung
// diagnostics. It is nil before Keys has been called.
func (l *KeyLookup) Resolution() *Resolution {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.resolution
}

// Err returns the error the most recent Keys call returned, nil when it
// returned keys or has not been called.
func (l *KeyLookup) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// CandidateFor returns the candidate whose key is key, compared by RFC 7638
// JWK thumbprint, so members that carry no key material (`kid`, `alg`, `use`)
// do not matter. When the same key was produced by several rungs, the first in
// ladder order is returned, which is the one a caller that tried the keys in
// order verified with.
func (res *Resolution) CandidateFor(key jose.JSONWebKey) (Candidate, bool) {
	if res == nil {
		return Candidate{}, false
	}
	wanted, ok := keyThumbprint(key)
	if !ok {
		return Candidate{}, false
	}
	for _, candidate := range res.Candidates {
		if thumbprint, ok := keyThumbprint(candidate.Key); ok && bytes.Equal(thumbprint, wanted) {
			return candidate, true
		}
	}
	return Candidate{}, false
}

// failureChainUntrusted is the `x5c` rung Failure recorded when a chain does
// not reach a configured trust anchor, or does not name the issuer's host.
const failureChainUntrusted = "certificate chain is not trusted"

// markChainUntrusted records on the `x5c` rung's diagnostic that the chain it
// reported was not trusted, so the diagnostics no longer claim it as usable.
func markChainUntrusted(resolution *Resolution) {
	for index := range resolution.Diagnostics {
		diagnostic := &resolution.Diagnostics[index]
		if diagnostic.Mechanism == RungX5C {
			diagnostic.Attempted = false
			diagnostic.CandidateCount = 0
			diagnostic.Failure = failureChainUntrusted
		}
	}
}

// issuerCandidates returns the candidates attributable to issuer, the JWT
// `iss`: those whose Candidate.Issuer equals it.
func issuerCandidates(candidates []Candidate, issuer string) []Candidate {
	narrowed := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Issuer == issuer {
			narrowed = append(narrowed, candidate)
		}
	}
	return narrowed
}

// requestFromHeader fills template with what a JWT's `iss` and protected header
// say about its signer.
func requestFromHeader(template Request, issuer string, header map[string]any) Request {
	request := template
	request.Issuer = issuer
	request.KeyID, _ = header["kid"].(string)
	request.Algorithm, _ = header["alg"].(string)
	request.X5C = headerX5C(header["x5c"])
	return request
}

// headerX5C reads an `x5c` header member as decoded into a map[string]any (a
// []any of strings) or into a typed header (a []string). Any other shape, or an
// entry that is not a string, yields nothing: the ladder treats a malformed
// chain as an absent one.
func headerX5C(raw any) []string {
	switch values := raw.(type) {
	case []string:
		return values
	case []any:
		chain := make([]string, 0, len(values))
		for _, value := range values {
			entry, ok := value.(string)
			if !ok {
				return nil
			}
			chain = append(chain, entry)
		}
		return chain
	default:
		return nil
	}
}

// candidateKeys returns the signature keys of candidates in order, each reduced
// to its public half.
func candidateKeys(candidates []Candidate) []jose.JSONWebKey {
	keys := make([]jose.JSONWebKey, 0, len(candidates))
	for _, candidate := range candidates {
		if key, ok := publicKey(candidate.Key); ok && isSignatureKey(key) {
			keys = append(keys, key)
		}
	}
	return keys
}

// keyThumbprint returns the RFC 7638 SHA-256 thumbprint of key's public half.
func keyThumbprint(key jose.JSONWebKey) ([]byte, bool) {
	public, ok := publicKey(key)
	if !ok {
		return nil, false
	}
	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, false
	}
	return thumbprint, true
}
