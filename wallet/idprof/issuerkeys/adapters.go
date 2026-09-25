package issuerkeys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"

	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
)

// This file adapts the resolver to the Token Status List checker's issuer
// key hook (statuslist.Checker.ResolveIssuerKeys), which receives the issuer
// and the protected header of a JWT that has not been verified yet and wants
// the candidate public keys back. The credential acceptor (wallet/acceptance)
// calls Resolve itself.

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

// X5CTrust is the relying-party trust policy for an `x5c` chain on an issuer
// JWT the library verifies outside the credential acceptor - in practice a
// Token Status List token. Its fields mean what the same fields of
// commonX509.SigningChainPolicy mean.
type X5CTrust struct {
	// TrustAnchors are the certificates a chain must reach. An empty list
	// trusts no chain, which is reported like a chain that reaches no anchor.
	TrustAnchors []*x509.Certificate
	// CRL tunes the revocation retrieval.
	CRL commonX509.CRLCheckerOptions
	// AllowUnadvertisedRevocation keeps a certificate that advertises no
	// revocation mechanism on the trust path.
	AllowUnadvertisedRevocation bool
	// KeyUsages constrains the leaf's extended key usage. Empty imposes none.
	KeyUsages []x509.ExtKeyUsage
	// HTTPClient performs the CRL retrievals when CRL.HTTPClient is nil. When
	// both are nil the Resolver's HTTPClient is used, so the deployment's
	// outbound network policy applies to CRL retrieval as it does to metadata.
	HTTPClient *http.Client
	// Now is the verification clock. A nil value uses the Resolver's.
	Now func() time.Time
}

// failureChainUntrusted is the `x5c` rung Failure recorded when a chain does
// not reach a configured trust anchor, or does not name the issuer's host.
const failureChainUntrusted = "certificate chain is not trusted"

// StatusListKeyFunc adapts the Resolver to the Token Status List checker's
// ResolveIssuerKeys hook (statuslist.ResolveIssuerKeysFunc). template carries
// what the token header does not, as for NewKeyLookup; x5c, when non-nil,
// enables the `x5c` chain as a key source. See StatusListKeys for the rules.
func (r *Resolver) StatusListKeyFunc(template Request, x5c *X5CTrust) func(ctx context.Context, issuer string, header map[string]any) ([]jose.JSONWebKey, error) {
	return func(ctx context.Context, issuer string, header map[string]any) ([]jose.JSONWebKey, error) {
		keys, _, err := r.StatusListKeys(ctx, template, x5c, issuer, header)
		return keys, err
	}
}

// StatusListKeys resolves the candidate public keys of an issuer-signed JWT
// that is not a credential, such as a Token Status List token, and returns the
// resolution they came from.
//
// The rules:
//
//  1. When the header carries an `x5c`, trust is non-nil, and the `x5c` rung
//     accepted the chain for this issuer (it reports the DNS name the chain
//     must be bound to), the chain is validated: the leaf must name that DNS
//     name exactly and the path must reach one of trust.TrustAnchors. The
//     leaf's key is then the first candidate, as MechanismX5CTrustedChain.
//  2. A chain that is merely not trusted - malformed, reaching no configured
//     anchor, or not naming the issuer's host - says something about the
//     caller's trust configuration rather than about the signer. It is recorded as
//     the `x5c` rung's failure ("certificate chain is not trusted") and the
//     ladder's candidates are still offered.
//  3. Any other refusal - a revoked certificate, a revocation status that
//     cannot be established - is the signer's own state and is returned as the
//     error, so a weaker rung cannot launder it.
//  4. The ladder's candidates follow, but only those whose Candidate.Issuer
//     equals issuer: the JWT's `iss` must be the identifier the key was
//     resolved for.
//
// issuer must be the issuer the caller bound the JWT to, not a value the JWT
// asserts on its own: the status list checker passes the credential's `iss`
// (statuslist.Checker.Check), so a token of another issuer finds no key here.
//
// No candidate at all is an *UnresolvedError with the diagnostics; a DID with
// no binding is a *DIDOnlyTrustError, as from Resolve. Every returned key is a
// public key. The returned Resolution's Candidates are exactly the returned
// keys, so Resolution.CandidateFor answers for the key that verified.
func (r *Resolver) StatusListKeys(ctx context.Context, template Request, trust *X5CTrust, issuer string, header map[string]any) ([]jose.JSONWebKey, *Resolution, error) {
	request := requestFromHeader(template, issuer, header)
	resolution, err := r.resolve(ctx, request)
	if err != nil {
		return nil, nil, err
	}

	var candidates []Candidate
	trusted, err := r.trustedChainCandidate(ctx, request, resolution, trust)
	if err != nil {
		return nil, nil, err
	}
	if trusted != nil {
		candidates = append(candidates, *trusted)
	}
	candidates = append(candidates, issuerCandidates(resolution.Candidates, issuer)...)

	narrowed := &Resolution{
		Candidates:    candidates,
		Diagnostics:   resolution.Diagnostics,
		IssuerDNSName: resolution.IssuerDNSName,
	}
	if len(candidates) == 0 {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, &UnresolvedError{Diagnostics: resolution.Diagnostics}
	}
	return candidateKeys(candidates), narrowed, nil
}

// trustedChainCandidate validates the `x5c` chain of request and returns its
// leaf key as a candidate, nil when there is no chain to validate or the chain
// is not trusted, and an error only for a refusal that must end the
// verification (rule 3 of StatusListKeys).
func (r *Resolver) trustedChainCandidate(ctx context.Context, request Request, resolution *Resolution, trust *X5CTrust) (*Candidate, error) {
	chain := x5cChain(request.X5C)
	if trust == nil || resolution.IssuerDNSName == "" || len(chain) == 0 || request.Issuer == "" {
		return nil, nil
	}
	untrusted := func() (*Candidate, error) {
		markChainUntrusted(resolution)
		return nil, nil
	}

	certificates, err := commonX509.DecodeX5CChain(chain)
	if err != nil {
		return untrusted()
	}
	// The binding is checked before the path is walked: it needs no network,
	// and a chain for another host must not cost a CRL retrieval.
	if err := commonX509.RequireLeafDNSName(certificates[0], resolution.IssuerDNSName, false); err != nil {
		return untrusted()
	}
	// An empty anchor set trusts no chain.
	if len(trust.TrustAnchors) == 0 {
		return untrusted()
	}
	now := r.now
	if trust.Now != nil {
		now = trust.Now
	}
	crlClient := trust.HTTPClient
	if crlClient == nil {
		crlClient = r.HTTPClient
	}
	if crlClient == nil {
		crlClient = defaultHTTPClient
	}
	result, err := commonX509.VerifySigningChainWithPolicy(ctx, certificates, commonX509.SigningChainPolicy{
		TrustAnchors:                trust.TrustAnchors,
		KeyUsages:                   trust.KeyUsages,
		CRL:                         trust.CRL,
		AllowUnadvertisedRevocation: trust.AllowUnadvertisedRevocation,
		CurrentTime:                 now(),
		HTTPClient:                  crlClient,
	})
	if err != nil {
		if chainRefusalIsStructural(err) {
			return untrusted()
		}
		return nil, err
	}
	leaf, ok := publicKey(jose.JSONWebKey{Key: certificates[0].PublicKey})
	if !ok {
		return untrusted()
	}
	return &Candidate{
		Key:               leaf,
		Issuer:            request.Issuer,
		Mechanism:         MechanismX5CTrustedChain,
		CertificateSHA256: result.Fingerprints,
	}, nil
}

// chainRefusalIsStructural reports whether a signing-chain refusal is about
// the caller's trust configuration (the chain reaches no configured anchor)
// rather than about the signer.
func chainRefusalIsStructural(err error) bool {
	return errors.Is(err, commonX509.ErrNoTrustAnchor)
}

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
