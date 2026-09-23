package federation

import (
	"context"
	"net/http"
	"slices"
	"time"
)

// Package defaults a zero-valued Resolver field stands for. They match the
// TypeScript resolver this package ports.
const (
	// DefaultMaxDepth bounds how many Entities discovery walks up from the
	// subject before giving up.
	DefaultMaxDepth = 6
	// DefaultMaxStatementBytes bounds one Entity Statement response.
	DefaultMaxStatementBytes int64 = 128 * 1024
	// DefaultHTTPTimeout is the timeout of the client used when Resolver
	// leaves HTTPClient nil.
	DefaultHTTPTimeout = 10 * time.Second
)

// Resolver discovers and validates Trust Chains (OpenID Federation 1.0
// Section 10). Zero-valued fields mean the package defaults. A Resolver keeps
// no state across calls: the Entity Statements it fetches are memoized only for
// the duration of one resolution.
type Resolver struct {
	// HTTPClient fetches Entity Statements. It is copied, never mutated, to
	// refuse redirects. Nil means a client with DefaultHTTPTimeout.
	HTTPClient *http.Client
	// TrustAnchors are the Trust Anchors a chain must end at.
	TrustAnchors []TrustAnchor
	// Now is the validation time. Nil means time.Now.
	Now func() time.Time
	// MaxDepth bounds discovery. Zero means DefaultMaxDepth; any other value
	// below 2 is refused.
	MaxDepth int
	// MaxStatementBytes bounds one Entity Statement response. Zero or less
	// means DefaultMaxStatementBytes.
	MaxStatementBytes int64
	// RequirePublicNetworkHost refuses to fetch from a host IsPublicNetworkHost
	// does not accept, so a Trust Chain cannot steer the Wallet at an internal
	// address.
	RequirePublicNetworkHost bool
	// IsPublicNetworkHost decides whether a host name is on the public
	// network. Nil with RequirePublicNetworkHost set refuses every host.
	IsPublicNetworkHost func(host string) bool
}

func (r *Resolver) client() *http.Client {
	base := r.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	clone := *base
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &clone
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Resolver) maxStatementBytes() int64 {
	if r.MaxStatementBytes > 0 {
		return r.MaxStatementBytes
	}
	return DefaultMaxStatementBytes
}

// ResolveTrustChains discovers every Trust Chain from subjectEntityID to a
// configured Trust Anchor (OpenID Federation 1.0 Section 10.1) and returns the
// valid ones, shortest first (Section 10.3). When none is valid the first
// validation failure is returned.
func (r *Resolver) ResolveTrustChains(ctx context.Context, subjectEntityID string) ([]*TrustChain, error) {
	run, err := r.newResolution(ctx)
	if err != nil {
		return nil, err
	}
	paths, err := run.resolveTrustPaths(subjectEntityID, nil)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, failure(ErrTrustChainUnresolved, "trust chain could not be resolved to a configured trust anchor")
	}
	slices.SortStableFunc(paths, func(left, right trustPath) int { return len(left.chain) - len(right.chain) })

	var chains []*TrustChain
	var firstErr error
	for _, path := range paths {
		chain, err := ValidateTrustChain(path.chain, subjectEntityID, r.TrustAnchors, run.now)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		chains = append(chains, chain)
	}
	if len(chains) == 0 {
		return nil, firstErr
	}
	return chains, nil
}

// resolution is the state of one discovery run. It memoizes Entity
// Configurations and Subordinate Statements, including failed fetches, so an
// Entity reached through several authority hints is fetched once.
type resolution struct {
	resolver       *Resolver
	ctx            context.Context
	now            time.Time
	anchorIDs      map[string]struct{}
	maxDepth       int
	configurations map[string]configurationResult
	subordinates   map[string]statementResult
}

type configurationResult struct {
	configuration *entityConfiguration
	err           error
}

type statementResult struct {
	statement string
	err       error
}

// trustPath is one discovered path from an Entity to a Trust Anchor: the
// Entity's configuration and the compact statements of the chain.
type trustPath struct {
	entityID      string
	configuration *entityConfiguration
	chain         []string
}

func (r *Resolver) newResolution(ctx context.Context) (*resolution, error) {
	if len(r.TrustAnchors) == 0 {
		return nil, failure(ErrTrustAnchorNotConfigured, "trust anchors must be configured")
	}
	maxDepth := r.MaxDepth
	if maxDepth == 0 {
		maxDepth = DefaultMaxDepth
	}
	if maxDepth < 2 {
		return nil, failure(ErrTrustChainUnresolved, "trust chain maximum depth is invalid")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	anchorIDs := make(map[string]struct{}, len(r.TrustAnchors))
	for _, anchor := range r.TrustAnchors {
		anchorIDs[anchor.EntityID] = struct{}{}
	}
	return &resolution{
		resolver:       r,
		ctx:            ctx,
		now:            r.now(),
		anchorIDs:      anchorIDs,
		maxDepth:       maxDepth,
		configurations: map[string]configurationResult{},
		subordinates:   map[string]statementResult{},
	}, nil
}

func (run *resolution) isAnchor(entityID string) bool {
	_, ok := run.anchorIDs[entityID]
	return ok
}

// resolveTrustPaths walks the authority hints of entityID up to configured
// Trust Anchors. visited holds the Entities already on the current path, so a
// loop of authority hints ends instead of recursing. A failure on one hint
// does not stop the others; it is returned only when no path was found.
func (run *resolution) resolveTrustPaths(entityID string, visited []string) ([]trustPath, error) {
	if slices.Contains(visited, entityID) {
		return nil, nil
	}
	if len(visited) >= run.maxDepth {
		return nil, failure(ErrTrustChainUnresolved, "trust chain resolution exceeded maximum depth")
	}
	configuration, err := run.entityConfiguration(entityID)
	if err != nil {
		return nil, err
	}
	if run.isAnchor(entityID) {
		return []trustPath{{entityID: entityID, configuration: configuration, chain: []string{configuration.raw}}}, nil
	}

	var paths []trustPath
	var firstErr error
	remember := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	nextVisited := append(slices.Clone(visited), entityID)
	for _, authorityHint := range configuration.authorityHints {
		superiorPaths, err := run.resolveTrustPaths(authorityHint, nextVisited)
		if err != nil {
			remember(err)
			continue
		}
		for _, superior := range superiorPaths {
			statement, err := run.subordinateStatement(superior.configuration, entityID)
			if err != nil {
				remember(err)
				continue
			}
			tail := superior.chain
			if !run.isAnchor(superior.entityID) {
				tail = tail[1:]
			}
			chain := append([]string{configuration.raw, statement}, tail...)
			paths = append(paths, trustPath{entityID: entityID, configuration: configuration, chain: chain})
		}
	}
	if len(paths) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return paths, nil
}

// entityConfiguration fetches and decodes the Entity Configuration of
// entityID once per resolution.
func (run *resolution) entityConfiguration(entityID string) (*entityConfiguration, error) {
	if cached, ok := run.configurations[entityID]; ok {
		return cached.configuration, cached.err
	}
	configuration, err := run.fetchEntityConfiguration(entityID)
	run.configurations[entityID] = configurationResult{configuration: configuration, err: err}
	return configuration, err
}

func (run *resolution) fetchEntityConfiguration(entityID string) (*entityConfiguration, error) {
	statementURL, err := EntityConfigurationURL(entityID)
	if err != nil {
		return nil, err
	}
	raw, err := run.resolver.fetchEntityStatement(run.ctx, statementURL)
	if err != nil {
		return nil, err
	}
	return decodeEntityConfiguration(raw, entityID)
}

// subordinateStatement fetches the Subordinate Statement superior issues about
// subjectEntityID from the superior's federation_fetch_endpoint, once per
// resolution.
func (run *resolution) subordinateStatement(superior *entityConfiguration, subjectEntityID string) (string, error) {
	endpoint, err := superior.federationFetchEndpoint()
	if err != nil {
		return "", err
	}
	statementURL, err := SubordinateStatementURL(endpoint, subjectEntityID)
	if err != nil {
		return "", err
	}
	if cached, ok := run.subordinates[statementURL]; ok {
		return cached.statement, cached.err
	}
	statement, err := run.resolver.fetchEntityStatement(run.ctx, statementURL)
	run.subordinates[statementURL] = statementResult{statement: statement, err: err}
	return statement, err
}

// entityConfiguration is the part of an Entity Configuration discovery reads
// before the chain is validated: its authority hints and its federation_entity
// metadata. None of it is trusted until the whole chain verifies.
type entityConfiguration struct {
	raw            string
	metadata       map[string]any
	authorityHints []string
}

func decodeEntityConfiguration(raw, expectedEntityID string) (*entityConfiguration, error) {
	payload, err := unverifiedJWTPayload(raw)
	if err != nil {
		return nil, failure(ErrTrustChainUnresolved, "entity configuration is not a JWT")
	}
	for _, name := range []string{"iss", "sub"} {
		if value, _ := payload[name].(string); value == "" {
			return nil, failure(ErrTrustChainUnresolved, "entity configuration %s claim is required", name)
		}
	}
	if payload["iss"] != expectedEntityID || payload["sub"] != expectedEntityID {
		return nil, failure(ErrTrustChainUnresolved, "entity configuration subject does not match entity identifier")
	}
	configuration := &entityConfiguration{raw: raw}
	if value, present := payload["metadata"]; present {
		metadata, ok := asObject(value)
		if !ok {
			return nil, failure(ErrTrustChainUnresolved, "entity configuration metadata claim must be an object")
		}
		configuration.metadata = metadata
	}
	if configuration.authorityHints, err = authorityHintsClaim(payload); err != nil {
		return nil, err
	}
	return configuration, nil
}

// authorityHintsClaim reads the authority_hints of an Entity Configuration
// (OpenID Federation 1.0 Section 3.1): Entity Identifiers whose configuration
// URL can be built.
func authorityHintsClaim(payload map[string]any) ([]string, error) {
	value, present := payload["authority_hints"]
	if !present {
		return nil, nil
	}
	hints, ok := asNonEmptyStringArray(value)
	if !ok {
		return nil, failure(ErrTrustChainUnresolved, "entity configuration authority_hints claim must be a string array")
	}
	for _, hint := range hints {
		if _, err := EntityConfigurationURL(hint); err != nil {
			return nil, failure(ErrTrustChainUnresolved, "entity configuration authority_hints value is invalid")
		}
	}
	return hints, nil
}

// federationFetchEndpoint reads the federation_fetch_endpoint a superior
// publishes in its federation_entity metadata (OpenID Federation 1.0 Section
// 5.1.1).
func (c *entityConfiguration) federationFetchEndpoint() (string, error) {
	entity, ok := asObject(c.metadata[federationEntityType])
	if !ok {
		return "", failure(ErrTrustChainUnresolved, "superior entity configuration must include federation_entity metadata")
	}
	endpoint, _ := entity["federation_fetch_endpoint"].(string)
	if endpoint == "" {
		return "", failure(ErrTrustChainUnresolved, "superior entity configuration must include federation_fetch_endpoint")
	}
	return endpoint, nil
}
