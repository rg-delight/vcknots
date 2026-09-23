package issuerkeys

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// defaultMaxDocumentBytes bounds every metadata document the ladder reads.
	// The documents involved - JWT VC Issuer Metadata, a JWK Set, a DID
	// Configuration - hold a handful of keys or credentials; anything larger is
	// a hostile or broken origin.
	defaultMaxDocumentBytes int64 = 64 << 10
	// defaultHTTPTimeout bounds one metadata retrieval end to end.
	defaultHTTPTimeout = 30 * time.Second
)

// defaultHTTPClient is used when the Resolver carries none. It is shared, which
// is what net/http intends: a Client is safe for concurrent use and pools its
// connections.
var defaultHTTPClient = &http.Client{Timeout: defaultHTTPTimeout}

func (r *Resolver) maxDocumentBytes() int64 {
	if r.MaxDocumentBytes > 0 {
		return r.MaxDocumentBytes
	}
	return defaultMaxDocumentBytes
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// httpClient returns the client used for metadata retrieval, with redirects
// refused.
//
// A redirect would let the host named by the issuer identifier hand the request
// to another host, and the answer would then be attributed to the first. The
// caller's client is never mutated: a copy carries the redirect policy, so a
// client shared with other code keeps its own.
func (r *Resolver) httpClient() *http.Client {
	base := r.HTTPClient
	if base == nil {
		base = defaultHTTPClient
	}
	clone := *base
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &clone
}

// allowedURL parses raw and reports whether the resolver may request it.
//
// Every location the ladder reads is a well-known path derived from an issuer
// identifier, so the rules are narrow on purpose: the URL must parse with a
// host, it must be https - or http while AllowHTTP is set, which exists for a
// local test origin - and it must carry neither a query nor a fragment, since
// neither can be part of a well-known location.
func (r *Resolver) allowedURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return nil, newMechanismError(ErrIssuerURLNotAllowed, "issuer identifier is not a URL")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !r.AllowHTTP {
			return nil, newMechanismError(ErrIssuerURLNotAllowed, "issuer identifier is not https")
		}
	default:
		return nil, newMechanismError(ErrIssuerURLNotAllowed, "issuer identifier is not https")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return nil, newMechanismError(ErrIssuerURLNotAllowed, "issuer identifier carries a query or fragment")
	}
	return parsed, nil
}

// originOf returns the scheme and authority of a URL, with a default port
// dropped, which is the form a DIF Well Known DID Configuration's `origin`
// claim is written in.
func originOf(parsed *url.URL) string {
	host := parsed.Host
	switch {
	case parsed.Scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	case parsed.Scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	}
	return parsed.Scheme + "://" + host
}

// fetchJSONObject retrieves a JSON object from target.
//
// The retrieval is deliberately narrow, because everything it reads is used to
// decide which key signed a credential: the request is a GET that asks for
// JSON and honours ctx, redirects are refused, the status must be a success,
// the response must be labelled as JSON, the body is bounded before and while
// it is read, and the result must be a JSON object rather than any other JSON
// value.
func (r *Resolver) fetchJSONObject(ctx context.Context, target *url.URL) (json.RawMessage, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "request could not be built")
	}
	request.Header.Set("Accept", "application/json")

	response, err := r.httpClient().Do(request)
	if err != nil {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "request failed")
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "redirects are not allowed")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "fetch failed: HTTP "+strconv.Itoa(response.StatusCode))
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "response is not labelled as JSON")
	}

	body, err := readBoundedBody(response, r.maxDocumentBytes())
	if err != nil {
		return nil, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil || probe == nil {
		return nil, newMechanismError(ErrIssuerMetadataInvalid, "response is not a JSON object")
	}
	return body, nil
}

// readBoundedBody reads at most max bytes of the response body and refuses an
// empty one.
//
// A declared Content-Length is checked before a single byte is read, so an
// origin that announces an oversized document costs nothing to refuse; the
// streaming read is still bounded, because the declaration is the origin's own
// and may be absent or untrue.
func readBoundedBody(response *http.Response, max int64) ([]byte, error) {
	if declared := response.Header.Get("Content-Length"); declared != "" {
		length, err := strconv.ParseInt(declared, 10, 64)
		if err != nil || length < 0 {
			return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "Content-Length is not a length")
		}
		if length > max {
			return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "response is too large")
		}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, max+1))
	if err != nil {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "body could not be read")
	}
	if int64(len(body)) > max {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "response is too large")
	}
	if len(body) == 0 {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "response is empty")
	}
	return body, nil
}
