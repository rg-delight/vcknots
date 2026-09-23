package did

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/idprof/types"
)

// Sentinel errors the did:web method plugin returns. A caller branches on the
// condition with errors.Is, or reads the stable code with common.CodeOf,
// instead of matching message text.
var (
	// ErrDIDWebIdentifierInvalid reports that the method-specific identifier
	// does not name a document URL under the rules of the did:web method
	// specification: an empty domain, an empty path segment, a segment that
	// carries a path separator, or a percent-escape that does not decode.
	ErrDIDWebIdentifierInvalid = common.NewCodedError("did_web_identifier_invalid", "did:web identifier does not name a DID document URL")
	// ErrDIDWebDocumentFetchFailed reports that the DID document could not be
	// retrieved: the request failed, the origin answered a redirect or a
	// non-2xx status, it did not label the body as a DID document, or the body
	// exceeded the configured cap.
	ErrDIDWebDocumentFetchFailed = common.NewCodedError("did_web_document_fetch_failed", "did:web document could not be retrieved")
	// ErrDIDWebDocumentInvalid reports that the retrieved body is not a usable
	// DID document: not a JSON object, or carrying an `id` that names another
	// DID than the one being resolved (W3C DID Core, section 5.1.1).
	ErrDIDWebDocumentInvalid = common.NewCodedError("did_web_document_invalid", "did:web document is not a usable DID document")
	// ErrDIDWebNoAssertionKey reports that the DID document declares no
	// assertion key this plugin can use. W3C DID Core makes `assertionMethod`
	// the verification relationship for expressing claims, so a document that
	// declares none - or declares only relationships such as `authentication` -
	// resolves to no key rather than to a key used outside its relationship.
	ErrDIDWebNoAssertionKey = common.NewCodedError("did_web_no_assertion_key", "did:web document declares no usable assertionMethod key")
	// ErrDIDWebOperationUnsupported reports an operation the did:web method
	// does not give a resolver: creating or updating the document is the
	// controller's own publication step on their web origin, not something a
	// resolving party can perform.
	ErrDIDWebOperationUnsupported = common.NewCodedError("did_web_operation_unsupported", "did:web profiles cannot be created or updated through this plugin")
)

const (
	// didWebPrefix is the DID scheme and method name of the did:web method.
	didWebPrefix = "did:web:"
	// didWebWellKnownPath is the path the did:web method specification gives a
	// DID whose method-specific identifier is a bare domain.
	didWebWellKnownPath = "/.well-known/did.json"
	// didWebDocumentFilename terminates the path of every other did:web DID.
	didWebDocumentFilename = "did.json"
	// didWebAcceptHeader asks for the representations W3C DID Core registers
	// for a JSON DID document, and for plain JSON, which is what most did:web
	// origins actually serve.
	didWebAcceptHeader = "application/did+json, application/json"
	// defaultDIDDocumentBytes bounds a DID document. A DID document holds a
	// handful of verification methods and service entries; anything larger is
	// a hostile or broken origin, and the cap keeps one request from spending
	// unbounded memory.
	defaultDIDDocumentBytes int64 = 64 << 10
	// defaultDIDHTTPTimeout bounds a DID document retrieval end to end.
	defaultDIDHTTPTimeout = 30 * time.Second
)

// didWebDocumentContentTypes are the media types a did:web origin may label a
// DID document with. The first two are the representations W3C DID Core
// registers for JSON and JSON-LD; the third is the plain JSON type origins
// serving a did.json file usually send.
var didWebDocumentContentTypes = []string{"application/did+json", "application/did+ld+json", "application/json"}

// DIDWebPlugin resolves did:web identifiers by retrieving the DID document the
// method specification places on the identified web origin, and returns the
// document's assertion keys as the profile's verification keys.
//
// The did:web method (https://w3c-ccg.github.io/did-method-web/) derives the
// document URL from the method-specific identifier: the first colon-separated
// part is the domain, with a port written percent-encoded, and every further
// part is a path segment. A bare domain resolves to
// https://<domain>/.well-known/did.json; anything else to
// https://<domain>/<segment>/.../did.json.
//
// Key selection follows W3C DID Core section 5.3: only verification methods
// reachable through the `assertionMethod` relationship are returned, because
// that is the relationship a DID controller declares for expressing claims. A
// method declared solely for `authentication` is never returned, so a key the
// controller published for logging in cannot be mistaken for a key that signs
// credentials. Each returned key keeps the verification method's `id` as its
// KeyID, so a caller can match it against a JWS `kid`.
//
// Nothing here decides whether the DID may be trusted for a given issuer: a
// DID document proves only that its controller published these keys.
type DIDWebPlugin struct {
	// HTTPClient retrieves the DID document. A nil value uses a client with a
	// 30 second timeout. The client's redirect policy is never used: this
	// plugin refuses redirects, so that the origin the identifier names is the
	// only origin that can answer for it.
	HTTPClient *http.Client
	// MaxDocumentBytes bounds the retrieved document. A value of zero or less
	// uses 64 KiB.
	MaxDocumentBytes int64
}

// Create reports that did:web profiles cannot be created by a resolving party.
// Creating one means publishing a document on the web origin the identifier
// names, which happens outside this library.
func (p *DIDWebPlugin) Create(opts ...types.CreateOption) (*types.IdentityProfile, error) {
	return nil, fmt.Errorf("%w: did:web documents are published by their controller", ErrDIDWebOperationUnsupported)
}

// Update reports that did:web profiles cannot be updated by a resolving party,
// for the same reason Create cannot create one.
func (p *DIDWebPlugin) Update(profile *types.IdentityProfile, opts ...types.UpdateOption) (*types.IdentityProfile, error) {
	return nil, fmt.Errorf("%w: did:web documents are updated by their controller", ErrDIDWebOperationUnsupported)
}

// Resolve retrieves the DID document of id and returns its assertion keys.
//
// The retrieval is deliberately narrow: the request is a GET that asks for a
// DID document, redirects are refused so that only the origin named by the
// identifier can answer, the response must be labelled as a DID document or as
// JSON, and the body is bounded before and while it is read. A document whose
// `id` names another DID is refused (W3C DID Core section 5.1.1), because a
// controller's document must identify the DID it describes.
func (p *DIDWebPlugin) Resolve(id string) (*types.IdentityProfile, error) {
	return p.ResolveContext(context.Background(), id)
}

// ResolveContext is Resolve with the document retrieval bounded by ctx, for a
// caller that resolves within a request of its own and must not outlive it.
func (p *DIDWebPlugin) ResolveContext(ctx context.Context, id string) (*types.IdentityProfile, error) {
	documentURL, err := WebDocumentURL(id)
	if err != nil {
		return nil, err
	}

	body, err := p.fetchDocument(ctx, documentURL)
	if err != nil {
		return nil, err
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil || document == nil {
		return nil, fmt.Errorf("%w: body is not a JSON object", ErrDIDWebDocumentInvalid)
	}
	if raw, ok := document["id"]; ok {
		var documentID string
		if err := json.Unmarshal(raw, &documentID); err == nil && documentID != id {
			return nil, fmt.Errorf("%w: document id names another DID", ErrDIDWebDocumentInvalid)
		}
	}

	keys := assertionMethodKeys(document, id)
	if len(keys) == 0 {
		return nil, ErrDIDWebNoAssertionKey
	}

	return &types.IdentityProfile{
		ID:     id,
		TypeID: IDProfileTypeID,
		Keys:   &jose.JSONWebKeySet{Keys: keys},
	}, nil
}

// Validate reports whether profile is a well-formed did:web profile.
//
// It checks the shape only. Unlike did:key, whose key material is carried by
// the identifier itself and can therefore be re-derived offline, a did:web
// profile can only be confirmed against its origin, and a validation call is
// not the place to make a network request: a caller that wants the current
// document calls Resolve.
func (p *DIDWebPlugin) Validate(profile *types.IdentityProfile) error {
	if profile == nil {
		return fmt.Errorf("%w: profile cannot be nil", types.ErrProfileValidation)
	}
	if profile.TypeID != IDProfileTypeID {
		return fmt.Errorf("%w: invalid type ID for did:web profile: %s", types.ErrProfileValidation, profile.TypeID)
	}
	if _, err := WebDocumentURL(profile.ID); err != nil {
		return err
	}
	if profile.Keys == nil || len(profile.Keys.Keys) == 0 {
		return fmt.Errorf("%w: did:web profile must have at least one key", types.ErrInvalidKeys)
	}
	for index := range profile.Keys.Keys {
		key := profile.Keys.Keys[index]
		if !key.Valid() || !key.IsPublic() {
			return fmt.Errorf("%w: key at index %d is not a valid public key", types.ErrInvalidKeys, index)
		}
	}
	return nil
}

// WebDocumentURL reports the URL the did:web method specification derives from
// a did:web identifier, without retrieving anything.
//
// It is exported because the URL is a decision in its own right: a caller that
// will only accept a DID document served by a particular origin - for example
// one that requires the DID to be hosted by the party it is already talking to
// - has to learn the host before a request is made, so that a mismatch costs no
// outbound request at all.
//
// The method-specific identifier is split on ":" and every part is
// percent-decoded, which is how a port reaches the domain part
// (did:web:example.com%3A8443). A part that is empty, that does not decode, or
// that carries a path separator makes the identifier unusable: those are the
// shapes that would let an identifier reach a path other than the one its
// segments spell out.
func WebDocumentURL(did string) (*url.URL, error) {
	if !strings.HasPrefix(did, didWebPrefix) {
		return nil, fmt.Errorf("%w: %q is not a did:web identifier", ErrDIDWebIdentifierInvalid, did)
	}
	methodSpecific := strings.TrimPrefix(did, didWebPrefix)
	if methodSpecific == "" {
		return nil, fmt.Errorf("%w: method-specific identifier is empty", ErrDIDWebIdentifierInvalid)
	}

	parts := strings.Split(methodSpecific, ":")
	for index, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil {
			decoded = ""
		}
		if decoded == "" || strings.ContainsAny(decoded, `/\`) {
			return nil, fmt.Errorf("%w: part %d is empty or carries a path separator", ErrDIDWebIdentifierInvalid, index)
		}
		parts[index] = decoded
	}

	domain := parts[0]
	authority, err := url.Parse("https://" + domain)
	if err != nil || !strings.EqualFold(authority.Host, domain) {
		return nil, fmt.Errorf("%w: domain part is not a usable host", ErrDIDWebIdentifierInvalid)
	}

	path := didWebWellKnownPath
	if segments := parts[1:]; len(segments) > 0 {
		encoded := make([]string, 0, len(segments)+1)
		for _, segment := range segments {
			encoded = append(encoded, encodePathSegment(segment))
		}
		encoded = append(encoded, didWebDocumentFilename)
		path = "/" + strings.Join(encoded, "/")
	}

	documentURL, err := url.Parse("https://" + domain + path)
	if err != nil {
		return nil, fmt.Errorf("%w: identifier does not form a URL", ErrDIDWebIdentifierInvalid)
	}
	return documentURL, nil
}

// pathSegmentUnreserved are the non-alphanumeric characters a did:web path
// segment keeps literally. The set is the one RFC 3986 calls unreserved plus
// the sub-delimiters that need no escaping in a path segment, which is what
// the method specification's reference URL construction leaves untouched.
const pathSegmentUnreserved = "-_.!~*'()"

// encodePathSegment percent-encodes one decoded did:web identifier part for use
// as a path segment, byte by byte over its UTF-8 encoding.
func encodePathSegment(segment string) string {
	var encoded strings.Builder
	for index := 0; index < len(segment); index++ {
		character := segment[index]
		switch {
		case character >= 'A' && character <= 'Z',
			character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			strings.IndexByte(pathSegmentUnreserved, character) >= 0:
			encoded.WriteByte(character)
		default:
			fmt.Fprintf(&encoded, "%%%02X", character)
		}
	}
	return encoded.String()
}

// fetchDocument retrieves documentURL and returns the response body, bounded by
// the configured cap.
func (p *DIDWebPlugin) fetchDocument(ctx context.Context, documentURL *url.URL) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, documentURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: request could not be built", ErrDIDWebDocumentFetchFailed)
	}
	request.Header.Set("Accept", didWebAcceptHeader)

	response, err := p.client().Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed", ErrDIDWebDocumentFetchFailed)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: origin returned HTTP %d", ErrDIDWebDocumentFetchFailed, response.StatusCode)
	}
	contentType := strings.ToLower(response.Header.Get("Content-Type"))
	if !containsAnyMediaType(contentType, didWebDocumentContentTypes) {
		return nil, fmt.Errorf("%w: response is not labelled as a DID document", ErrDIDWebDocumentFetchFailed)
	}
	return readBoundedBody(response, p.maxDocumentBytes(), ErrDIDWebDocumentFetchFailed)
}

// client returns the HTTP client used for retrieval, with redirects refused.
// The caller's client is never mutated: a copy carries the redirect policy, so
// a client shared with other code keeps its own.
func (p *DIDWebPlugin) client() *http.Client {
	base := p.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: defaultDIDHTTPTimeout}
	}
	clone := *base
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &clone
}

func (p *DIDWebPlugin) maxDocumentBytes() int64 {
	if p.MaxDocumentBytes > 0 {
		return p.MaxDocumentBytes
	}
	return defaultDIDDocumentBytes
}

// containsAnyMediaType reports whether the lowercased Content-Type header value
// names one of wanted.
func containsAnyMediaType(contentType string, wanted []string) bool {
	for _, mediaType := range wanted {
		if strings.Contains(contentType, mediaType) {
			return true
		}
	}
	return false
}

// readBoundedBody reads at most max bytes of the response body and refuses an
// empty one.
//
// A declared Content-Length is checked before a single byte is read, so an
// origin that announces an oversized document costs nothing to refuse; the
// streaming read is still bounded, because the declaration is the origin's own
// and may be absent or untrue.
func readBoundedBody(response *http.Response, max int64, sentinel error) ([]byte, error) {
	if declared := response.Header.Get("Content-Length"); declared != "" {
		length, err := strconv.ParseInt(declared, 10, 64)
		if err != nil || length < 0 {
			return nil, fmt.Errorf("%w: Content-Length is not a length", sentinel)
		}
		if length > max {
			return nil, fmt.Errorf("%w: document exceeds the %d byte cap", sentinel, max)
		}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("%w: body could not be read", sentinel)
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("%w: document exceeds the %d byte cap", sentinel, max)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: document is empty", sentinel)
	}
	return body, nil
}

// assertionMethodKeys returns the public keys the DID document declares through
// its `assertionMethod` relationship, in the order W3C DID Core allows them to
// be written: verification methods embedded in `assertionMethod` itself first,
// then the entries of `verificationMethod` that `assertionMethod` refers to.
//
// A document with no `assertionMethod` yields nothing, even when it carries
// verification methods under another relationship.
func assertionMethodKeys(document map[string]json.RawMessage, did string) []jose.JSONWebKey {
	assertionMethods := rawArray(document["assertionMethod"])
	if len(assertionMethods) == 0 {
		return nil
	}

	referenced := make(map[string]struct{}, len(assertionMethods))
	for _, entry := range assertionMethods {
		if id := verificationMethodReference(entry); id != "" {
			referenced[id] = struct{}{}
		}
	}

	keys := make([]jose.JSONWebKey, 0, len(assertionMethods))
	for _, entry := range assertionMethods {
		if key, ok := verificationMethodKey(entry, did); ok {
			keys = append(keys, key)
		}
	}
	for _, entry := range rawArray(document["verificationMethod"]) {
		id := verificationMethodReference(entry)
		if id == "" {
			continue
		}
		if _, wanted := referenced[id]; !wanted {
			continue
		}
		if key, ok := verificationMethodKey(entry, did); ok {
			keys = append(keys, key)
		}
	}
	return keys
}

// verificationMethodReference reports the verification method identifier an
// `assertionMethod` or `verificationMethod` entry carries, whether the entry is
// the bare identifier string W3C DID Core allows as a reference or an embedded
// verification method object.
func verificationMethodReference(entry json.RawMessage) string {
	var id string
	if err := json.Unmarshal(entry, &id); err == nil {
		return id
	}
	var method struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(entry, &method); err != nil {
		return ""
	}
	return method.ID
}

// verificationMethodKey reports the public key an embedded verification method
// carries, when the method belongs to did and publishes its key as a JWK.
//
// The identifier must be a DID URL of did itself (RFC-style `<did>#<fragment>`),
// so a document cannot hand out a key that belongs to some other DID, and the
// key keeps that identifier as its KeyID so a caller can match it against a JWS
// `kid`. A method that publishes its key in another format - publicKeyMultibase,
// for instance - is skipped rather than refused, because a document may mix
// representations and the other entries are still usable.
func verificationMethodKey(entry json.RawMessage, did string) (jose.JSONWebKey, bool) {
	var method struct {
		ID           string          `json:"id"`
		PublicKeyJWK json.RawMessage `json:"publicKeyJwk"`
	}
	if err := json.Unmarshal(entry, &method); err != nil {
		return jose.JSONWebKey{}, false
	}
	if !strings.HasPrefix(method.ID, did+"#") {
		return jose.JSONWebKey{}, false
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(method.PublicKeyJWK, &probe); err != nil || probe == nil {
		return jose.JSONWebKey{}, false
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(method.PublicKeyJWK); err != nil {
		return jose.JSONWebKey{}, false
	}
	if !key.Valid() || !key.IsPublic() {
		return jose.JSONWebKey{}, false
	}
	key.KeyID = method.ID
	return key, true
}

// rawArray reports the elements of a JSON array member, or nothing when the
// member is absent or is not an array.
func rawArray(raw json.RawMessage) []json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err != nil {
		return nil
	}
	return elements
}
