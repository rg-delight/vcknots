package oid4vp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// Sealed admissions.
//
// A Wallet asks the Holder for consent between admitting a request and
// answering it. An integrator whose calls are stateless cannot keep the
// *AdmittedRequest across that gap, and parsing the Request Object again as a
// Request Object passed by value is refused where the profile requires
// delivery by reference (HAIP 1.0 §5.1, Options.RequireSignedRequestByReference):
// only a fetch by this library establishes that delivery.
//
// A sealed admission carries that fact across the gap without weakening the
// rule. Seal records what the first admission observed - the Request Object
// as fetched from request_uri, the delivery by reference, the wallet_nonce the
// library sent for it, the outer client_id, the instant it was authenticated
// at and the profile it was admitted under - and seals the record with
// HMAC-SHA256 under a key only the caller holds. ReadmitRequest (and
// ReadmitDraft24Request) accept the record only when the seal verifies under
// that key, and then authenticate the Request Object again: its signature, the
// client authentication its Client Identifier Prefix selects, the wallet_nonce
// echo and every profile option, on the clock of the first admission. A
// Request Object handed over by value without a seal is refused exactly as
// before. Nothing on the wire changes: the Verifier sees one request_uri
// fetch and one response.
//
// The record is versioned: "v1." followed by the base64url JSON record and
// the base64url HMAC-SHA256 tag, separated by ".". The tag covers a label
// naming the version and the record, so a record is never read under a
// version it was not sealed for.

// MinSealKeyBytes is the shortest key Seal and the re-admission methods
// accept: the output length of SHA-256, below which RFC 2104 Section 3
// discourages HMAC keys.
const MinSealKeyBytes = 32

const (
	sealedAdmissionVersion = "v1"
	// sealedAdmissionLabel is MACed before the record, so a tag made for
	// another purpose or another version under the same key never verifies.
	sealedAdmissionLabel = "vcknots/oid4vp/sealed-admission/v1"
	// maxSealedAdmissionBytes bounds a sealed admission before it is decoded:
	// a record holds at most one bounded Request Object.
	maxSealedAdmissionBytes = 2 * maxRequestObjectBytes

	sealedWireOpenID4VP1 = "openid4vp-1.0"
	sealedWireDraft24    = "openid4vp-draft-24"
)

var (
	// ErrSealKeyTooShort reports a sealing key shorter than MinSealKeyBytes.
	ErrSealKeyTooShort = common.NewCodedError("sealed_admission_key_too_short", "the sealed admission key is shorter than 32 bytes")
	// ErrAdmissionNotSealable reports a handle whose admission cannot be
	// sealed: its Request Object did not come from a request_uri fetch by this
	// library (it was passed by value, or the request was plain parameters or
	// a Digital Credentials API invocation). Such a request has no delivery
	// fact to carry; a caller keeps its Request Object or parameters instead.
	ErrAdmissionNotSealable = common.NewCodedError("admission_not_sealable", "only a Request Object the presenter fetched from request_uri can be sealed")
	// ErrSealedAdmissionInvalid reports a sealed admission that is not
	// accepted: malformed, of an unknown version, altered, sealed under
	// another key, or recorded for another protocol version or profile than
	// the re-admission runs under.
	ErrSealedAdmissionInvalid = common.NewCodedError("sealed_admission_invalid", "the sealed admission is malformed, altered, sealed with another key or recorded for another profile")
)

// sealedAdmissionRecord is the sealed JSON record.
type sealedAdmissionRecord struct {
	Wire          string `json:"wire"`
	Profile       string `json:"profile"`
	Delivery      string `json:"delivery"`
	ClientID      string `json:"client_id"`
	WalletNonce   string `json:"wallet_nonce,omitempty"`
	AdmittedAt    string `json:"admitted_at"`
	RequestObject string `json:"request_object"`
}

var (
	_ types.RequestReadmitter        = (*Oid4vpPresenter)(nil)
	_ types.Draft24RequestReadmitter = (*Oid4vpPresenter)(nil)
)

// Seal returns the sealed record of this admission under key, for a caller
// that answers the request in a later, stateless call. The record holds the
// Request Object as fetched from request_uri, the delivery by reference, the
// wallet_nonce sent for it, the outer client_id, the instant it was
// authenticated at and the profile it was admitted under, and is sealed with
// HMAC-SHA256. ReadmitRequest (or ReadmitDraft24Request) accepts it only under
// the same key, so a profile that requires delivery by reference (HAIP 1.0
// §5.1) still refuses a Request Object handed over by value without a seal.
//
// Only a request whose Request Object this library fetched from request_uri
// can be sealed (ErrAdmissionNotSealable). key must hold at least
// MinSealKeyBytes bytes (ErrSealKeyTooShort); the caller keeps it secret and
// hands the same key to the re-admission.
//
// The record contains the Request Object, which is readable to whoever holds
// the sealed value; the seal protects its integrity, not its confidentiality.
func (r *AdmittedRequest) Seal(key []byte) (types.SealedAdmission, error) {
	if len(key) < MinSealKeyBytes {
		return "", ErrSealKeyTooShort
	}
	if r == nil || r.req == nil || r.admission.source != sourceReference || r.requestObject == "" || r.admission.admittedAt.IsZero() {
		return "", ErrAdmissionNotSealable
	}
	record := sealedAdmissionRecord{
		Wire:          sealedWireName(r.wire),
		Profile:       r.admission.profile,
		Delivery:      sourceReference.delivery(),
		ClientID:      r.admission.outerClientID,
		WalletNonce:   r.admission.walletNonce,
		AdmittedAt:    r.admission.admittedAt.UTC().Format(time.RFC3339Nano),
		RequestObject: r.requestObject,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("failed to encode the sealed admission: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(encoded)
	tag := base64.RawURLEncoding.EncodeToString(sealedAdmissionTag(key, body))
	return types.SealedAdmission(sealedAdmissionVersion + "." + body + "." + tag), nil
}

// ReadmitRequest re-admits an OpenID4VP 1.0 request from a sealed admission
// (see AdmittedRequest.Seal). The seal must verify under key and name this
// presenter's profile; the Request Object is then authenticated again as the
// one this library fetched from request_uri, with the wallet_nonce it sent,
// on the clock of the first admission, so an expiry that passed since then
// does not refuse it (RequestObjectVerification.ExpiresAt reports it). Every
// other check runs again, a certificate chain and its revocation included.
// The result is an *AdmittedRequest, which can be sealed again.
func (p *Oid4vpPresenter) ReadmitRequest(ctx context.Context, sealed types.SealedAdmission, key []byte) (types.AdmittedRequest, error) {
	return asAdmitted(p.readmitRequest(ctx, sealed, key))
}

// ReadmitDraft24Request is ReadmitRequest for a Draft 24 request.
func (p *Oid4vpPresenter) ReadmitDraft24Request(ctx context.Context, sealed types.SealedAdmission, key []byte) (types.AdmittedRequest, error) {
	return asAdmitted(p.readmitDraft24Request(ctx, sealed, key))
}

func (p *Oid4vpPresenter) readmitRequest(ctx context.Context, sealed types.SealedAdmission, key []byte) (*AdmittedRequest, error) {
	if _, err := p.profileOptions(); err != nil {
		return nil, err
	}
	record, admittedAt, err := p.openSealedAdmission(sealed, key, wireOpenID4VP1)
	if err != nil {
		return nil, err
	}
	builder, err := p.newRequestBuilder(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := parseOID4VPClientID(record.ClientID); err != nil {
		return nil, fmt.Errorf("%w: the sealed client_id is not an OpenID4VP 1.0 Client Identifier: %w", ErrSealedAdmissionInvalid, err)
	}
	builder.expectedClientID = record.ClientID
	builder.replayReference(record.WalletNonce, admittedAt)
	builder.withRequestObject(record.RequestObject)
	return p.finishParse(&builder.requestCore, builder.Build, wireOpenID4VP1)
}

func (p *Oid4vpPresenter) readmitDraft24Request(ctx context.Context, sealed types.SealedAdmission, key []byte) (*AdmittedRequest, error) {
	if _, err := p.profileOptions(); err != nil {
		return nil, err
	}
	record, admittedAt, err := p.openSealedAdmission(sealed, key, wireDraft24)
	if err != nil {
		return nil, err
	}
	builder, err := p.newDraft24RequestBuilder(ctx)
	if err != nil {
		return nil, err
	}
	if record.ClientID != "" {
		if _, err := parseDraft24ClientID(record.ClientID); err != nil {
			return nil, fmt.Errorf("%w: the sealed client_id is not a Draft 24 Client Identifier: %w", ErrSealedAdmissionInvalid, err)
		}
	}
	builder.expectedClientID = record.ClientID
	builder.replayReference(record.WalletNonce, admittedAt)
	builder.withRequestObject(record.RequestObject)
	return p.finishParse(&builder.requestCore, builder.Build, wireDraft24)
}

// replayReference sets up a parse to authenticate a sealed Request Object as
// the one fetched from request_uri, with the wallet_nonce sent for it, at the
// instant of the sealed admission.
func (c *requestCore) replayReference(walletNonce string, admittedAt time.Time) {
	c.requestSource = sourceReference
	c.sentWalletNonce = walletNonce
	c.readmitAt = admittedAt
}

// openSealedAdmission verifies sealed under key and returns its record, which
// must be for wire and for the profile this presenter admits wire under.
func (p *Oid4vpPresenter) openSealedAdmission(sealed types.SealedAdmission, key []byte, wire wireContract) (*sealedAdmissionRecord, time.Time, error) {
	if len(key) < MinSealKeyBytes {
		return nil, time.Time{}, ErrSealKeyTooShort
	}
	invalid := func(reason string) (*sealedAdmissionRecord, time.Time, error) {
		return nil, time.Time{}, fmt.Errorf("%w: %s", ErrSealedAdmissionInvalid, reason)
	}
	if len(sealed) > maxSealedAdmissionBytes {
		return invalid("the sealed admission is too large")
	}
	version, rest, found := strings.Cut(string(sealed), ".")
	if !found || version != sealedAdmissionVersion {
		return invalid("the sealed admission is not of version " + sealedAdmissionVersion)
	}
	body, encodedTag, found := strings.Cut(rest, ".")
	if !found || strings.Contains(encodedTag, ".") {
		return invalid("the sealed admission is malformed")
	}
	tag, err := base64.RawURLEncoding.DecodeString(encodedTag)
	if err != nil || !hmac.Equal(tag, sealedAdmissionTag(key, body)) {
		return invalid("the seal does not verify under this key")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return invalid("the sealed record is not base64url")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record sealedAdmissionRecord
	if err := decoder.Decode(&record); err != nil {
		return invalid("the sealed record is not a v1 record")
	}
	switch {
	case record.Wire != sealedWireName(wire):
		return invalid(fmt.Sprintf("the admission was sealed for %s, not %s", record.Wire, sealedWireName(wire)))
	case record.Profile != p.admissionProfile(wire):
		return invalid(fmt.Sprintf("the admission was sealed under the %s profile, not %s", record.Profile, p.admissionProfile(wire)))
	case record.Delivery != sourceReference.delivery():
		return invalid("the sealed Request Object was not delivered by reference")
	case record.RequestObject == "":
		return invalid("the sealed record carries no Request Object")
	}
	admittedAt, err := time.Parse(time.RFC3339Nano, record.AdmittedAt)
	if err != nil || admittedAt.IsZero() {
		return invalid("the sealed admission time is malformed")
	}
	return &record, admittedAt, nil
}

// sealedAdmissionTag is the HMAC-SHA256 tag of a v1 record body under key.
func sealedAdmissionTag(key []byte, body string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(sealedAdmissionLabel))
	mac.Write([]byte{0})
	mac.Write([]byte(body))
	return mac.Sum(nil)
}

// sealedWireName names a wire contract in a sealed record.
func sealedWireName(wire wireContract) string {
	if wire == wireDraft24 {
		return sealedWireDraft24
	}
	return sealedWireOpenID4VP1
}

// admissionProfile is the name of the profile p admits a request of wire
// under: Draft 24 for the Draft 24 contract, which the presenter's profile
// does not apply to, and the presenter's profile otherwise.
func (p *Oid4vpPresenter) admissionProfile(wire wireContract) string {
	if wire == wireDraft24 {
		return profile.Draft24().Name()
	}
	return p.Profile.Name()
}
