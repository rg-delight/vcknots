package x509

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// CRLCheckErrorKind distinguishes an unavailable status from a revoked certificate.
type CRLCheckErrorKind string

const (
	CRLErrorUnsupported CRLCheckErrorKind = "unsupported"
	CRLErrorBudget      CRLCheckErrorKind = "budget"
	CRLErrorFetch       CRLCheckErrorKind = "fetch"
	CRLErrorParse       CRLCheckErrorKind = "parse"
	CRLErrorIssuer      CRLCheckErrorKind = "issuer"
	CRLErrorSignature   CRLCheckErrorKind = "signature"
	CRLErrorStale       CRLCheckErrorKind = "stale"
	CRLErrorScope       CRLCheckErrorKind = "scope"
	CRLErrorRevoked     CRLCheckErrorKind = "revoked"
)

// CRLCheckError retains the cause for errors.Is/errors.As and observability.
type CRLCheckError struct {
	Kind         CRLCheckErrorKind
	URL          string
	Subject      string
	SerialNumber string
	Reason       string
	Err          error
}

func (e *CRLCheckError) Error() string {
	return fmt.Sprintf("certificate revocation %s: %s", e.Kind, e.Reason)
}

func (e *CRLCheckError) Unwrap() error { return e.Err }

// CRLCheckResult does not describe certificates without mechanisms as checked.
type CRLCheckResult struct {
	CheckedCertificates     int
	NoMechanismCertificates int
}

// CRLCheckerOptions supplies the guarded outbound client and optional durable
// DER cache. A checker belongs to one verification session, never a global pool.
type CRLCheckerOptions struct {
	HTTPClient    *http.Client
	Cache         CRLCache
	MaxFetches    int
	FetchTimeout  time.Duration
	RequireStatus bool
}

// CRLChecker shares downloads (including failures) between candidate paths.
// PKIX validation must succeed before a caller supplies a path to Check.
type CRLChecker struct {
	client        *http.Client
	cache         CRLCache
	maxFetches    int
	fetchTimeout  time.Duration
	requireStatus bool
	mu            sync.Mutex
	fetches       int
	loads         map[string]*crlDownload
}

func NewCRLChecker(options CRLCheckerOptions) (*CRLChecker, error) {
	if options.HTTPClient == nil {
		return nil, fmt.Errorf("CRL HTTP client is required")
	}
	if options.MaxFetches < 0 || options.FetchTimeout < 0 {
		return nil, fmt.Errorf("CRL fetch budget and timeout must not be negative")
	}
	if options.MaxFetches == 0 {
		options.MaxFetches = 16
	}
	if options.FetchTimeout == 0 {
		options.FetchTimeout = 10 * time.Second
	}
	client := *options.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &CRLChecker{
		client: &client, cache: options.Cache, maxFetches: options.MaxFetches,
		fetchTimeout: options.FetchTimeout, requireStatus: options.RequireStatus,
		loads: make(map[string]*crlDownload),
	}, nil
}

// Check verifies revocation below the anchor in a leaf-first, anchor-last path.
// It never follows OCSP and never treats missing mechanisms as a CRL verdict.
func (c *CRLChecker) Check(ctx context.Context, path []*x509.Certificate, now time.Time) (CRLCheckResult, error) {
	result := CRLCheckResult{}
	if len(path) == 0 || now.IsZero() {
		return result, &CRLCheckError{Kind: CRLErrorUnsupported, Reason: "nonempty path and verification time are required"}
	}
	for _, cert := range path {
		if cert == nil || cert.SerialNumber == nil {
			return result, &CRLCheckError{Kind: CRLErrorUnsupported, Reason: "path contains an invalid certificate"}
		}
	}
	for i, cert := range path[:len(path)-1] {
		if err := ctx.Err(); err != nil {
			return result, crlError(CRLErrorFetch, cert, "", "verification context ended", err)
		}
		urls, advertised, err := certificateCRLURLs(cert)
		if err != nil {
			return result, crlError(CRLErrorUnsupported, cert, "", err.Error(), err)
		}
		if len(urls) == 0 {
			ocsp, err := certificateAdvertisesOCSP(cert)
			if err != nil || advertised || ocsp || c.requireStatus {
				return result, crlError(CRLErrorUnsupported, cert, "", "no usable CRL distribution point; OCSP is not consulted", err)
			}
			result.NoMechanismCertificates++
			continue
		}
		issuer := path[i+1]
		if issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
			return result, crlError(CRLErrorIssuer, cert, "", "issuer has no cRLSign key usage", nil)
		}
		var lastErr *CRLCheckError
		for _, location := range urls {
			lastErr = c.checkCRL(ctx, cert, issuer, location, now)
			if lastErr == nil {
				break
			}
			if lastErr.Kind == CRLErrorRevoked || lastErr.Kind == CRLErrorBudget {
				return result, lastErr
			}
		}
		if lastErr != nil {
			return result, lastErr
		}
		result.CheckedCertificates++
	}
	return result, nil
}

func crlError(kind CRLCheckErrorKind, cert *x509.Certificate, location, reason string, err error) *CRLCheckError {
	return &CRLCheckError{Kind: kind, URL: location, Subject: cert.Subject.String(),
		SerialNumber: cert.SerialNumber.Text(16), Reason: reason, Err: err}
}

func (c *CRLChecker) checkCRL(ctx context.Context, cert, issuer *x509.Certificate, location string, now time.Time) *CRLCheckError {
	loaded, loadErr := c.load(ctx, location, now)
	if loadErr != nil {
		return crlError(loadErr.Kind, cert, location, loadErr.Reason, loadErr.Err)
	}
	crl, err := parseStrictCRL(loaded.der)
	if err != nil {
		return crlError(CRLErrorParse, cert, location, "CRL could not be parsed", err)
	}
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) ||
		(len(crl.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 && !bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId)) {
		return crlError(CRLErrorIssuer, cert, location, "CRL issuer does not match the certificate issuer", nil)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return crlError(CRLErrorSignature, cert, location, "CRL issuer signature does not verify", err)
	}
	if crl.NextUpdate.IsZero() || now.Before(crl.ThisUpdate) || now.After(crl.NextUpdate) {
		return crlError(CRLErrorStale, cert, location, "CRL has no nextUpdate or is not current", nil)
	}
	if err := checkCRLExtensions(crl); err != nil {
		return crlError(CRLErrorUnsupported, cert, location, err.Error(), err)
	}
	// A cache stores issuer-signed, current, understood DER, including a CRL
	// that may be out of scope for this particular certificate. Every use
	// verifies it again; neither scope nor non-revocation is cached.
	c.remember(ctx, location, loaded, crl)
	if err := checkCRLScope(crl, cert, location); err != nil {
		return crlError(CRLErrorScope, cert, location, err.Error(), err)
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return crlError(CRLErrorRevoked, cert, location, "certificate serial is listed as revoked", nil)
		}
	}
	return nil
}
