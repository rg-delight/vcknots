package x509

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const MaxCRLBytes = 8 * 1024 * 1024
const maxCRLCacheAge = 24 * time.Hour

// CRLCache is a caller-owned durable DER cache, not a status/verdict cache.
// Load errors are treated as misses; Store errors do not weaken verification.
type CRLCache interface {
	Load(ctx context.Context, url string, now time.Time) (*CRLCacheEntry, error)
	Store(ctx context.Context, entry CRLCacheEntry) error
}

type CRLCacheEntry struct {
	URL        string
	DER        []byte
	ThisUpdate time.Time
	NextUpdate time.Time
	FetchedAt  time.Time
	ExpiresAt  time.Time
}

type crlDownload struct {
	done      chan struct{}
	der       []byte
	fetchedAt time.Time
	network   bool
	err       *CRLCheckError
	remember  sync.Once
}

func (c *CRLChecker) load(ctx context.Context, location string, now time.Time) (*crlDownload, *CRLCheckError) {
	c.mu.Lock()
	loaded, exists := c.loads[location]
	if !exists {
		loaded = &crlDownload{done: make(chan struct{})}
		c.loads[location] = loaded
	}
	c.mu.Unlock()
	if exists {
		select {
		case <-loaded.done:
			return loaded, loaded.err
		case <-ctx.Done():
			return nil, &CRLCheckError{Kind: CRLErrorFetch, Reason: "CRL wait cancelled", Err: ctx.Err()}
		}
	}
	defer close(loaded.done)
	if c.cache != nil {
		cached, err := c.cache.Load(ctx, location, now)
		if err == nil && cached != nil && cacheEntryCurrent(cached, location, now) {
			if len(cached.DER) == 0 || len(cached.DER) > MaxCRLBytes {
				loaded.err = &CRLCheckError{Kind: CRLErrorParse, Reason: "cached CRL is empty or exceeds 8 MiB"}
				return loaded, loaded.err
			}
			loaded.der = append([]byte(nil), cached.DER...)
			loaded.fetchedAt = cached.FetchedAt
			return loaded, nil
		}
	}
	if err := ctx.Err(); err != nil {
		loaded.err = &CRLCheckError{Kind: CRLErrorFetch, Reason: "CRL request cancelled", Err: err}
		return loaded, loaded.err
	}
	c.mu.Lock()
	if c.fetches >= c.maxFetches {
		c.mu.Unlock()
		loaded.err = &CRLCheckError{Kind: CRLErrorBudget, Reason: fmt.Sprintf("CRL fetch budget of %d exhausted", c.maxFetches)}
		return loaded, loaded.err
	}
	c.fetches++
	c.mu.Unlock()
	der, err := c.fetch(ctx, location)
	if err != nil {
		loaded.err = &CRLCheckError{Kind: CRLErrorFetch, Reason: "CRL download failed", Err: err}
		return loaded, loaded.err
	}
	loaded.der, loaded.fetchedAt, loaded.network = der, now, true
	return loaded, nil
}

func cacheEntryCurrent(entry *CRLCacheEntry, location string, now time.Time) bool {
	return entry.URL == location && !entry.FetchedAt.IsZero() && !now.Before(entry.FetchedAt) &&
		!now.After(entry.FetchedAt.Add(maxCRLCacheAge)) && !entry.ExpiresAt.IsZero() &&
		!now.After(entry.ExpiresAt) && !entry.NextUpdate.IsZero() && !now.After(entry.NextUpdate)
}

func (c *CRLChecker) remember(ctx context.Context, location string, loaded *crlDownload, crl *x509.RevocationList) {
	if c.cache == nil || !loaded.network {
		return
	}
	loaded.remember.Do(func() {
		expiresAt := loaded.fetchedAt.Add(maxCRLCacheAge)
		if crl.NextUpdate.Before(expiresAt) {
			expiresAt = crl.NextUpdate
		}
		_ = c.cache.Store(ctx, CRLCacheEntry{URL: location, DER: append([]byte(nil), loaded.der...),
			ThisUpdate: crl.ThisUpdate, NextUpdate: crl.NextUpdate,
			FetchedAt: loaded.fetchedAt, ExpiresAt: expiresAt})
	})
}

func canonicalCRLURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") ||
		u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.TrimSpace(raw) != raw {
		return "", fmt.Errorf("CRL distribution point requires an absolute http(s) URL without userinfo or fragment")
	}
	for _, value := range raw {
		if value < 0x21 || value > 0x7e {
			return "", fmt.Errorf("CRL URI is not IA5 text")
		}
	}
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		u.Host = strings.TrimSuffix(u.Host, ":"+u.Port())
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func (c *CRLChecker) fetch(ctx context.Context, location string) ([]byte, error) {
	if _, err := canonicalCRLURL(location); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/pkix-crl, application/octet-stream;q=0.9, */*;q=0.1")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("CRL returned HTTP %d; redirects are not followed", response.StatusCode)
	}
	if declared := response.Header.Get("Content-Length"); declared != "" {
		length, err := strconv.ParseInt(declared, 10, 64)
		if err != nil || length < 0 || length > MaxCRLBytes {
			return nil, fmt.Errorf("CRL Content-Length is invalid or exceeds 8 MiB")
		}
	}
	der, err := io.ReadAll(io.LimitReader(response.Body, MaxCRLBytes+1))
	if err != nil {
		return nil, err
	}
	if len(der) == 0 || len(der) > MaxCRLBytes {
		return nil, fmt.Errorf("CRL body is empty or exceeds 8 MiB")
	}
	return der, nil
}
