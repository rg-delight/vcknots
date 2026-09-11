package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

func mustURIField(t *testing.T, raw string) common.URIField {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", raw, err)
	}
	return common.URIField(*parsed)
}

func noopProofFactory(string) (string, error) {
	return "dpop-proof", nil
}

// §8.3.1.2: a 400 invalid_proof response must surface as a typed error so the
// caller can branch with errors.Is while still seeing the HTTP status.
func TestCredentialEndpointError_InvalidProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_proof",
			"error_description": "x",
		})
	}))
	defer server.Close()

	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	_, err := receiver.PostCredentialEndpointWithDpopRetry(mustURIField(t, server.URL), "access-1", []byte("{}"), "application/json", noopProofFactory)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, types.ErrInvalidProof) {
		t.Fatalf("errors.Is(ErrInvalidProof) = false, err = %v", err)
	}
	var endpointErr *types.CredentialEndpointError
	if !errors.As(err, &endpointErr) {
		t.Fatalf("errors.As(*CredentialEndpointError) = false, err = %v", err)
	}
	if endpointErr.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want 400", endpointErr.StatusCode)
	}
	if endpointErr.Description != "x" {
		t.Errorf("Description = %q, want %q", endpointErr.Description, "x")
	}
	if endpointErr.Code != "invalid_proof" {
		t.Errorf("Code = %q, want invalid_proof", endpointErr.Code)
	}
}

// A non-JSON body must still produce a typed error carrying the HTTP status.
func TestCredentialEndpointError_NonJSONKeepsStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	_, err := receiver.PostCredentialEndpointWithDpopRetry(mustURIField(t, server.URL), "access-1", []byte("{}"), "application/json", noopProofFactory)
	var endpointErr *types.CredentialEndpointError
	if !errors.As(err, &endpointErr) {
		t.Fatalf("errors.As(*CredentialEndpointError) = false, err = %v", err)
	}
	if endpointErr.StatusCode != http.StatusForbidden || endpointErr.Code != "" {
		t.Fatalf("error = %#v, want status 403 with empty code", endpointErr)
	}
}

// §8.3.1 / §8.3.1.2: on invalid_nonce the wallet fetches a fresh c_nonce and
// retries exactly once, rebuilding the proof with the new nonce.
func TestPostCredentialEndpointWithNonceRetry_Success(t *testing.T) {
	var credentialCalls int
	var buildNonces []string
	nonceCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nonce":
			nonceCalls++
			_ = mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "fresh-nonce"})
		case "/credential":
			credentialCalls++
			if credentialCalls == 1 {
				_ = mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_nonce"})
				return
			}
			_ = mockserver.JSONResponse(w, http.StatusOK, map[string]string{"credential": "credential-jwt"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	nonceEndpoint := mustURIField(t, server.URL+"/nonce")
	response, usedNonce, err := receiver.PostCredentialEndpointWithNonceRetry(
		mustURIField(t, server.URL+"/credential"),
		"access-1",
		&nonceEndpoint,
		"initial-nonce",
		func(cNonce string) ([]byte, string, error) {
			buildNonces = append(buildNonces, cNonce)
			return []byte(`{"proof":"` + cNonce + `"}`), "application/json", nil
		},
		noopProofFactory,
	)
	if err != nil {
		t.Fatalf("PostCredentialEndpointWithNonceRetry() error = %v", err)
	}
	if string(response.Body) != `{"credential":"credential-jwt"}`+"\n" {
		t.Fatalf("response body = %q", string(response.Body))
	}
	if usedNonce != "fresh-nonce" {
		t.Fatalf("usedNonce = %q, want fresh-nonce", usedNonce)
	}
	if nonceCalls != 1 {
		t.Fatalf("nonce endpoint calls = %d, want 1", nonceCalls)
	}
	if credentialCalls != 2 {
		t.Fatalf("credential endpoint calls = %d, want 2", credentialCalls)
	}
	if len(buildNonces) != 2 || buildNonces[0] != "initial-nonce" || buildNonces[1] != "fresh-nonce" {
		t.Fatalf("build nonces = %#v", buildNonces)
	}
}

func TestPostCredentialEndpointWithNonceRetry_SecondInvalidNonceStops(t *testing.T) {
	credentialCalls := 0
	nonceCalls := 0
	buildCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nonce":
			nonceCalls++
			_ = mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "fresh-nonce"})
		case "/credential":
			credentialCalls++
			_ = mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_nonce"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	nonceEndpoint := mustURIField(t, server.URL+"/nonce")
	_, _, err := receiver.PostCredentialEndpointWithNonceRetry(
		mustURIField(t, server.URL+"/credential"),
		"access-1",
		&nonceEndpoint,
		"initial-nonce",
		func(cNonce string) ([]byte, string, error) {
			buildCalls++
			return []byte("{}"), "application/json", nil
		},
		noopProofFactory,
	)
	if !errors.Is(err, types.ErrInvalidNonce) {
		t.Fatalf("error = %v, want invalid_nonce", err)
	}
	if credentialCalls != 2 {
		t.Fatalf("credential endpoint calls = %d, want 2 (no third attempt)", credentialCalls)
	}
	if nonceCalls != 1 {
		t.Fatalf("nonce endpoint calls = %d, want 1", nonceCalls)
	}
	if buildCalls != 2 {
		t.Fatalf("build calls = %d, want 2", buildCalls)
	}
}

func TestPostCredentialEndpointWithNonceRetry_NoNonceEndpoint(t *testing.T) {
	credentialCalls := 0
	buildCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credentialCalls++
		_ = mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_nonce"})
	}))
	defer server.Close()

	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	_, usedNonce, err := receiver.PostCredentialEndpointWithNonceRetry(
		mustURIField(t, server.URL+"/credential"),
		"access-1",
		nil,
		"initial-nonce",
		func(cNonce string) ([]byte, string, error) {
			buildCalls++
			return []byte("{}"), "application/json", nil
		},
		noopProofFactory,
	)
	if !errors.Is(err, types.ErrInvalidNonce) {
		t.Fatalf("error = %v, want invalid_nonce", err)
	}
	if credentialCalls != 1 || buildCalls != 1 {
		t.Fatalf("credential calls = %d, build calls = %d; want 1 and 1", credentialCalls, buildCalls)
	}
	if usedNonce != "initial-nonce" {
		t.Fatalf("usedNonce = %q, want initial-nonce", usedNonce)
	}
}

// §9.1/§9.2: a deferred response carries transaction_id and interval; the
// interval must survive JSON decoding.
func TestDecodeDeferredCredentialResponse_Interval(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"transaction_id":"t","interval":5}`))
	}))
	defer server.Close()

	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	response, err := receiver.RequestDeferredCredentialWithDpopRetry(
		mustURIField(t, server.URL+"/deferred"),
		"access-1",
		types.DeferredCredentialRequest{TransactionID: "t"},
		noopProofFactory,
	)
	if err != nil {
		t.Fatalf("RequestDeferredCredentialWithDpopRetry() error = %v", err)
	}
	if response.TransactionID != "t" || response.Interval != 5 {
		t.Fatalf("response = %#v, want interval 5", response)
	}
}

// §14.6: batch_size defaults to one when absent or non-positive.
func TestCredentialIssuerMetadata_BatchSize(t *testing.T) {
	withBatch := &types.CredentialIssuerMetadata{
		BatchCredentialIssuance: &types.BatchCredentialIssuance{BatchSize: 3},
	}
	if got := withBatch.BatchSize(); got != 3 {
		t.Errorf("BatchSize() = %d, want 3", got)
	}

	absent := &types.CredentialIssuerMetadata{}
	if got := absent.BatchSize(); got != 1 {
		t.Errorf("BatchSize() with no metadata = %d, want 1", got)
	}

	nonPositive := &types.CredentialIssuerMetadata{
		BatchCredentialIssuance: &types.BatchCredentialIssuance{BatchSize: 0},
	}
	if got := nonPositive.BatchSize(); got != 1 {
		t.Errorf("BatchSize() with 0 = %d, want 1", got)
	}

	var nilMetadata *types.CredentialIssuerMetadata
	if got := nilMetadata.BatchSize(); got != 1 {
		t.Errorf("BatchSize() on nil = %d, want 1", got)
	}

	raw := []byte(`{"credential_issuer":"https://issuer.example","batch_credential_issuance":{"batch_size":3}}`)
	var decoded types.CredentialIssuerMetadata
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	if got := decoded.BatchSize(); got != 3 {
		t.Errorf("decoded BatchSize() = %d, want 3", got)
	}
}

// §8.2: credential_response_encryption is exactly jwk+enc (+zip), with no
// top-level alg; enc picks the first value the library can decrypt.
func TestCredentialResponseEncryptionParameters(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	jwk := &jose.JSONWebKey{Key: &key.PublicKey, Algorithm: string(jose.ECDH_ES)}

	metadata := &types.CredentialIssuerMetadata{
		CredentialResponseEncryption: &types.CredentialResponseEncryption{
			EncValuesSupported: []string{"A128GCM"},
		},
	}
	params, err := CredentialResponseEncryptionParameters(metadata, jwk)
	if err != nil {
		t.Fatalf("CredentialResponseEncryptionParameters() error = %v", err)
	}
	if _, ok := params["alg"]; ok {
		t.Errorf("params must not contain a top-level alg: %#v", params)
	}
	if params["enc"] != "A128GCM" {
		t.Errorf("enc = %v, want A128GCM", params["enc"])
	}
	if _, ok := params["zip"]; ok {
		t.Errorf("zip must be absent when not advertised: %#v", params)
	}
	if _, ok := params["jwk"]; !ok {
		t.Errorf("jwk must be present: %#v", params)
	}

	// First unsupported value is skipped in favor of the first supported one.
	metadata.CredentialResponseEncryption.EncValuesSupported = []string{"unsupported-enc", "A256GCM"}
	params, err = CredentialResponseEncryptionParameters(metadata, jwk)
	if err != nil {
		t.Fatalf("CredentialResponseEncryptionParameters() error = %v", err)
	}
	if params["enc"] != "A256GCM" {
		t.Errorf("enc = %v, want A256GCM", params["enc"])
	}

	// zip appears only when zip_values_supported advertises DEF.
	metadata.CredentialResponseEncryption.ZipValuesSupported = []string{"DEF"}
	params, err = CredentialResponseEncryptionParameters(metadata, jwk)
	if err != nil {
		t.Fatalf("CredentialResponseEncryptionParameters() error = %v", err)
	}
	if params["zip"] != "DEF" {
		t.Errorf("zip = %v, want DEF", params["zip"])
	}

	// encryption_required with no key is an error.
	required := true
	metadata.CredentialResponseEncryption.EncryptionRequired = &required
	if _, err := CredentialResponseEncryptionParameters(metadata, nil); err == nil {
		t.Error("expected error when encryption is required and key is nil")
	}

	// No supported enc value is an error.
	metadata.CredentialResponseEncryption.EncryptionRequired = nil
	metadata.CredentialResponseEncryption.EncValuesSupported = []string{"unsupported-enc"}
	if _, err := CredentialResponseEncryptionParameters(metadata, jwk); err == nil {
		t.Error("expected error when no advertised enc is supported")
	}
	metadata.CredentialResponseEncryption.EncValuesSupported = nil
	if _, err := CredentialResponseEncryptionParameters(metadata, jwk); err == nil {
		t.Error("expected error when enc_values_supported is empty")
	}

	// No encryption metadata means nothing to add.
	if params, err := CredentialResponseEncryptionParameters(&types.CredentialIssuerMetadata{}, jwk); err != nil || params != nil {
		t.Errorf("no encryption metadata: params = %#v, err = %v", params, err)
	}
}

// §8.2: a response JWE carrying zip=DEF must decode to the inflated plaintext.
func TestOid4vciReceiver_DecodeCredentialResponseZip(t *testing.T) {
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate recipient key: %v", err)
	}
	plaintext := []byte(`{"credential":"credential-jwt","interval":5}`)
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.ECDH_ES, Key: &recipient.PublicKey, KeyID: "wallet-enc-key"},
		(&jose.EncrypterOptions{Compression: jose.DEFLATE}).WithContentType("json"),
	)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}
	encrypted, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt response: %v", err)
	}
	serialized, err := encrypted.CompactSerialize()
	if err != nil {
		t.Fatalf("failed to serialize response: %v", err)
	}
	parsedJWE, err := jose.ParseEncrypted(serialized, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatalf("failed to parse response JWE: %v", err)
	}
	if parsedJWE.Header.ExtraHeaders[jose.HeaderKey("zip")] != string(jose.DEFLATE) {
		t.Fatalf("zip header = %#v, want DEF", parsedJWE.Header.ExtraHeaders[jose.HeaderKey("zip")])
	}

	receiver := &Oid4vciReceiver{}
	decoded, err := receiver.DecodeCredentialResponse([]byte(serialized), "application/jwt", recipient)
	if err != nil {
		t.Fatalf("DecodeCredentialResponse() error = %v (zip must be inflated by go-jose)", err)
	}
	if decoded.Credential != "credential-jwt" || decoded.Interval != 5 {
		t.Fatalf("decoded response = %#v", decoded)
	}
}
