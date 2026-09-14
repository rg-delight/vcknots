package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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

// §8.2 response encryption: the wallet may publish an RSA response-encryption
// key, so a Credential Response the issuer encrypted to it with RSA-OAEP-256
// must decrypt. go-jose v4 implements only RSA-OAEP-256 among the OAEP
// variants, and RFC 8017 Section 7.2 RSA1_5 must never be accepted.
func TestOid4vciReceiver_DecodeCredentialResponseRSA(t *testing.T) {
	recipient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate recipient key: %v", err)
	}
	plaintext := []byte(`{"credential":"rsa-credential","notification_id":"notif-1"}`)
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &recipient.PublicKey, KeyID: "wallet-rsa-enc-key"},
		(&jose.EncrypterOptions{}).WithContentType("json"),
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

	receiver := &Oid4vciReceiver{}
	decoded, err := receiver.DecodeCredentialResponse([]byte(serialized), "application/jwt", recipient)
	if err != nil {
		t.Fatalf("DecodeCredentialResponse() error = %v (an RSA response key must be decryptable)", err)
	}
	if decoded.Credential != "rsa-credential" || decoded.NotificationID != "notif-1" {
		t.Fatalf("decoded response = %#v", decoded)
	}

	for _, alg := range supportedJWEKeyAlgorithms() {
		if alg == jose.RSA1_5 {
			t.Fatal("RSA1_5 must never be accepted for response decryption")
		}
	}
}

// §8.2: "Credential Request encryption MUST be used if the
// `credential_response_encryption` parameter is included, to prevent it being
// substituted by an attacker." An issuer that advertises no
// credential_request_encryption leaves the wallet no way to satisfy that, so the
// request must fail rather than travel in the clear with the wallet's response
// encryption key exposed to substitution.
func TestEncodeCredentialRequestFailsWhenRequestEncryptionUnavailable(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	request := map[string]any{
		"credential_configuration_id": "cfg",
		"credential_response_encryption": map[string]any{
			"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
			"enc": "A128GCM",
		},
	}

	for _, tt := range []struct {
		name     string
		metadata *types.CredentialIssuerMetadata
	}{
		{name: "no metadata", metadata: nil},
		{name: "metadata without credential_request_encryption", metadata: &types.CredentialIssuerMetadata{CredentialIssuer: "https://issuer.example"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body, contentType, err := receiver.EncodeCredentialRequest(request, tt.metadata)
			if err == nil {
				t.Fatalf("EncodeCredentialRequest() = %s (%s), want an error", body, contentType)
			}
			if !strings.Contains(err.Error(), "credential_response_encryption was requested but the issuer does not advertise credential_request_encryption") {
				t.Fatalf("error = %v", err)
			}
		})
	}

	t.Run("a request without response encryption is still sent as plain JSON", func(t *testing.T) {
		body, contentType, err := receiver.EncodeCredentialRequest(map[string]any{"credential_configuration_id": "cfg"}, nil)
		if err != nil {
			t.Fatalf("EncodeCredentialRequest() error = %v", err)
		}
		if contentType != "application/json" || !strings.Contains(string(body), "credential_configuration_id") {
			t.Fatalf("body = %s, contentType = %q", body, contentType)
		}
	})

	t.Run("an issuer advertising request encryption encrypts the same request", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		metadata := &types.CredentialIssuerMetadata{
			CredentialRequestEncryption: &types.CredentialRequestEncryption{
				Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
					Key: key.Public(), KeyID: "issuer-enc-1", Use: "enc", Algorithm: "ECDH-ES",
				}}},
				EncValuesSupported: []string{"A128GCM"},
			},
		}
		body, contentType, err := receiver.EncodeCredentialRequest(request, metadata)
		if err != nil {
			t.Fatalf("EncodeCredentialRequest() error = %v", err)
		}
		if contentType != "application/jwt" {
			t.Fatalf("contentType = %q, want application/jwt", contentType)
		}
		decrypted, err := decryptCompactJWE(t, string(body), key)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(decrypted), "credential_response_encryption") {
			t.Fatalf("decrypted request = %s", decrypted)
		}
	})
}

func decryptCompactJWE(t *testing.T, compact string, key *ecdsa.PrivateKey) ([]byte, error) {
	t.Helper()
	jwe, err := jose.ParseEncrypted(compact, supportedJWEKeyAlgorithms(), supportedJWEContentEncryptions())
	if err != nil {
		return nil, err
	}
	return jwe.Decrypt(key)
}

// §12.2.4.1 makes proof_signing_alg_values_supported "REQUIRED ... The Wallet
// uses one of them to sign the proof", and §8.2.1.1 requires the proof's alg
// header to match one of the listed values.
func TestCredentialProofUsesIssuerAdvertisedAlgorithm(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The key states no alg of its own, which is where the previous ES256
	// default produced a proof this key cannot even sign.
	key := jose.JSONWebKey{Key: privateKey, KeyID: "holder-1", Use: "sig"}

	proof, err := receiver.CreateCredentialRequestJWTProofWithOptions(key, ProofOptions{
		Audience:         "https://issuer.example",
		Nonce:            "c-nonce-1",
		SigningAlgValues: []jose.SignatureAlgorithm{jose.ES384},
	})
	if err != nil {
		t.Fatalf("CreateCredentialRequestJWTProofWithOptions() error = %v", err)
	}

	parsed, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}
	if parsed.Headers[0].Algorithm != string(jose.ES384) {
		t.Fatalf("proof alg = %q, want ES384", parsed.Headers[0].Algorithm)
	}
	if parsed.Headers[0].JSONWebKey == nil || parsed.Headers[0].JSONWebKey.Algorithm != string(jose.ES384) {
		t.Fatalf("proof jwk header = %#v", parsed.Headers[0].JSONWebKey)
	}
	var claims map[string]any
	if err := parsed.Claims(privateKey.Public(), &claims); err != nil {
		t.Fatalf("failed to verify proof: %v", err)
	}
	if claims["aud"] != "https://issuer.example" || claims["nonce"] != "c-nonce-1" {
		t.Fatalf("proof claims = %#v", claims)
	}
}

func TestCredentialProofFailsWhenNoSharedAlgorithm(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := jose.JSONWebKey{Key: privateKey, KeyID: "holder-1", Algorithm: string(jose.ES256), Use: "sig"}

	proof, err := receiver.CreateCredentialRequestJWTProofWithOptions(key, ProofOptions{
		Audience:         "https://issuer.example",
		SigningAlgValues: []jose.SignatureAlgorithm{jose.ES384, jose.EdDSA},
	})
	if err == nil {
		t.Fatalf("CreateCredentialRequestJWTProofWithOptions() = %q, want an error", proof)
	}
	if !errors.Is(err, ErrProofAlgorithmNotSupported) {
		t.Fatalf("errors.Is(ErrProofAlgorithmNotSupported) = false, err = %v", err)
	}

	if _, err := SelectProofSigningAlgorithm(key, []jose.SignatureAlgorithm{jose.ES256, jose.ES384}); err != nil {
		t.Fatalf("a listed key algorithm must be kept: %v", err)
	}
}

// An issuer that publishes no proof_signing_alg_values_supported states no
// constraint, and the key's own algorithm is used.
func TestCredentialProofUnconstrainedWhenIssuerListsNone(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := jose.JSONWebKey{Key: privateKey, KeyID: "holder-1", Algorithm: string(jose.ES256), Use: "sig"}

	proof, err := receiver.CreateCredentialRequestJWTProofWithOptions(key, ProofOptions{Audience: "https://issuer.example"})
	if err != nil {
		t.Fatalf("CreateCredentialRequestJWTProofWithOptions() error = %v", err)
	}
	parsed, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}
	if parsed.Headers[0].Algorithm != string(jose.ES256) {
		t.Fatalf("proof alg = %q, want ES256", parsed.Headers[0].Algorithm)
	}

	// The established entry points delegate here with no constraint, so they
	// keep producing the same proof.
	//lint:ignore SA1019 the legacy entry point is exactly what this case pins
	legacy, err := receiver.CreateCredentialRequestJWTProof(key, "https://issuer.example", "")
	if err != nil {
		t.Fatalf("CreateCredentialRequestJWTProof() error = %v", err)
	}
	if _, err := jwt.ParseSigned(legacy, []jose.SignatureAlgorithm{jose.ES256}); err != nil {
		t.Fatalf("failed to parse proof from the legacy entry point: %v", err)
	}
}

// TestEncodeCredentialRequestTakesTheJWEAlgFromTheChosenKey covers Section 10
// (Encrypted Credential Requests and Responses): "The `alg` parameter MUST be
// present. The JWE `alg` algorithm used MUST be equal to the `alg` value of the
// chosen JWK. If the selected public key contains a `kid` parameter, the JWE
// MUST include the same value in the `kid` JWE Header Parameter."
//
// Section 12.2.4 defines credential_request_encryption with jwks,
// enc_values_supported, zip_values_supported and encryption_required only:
// there is no alg_values_supported member to read the algorithm from.
func TestEncodeCredentialRequestTakesTheJWEAlgFromTheChosenKey(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	request := map[string]any{"credential_configuration_id": "pid"}

	requestEncryption := func(key jose.JSONWebKey) *types.CredentialIssuerMetadata {
		return &types.CredentialIssuerMetadata{
			CredentialRequestEncryption: &types.CredentialRequestEncryption{
				Jwks:               jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}},
				EncValuesSupported: []string{"A128GCM"},
			},
		}
	}

	t.Run("an EC key without alg is encrypted with ECDH-ES", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		metadata := requestEncryption(jose.JSONWebKey{Key: privateKey.Public(), KeyID: "issuer-ec-1", Use: "enc"})
		body, contentType, err := receiver.EncodeCredentialRequest(request, metadata)
		if err != nil {
			t.Fatalf("EncodeCredentialRequest() error = %v", err)
		}
		if contentType != "application/jwt" {
			t.Fatalf("contentType = %q, want application/jwt", contentType)
		}
		header := parseCompactJWEHeader(t, string(body))
		if header.Algorithm != string(jose.ECDH_ES) {
			t.Fatalf("JWE alg = %q, want ECDH-ES", header.Algorithm)
		}
		if header.KeyID != "issuer-ec-1" {
			t.Fatalf("JWE kid = %q, want the chosen JWK kid", header.KeyID)
		}
	})

	// An RSA JWK used to be handed to jose.NewEncrypter with ECDH-ES, which is
	// simply the wrong algorithm for the key type.
	t.Run("an RSA key without alg is encrypted with RSA-OAEP-256", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		metadata := requestEncryption(jose.JSONWebKey{Key: privateKey.Public(), KeyID: "issuer-rsa-1", Use: "enc"})
		body, contentType, err := receiver.EncodeCredentialRequest(request, metadata)
		if err != nil {
			t.Fatalf("EncodeCredentialRequest() error = %v", err)
		}
		if contentType != "application/jwt" {
			t.Fatalf("contentType = %q, want application/jwt", contentType)
		}
		header := parseCompactJWEHeader(t, string(body))
		if header.Algorithm != string(jose.RSA_OAEP_256) {
			t.Fatalf("JWE alg = %q, want RSA-OAEP-256", header.Algorithm)
		}
		if header.KeyID != "issuer-rsa-1" {
			t.Fatalf("JWE kid = %q, want the chosen JWK kid", header.KeyID)
		}
		// The issuer must be able to decrypt what the wallet sent.
		jwe, err := jose.ParseEncrypted(string(body), []jose.KeyAlgorithm{jose.RSA_OAEP_256}, supportedJWEContentEncryptions())
		if err != nil {
			t.Fatalf("failed to parse the request JWE: %v", err)
		}
		plaintext, err := jwe.Decrypt(privateKey)
		if err != nil {
			t.Fatalf("failed to decrypt the request JWE: %v", err)
		}
		if !strings.Contains(string(plaintext), "credential_configuration_id") {
			t.Fatalf("decrypted request = %s", plaintext)
		}
	})

	t.Run("the JWK alg wins over the key type default", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		metadata := requestEncryption(jose.JSONWebKey{
			Key: privateKey.Public(), KeyID: "issuer-ec-2", Use: "enc", Algorithm: "ECDH-ES+A256KW",
		})
		body, _, err := receiver.EncodeCredentialRequest(request, metadata)
		if err != nil {
			t.Fatalf("EncodeCredentialRequest() error = %v", err)
		}
		if header := parseCompactJWEHeader(t, string(body)); header.Algorithm != string(jose.ECDH_ES_A256KW) {
			t.Fatalf("JWE alg = %q, want ECDH-ES+A256KW", header.Algorithm)
		}
	})

	// RFC 8017 RSAES-PKCS1-v1_5 is the Bleichenbacher-attackable scheme this
	// wallet must never be talked into using, whoever asks.
	t.Run("RSA1_5 is rejected", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		metadata := requestEncryption(jose.JSONWebKey{
			Key: privateKey.Public(), KeyID: "issuer-rsa-2", Use: "enc", Algorithm: "RSA1_5",
		})
		body, contentType, err := receiver.EncodeCredentialRequest(request, metadata)
		if err == nil {
			t.Fatalf("EncodeCredentialRequest() = %s (%s), want an error", body, contentType)
		}
		if !strings.Contains(err.Error(), "unsupported encryption algorithm: RSA1_5") {
			t.Fatalf("error = %v", err)
		}
	})

	// A key type that admits no key agreement or key encryption algorithm is an
	// error rather than a silent ECDH-ES fallback.
	t.Run("a key type with no encryption algorithm is rejected", func(t *testing.T) {
		metadata := requestEncryption(jose.JSONWebKey{Key: []byte("symmetric-secret"), KeyID: "issuer-oct-1", Use: "enc"})
		body, contentType, err := receiver.EncodeCredentialRequest(request, metadata)
		if err == nil {
			t.Fatalf("EncodeCredentialRequest() = %s (%s), want an error", body, contentType)
		}
		if !strings.Contains(err.Error(), "omits the required alg parameter") {
			t.Fatalf("error = %v", err)
		}
	})
}

// TestSelectEncryptionKeyHonoursTheJWKParameters covers the Section 10 key
// selection rule: "In the case where multiple public keys are available, any may
// be selected based on the information about each key, such as the `kty` (Key
// Type), `use` (Public Key Use), `alg` (Algorithm), and other JWK parameters."
func TestSelectEncryptionKeyHonoursTheJWKParameters(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a signature key is never selected for encryption", func(t *testing.T) {
		jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: ecKey.Public(), KeyID: "issuer-sig-1", Use: "sig"},
			{Key: rsaKey.Public(), KeyID: "issuer-enc-1", Use: "enc"},
		}}
		selected, err := selectEncryptionKey(jwks)
		if err != nil {
			t.Fatalf("selectEncryptionKey() error = %v", err)
		}
		if selected.KeyID != "issuer-enc-1" {
			t.Fatalf("selected kid = %q, want issuer-enc-1", selected.KeyID)
		}
	})

	t.Run("a key whose alg this wallet cannot use is skipped", func(t *testing.T) {
		jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: rsaKey.Public(), KeyID: "issuer-rsa15", Use: "enc", Algorithm: "RSA1_5"},
			{Key: ecKey.Public(), KeyID: "issuer-ecdh", Use: "enc", Algorithm: "ECDH-ES"},
		}}
		selected, err := selectEncryptionKey(jwks)
		if err != nil {
			t.Fatalf("selectEncryptionKey() error = %v", err)
		}
		if selected.KeyID != "issuer-ecdh" {
			t.Fatalf("selected kid = %q, want issuer-ecdh", selected.KeyID)
		}
	})

	t.Run("a JWKS of signature keys only is an error", func(t *testing.T) {
		jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: ecKey.Public(), KeyID: "issuer-sig-1", Use: "sig"},
		}}
		if selected, err := selectEncryptionKey(jwks); err == nil {
			t.Fatalf("selectEncryptionKey() = %#v, want an error", selected)
		}
	})

	t.Run("an empty JWKS is an error", func(t *testing.T) {
		if selected, err := selectEncryptionKey(&jose.JSONWebKeySet{}); err == nil {
			t.Fatalf("selectEncryptionKey() = %#v, want an error", selected)
		}
	})
}

// parseCompactJWEHeader reads the protected header of a compact JWE without
// decrypting it, so a test can assert the alg and kid Section 10 requires.
func parseCompactJWEHeader(t *testing.T, compact string) jose.Header {
	t.Helper()
	jwe, err := jose.ParseEncrypted(
		compact,
		[]jose.KeyAlgorithm{jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW, jose.RSA_OAEP_256},
		supportedJWEContentEncryptions(),
	)
	if err != nil {
		t.Fatalf("failed to parse the request JWE: %v", err)
	}
	return jwe.Header
}

// ---------------------------------------------------------------------------
// P2-C: token_type / DPoP rules.
// ---------------------------------------------------------------------------

// RequireBearerTokenType validates the Final 1.0 anonymous Pre-Authorized Code
// token response. token_type is REQUIRED (OpenID4VCI 1.0 §6.1) and case
// insensitive (RFC 6749 §7.1), so a Bearer spelling is accepted whatever its
// case and an unknown value is refused.
func TestRequireBearerTokenType(t *testing.T) {
	t.Run("bearer is case insensitive", func(t *testing.T) {
		for _, tokenType := range []string{"Bearer", "bearer", "BEARER", " Bearer "} {
			if err := RequireBearerTokenType(&types.CredentialIssuanceAccessToken{Token: "access-1", TokenType: tokenType}); err != nil {
				t.Fatalf("RequireBearerTokenType(%q) error = %v", tokenType, err)
			}
		}
	})

	t.Run("dpop is refused with ErrDPoPRequired", func(t *testing.T) {
		for _, tokenType := range []string{"DPoP", "dpop"} {
			err := RequireBearerTokenType(&types.CredentialIssuanceAccessToken{Token: "access-1", TokenType: tokenType})
			if !errors.Is(err, ErrDPoPRequired) {
				t.Fatalf("RequireBearerTokenType(%q) error = %v, want ErrDPoPRequired", tokenType, err)
			}
		}
	})

	t.Run("unknown token_type is refused", func(t *testing.T) {
		err := RequireBearerTokenType(&types.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "MAC"})
		if err == nil {
			t.Fatal("RequireBearerTokenType(MAC) = nil, want an error")
		}
		if errors.Is(err, ErrDPoPRequired) {
			t.Fatalf("RequireBearerTokenType(MAC) = ErrDPoPRequired, want an unsupported token_type error")
		}
	})

	t.Run("nil token response is refused", func(t *testing.T) {
		if err := RequireBearerTokenType(nil); err == nil {
			t.Fatal("RequireBearerTokenType(nil) = nil, want an error")
		}
	})
}

// A bearer token cannot answer an RFC 9449 §8 DPoP challenge: it has no key to
// sign the proof the challenge asks for. The transport fails closed with
// ErrDPoPRequired after exactly one request, whether the challenge arrives as a
// DPoP-Nonce header or a WWW-Authenticate scheme.
func TestBearerTokenDPoPChallengeFailsClosed(t *testing.T) {
	challenges := map[string]http.HandlerFunc{
		"DPoP-Nonce header": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("DPoP-Nonce", "server-dpop-nonce")
			_ = mockserver.JSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "use_dpop_nonce"})
		},
		"WWW-Authenticate challenge": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
			_ = mockserver.JSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		},
	}
	for name, challenge := range challenges {
		t.Run(name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				challenge(w, r)
			}))
			defer server.Close()

			receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
			_, _, err := receiver.PostCredentialEndpointWithNonceRetryForToken(
				t.Context(),
				mustURIField(t, server.URL+"/credential"),
				types.CredentialIssuanceAccessToken{Token: "bearer-access-1", TokenType: "Bearer"},
				nil,
				"initial-nonce",
				func(string) ([]byte, string, error) { return []byte("{}"), "application/json", nil },
				noopProofFactory,
			)
			if !errors.Is(err, ErrDPoPRequired) {
				t.Fatalf("error = %v, want ErrDPoPRequired", err)
			}
			if calls != 1 {
				t.Fatalf("credential requests = %d, want 1: a bearer token cannot answer a DPoP challenge", calls)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// P2-D: invalid_nonce priority and DPoP nonce state across an interruption.
// ---------------------------------------------------------------------------

// OpenID4VCI 1.0 §8.3.1.2: an "invalid_nonce" answer means the proof carried a
// stale c_nonce, so the wallet refreshes it from the Nonce Endpoint. That must
// win over an RFC 9449 §8 DPoP-Nonce header on the same response, or the one
// retry would be spent re-signing a DPoP proof and the c_nonce retry would never
// run.
func TestInvalidNonceTakesPriorityOverDPoPChallenge(t *testing.T) {
	credentialCalls := 0
	nonceCalls := 0
	buildNonces := []string{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nonce":
			nonceCalls++
			_ = mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "fresh-nonce"})
		case "/credential":
			credentialCalls++
			if credentialCalls == 1 {
				w.Header().Set("DPoP-Nonce", "server-dpop-nonce")
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
	_, usedNonce, err := receiver.PostCredentialEndpointWithNonceRetry(
		mustURIField(t, server.URL+"/credential"),
		"access-1",
		&nonceEndpoint,
		"initial-nonce",
		func(cNonce string) ([]byte, string, error) {
			buildNonces = append(buildNonces, cNonce)
			return []byte("{}"), "application/json", nil
		},
		noopProofFactory,
	)
	if err != nil {
		t.Fatalf("PostCredentialEndpointWithNonceRetry() error = %v", err)
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

// A second invalid_nonce stops with the typed §8.3.1.2 sentinel even when every
// response also carries a DPoP-Nonce header.
func TestInvalidNonceWithDPoPNonceSecondFailureReturnsErrInvalidNonce(t *testing.T) {
	credentialCalls := 0
	nonceCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nonce":
			nonceCalls++
			_ = mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "fresh-nonce"})
		case "/credential":
			credentialCalls++
			w.Header().Set("DPoP-Nonce", "server-dpop-nonce")
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
		func(string) ([]byte, string, error) { return []byte("{}"), "application/json", nil },
		noopProofFactory,
	)
	if !errors.Is(err, types.ErrInvalidNonce) {
		t.Fatalf("error = %v, want ErrInvalidNonce", err)
	}
	if credentialCalls != 2 {
		t.Fatalf("credential endpoint calls = %d, want 2 (no third attempt)", credentialCalls)
	}
	if nonceCalls != 1 {
		t.Fatalf("nonce endpoint calls = %d, want 1", nonceCalls)
	}
}

// ExportDPoPNonces must hand out a copy: a caller carrying the nonces across an
// interruption cannot mutate the receiver's own store.
func TestExportDPoPNoncesReturnsCopy(t *testing.T) {
	fixture := newDPoPNonceTestServer(t, "server-dpop-nonce-1")
	receiver := &Oid4vciReceiver{HTTPClient: fixture.server.Client(), AllowHTTP: true}
	if _, err := receiver.FetchNonceResponse(t.Context(), mustURIField(t, fixture.server.URL+"/nonce")); err != nil {
		t.Fatalf("FetchNonceResponse() error = %v", err)
	}

	exported := receiver.ExportDPoPNonces()
	if len(exported) == 0 {
		t.Fatal("ExportDPoPNonces() returned no server entries")
	}
	for key := range exported {
		exported[key] = "tampered"
	}
	for key, nonce := range receiver.ExportDPoPNonces() {
		if nonce == "tampered" {
			t.Fatalf("mutating the exported map changed the receiver store (key %q)", key)
		}
	}
}

// Export then Import carries the RFC 9449 §8.2 nonce store across the process
// interruption the receiver's in-memory map cannot survive, so the first proof
// after the resume is already seeded instead of paying a wasted challenge round
// trip.
func TestExportImportDPoPNoncesSeedsRetryAfterInterruption(t *testing.T) {
	fixture := newDPoPNonceTestServer(t, "server-dpop-nonce-1")
	exporter := &Oid4vciReceiver{HTTPClient: fixture.server.Client(), AllowHTTP: true}
	receiver := &Oid4vciReceiver{HTTPClient: fixture.server.Client(), AllowHTTP: true}
	key := newDPoPNonceTestKey(t)

	if _, err := exporter.FetchNonceResponse(t.Context(), mustURIField(t, fixture.server.URL+"/nonce")); err != nil {
		t.Fatalf("FetchNonceResponse() error = %v", err)
	}
	receiver.ImportDPoPNonces(exporter.ExportDPoPNonces())

	postOneCredentialRequest(t, receiver, key, fixture.server.URL+"/credential")

	proofs := fixture.proofs()
	if len(proofs) != 1 {
		t.Fatalf("credential requests = %d, want exactly one", len(proofs))
	}
	claims := dpopProofClaims(t, proofs[0])
	if claims["nonce"] != "server-dpop-nonce-1" {
		t.Fatalf("first proof after import nonce = %#v, want server-dpop-nonce-1", claims["nonce"])
	}
}

// ---------------------------------------------------------------------------
// P2-E G5: the Nonce Response c_nonce is REQUIRED.
// ---------------------------------------------------------------------------

// OpenID4VCI 1.0 §7.2: "c_nonce: REQUIRED. String containing a challenge to be
// used when creating a proof of possession of the key." A 2xx Nonce Response
// that omits it, or returns it empty, fails closed as ErrNonceResponseInvalid.
func TestFetchNonceResponseRejectsEmptyCNonce(t *testing.T) {
	bodies := map[string]map[string]any{
		"empty c_nonce":   {"c_nonce": ""},
		"missing c_nonce": {},
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = mockserver.JSONResponse(w, http.StatusOK, body)
			}))
			defer server.Close()

			receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
			response, err := receiver.FetchNonceResponse(t.Context(), mustURIField(t, server.URL+"/nonce"))
			if !errors.Is(err, types.ErrNonceResponseInvalid) {
				t.Fatalf("error = %v, want ErrNonceResponseInvalid", err)
			}
			if response != nil {
				t.Fatalf("response = %#v, want nil", response)
			}
		})
	}
}
