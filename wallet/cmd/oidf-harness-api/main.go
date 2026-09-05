package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/trustknots/vcknots/wallet/env"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	wallet "github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

type harnessConfig struct {
	VCI struct {
		ClientAttesterIssuer   string             `json:"client_attestation_issuer"`
		ClientAttesterKeysJWKS jose.JSONWebKeySet `json:"client_attester_keys_jwks"`
	} `json:"vci"`
	Client struct {
		ClientID string             `json:"client_id"`
		JWKS     jose.JSONWebKeySet `json:"jwks"`
	} `json:"client"`
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: oidf-harness-api <vci-receive|vp-authorize>")
	}

	switch os.Args[1] {
	case "vci-receive":
		if err := runVCIReceive(os.Args[2:]); err != nil {
			fail(err.Error())
		}
	case "vp-authorize":
		if err := runVPAuthorize(os.Args[2:]); err != nil {
			fail(err.Error())
		}
	default:
		fail("unknown command %q", os.Args[1])
	}
}

func runVPAuthorize(args []string) error {
	flags := flag.NewFlagSet("vp-authorize", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	authorizeURL := flags.String("authorize-url", "", "OID4VP authorization request URL")
	suiteDir := flags.String("suite-dir", defaultSuiteDir(), "OIDF conformance suite directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*authorizeURL) == "" {
		return fmt.Errorf("--authorize-url is required")
	}

	holderKey, err := generateHolderSigningKey()
	if err != nil {
		return err
	}
	credentialJWT, err := issueOIDFVPFixtureCredential(holderKey.PublicKey(), *suiteDir, strings.Contains(*authorizeURL, "wallet-haip-test-plan"))
	if err != nil {
		return err
	}

	credStore := &memoryCredStore{entries: map[string]credstoreTypes.CredentialEntry{}}
	credStoreDispatcher, err := credstore.NewCredStoreDispatcher(credstore.WithPlugin(0, credStore))
	if err != nil {
		return err
	}
	if err := credStoreDispatcher.SaveCredentialEntry(credstoreTypes.CredentialEntry{
		Id:         "oidf-vp-fixture-credential",
		ReceivedAt: time.Now(),
		Raw:        []byte(credentialJWT),
		MimeType:   string(credential.SDJwtVC),
	}, 0); err != nil {
		return err
	}

	httpClient := insecureHTTPClient()
	vpPresenter := &oid4vp.Oid4vpPresenter{
		AllowHTTP:              env.IsHTTPAllowed(),
		HTTPClient:             httpClient,
		InsecureSkipX509Verify: true,
	}
	parsedRequest, err := vpPresenter.ParsePresentationRequest(*authorizeURL)
	if err != nil {
		return walletRejectionError{message: err.Error()}
	}
	if parsedRequest.ResponseURI == "" {
		return walletRejectionError{message: "response_uri is not specified"}
	}
	responseURI, err := url.Parse(parsedRequest.ResponseURI)
	if err != nil {
		return walletRejectionError{message: "invalid response_uri: " + err.Error()}
	}
	if parsedRequest.ResponseURI != "" {
		if !strings.HasSuffix(responseURI.Path, "/responseuri") {
			return walletRejectionError{message: "response_uri is not the configured direct-post endpoint: " + parsedRequest.ResponseURI}
		}
	}
	presentationDispatcher, err := presenter.NewPresentationDispatcher(
		presenter.WithPlugin(0, vpPresenter),
	)
	if err != nil {
		return err
	}
	api, err := wallet.NewWalletWithConfig(wallet.Config{
		CredStore: credStoreDispatcher,
		Presenter: presentationDispatcher,
	})
	if err != nil {
		return err
	}

	body, err := api.SubmitOID4VPFinalAuthorizationRequest(parsedRequest, *responseURI, holderKey)
	if err != nil {
		if len(parsedRequest.TransactionData) > 0 {
			return walletRejectionError{message: err.Error()}
		}
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"suite_response_body": body,
	})
}

type walletRejectionError struct {
	message string
}

func (e walletRejectionError) Error() string {
	return "wallet rejected request: " + e.message
}

func runVCIReceive(args []string) error {
	flags := flag.NewFlagSet("vci-receive", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	offerURL := flags.String("offer-url", "", "openid-credential-offer URL")
	suiteDir := flags.String("suite-dir", defaultSuiteDir(), "OIDF conformance suite directory")
	conformanceServer := flags.String("conformance-server", defaultConformanceServer(), "OIDF conformance server origin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*offerURL) == "" {
		return fmt.Errorf("--offer-url is required")
	}

	config, err := readHarnessConfig(*suiteDir)
	if err != nil {
		return err
	}
	if len(config.Client.JWKS.Keys) == 0 {
		return fmt.Errorf("suite client config does not contain a client key")
	}
	if len(config.VCI.ClientAttesterKeysJWKS.Keys) == 0 {
		return fmt.Errorf("suite client config does not contain a client attester key")
	}

	offer, err := wallet.ParseCredentialOfferURL(*offerURL)
	if err != nil {
		return err
	}
	holderKey, err := generateHolderKey()
	if err != nil {
		return err
	}
	responseEncryptionKey, err := generateCredentialResponseEncryptionKey()
	if err != nil {
		return err
	}
	httpClient := insecureHTTPClient()
	receiverDispatcher, err := receiver.NewReceivingDispatcher(
		receiver.WithPlugin(types.Oid4vci, &oid4vci.Oid4vciReceiver{HTTPClient: httpClient, AllowHTTP: env.IsHTTPAllowed()}),
	)
	if err != nil {
		return err
	}
	api, err := wallet.NewWalletWithConfig(wallet.Config{Receiver: receiverDispatcher})
	if err != nil {
		return err
	}
	result, err := api.ReceiveOID4VCIFinalCredential(wallet.OID4VCIFinalReceiveRequest{
		CredentialOffer:                 offer,
		Type:                            types.Oid4vci,
		ClientID:                        config.Client.ClientID,
		RedirectURI:                     trimTrailingSlash(*conformanceServer) + "/test/a/oidf-vci-issuer-test/callback",
		HolderKey:                       holderKey,
		ClientKey:                       config.Client.JWKS.Keys[0],
		AttesterKey:                     config.VCI.ClientAttesterKeysJWKS.Keys[0],
		AttesterIssuer:                  config.VCI.ClientAttesterIssuer,
		CredentialResponseEncryptionKey: &responseEncryptionKey,
		HTTPClient:                      httpClient,
	})
	if err != nil {
		return err
	}

	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"saved_credentials": len(result.SavedCredentials),
		"notification_id":   result.CredentialResponse.NotificationID,
		"transaction_id":    result.CredentialResponse.TransactionID,
	})
}

func readHarnessConfig(suiteDir string) (*harnessConfig, error) {
	path := filepath.Join(suiteDir, "scripts/test-configs-rp-against-op/vci-issuer-test-config-client_attestation-client-auth-dpop.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read VCI harness config: %w", err)
	}
	var config harnessConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse VCI harness config: %w", err)
	}
	return &config, nil
}

func generateHolderKey() (jose.JSONWebKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("failed to generate holder key: %w", err)
	}
	return jose.JSONWebKey{
		Key:       key,
		KeyID:     "vcknots-oidf-holder-key",
		Algorithm: "ES256",
		Use:       "sig",
	}, nil
}

type signingKeyEntry struct {
	id  string
	key *ecdsa.PrivateKey
}

func generateHolderSigningKey() (*signingKeyEntry, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate holder key: %w", err)
	}
	return &signingKeyEntry{id: "vcknots-oidf-holder-key", key: key}, nil
}

func (k *signingKeyEntry) ID() string {
	return k.id
}

func (k *signingKeyEntry) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       &k.key.PublicKey,
		KeyID:     k.id,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
}

func (k *signingKeyEntry) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, k.key, digest[:])
}

func issueOIDFVPFixtureCredential(holderPublicKey jose.JSONWebKey, suiteDir string, haip bool) (string, error) {
	signingKey, x5c, err := oidfVPSigningKey(suiteDir, haip)
	if err != nil {
		return "", err
	}

	claims := map[string]string{
		"given_name":  "TARO",
		"family_name": "TEST",
		"birthdate":   "2000-03-03",
	}
	disclosures := make([]string, 0, len(claims))
	disclosureHashes := make([]string, 0, len(claims))
	for _, name := range []string{"given_name", "family_name", "birthdate"} {
		disclosure, digest, err := createSDJWTDisclosure("salt-"+name, name, claims[name])
		if err != nil {
			return "", err
		}
		disclosures = append(disclosures, disclosure)
		disclosureHashes = append(disclosureHashes, digest)
	}

	now := time.Now().Unix()
	holderPublicJWK := holderPublicKey.Public()
	payload := map[string]any{
		"iss":     "https://issuer.example.test",
		"vct":     "urn:eudi:pid:1",
		"cnf":     map[string]any{"jwk": holderPublicJWK},
		"iat":     now,
		"nbf":     now,
		"exp":     now + 3600,
		"_sd":     disclosureHashes,
		"_sd_alg": "sha-256",
	}

	options := (&jose.SignerOptions{}).WithType("dc+sd-jwt")
	if haip {
		if len(x5c) == 0 {
			return "", fmt.Errorf("HAIP VP signing key is missing x5c")
		}
		options = options.WithHeader("x5c", x5c)
	} else {
		options = options.WithHeader("kid", "vcknots-oidf-harness-issuer")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signingKey.Key}, options)
	if err != nil {
		return "", err
	}
	issuerJWT, err := jwt.Signed(signer).Claims(payload).Serialize()
	if err != nil {
		return "", err
	}
	return issuerJWT + "~" + strings.Join(disclosures, "~") + "~", nil
}

func oidfVPSigningKey(suiteDir string, haip bool) (jose.JSONWebKey, []string, error) {
	if !haip {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return jose.JSONWebKey{}, nil, fmt.Errorf("failed to generate VP fixture issuer key: %w", err)
		}
		return jose.JSONWebKey{Key: key, KeyID: "vcknots-oidf-harness-issuer", Algorithm: string(jose.ES256), Use: "sig"}, nil, nil
	}

	path := filepath.Join(suiteDir, "scripts/certs-keys/vp-signing-jwk.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return jose.JSONWebKey{}, nil, fmt.Errorf("failed to read VP signing JWK: %w", err)
	}
	var key jose.JSONWebKey
	if err := json.Unmarshal(data, &key); err != nil {
		return jose.JSONWebKey{}, nil, fmt.Errorf("failed to parse VP signing JWK: %w", err)
	}
	var raw struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return jose.JSONWebKey{}, nil, fmt.Errorf("failed to parse VP signing x5c: %w", err)
	}
	key.Algorithm = string(jose.ES256)
	key.Use = "sig"
	return key, raw.X5C, nil
}

func createSDJWTDisclosure(salt, name, value string) (string, string, error) {
	disclosureBytes, err := json.Marshal([]any{salt, name, value})
	if err != nil {
		return "", "", err
	}
	disclosure := base64.RawURLEncoding.EncodeToString(disclosureBytes)
	digest := sha256.Sum256([]byte(disclosure))
	return disclosure, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

type memoryCredStore struct {
	entries map[string]credstoreTypes.CredentialEntry
}

func (m *memoryCredStore) SaveCredentialEntry(entry credstoreTypes.CredentialEntry, location credstoreTypes.SupportedCredStoreTypes) error {
	m.entries[entry.Id] = entry
	return nil
}

func (m *memoryCredStore) GetCredentialEntries(offset int, limit *int, location credstoreTypes.SupportedCredStoreTypes) (*credstoreTypes.GetCredentialEntriesResult, error) {
	entries := make([]credstoreTypes.CredentialEntry, 0, len(m.entries))
	for _, entry := range m.entries {
		entries = append(entries, entry)
	}
	if offset > len(entries) {
		offset = len(entries)
	}
	end := len(entries)
	if limit != nil && offset+*limit < end {
		end = offset + *limit
	}
	selected := entries[offset:end]
	total := len(entries)
	return &credstoreTypes.GetCredentialEntriesResult{Entries: &selected, TotalCount: &total}, nil
}

func (m *memoryCredStore) GetCredentialEntry(id string, location credstoreTypes.SupportedCredStoreTypes) (*credstoreTypes.CredentialEntry, error) {
	entry, ok := m.entries[id]
	if !ok {
		return nil, fmt.Errorf("credential not found: %s", id)
	}
	return &entry, nil
}

func generateCredentialResponseEncryptionKey() (jose.JSONWebKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("failed to generate credential response encryption key: %w", err)
	}
	return jose.JSONWebKey{
		Key:       key,
		KeyID:     "vcknots-vci-credential-response-enc",
		Algorithm: "ECDH-ES",
		Use:       "enc",
	}, nil
}

func insecureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func defaultSuiteDir() string {
	if value := os.Getenv("OIDF_CONFORMANCE_SUITE_DIR"); value != "" {
		return value
	}
	return filepath.Clean("../../openid-conformance-suite")
}

func defaultConformanceServer() string {
	if value := os.Getenv("CONFORMANCE_SERVER"); value != "" {
		return value
	}
	return "https://localhost.emobix.co.uk:8443"
}

func trimTrailingSlash(value string) string {
	return strings.TrimRight(value, "/")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
