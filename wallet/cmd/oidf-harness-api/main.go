package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	wallet "github.com/trustknots/vcknots/wallet"
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
		fail("usage: oidf-harness-api <vci-receive>")
	}

	switch os.Args[1] {
	case "vci-receive":
		if err := runVCIReceive(os.Args[2:]); err != nil {
			fail(err.Error())
		}
	default:
		fail("unknown command %q", os.Args[1])
	}
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
		receiver.WithPlugin(types.Oid4vci, &oid4vci.Oid4vciReceiver{HTTPClient: httpClient}),
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
