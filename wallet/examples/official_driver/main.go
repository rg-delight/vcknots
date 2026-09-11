// Command official_driver is an external consumer of the public Wallet APIs.
// Protocol errors propagate unchanged; this command does not repair protocol messages.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	"github.com/trustknots/vcknots/wallet/keystore"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

type configuration struct {
	StateDirectory  string   `json:"stateDirectory"`
	TLSCAFiles      []string `json:"tlsCAFiles"`
	VerifierCAFiles []string `json:"verifierCAFiles"`
	HolderKeyFile   string   `json:"holderKeyFile"`
	DPoPKeyFile     string   `json:"dpopKeyFile"`
	ClientKeyFile   string   `json:"clientKeyFile"`
	ClientID        string   `json:"clientId"`

	Profile                             string   `json:"profile"`
	VerifierAllowUnadvertisedRevocation bool     `json:"verifierAllowUnadvertisedRevocation"`
	WalletAudience                      []string `json:"walletAudience"`
	IssuerCAFiles                       []string `json:"issuerCAFiles"`
	IssuerAllowUnadvertisedRevocation   bool     `json:"issuerAllowUnadvertisedRevocation"`
	IssuerJWKSFiles                     []string `json:"issuerJWKSFiles"`
	RequireHolderBinding                bool     `json:"requireHolderBinding"`
}

type operation struct {
	Name   string `json:"operation"`
	URI    string `json:"uri"`
	TxCode string `json:"txCode"`
}

func decode(reader io.Reader, value any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected exactly one JSON document")
	}
	return nil
}

func readKey(path string) (keystore.KeyEntry, error) {
	if path == "" {
		return nil, fmt.Errorf("key file is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return keystore.NewKeyEntryFromJWKBytes(raw)
}

func addRoots(pool *x509.CertPool, paths []string) error {
	for _, path := range paths {
		pem, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("CA file contains no certificates: %s", path)
		}
	}
	return nil
}

// readTrustAnchors parses every CERTIFICATE block in each PEM file. A file with
// no parseable certificate is rejected so a typo cannot silently disable trust.
func readTrustAnchors(paths []string) ([]*x509.Certificate, error) {
	var anchors []*x509.Certificate
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		rest := raw
		added := 0
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			anchors = append(anchors, certificate)
			added++
		}
		if added == 0 {
			return nil, fmt.Errorf("CA file contains no certificates: %s", path)
		}
	}
	return anchors, nil
}

// readIssuerKeys parses JWKS-formatted files and rejects any private key so the
// operator cannot accidentally hand signing material to the acceptance policy.
func readIssuerKeys(paths []string) ([]jose.JSONWebKey, error) {
	var keys []jose.JSONWebKey
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(raw, &set); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if len(set.Keys) == 0 {
			return nil, fmt.Errorf("JWKS file contains no keys: %s", path)
		}
		for i := range set.Keys {
			if !set.Keys[i].IsPublic() {
				return nil, fmt.Errorf("JWKS file contains a non-public key: %s", path)
			}
			keys = append(keys, set.Keys[i])
		}
	}
	return keys, nil
}

func compose(config configuration, dpop, client keystore.KeyEntry) (*wallet.Wallet, error) {
	if config.StateDirectory == "" || config.ClientID == "" {
		return nil, fmt.Errorf("stateDirectory and clientId are required")
	}
	selectedProfile, err := profile.Profile(config.Profile).Normalize()
	if err != nil {
		return nil, fmt.Errorf("invalid profile: %w", err)
	}
	if config.VerifierAllowUnadvertisedRevocation && len(config.VerifierCAFiles) == 0 {
		return nil, fmt.Errorf("verifierAllowUnadvertisedRevocation requires verifierCAFiles")
	}
	if len(config.WalletAudience) > 0 && len(config.VerifierCAFiles) == 0 {
		return nil, fmt.Errorf("walletAudience requires verifierCAFiles")
	}
	if config.IssuerAllowUnadvertisedRevocation && len(config.IssuerCAFiles) == 0 {
		return nil, fmt.Errorf("issuerAllowUnadvertisedRevocation requires issuerCAFiles")
	}

	tlsRoots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if err := addRoots(tlsRoots, config.TLSCAFiles); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: tlsRoots}
	httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	// Trust anchors for signed Request Objects. No verifierCAFiles means no
	// validation options at all: the library then has no anchors and rejects
	// every X.509 Request Object (fail-closed).
	var requestObjectValidation *oid4vp.RequestObjectValidationOptions
	if len(config.VerifierCAFiles) > 0 {
		anchors, err := readTrustAnchors(config.VerifierCAFiles)
		if err != nil {
			return nil, err
		}
		requestObjectValidation = &oid4vp.RequestObjectValidationOptions{
			TrustAnchors:                anchors,
			AllowUnadvertisedRevocation: config.VerifierAllowUnadvertisedRevocation,
			WalletAudience:              config.WalletAudience,
		}
		requestObjectValidation.CRL.HTTPClient = httpClient
	}

	// Credential acceptance. Absent issuer trust this stays nil so the library
	// applies only its minimum rules.
	var acceptance *wallet.CredentialAcceptancePolicy
	if len(config.IssuerCAFiles) > 0 || len(config.IssuerJWKSFiles) > 0 || config.RequireHolderBinding {
		acceptance = &wallet.CredentialAcceptancePolicy{RequireHolderBinding: config.RequireHolderBinding}
		if len(config.IssuerCAFiles) > 0 {
			anchors, err := readTrustAnchors(config.IssuerCAFiles)
			if err != nil {
				return nil, err
			}
			acceptance.IssuerX509 = &wallet.IssuerX509TrustOptions{
				TrustAnchors:                anchors,
				AllowUnadvertisedRevocation: config.IssuerAllowUnadvertisedRevocation,
				HTTPClient:                  httpClient,
			}
		}
		if len(config.IssuerJWKSFiles) > 0 {
			keys, err := readIssuerKeys(config.IssuerJWKSFiles)
			if err != nil {
				return nil, err
			}
			acceptance.ResolveIssuerKeys = func(issuer string, header map[string]any) ([]jose.JSONWebKey, error) {
				return keys, nil
			}
		}
	}

	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{HTTPClient: httpClient, Profile: selectedProfile}))
	if err != nil {
		return nil, err
	}
	presenting, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenter.Oid4vp, &oid4vp.Oid4vpPresenter{HTTPClient: httpClient, RequestObjectValidation: requestObjectValidation, Profile: selectedProfile}))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(config.StateDirectory, 0700); err != nil {
		return nil, err
	}
	storage, err := local.NewLocalCredentialStorage(filepath.Join(config.StateDirectory, "credentials.db"))
	if err != nil {
		return nil, err
	}
	store, err := credstore.NewCredStoreDispatcher(credstore.WithPlugin(local.Local, storage))
	if err != nil {
		return nil, err
	}
	return wallet.NewWalletWithConfig(wallet.Config{
		CredStore:            store,
		Receiver:             receiving,
		Presenter:            presenting,
		Profile:              selectedProfile,
		CredentialAcceptance: acceptance,
		DPoP:                 wallet.DPoPConfig{Enabled: true, Key: dpop},
		ClientAuth:           wallet.ClientAuthConfig{Method: receiverTypes.PrivateKeyJwt, ClientID: config.ClientID, Key: client},
	})
}

func run(config configuration, request operation) (any, error) {
	if request.Name != "public-keys" && request.Name != "receive-preauth" && request.Name != "present" && request.Name != "list" {
		return nil, fmt.Errorf("unsupported operation: %s", request.Name)
	}
	holder, err := readKey(config.HolderKeyFile)
	if err != nil {
		return nil, err
	}
	dpop, err := readKey(config.DPoPKeyFile)
	if err != nil {
		return nil, err
	}
	client, err := readKey(config.ClientKeyFile)
	if err != nil {
		return nil, err
	}
	if request.Name == "public-keys" {
		return map[string]any{"holder": holder.PublicKey(), "dpop": dpop.PublicKey(), "client": client.PublicKey()}, nil
	}
	w, err := compose(config, dpop, client)
	if err != nil {
		return nil, err
	}
	switch request.Name {
	case "receive-preauth":
		offer, err := wallet.ParseCredentialOfferURL(request.URI)
		if err != nil {
			return nil, err
		}
		saved, err := w.ReceiveCredential(wallet.ReceiveCredentialRequest{CredentialOffer: offer, Type: receiverTypes.Oid4vci, Key: holder, RequestedFormat: credential.SDJwtVC, TxCode: request.TxCode})
		if err != nil {
			return nil, err
		}
		return map[string]any{"credentialId": saved.Entry.Id, "verification": saved.Verification}, nil
	case "present":
		redirectURI, err := w.PresentCredential(request.URI, holder, nil)
		if err != nil {
			return nil, err
		}
		return map[string]any{"redirectUri": redirectURI}, nil
	case "list":
		entries, total, err := w.GetCredentialEntries(wallet.GetCredentialEntriesRequest{})
		if err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(entries))
		for _, entry := range entries {
			ids = append(ids, entry.Entry.Id)
		}
		return map[string]any{"credentialIds": ids, "total": total}, nil
	}
	return nil, fmt.Errorf("unreachable operation")
}

func main() {
	configPath := flag.String("config", "", "configuration JSON path")
	flag.Parse()
	if *configPath == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: official_driver -config <path> < operation.json")
		os.Exit(2)
	}
	configFile, err := os.Open(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var config configuration
	err = decode(configFile, &config)
	configFile.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var request operation
	if err := decode(os.Stdin, &request); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result, err := run(config, request)
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"operation": request.Name, "error": err.Error()})
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
