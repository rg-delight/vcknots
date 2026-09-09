// Command official_driver is an external consumer of the public Wallet APIs.
// Protocol errors propagate unchanged; this command does not repair protocol messages.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	"github.com/trustknots/vcknots/wallet/keystore"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
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

func compose(config configuration, dpop, client keystore.KeyEntry) (*wallet.Wallet, error) {
	if config.StateDirectory == "" || config.ClientID == "" {
		return nil, fmt.Errorf("stateDirectory and clientId are required")
	}
	tlsRoots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if err := addRoots(tlsRoots, config.TLSCAFiles); err != nil {
		return nil, err
	}
	verifierRoots := x509.NewCertPool()
	if err := addRoots(verifierRoots, config.VerifierCAFiles); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: tlsRoots}
	httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{HTTPClient: httpClient}))
	if err != nil {
		return nil, err
	}
	presenting, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenter.Oid4vp, &oid4vp.Oid4vpPresenter{HTTPClient: httpClient, X509TrustChainRoots: verifierRoots}))
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
		CredStore:  store,
		Receiver:   receiving,
		Presenter:  presenting,
		DPoP:       wallet.DPoPConfig{Enabled: true, Key: dpop},
		ClientAuth: wallet.ClientAuthConfig{Method: receiverTypes.PrivateKeyJwt, ClientID: config.ClientID, Key: client},
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
		return map[string]any{"credentialId": saved.Entry.Id}, nil
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
