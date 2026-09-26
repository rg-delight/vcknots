package main

// OID4VCI Final 1.0 Conformance Test (Issuer-Initiated, SD-JWT VC)
//
// Setup:
//  1. Open https://www.certification.openid.net/ and create a test plan:
//     - Test plan: "OpenID for Verifiable Credential Issuance 1.0 Final/HAIP: Test a Wallet"
//     - Credential Format: sd_jwt_vc
//     - Authorization Code Flow Variant: issuer_initiated
//     - Credential Offer Variant: by_value or by_reference
//  2. Run each test module; copy the openid-credential-offer:// URI shown by the suite.
//  3. Execute: go run conformance_sdjwt.go "<openid-credential-offer-uri>"

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/examples/common"
)

const preAuthorizedGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

var txCodeInDescriptionPattern = regexp.MustCompile(`<([^<>]+)>`)

func validateAnonymousPreAuthorizedFlow(offer *wallet.CredentialOffer) error {
	if offer == nil {
		return fmt.Errorf("credential offer is required")
	}

	grant, ok := offer.Grants[preAuthorizedGrantType]
	if !ok || grant == nil || grant.PreAuthorizedCode == "" {
		return fmt.Errorf("this sample only supports issuer_initiated pre-authorized flow (%s); configure the test plan to avoid client_attestation and provide a valid credential offer", preAuthorizedGrantType)
	}

	return nil
}

func resolveTxCode(offer *wallet.CredentialOffer, explicitTxCode string, logger *slog.Logger) (string, error) {
	if offer == nil {
		return "", fmt.Errorf("credential offer is required")
	}

	grant := offer.Grants[preAuthorizedGrantType]
	if grant == nil || grant.TxCode == nil {
		return "", nil
	}

	txCode := strings.TrimSpace(explicitTxCode)
	if txCode != "" {
		return txCode, nil
	}

	if grant.TxCode.Description != "" {
		if m := txCodeInDescriptionPattern.FindStringSubmatch(grant.TxCode.Description); len(m) == 2 {
			derived := strings.TrimSpace(m[1])
			if derived != "" {
				logger.Info("Using tx_code extracted from credential offer description")
				return derived, nil
			}
		}
	}

	return "", fmt.Errorf("tx_code is required by credential offer; pass it as 2nd arg or OID4VCI_TX_CODE")
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if len(os.Args) < 2 {
		logger.Error("Usage: conformance_sdjwt <openid-credential-offer-uri> [tx_code]")
		os.Exit(1)
	}

	explicitTxCode := strings.TrimSpace(os.Getenv("OID4VCI_TX_CODE"))
	if len(os.Args) >= 3 {
		explicitTxCode = strings.TrimSpace(os.Args[2])
	}

	// wallet.NewWalletWithConfig fills every nil field with its default
	// implementation. The credential acceptance policy is required: the
	// conformance suite signs its SD-JWT VC with x5c, so its certificate
	// authority is passed in VCKNOTS_ISSUER_CA_PATH.
	issuerAcceptance, err := common.SampleIssuerAcceptance(os.Getenv("VCKNOTS_ISSUER_CA_PATH"), false)
	if err != nil {
		logger.Error("Failed to load the issuer trust", "error", err)
		os.Exit(1)
	}
	w, err := wallet.NewWalletWithConfig(wallet.Config{CredentialAcceptance: issuerAcceptance})
	if err != nil {
		logger.Error("Failed to initialize wallet", "error", err)
		os.Exit(1)
	}

	logger.Info("Wallet initialized")

	ctx := context.Background()
	holderKey := common.NewMockKeyEntry()
	// ResolveCredentialOffer takes the by_value (credential_offer) and the
	// by_reference (credential_offer_uri) forms of OpenID4VCI 1.0 Section 4.1.
	offer, err := w.ResolveCredentialOffer(ctx, os.Args[1])
	if err != nil {
		logger.Error("Failed to resolve credential offer", "error", err)
		os.Exit(1)
	}
	logger.Info("Parsed credential offer",
		"issuer", offer.CredentialIssuer.String(),
		"configuration_ids", offer.CredentialConfigurationIDs,
	)
	if err := validateAnonymousPreAuthorizedFlow(offer); err != nil {
		logger.Error("Invalid test plan / offer for this sample", "error", err)
		logger.Error("Set Authorization Code Flow Variant to issuer_initiated and disable client_attestation-based client authentication")
		os.Exit(1)
	}
	txCode, err := resolveTxCode(offer, explicitTxCode, logger)
	if err != nil {
		logger.Error("Missing tx_code", "error", err)
		os.Exit(1)
	}

	// OpenID4VCI 1.0 Pre-Authorized Code Flow: the Token Request (Section
	// 6), then the Credential Request (Section 8) with a key proof for the
	// holder key.
	grant, err := w.AuthorizePreAuthorizedIssuance(ctx, wallet.PreAuthorizedIssuanceRequest{
		CredentialOffer: offer,
		TxCode:          txCode,
	})
	if err != nil {
		logger.Error("Failed to obtain an access token", "error", err)
		os.Exit(1)
	}
	result, err := w.RequestCredential(ctx, grant, wallet.CredentialRequest{
		HolderKeys: []wallet.IKeyEntry{holderKey},
	})
	if err != nil {
		logger.Error("Failed to receive credential", "error", err)
		os.Exit(1)
	}
	if result.Deferred != nil || len(result.Credentials) == 0 {
		logger.Error("The issuer deferred the credential; this sample does not poll")
		os.Exit(1)
	}
	savedCredential := result.Credentials[0]

	logger.Info("=== Credential Received ===")
	logger.Info("Entry ID", "id", savedCredential.Entry.Id)
	logger.Info("MimeType", "mime_type", savedCredential.Entry.MimeType)
	logger.Info("Received At", "received_at", savedCredential.Entry.ReceivedAt)
	logger.Info("Credential payload stored")
}
