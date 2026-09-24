package wallet

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/common"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// oid4vciDiscovery is the metadata an issuance resolves before it sends
// anything to an authorization server.
type oid4vciDiscovery struct {
	issuerMetadata              *receiverTypes.CredentialIssuerMetadata
	authorizationServerMetadata *receiverTypes.AuthorizationServerMetadata
	// authorizationServer is the RFC 8414 issuer identifier the authorization
	// server metadata was verified against.
	authorizationServer string
}

// authorizationServerSelector picks the authorization server of an issuance
// from the Credential Issuer metadata; issuerEndpoint is the Credential Issuer
// Identifier.
type authorizationServerSelector func(issuerMetadata *receiverTypes.CredentialIssuerMetadata, issuerEndpoint common.URIField) (common.URIField, error)

// offeredAuthorizationServer selects the authorization server the way a new
// issuance does: the grant's authorization_server hint when there is one
// (SelectOID4VCIAuthorizationServer).
func offeredAuthorizationServer(grant *CredentialOfferGrant) authorizationServerSelector {
	return func(issuerMetadata *receiverTypes.CredentialIssuerMetadata, issuerEndpoint common.URIField) (common.URIField, error) {
		return SelectOID4VCIAuthorizationServer(issuerMetadata, grant, issuerEndpoint)
	}
}

// discoverOID4VCIIssuer resolves the Credential Issuer metadata for
// issuerIdentifier (§12.2.2), or takes cached, whose credential_issuer must be
// identical to it either way (§12.2.4). It then selects the authorization
// server and resolves its metadata, whose issuer must be identical to the
// identifier it was fetched for (RFC 8414 §3.3).
func discoverOID4VCIIssuer(
	transport receiverTypes.Receiver,
	receivingType receiverTypes.SupportedReceivingTypes,
	issuerIdentifier string,
	cached *receiverTypes.CredentialIssuerMetadata,
	selectServer authorizationServerSelector,
) (*oid4vciDiscovery, error) {
	issuerEndpoint, err := common.ParseURIField(issuerIdentifier)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential issuer endpoint: %w", err)
	}
	issuerMetadata, err := resolveOID4VCIIssuerMetadata(transport, receivingType, issuerIdentifier, cached)
	if err != nil {
		return nil, err
	}

	authorizationServerEndpoint, err := selectServer(issuerMetadata, *issuerEndpoint)
	if err != nil {
		return nil, err
	}
	authorizationServerMetadata, err := transport.FetchAuthorizationServerMetadata(authorizationServerEndpoint, receivingType)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}
	if authorizationServerMetadata == nil {
		return nil, fmt.Errorf("authorization server metadata is nil")
	}
	if authorizationServerMetadata.Issuer.String() != authorizationServerEndpoint.String() {
		return nil, fmt.Errorf(
			"authorization server metadata issuer %q does not match the selected authorization server %q",
			authorizationServerMetadata.Issuer.String(), authorizationServerEndpoint.String())
	}
	return &oid4vciDiscovery{
		issuerMetadata:              issuerMetadata,
		authorizationServerMetadata: authorizationServerMetadata,
		authorizationServer:         authorizationServerEndpoint.String(),
	}, nil
}

// resolveOID4VCIIssuerMetadata fetches the Credential Issuer metadata for
// issuerIdentifier (§12.2.2), or takes cached, and requires its
// credential_issuer to be identical to issuerIdentifier (§12.2.4).
func resolveOID4VCIIssuerMetadata(
	transport receiverTypes.Receiver,
	receivingType receiverTypes.SupportedReceivingTypes,
	issuerIdentifier string,
	cached *receiverTypes.CredentialIssuerMetadata,
) (*receiverTypes.CredentialIssuerMetadata, error) {
	issuerMetadata := cached
	if issuerMetadata == nil {
		issuerEndpoint, err := common.ParseURIField(issuerIdentifier)
		if err != nil {
			return nil, fmt.Errorf("failed to parse credential issuer endpoint: %w", err)
		}
		issuerMetadata, err = transport.FetchIssuerMetadata(*issuerEndpoint, receivingType)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
		}
		if issuerMetadata == nil {
			return nil, fmt.Errorf("issuer metadata is nil")
		}
	}
	if issuerMetadata.CredentialIssuer != issuerIdentifier {
		return nil, fmt.Errorf("credential issuer metadata identifier %q does not match the credential issuer %q: %w",
			issuerMetadata.CredentialIssuer, issuerIdentifier, ErrIssuerIdentifierMismatch)
	}
	return issuerMetadata, nil
}
