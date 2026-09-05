package oid4vci

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestIssuerMetadataDoesNotRetryInvalidOrForbiddenResponses(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusInternalServerError, http.StatusNotFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if requests == 1 {
					w.WriteHeader(status)
					fmt.Fprint(w, `{"credential_request_encryption":{"encryption_required":"invalid"}}`)
					return
				}
				fmt.Fprint(w, `{"credential_request_encryption":{"encryption_required":false}}`)
			}))
			defer server.Close()
			endpoint, err := common.ParseURIField(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
			metadata, err := receiver.FetchIssuerMetadata(*endpoint, types.Oid4vci)
			if err == nil || metadata != nil {
				t.Fatalf("metadata = %v, error = %v; want failure", metadata, err)
			}
			if requests != 1 {
				t.Fatalf("requests = %d, want 1", requests)
			}
		})
	}
}

func TestIssuerMetadataRetriesOnlyMissingDistinctLocalDiscoveryPath(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/.well-known/openid-credential-issuer/tenant" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"credential_issuer":"https://discarded.example","credential_request_encryption":{"encryption_required":true}}`)
			return
		}
		fmt.Fprint(w, `{"credential_issuer":"https://accepted.example"}`)
	}))
	defer server.Close()
	endpoint, err := common.ParseURIField(server.URL + "/tenant")
	if err != nil {
		t.Fatal(err)
	}
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	metadata, err := receiver.FetchIssuerMetadata(*endpoint, types.Oid4vci)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[1] != "/tenant/.well-known/openid-credential-issuer" {
		t.Fatalf("paths = %v", paths)
	}
	if metadata.CredentialIssuer != "https://accepted.example" || metadata.CredentialRequestEncryption != nil {
		t.Fatalf("metadata from discarded response leaked: %+v", metadata)
	}
}
