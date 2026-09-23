package observe

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func observed(t *testing.T, base http.RoundTripper, request *http.Request) (Exchange, *http.Response, error) {
	t.Helper()
	recorder := NewRecorder(4)
	response, err := Transport(base, recorder).RoundTrip(request)
	exchanges := recorder.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("recorded %d exchanges, want 1", len(exchanges))
	}
	return exchanges[0], response, err
}

func TestTransportReportsTheExchange(t *testing.T) {
	ctx := WithResponseEncryption(WithEndpoint(context.Background(), EndpointCredential), true)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://user:secret@issuer.example/credential?x=1#frag", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("DPoP", "proof")
	request.Header.Set("OAuth-Client-Attestation", "attestation")
	request.Header.Set("Content-Type", "application/jwt; charset=utf-8")
	base := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": {"APPLICATION/JWT"}}, Body: http.NoBody}, nil
	})

	exchange, response, err := observed(t, base, request)
	if err != nil || response.StatusCode != http.StatusAccepted {
		t.Fatalf("round trip changed: %v %v", response, err)
	}
	if exchange.Endpoint != EndpointCredential || exchange.Method != http.MethodPost || exchange.StatusCode != http.StatusAccepted {
		t.Fatalf("exchange = %+v", exchange)
	}
	if got := exchange.URL.String(); got != "https://issuer.example/credential?x=1" {
		t.Fatalf("URL = %q, want userinfo and fragment removed", got)
	}
	if !exchange.DPoP || !exchange.ClientAttestation || !exchange.RequestJWT || !exchange.ResponseJWT {
		t.Fatalf("header facts = %+v", exchange)
	}
	if exchange.ResponseEncrypted == nil || !*exchange.ResponseEncrypted {
		t.Fatalf("ResponseEncrypted = %v", exchange.ResponseEncrypted)
	}
	if exchange.StartedAt.IsZero() || exchange.Duration < 0 {
		t.Fatalf("timing = %v %v", exchange.StartedAt, exchange.Duration)
	}
	if request.URL.User == nil {
		t.Fatal("the observed URL must be a copy")
	}
}

func TestTransportReportsAFailedRoundTripWithoutAStatus(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://issuer.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("dial failed")
	exchange, response, err := observed(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, failure
	}), request)
	if !errors.Is(err, failure) || response != nil {
		t.Fatalf("round trip changed: %v %v", response, err)
	}
	if exchange.Endpoint != EndpointOther || exchange.StatusCode != 0 || exchange.ResponseEncrypted != nil {
		t.Fatalf("exchange = %+v", exchange)
	}
}

func TestTransportWithoutObserverIsBase(t *testing.T) {
	base := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	if got := Transport(base, nil); got == nil {
		t.Fatal("Transport(base, nil) = nil")
	}
	if Transport(nil, nil) != http.DefaultTransport {
		t.Fatal("a nil base must fall back to http.DefaultTransport")
	}
}

func TestLabels(t *testing.T) {
	if EndpointOf(context.Background()) != EndpointOther {
		t.Fatal("an unlabelled context is EndpointOther")
	}
	outer := WithEndpoint(context.Background(), EndpointCredential)
	if EndpointOf(WithEndpoint(outer, EndpointNonce)) != EndpointNonce {
		t.Fatal("an inner label replaces the outer one")
	}
	if _, ok := ResponseEncryptionOf(outer); ok {
		t.Fatal("no encryption annotation was made")
	}

	source := WithResponseEncryption(WithEndpoint(context.Background(), EndpointResponse), false)
	inherited := Inherit(context.Background(), source)
	if EndpointOf(inherited) != EndpointResponse {
		t.Fatal("Inherit must copy the endpoint label")
	}
	if encrypted, ok := ResponseEncryptionOf(inherited); !ok || encrypted {
		t.Fatal("Inherit must copy the encryption annotation")
	}
	if EndpointOf(Inherit(context.Background(), context.Background())) != EndpointOther {
		t.Fatal("Inherit must not invent a label")
	}
}

func TestRecorderKeepsThePrefixAndReportsTruncation(t *testing.T) {
	recorder := NewRecorder(2)
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recorder.ObserveExchange(Exchange{Endpoint: EndpointToken, URL: &url.URL{}, StartedAt: time.Now()})
		}()
	}
	wg.Wait()
	if got := len(recorder.Exchanges()); got != 2 || !recorder.Truncated() {
		t.Fatalf("kept %d, truncated %v", got, recorder.Truncated())
	}

	var absent *Recorder
	absent.ObserveExchange(Exchange{})
	if absent.Exchanges() == nil || absent.Truncated() {
		t.Fatal("a nil Recorder is empty and never truncated")
	}
}
