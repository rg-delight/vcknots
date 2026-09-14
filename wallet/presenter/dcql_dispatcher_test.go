package presenter

import (
	"errors"
	"net/url"
	"reflect"
	"testing"

	"github.com/trustknots/vcknots/wallet/presenter/types"
)

func TestPresentationDispatcher_PresentDCQL_RequiresRegisteredCapability(t *testing.T) {
	endpoint := url.URL{Scheme: "https", Host: "verifier.example", Path: "/response"}
	tests := []struct {
		name   string
		plugin types.Presenter
		op     string
	}{
		{name: "no registered plugin", op: "get_plugin"},
		{name: "plugin has only single-query Present", plugin: &mockPresenter{}, op: "present_dcql"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispatcher, err := NewPresentationDispatcher()
			if err != nil {
				t.Fatalf("NewPresentationDispatcher() error = %v", err)
			}
			if tt.plugin != nil {
				if err := dispatcher.registerPlugin(types.Oid4vp, tt.plugin); err != nil {
					t.Fatalf("register plugin: %v", err)
				}
			}
			redirect, err := dispatcher.PresentDCQL(types.Oid4vp, endpoint, map[string][]string{"identity": {"presentation"}}, &PresentationRequest{})
			if redirect != "" || !errors.Is(err, types.ErrUnsupportedProtocol) {
				t.Fatalf("PresentDCQL() = (%q, %v), want ErrUnsupportedProtocol", redirect, err)
			}
			var presenterError *types.PresenterError
			if !errors.As(err, &presenterError) || presenterError.Protocol != types.Oid4vp || presenterError.Op != tt.op {
				t.Fatalf("expected contextual PresenterError, got %#v", err)
			}
		})
	}
}

func TestPresentationDispatcher_PresentDCQL_ForwardsAllInputsAndResult(t *testing.T) {
	endpoint := url.URL{Scheme: "https", Host: "verifier.example", Path: "/response"}
	tokens := map[string][]string{"identity": {"identity-token"}, "accounts": {"account-one", "account-two"}}
	request := &PresentationRequest{State: "state"}
	called := 0
	plugin := &dcqlDispatchPresenter{present: func(protocol types.SupportedPresentationProtocol, gotEndpoint url.URL, gotTokens map[string][]string, gotRequest *PresentationRequest) (string, error) {
		called++
		if protocol != types.Oid4vp || gotEndpoint != endpoint || !reflect.DeepEqual(gotTokens, tokens) || gotRequest != request {
			t.Errorf("plugin received modified inputs: protocol=%v endpoint=%v tokens=%v request=%#v", protocol, gotEndpoint, gotTokens, gotRequest)
		}
		return "https://verifier.example/complete", nil
	}}
	dispatcher, err := NewPresentationDispatcher(WithPlugin(types.Oid4vp, plugin))
	if err != nil {
		t.Fatalf("NewPresentationDispatcher() error = %v", err)
	}
	redirect, err := dispatcher.PresentDCQL(types.Oid4vp, endpoint, tokens, request)
	if err != nil || redirect != "https://verifier.example/complete" || called != 1 {
		t.Fatalf("PresentDCQL() = (%q, %v), calls=%d", redirect, err, called)
	}
}

func TestPresentationDispatcher_PresentDCQL_PreservesPluginError(t *testing.T) {
	endpoint := url.URL{Scheme: "https", Host: "verifier.example", Path: "/response"}
	failure := errors.New("verifier rejected authorization response")
	plugin := &dcqlDispatchPresenter{present: func(types.SupportedPresentationProtocol, url.URL, map[string][]string, *PresentationRequest) (string, error) {
		return "", failure
	}}
	dispatcher, err := NewPresentationDispatcher(WithPlugin(types.Oid4vp, plugin))
	if err != nil {
		t.Fatalf("NewPresentationDispatcher() error = %v", err)
	}
	redirect, err := dispatcher.PresentDCQL(types.Oid4vp, endpoint, map[string][]string{"identity": {"token"}}, &PresentationRequest{})
	if redirect != "" || !errors.Is(err, failure) {
		t.Fatalf("PresentDCQL() = (%q, %v), want plugin error", redirect, err)
	}
	var presenterError *types.PresenterError
	if !errors.As(err, &presenterError) || presenterError.Op != "present_dcql" || presenterError.Endpoint != endpoint.String() {
		t.Fatalf("expected endpoint and operation in PresenterError, got %#v", err)
	}
}

type dcqlDispatchPresenter struct {
	mockPresenter
	present func(types.SupportedPresentationProtocol, url.URL, map[string][]string, *PresentationRequest) (string, error)
}

func (p *dcqlDispatchPresenter) PresentDCQL(protocol types.SupportedPresentationProtocol, endpoint url.URL, tokens map[string][]string, request *PresentationRequest) (string, error) {
	return p.present(protocol, endpoint, tokens, request)
}
