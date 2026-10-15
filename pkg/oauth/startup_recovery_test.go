package oauth

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/runtimeharpoon/hostbus"
	"go.uber.org/fx"
)

func TestStartupDiscoveryRecoversWithoutRestart(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"refused", "429", "503", "404-timeout", "issuer-503", "503-valid"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			var recovered atomic.Bool
			enteredRetry := make(chan time.Duration, 1)
			allowRetry := make(chan struct{})
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				status, body := http.StatusNotFound, "not found"
				header := make(http.Header)
				header.Set("Content-Type", "application/json")
				switch req.URL.Path {
				case "/mcp":
					status = http.StatusUnauthorized
				case "/.well-known/oauth-protected-resource":
					status, body = http.StatusOK, `{"resource":"https://mcp.example.test/mcp","authorization_servers":["https://mcp.example.test"]}`
				case "/.well-known/oauth-authorization-server":
					status, body = http.StatusOK, `{"issuer":"https://mcp.example.test","authorization_endpoint":"https://mcp.example.test/authorize","token_endpoint":"https://mcp.example.test/token"}`
				}
				if !recovered.Load() {
					switch failure {
					case "refused":
						return nil, syscall.ECONNREFUSED
					case "429":
						status, body = http.StatusTooManyRequests, `{"error":"temporarily_unavailable"}`
						header.Set("Retry-After", "12")
					case "503-valid":
						status, body = http.StatusServiceUnavailable, `{"resource":"https://mcp.example.test/mcp"}`
					case "503":
						status, body = http.StatusServiceUnavailable, "warming up"
					case "404-timeout":
						if req.URL.Path == "/.well-known/oauth-protected-resource" {
							return nil, context.DeadlineExceeded
						}
					case "issuer-503":
						if req.URL.Path == "/.well-known/oauth-authorization-server" {
							status, body = http.StatusServiceUnavailable, "warming up"
						}
					}
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
			})}
			state := NewDiscoveryState()
			catalog := hostbus.NewStartupCatalogState()
			bus := &recordingBus{notify: make(chan struct{})}
			target, _ := url.Parse("https://mcp.example.test/mcp")
			app := fx.New(fx.NopLogger, fx.Provide(
				func() *runtimeconfig.MCPConfig {
					return &runtimeconfig.MCPConfig{ServerURL: target, TransportKind: runtimeconfig.MCPTransportHTTPStreamable}
				},
				fx.Annotate(func() *http.Client { return client }, fx.ResultTags(`name:"mcp_client"`)),
				func() hostbus.HostRegistrationBus { return bus },
				func() *DiscoveryState { return state },
				func() *hostbus.StartupCatalogState { return catalog },
				func() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) },
			), fx.Invoke(func(p discoveryParams) error {
				return startOAuthDiscoveryWithRetryPolicy(p, deterministicOAuthDiscoveryRetryPolicy(enteredRetry, allowRetry))
			}))
			if err := app.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = app.Stop(context.Background()) })
			select {
			case delay := <-enteredRetry:
				if failure == "429" && delay < 12*time.Second {
					t.Fatalf("ignored Retry-After: %s", delay)
				}
			case <-time.After(time.Second):
				t.Fatal("transient startup failure did not retry")
			}
			if state.IsDone() {
				t.Fatal("discovery settled before recovery")
			}
			bus.mu.Lock()
			premature := len(bus.bundles)
			bus.mu.Unlock()
			if premature != 0 {
				t.Fatal("published incomplete OAuth catalog")
			}
			recovered.Store(true)
			close(allowRetry)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if err := catalog.Wait(ctx); err != nil {
				t.Fatalf("catalog did not recover: %v", err)
			}
			if _, _, _, err, ok := state.Wait(time.Second); !ok || err != nil {
				t.Fatalf("discovery did not recover: %v", err)
			}
			bus.mu.Lock()
			defer bus.mu.Unlock()
			if len(bus.bundles) != 1 {
				t.Fatalf("want one complete bundle, got %d", len(bus.bundles))
			}
			foundToken := false
			for _, record := range bus.bundles[0].URLs {
				if fmt.Sprint(record.URL) == "https://mcp.example.test/token" {
					foundToken = true
				}
			}
			if !foundToken {
				t.Fatal("recovered catalog has no token endpoint")
			}
		})
	}
}
