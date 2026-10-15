package oauth

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"syscall"
	"testing"
	"time"
)

func TestStartupRetryDoesNotHidePermanentFailures(t *testing.T) {
	t.Parallel()
	for _, err := range []error{context.Canceled, errors.New("invalid metadata"), x509.UnknownAuthorityError{}} {
		if startupRetryForError(err).transient {
			t.Fatalf("permanent failure retried: %v", err)
		}
	}
	for _, status := range []int{400, 401, 403, 501} {
		if startupRetryForStatus(status, nil).transient {
			t.Fatalf("status %d retried", status)
		}
	}
	transient := startupRetryForError(syscall.ECONNREFUSED)
	missing := startupRetryForStatus(http.StatusNotFound, nil)
	if combineStartupRetries([]startupRetry{missing}).transient {
		t.Fatal("plain MCP 404 retried")
	}
	if !combineStartupRetries([]startupRetry{missing, transient}).transient {
		t.Fatal("fallback 404 suppressed recovery")
	}
	if combineStartupRetries([]startupRetry{transient, {}}).transient {
		t.Fatal("permanent failure suppressed")
	}
}

func TestStartupRetryAfterBounds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"12", 12 * time.Second}, {"999999999", 10 * time.Minute}, {"-1", 0}, {"garbage", 0},
	} {
		if got := startupRetryForStatus(429, http.Header{"Retry-After": {tc.value}}).after; got != tc.want {
			t.Errorf("%q: %s, want %s", tc.value, got, tc.want)
		}
	}
	when := time.Now().Add(time.Minute).UTC().Format(http.TimeFormat)
	if got := startupRetryForStatus(503, http.Header{"Retry-After": {when}}).after; got < 58*time.Second || got > time.Minute {
		t.Fatalf("HTTP date ignored: %s", got)
	}
}
