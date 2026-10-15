package oauth

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// startupRetry records retry advice without exposing transport errors or headers
// in health JSON. Missing optional paths are neutral; at least one transient
// failure and no permanent failures are required to retry a discovery cycle.
type startupRetry struct {
	transient bool
	missing   bool
	after     time.Duration
}

func startupRetryForError(err error) startupRetry {
	if errors.Is(err, context.Canceled) {
		return startupRetry{}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return startupRetry{transient: true}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return startupRetry{transient: true}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsTemporary {
		return startupRetry{transient: true}
	}
	return startupRetry{}
}

func startupRetryForStatus(status int, header http.Header) startupRetry {
	switch status {
	case http.StatusNotFound:
		return startupRetry{missing: true}
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		advice := startupRetry{transient: true}
		value := strings.TrimSpace(header.Get("Retry-After"))
		if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
			// Bound server-controlled delays and avoid duration overflow.
			if seconds > 600 {
				seconds = 600
			}
			advice.after = time.Duration(seconds) * time.Second
		} else if when, err := http.ParseTime(value); err == nil {
			advice.after = max(0, min(time.Until(when), 10*time.Minute))
		}
		return advice
	default:
		return startupRetry{}
	}
}

func combineStartupRetries(attempts []startupRetry) startupRetry {
	result := startupRetry{}
	for _, attempt := range attempts {
		if !attempt.transient && !attempt.missing {
			return startupRetry{}
		}
		result.transient = result.transient || attempt.transient
		result.after = max(result.after, attempt.after)
	}
	return result
}

func protectedResourceStartupRetry(attempts []DiscoveryAttempt) startupRetry {
	advice := make([]startupRetry, 0, len(attempts))
	for _, attempt := range attempts {
		if attempt.Tried {
			advice = append(advice, attempt.retry)
		}
	}
	return combineStartupRetries(advice)
}
