package hfclient

import (
	"net/http"
	"testing"
	"time"
)

// TestDefaultHTTPClient_BoundsAndReusesUpstreamConnections guards the
// transport settings that keep a many-file mirror from exhausting the
// local ephemeral port range. With Go's default MaxIdleConnsPerHost of 2,
// a high-concurrency client opens and closes a fresh connection for nearly
// every request; over a 200k-file dataset that produced
// "Only one usage of each socket address" dial failures on Windows.
func TestDefaultHTTPClient_BoundsAndReusesUpstreamConnections(t *testing.T) {
	tr, ok := defaultHTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("defaultHTTPClient.Transport = %T, want *http.Transport", defaultHTTPClient.Transport)
	}
	if tr.MaxIdleConnsPerHost < 8 {
		t.Errorf("MaxIdleConnsPerHost = %d, want a reusable per-host pool", tr.MaxIdleConnsPerHost)
	}
	if tr.MaxConnsPerHost <= 0 {
		t.Errorf("MaxConnsPerHost = %d, want a finite concurrency bound", tr.MaxConnsPerHost)
	}
	if tr.IdleConnTimeout <= 0 {
		t.Errorf("IdleConnTimeout = %v, want a positive idle timeout", tr.IdleConnTimeout)
	}
	if tr.IdleConnTimeout < time.Second {
		t.Errorf("IdleConnTimeout = %v, too short for connection reuse", tr.IdleConnTimeout)
	}
}
