package casserver

// Regression tests for two bugs found during a manual code-quality
// review: a ranged xorb fetch silently dropping its own Content-Length
// header, and HEAD /v1/xorbs/{prefix}/{hash} skipping the prefix
// validation GET already enforces.

import (
	"bytes"
	"net/http"
	"strconv"
	"testing"
)

func TestFetchXorb_RangedResponseHasContentLength(t *testing.T) {
	ts, _ := newTestServer(t)

	payloads := [][]byte{[]byte("chunk one"), []byte("chunk two, a bit longer")}
	blob, xorbHash, _ := buildXorb(t, payloads)

	resp, err := http.Post(ts.URL+"/v1/xorbs/default/"+xorbHash.Hex(), "application/octet-stream", bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("POST xorb error = %v", err)
	}
	resp.Body.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/xorbs/default/"+xorbHash.Hex(), nil)
	req.Header.Set("Range", "bytes=0-4")
	rangeResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("ranged GET error = %v", err)
	}
	defer rangeResp.Body.Close()

	if rangeResp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", rangeResp.StatusCode)
	}
	got := rangeResp.Header.Get("Content-Length")
	if got == "" {
		t.Fatal("Content-Length missing on a 206 response - WriteHeader must be called after, not before, setting it")
	}
	if want := strconv.Itoa(5); got != want {
		t.Errorf("Content-Length = %q, want %q", got, want)
	}
}

func TestParseByteRange_OpenEndedAndSuffix(t *testing.T) {
	cases := []struct {
		name      string
		header    string
		total     int64
		wantStart int64
		wantEnd   int64
		wantRange bool
		wantErr   bool
	}{
		{name: "empty means no range", header: "", total: 100, wantRange: false},
		{name: "closed range", header: "bytes=10-19", total: 100, wantStart: 10, wantEnd: 19, wantRange: true},
		{name: "closed range clamps to EOF", header: "bytes=90-999", total: 100, wantStart: 90, wantEnd: 99, wantRange: true},
		{name: "open ended is through EOF", header: "bytes=0-", total: 100, wantStart: 0, wantEnd: 99, wantRange: true},
		{name: "open ended mid file", header: "bytes=50-", total: 100, wantStart: 50, wantEnd: 99, wantRange: true},
		{name: "suffix range", header: "bytes=-10", total: 100, wantStart: 90, wantEnd: 99, wantRange: true},
		{name: "suffix larger than file is whole file", header: "bytes=-1000", total: 100, wantStart: 0, wantEnd: 99, wantRange: true},
		{name: "start at EOF is unsatisfiable", header: "bytes=100-", total: 100, wantErr: true},
		{name: "zero suffix is unsatisfiable", header: "bytes=-0", total: 100, wantErr: true},
		{name: "empty total with open ended is unsatisfiable", header: "bytes=0-", total: 0, wantErr: true},
		{name: "multi range unsupported", header: "bytes=0-9,20-29", total: 100, wantErr: true},
		{name: "missing dash", header: "bytes=10", total: 100, wantErr: true},
		{name: "bad prefix", header: "BYTES=0-9", total: 100, wantErr: true},
		{name: "overflow", header: "bytes=0-99999999999999999999", total: 100, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, hasRange, err := parseByteRange(tc.header, tc.total)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseByteRange(%q, %d) error = nil, want non-nil", tc.header, tc.total)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseByteRange(%q, %d) error = %v", tc.header, tc.total, err)
			}
			if hasRange != tc.wantRange {
				t.Errorf("hasRange = %v, want %v", hasRange, tc.wantRange)
			}
			if start != tc.wantStart || end != tc.wantEnd {
				t.Errorf("range = %d-%d, want %d-%d", start, end, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestHeadXorb_WrongPrefixReturns400(t *testing.T) {
	ts, _ := newTestServer(t)

	payloads := [][]byte{[]byte("chunk one")}
	blob, xorbHash, _ := buildXorb(t, payloads)
	resp, err := http.Post(ts.URL+"/v1/xorbs/default/"+xorbHash.Hex(), "application/octet-stream", bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("POST xorb error = %v", err)
	}
	resp.Body.Close()

	headResp, err := http.Head(ts.URL + "/v1/xorbs/bogus-prefix/" + xorbHash.Hex())
	if err != nil {
		t.Fatalf("HEAD error = %v", err)
	}
	defer headResp.Body.Close()
	if headResp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (same prefix validation GET already enforces)", headResp.StatusCode)
	}
}
