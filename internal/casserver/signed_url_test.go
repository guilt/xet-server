package casserver

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/guilt/xet-server/internal/auth"
	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/reconwire"
	"github.com/guilt/xet-server/internal/shardformat"
	"github.com/guilt/xet-server/internal/storage/fsstore"
)

func shardformatFile(fileHash, xorbHash merklehash.Hash, size, chunks uint32) shardformat.FileEntry {
	return shardformat.FileEntry{
		Header:  shardformat.FileDataSequenceHeader{FileHash: fileHash},
		Entries: []shardformat.FileDataSequenceEntry{{XorbHash: xorbHash, UnpackedSegmentBytes: size, ChunkIndexStart: 0, ChunkIndexEnd: chunks}},
	}
}

func writeFooterlessShard(w *bytes.Buffer, file shardformat.FileEntry, xorb shardformat.XorbEntry) {
	shardformat.WriteHeader(w, shardformat.Header{Version: 2, FooterSize: 0})
	h := file.Header
	h.NumEntries = uint32(len(file.Entries))
	shardformat.WriteFileDataSequenceHeader(w, h)
	for _, e := range file.Entries {
		shardformat.WriteFileDataSequenceEntry(w, e)
	}
	shardformat.WriteFileDataSequenceHeader(w, shardformat.BookendFileHeader())
	xh := xorb.Header
	xh.NumEntries = uint32(len(xorb.Chunks))
	shardformat.WriteXorbChunkSequenceHeader(w, xh)
	for _, c := range xorb.Chunks {
		shardformat.WriteXorbChunkSequenceEntry(w, c)
	}
	shardformat.WriteXorbChunkSequenceHeader(w, shardformat.BookendXorbHeader())
}

const signedURLTestSecret = "signed-url-fixture-secret-not-a-real-credential"

var signedURLTestRepo = auth.Repo{Type: "model", ID: "alice/signed-url-test"}

// newSignedTestServer is a CAS with SignedTokenAuth and the fetch-URL
// signer installed, as cmd/xetd wires them when -auth-token is set.
func newSignedTestServer(t *testing.T, sign bool) (*httptest.Server, *auth.SignedTokenAuth) {
	t.Helper()
	store, err := fsstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signed := auth.NewSignedTokenAuth(signedURLTestSecret)
	casSrv := New(store)
	casSrv.SetAuthenticator(signed)
	if sign {
		casSrv.SetFetchURLSigner(signed, time.Minute)
	}
	ts := httptest.NewServer(casSrv)
	t.Cleanup(ts.Close)
	return ts, signed
}

func doAuthed(t *testing.T, method, u, bearer string, body []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, u, bytes.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// uploadSignedFixture uploads one xorb and a shard for a file made of it,
// as the shared secret, and returns the file hash and the xorb bytes.
func uploadSignedFixture(t *testing.T, ts *httptest.Server) (merklehash.Hash, []byte) {
	t.Helper()
	payloads := [][]byte{[]byte("bytes fetched through a signed url"), []byte("second chunk")}
	blob, xorbHash, chunkHashes := buildXorb(t, payloads)
	resp := doAuthed(t, "POST", ts.URL+"/v1/xorbs/"+xorbPrefix+"/"+xorbHash.Hex(), signedURLTestSecret, blob)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload xorb: %d", resp.StatusCode)
	}
	fileHash := merklehash.ComputeDataHash(bytes.Join(payloads, nil))
	entry := xorbEntryOf(xorbHash, chunkHashes, payloads)
	file := shardformatFile(fileHash, xorbHash, entry.Header.NumBytesInXorb, uint32(len(chunkHashes)))
	var up bytes.Buffer
	writeFooterlessShard(&up, file, entry)
	resp = doAuthed(t, "POST", ts.URL+"/v1/shards", signedURLTestSecret, up.Bytes())
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload shard: %d", resp.StatusCode)
	}
	return fileHash, blob
}

// A client downloading with auth on fetches the xorb URLs of a
// reconstruction response with no Authorization header at all (on the
// real Hub they are presigned CDN URLs), so every URL the server hands
// out for its own byte-serving endpoint must carry its credential.
func TestFetchURL_CarriesAReadTokenForTheCaller(t *testing.T) {
	ts, signed := newSignedTestServer(t, true)
	fileHash, blob := uploadSignedFixture(t, ts)
	readToken, _, err := signed.MintToken(auth.ScopeRead, "carol", signedURLTestRepo, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	for _, version := range []string{"v1", "v2"} {
		resp := doAuthed(t, "GET", ts.URL+"/"+version+"/reconstructions/"+fileHash.Hex(), readToken, nil)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s reconstruction: %d %s", version, resp.StatusCode, body)
		}
		var fetchURL string
		if version == "v1" {
			var r reconwire.ResponseV1
			if err := json.Unmarshal(body, &r); err != nil {
				t.Fatal(err)
			}
			for _, entries := range r.FetchInfo {
				fetchURL = entries[0].URL
			}
		} else {
			var r reconwire.ResponseV2
			if err := json.Unmarshal(body, &r); err != nil {
				t.Fatal(err)
			}
			for _, entries := range r.Xorbs {
				fetchURL = entries[0].URL
			}
		}
		parsed, err := url.Parse(fetchURL)
		if err != nil || parsed.Query().Get(urlTokenParam) == "" {
			t.Fatalf("%s fetch url %q carries no %s: the client will fetch it unauthenticated and get 401", version, fetchURL, urlTokenParam)
		}
		principal, err := signed.VerifyURLToken(parsed.Query().Get(urlTokenParam))
		if err != nil || principal.Subject() != "carol" || principal.HasScope(auth.ScopeWrite) {
			t.Fatalf("%s url token: err=%v subject=%v; want a read-only token bound to the caller", version, err, principal)
		}
		if got := auth.RepoOf(principal); got != signedURLTestRepo {
			t.Fatalf("%s url token repo = %v, want %v (the signed URL must stay bound to the repo that requested it)", version, got, signedURLTestRepo)
		}

		// Fetched exactly as the client does: no headers.
		for _, method := range []string{"GET", "HEAD"} {
			resp = doAuthed(t, method, fetchURL, "", nil)
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s %s with no header: %d %s", method, version, resp.StatusCode, got)
			}
			if method == "GET" && !bytes.Equal(got, blob) {
				t.Fatalf("%s signed url served %d bytes, want the %d-byte xorb", version, len(got), len(blob))
			}
		}

		// Stripped, tampered, or moved to a write route, the token is worthless.
		bare := strings.SplitN(fetchURL, "?", 2)[0]
		if resp = doAuthed(t, "GET", bare, "", nil); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET without the token: %d, want 401", resp.StatusCode)
		}
		resp.Body.Close()
		if resp = doAuthed(t, "GET", bare+"?"+urlTokenParam+"=xst1.9999999999.read.6361726f6c.00", "", nil); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET with a forged token: %d, want 401", resp.StatusCode)
		}
		resp.Body.Close()
		if resp = doAuthed(t, "POST", bare+"?"+urlTokenParam+"="+url.QueryEscape(parsed.Query().Get(urlTokenParam)), "", blob); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("POST with a url token: %d, want 401 (only the byte-serving routes read the query string)", resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// Without a signer (auth off, or a backend that presigns), URLs are
// exactly what they were.
func TestFetchURL_UnsignedWhenNoSignerConfigured(t *testing.T) {
	ts, signed := newSignedTestServer(t, false)
	fileHash, _ := uploadSignedFixture(t, ts)
	readToken, _, _ := signed.MintToken(auth.ScopeRead, "carol", signedURLTestRepo, time.Minute)
	resp := doAuthed(t, "GET", ts.URL+"/v2/reconstructions/"+fileHash.Hex(), readToken, nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var r reconwire.ResponseV2
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatal(err)
	}
	for _, entries := range r.Xorbs {
		if strings.Contains(entries[0].URL, "?") {
			t.Fatalf("url %q carries a query string without a signer", entries[0].URL)
		}
	}
}
