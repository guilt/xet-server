package casserver

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/shardformat"
)

// A global-dedup answer must never expose raw chunk hashes: a caller
// holding one chunk would otherwise learn every other chunk hash (and
// file identity) in the matching xorbs. xet-core matches chunks by
// DataHash::hmac(key), with a fresh key per response carried in the
// footer, so a client can only match chunks it already holds.
func TestChunkDedup_AnswerIsKeyedPerResponse(t *testing.T) {
	ts, _ := newTestServer(t)
	payloads := [][]byte{[]byte("chunk the caller already holds"), []byte("chunk the caller has never seen"), []byte("third chunk")}
	blob, xorbHash, chunkHashes := buildXorb(t, payloads)
	resp, err := http.Post(ts.URL+"/v1/xorbs/"+xorbPrefix+"/"+xorbHash.Hex(), "application/octet-stream", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	fileHash := merklehash.ComputeDataHash(bytes.Join(payloads, nil))
	uploadFooterlessShard(t, ts, fileHash, xorbHash, chunkHashes, []uint32{uint32(len(payloads[0])), uint32(len(payloads[1])), uint32(len(payloads[2]))})

	fetch := func() ([]byte, *shardformat.Shard) {
		t.Helper()
		resp, err := http.Get(ts.URL + "/v1/chunks/" + chunkDedupPrefix + "/" + chunkHashes[0].Hex())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("dedup query status = %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		shard, err := shardformat.ReadShard(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("dedup response does not parse: %v", err)
		}
		return body, shard
	}

	body1, shard1 := fetch()
	_, shard2 := fetch()

	for i, shard := range []*shardformat.Shard{shard1, shard2} {
		if shard.Footer.ChunkHashHMACKey.IsZero() {
			t.Fatalf("answer %d has a zero HMAC key", i+1)
		}
		if len(shard.Files) != 0 {
			t.Fatalf("answer %d carries %d file entries, want none", i+1, len(shard.Files))
		}
		if len(shard.Xorbs) != 1 || shard.Xorbs[0].Header.XorbHash != xorbHash {
			t.Fatalf("answer %d does not describe the uploaded xorb", i+1)
		}
		for j, c := range shard.Xorbs[0].Chunks {
			want := chunkHashes[j].HMAC(shard.Footer.ChunkHashHMACKey)
			if c.ChunkHash != want {
				t.Fatalf("answer %d chunk %d = %s, want keyed %s", i+1, j, c.ChunkHash.Hex()[:8], want.Hex()[:8])
			}
			if c.ChunkHash == chunkHashes[j] {
				t.Fatalf("answer %d chunk %d still uses its raw hash", i+1, j)
			}
		}
	}
	if shard1.Footer.ChunkHashHMACKey == shard2.Footer.ChunkHashHMACKey {
		t.Fatal("two answers reused the same key; a leaked key would unlock other responses")
	}

	// Every raw chunk hash is absent from the wire bytes, and every keyed
	// hash the client can compute for a chunk it holds is present.
	for _, raw := range chunkHashes {
		if bytes.Contains(body1, raw.Bytes()) {
			t.Fatalf("response contains raw chunk hash %s", raw.Hex()[:8])
		}
		keyed := raw.HMAC(shard1.Footer.ChunkHashHMACKey)
		if !bytes.Contains(body1, keyed.Bytes()) {
			t.Fatalf("response does not contain keyed hash %s for a chunk the caller holds", keyed.Hex()[:8])
		}
	}
}
