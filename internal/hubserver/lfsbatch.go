package hubserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/guilt/xet-server/internal/auth"
)

// lfsBatchRequest is the git-lfs Batch API request (docs/api/batch.md).
// Both real callers are modeled: huggingface_hub's upload path, which
// only reads transfer/oid/size back, and the stock git-lfs client, which
// needs per-object actions.
type lfsBatchRequest struct {
	Operation string   `json:"operation"`
	Transfers []string `json:"transfers"`
	Ref       struct {
		Name string `json:"name"`
	} `json:"ref"`
	Objects []struct {
		OID  string `json:"oid"`
		Size int64  `json:"size"`
	} `json:"objects"`
	HashAlgo string `json:"hash_algo"`
}

// lfsAction is one entry of an object's "actions": where to transfer it
// and what headers to send. For the xet transfer the header map is how
// git-xet learns the CAS URL and its access token (see uploadActionFor).
type lfsAction struct {
	Href      string            `json:"href"`
	Header    map[string]string `json:"header,omitempty"`
	ExpiresIn int64             `json:"expires_in,omitempty"`
}

// lfsObjectError is a per-object failure inside an otherwise successful
// batch; git-lfs reports the message for that object and continues.
type lfsObjectError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type lfsBatchObject struct {
	OID           string                `json:"oid"`
	Size          int64                 `json:"size"`
	Authenticated bool                  `json:"authenticated,omitempty"`
	Actions       map[string]*lfsAction `json:"actions,omitempty"`
	Error         *lfsObjectError       `json:"error,omitempty"`
}

type lfsBatchResponse struct {
	Transfer string           `json:"transfer"`
	Objects  []lfsBatchObject `json:"objects"`
	HashAlgo string           `json:"hash_algo,omitempty"`
}

// maxLFSBatchBytes caps a batch request body. A batch is pure metadata -
// an oid/size pair per file - so even a maximally-sized legitimate request
// is a few tens of KB; this bound is generous by orders of magnitude while
// still refusing an unbounded body. Without it, json.Decode on r.Body will
// happily stream and buffer a multi-GB request.
const maxLFSBatchBytes = 4 * 1024 * 1024

// maxLFSBatchObjects caps how many objects one batch may carry. Real
// clients chunk uploads at 256 per batch (huggingface_hub's
// UPLOAD_BATCH_MAX_NUM_FILES; git-lfs uses 100), so 4096 leaves a wide
// margin. The cap matters because the response ECHOES every object back:
// without it a compact request listing millions of one-byte oids costs
// little to send but forces a proportional allocation here plus a far
// larger response - a cheap amplification primitive. Rejecting is correct
// rather than truncating, since silently dropping objects would make the
// client believe files were negotiated that never were.
const maxLFSBatchObjects = 4096

// Transfer adapter names, as git-lfs and git-xet register them.
const (
	transferBasic = "basic"
	transferXet   = "xet"
)

// Header names git-xet reads off the upload action (git_xet/src/constants.rs).
const (
	headerXetCasURL          = "X-Xet-Cas-Url"
	headerXetAccessToken     = "X-Xet-Access-Token"
	headerXetTokenExpiration = "X-Xet-Token-Expiration"
	headerXetSessionID       = "X-Xet-Session-Id"
)

// handleLFSBatch implements POST /{repo_id}.git/info/lfs/objects/batch,
// the entry point of both upload paths and of git-lfs downloads.
//
// Uploads: when the client offers the "xet" transfer (git-xet installed,
// or huggingface_hub with hf_xet), the reply is transfer "xet". Each
// object not yet stored gets an "upload" action whose href is this
// server's xet-write-token route (git-xet re-fetches a token there when
// the one in the headers nears expiry) and whose headers carry the CAS
// URL, a freshly minted write token, and its expiry - the three things
// git-xet's upload_one requires. huggingface_hub ignores the actions and
// fetches its own token; either way the bytes flow to the CAS as xorbs
// and shards, never through this server. A client that only offers
// "basic" cannot upload here (this server stores nothing but xorbs), so
// each of its objects gets a per-object error explaining what to install.
//
// Downloads: git-xet does not implement downloads, so the reply is
// transfer "basic" with a "download" action per object pointing at this
// server's objects/{oid} route (lfsobjects.go), authenticated by a minted
// read token in the action header. Objects no shard has described get
// the per-object 404 the spec asks for, which git-lfs reports as a
// missing object rather than failing the whole batch.
func (s *Server) handleLFSBatch(w http.ResponseWriter, r *http.Request, repo auth.Repo) {
	if r.Method != http.MethodPost {
		lfsError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Bound the body before decoding it (same pattern as casserver's xorb
	// and shard uploads). MaxBytesReader also makes the failure explicit
	// via *http.MaxBytesError rather than a generic decode error, so an
	// oversize body reports 413 instead of a misleading 400 "invalid JSON".
	r.Body = http.MaxBytesReader(w, r.Body, maxLFSBatchBytes)

	var req lfsBatchRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			lfsError(w, "batch request body exceeds maximum size", http.StatusRequestEntityTooLarge)
			return
		}
		lfsError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Decode stops at the end of the first JSON value and silently ignores
	// whatever follows, so `{"operation":"upload"}<anything>` would be
	// accepted as a well-formed batch. Require the body to be exactly one
	// JSON value: a second Decode must hit EOF (trailing whitespace is
	// skipped by the decoder, so a trailing newline still qualifies).
	// Lenient trailing-data handling is how two intermediaries end up
	// disagreeing about what a request said. (Found by FuzzLFSBatchHandler.)
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		lfsError(w, "unexpected trailing data after JSON body", http.StatusBadRequest)
		return
	}
	if len(req.Objects) > maxLFSBatchObjects {
		lfsError(w, "too many objects in one batch", http.StatusRequestEntityTooLarge)
		return
	}
	if req.HashAlgo != "" && req.HashAlgo != "sha256" {
		lfsError(w, "unsupported hash_algo: "+req.HashAlgo, http.StatusUnprocessableEntity)
		return
	}

	var scope auth.Scope
	switch req.Operation {
	case "upload":
		scope = auth.ScopeWrite
	case "download":
		scope = auth.ScopeRead
	default:
		lfsError(w, "unsupported operation: "+req.Operation, http.StatusBadRequest)
		return
	}
	// Authenticate only once the body is known to be a batch for a real
	// operation, so the fuzz-facing bounds above never depend on auth
	// state - but before any repo state is touched.
	principal, ok := s.lfsAuthenticate(w, r, scope, repo)
	if !ok {
		return
	}

	// Only touch repo state once the request is known to be well-formed.
	// getOrCreateRepo allocates a repoState (plus a revisionState) the
	// first time any repo ID is seen, so doing it before validation would
	// let a flood of malformed requests bearing random repo IDs grow the
	// repos map without ever submitting a valid batch.
	s.getOrCreateRepo(repo.Type, repo.ID)

	resp := lfsBatchResponse{
		HashAlgo: "sha256",
		// Exact capacity: len is already bounded above, so this cannot be
		// used to force an oversized allocation.
		Objects: make([]lfsBatchObject, 0, len(req.Objects)),
	}
	base := lfsBaseURL(r)
	switch req.Operation {
	case "upload":
		s.fillUploadBatch(&resp, &req, repo, base, principal.Subject())
	case "download":
		s.fillDownloadBatch(r, &resp, &req, repo, base, principal.Subject())
	}
	writeLFSJSON(w, http.StatusOK, resp)
}

// objectStored reports whether the CAS can serve oid: a shard declared
// this SHA-256 and the reconstruction it maps to is known.
func (s *Server) objectStored(oid string) (size int64, ok bool) {
	xetHash, known := s.CAS.XetHashForSHA256(oid)
	if !known {
		return 0, false
	}
	return s.CAS.FileSize(xetHash)
}

// missingXorbCount is how many of oid's xorbs this replica lacks; 0 for
// a file that can be served now (or one the CAS cannot even find, which
// objectStored already reported).
func (s *Server) missingXorbCount(ctx context.Context, oid string) int {
	xetHash, known := s.CAS.XetHashForSHA256(oid)
	if !known {
		return 0
	}
	missing, err := s.CAS.MissingXorbs(ctx, xetHash)
	if err != nil {
		return 0
	}
	return len(missing)
}

func offersTransfer(transfers []string, name string) bool {
	for _, t := range transfers {
		if t == name {
			return true
		}
	}
	return false
}

// branchFromRef turns git-lfs's ref.name ("refs/heads/main") into the
// revision segment of the token route; anything unparseable falls back
// to the default revision, since this server keys nothing by branch on
// the LFS path and the segment only has to be a valid revision name.
// repoURLPath renders a repo for a URL: models keep the traditional bare
// "{owner}/{name}" form, while other repo types carry their pluralized
// prefix (the same shape resolve and /api/ URLs use).
func repoURLPath(repo auth.Repo) string {
	if repo.Type == "" || repo.Type == "model" {
		return repo.ID
	}
	return repo.Type + "s/" + repo.ID
}

func branchFromRef(refName string) string {
	branch := strings.TrimPrefix(refName, "refs/heads/")
	if branch == "" || strings.ContainsAny(branch, "/ ") {
		return defaultRevision
	}
	return branch
}

func (s *Server) fillUploadBatch(resp *lfsBatchResponse, req *lfsBatchRequest, repo auth.Repo, base, subject string) {
	xet := offersTransfer(req.Transfers, transferXet)
	if xet {
		resp.Transfer = transferXet
	} else {
		resp.Transfer = transferBasic
	}

	// One token and one session id per batch: git-xet uploads objects
	// sequentially with a fresh FileUploadSession each, and the same
	// credential is valid for all of them.
	var upload *lfsAction
	if xet && len(req.Objects) > 0 {
		token, exp, err := s.mintToken(auth.ScopeWrite, subject, repo)
		if err != nil {
			for _, obj := range req.Objects {
				resp.Objects = append(resp.Objects, lfsBatchObject{OID: obj.OID, Size: obj.Size,
					Error: &lfsObjectError{Code: http.StatusInternalServerError, Message: "mint upload token: " + err.Error()}})
			}
			return
		}
		session, _ := randomToken()
		// No expires_in on the xet action: git-lfs refuses to start a
		// transfer whose action has expired, but the token inside is
		// git-xet's business - it refreshes through href on its own when
		// X-Xet-Token-Expiration nears, so a short -token-ttl must not
		// make git-lfs give up before the agent even starts.
		upload = &lfsAction{
			Href: base + "/api/" + repo.Type + "s/" + repo.ID + "/xet-write-token/" + branchFromRef(req.Ref.Name),
			Header: map[string]string{
				headerXetCasURL:          s.CASBaseURL,
				headerXetAccessToken:     token,
				headerXetTokenExpiration: strconv.FormatInt(exp.Unix(), 10),
				headerXetSessionID:       session,
			},
		}
	}

	for _, obj := range req.Objects {
		out := lfsBatchObject{OID: obj.OID, Size: obj.Size}
		switch {
		case !isLFSOID(obj.OID) || obj.Size < 0:
			out.Error = &lfsObjectError{Code: http.StatusUnprocessableEntity, Message: "oid must be a lowercase hex SHA-256 and size non-negative"}
		case func() bool { _, stored := s.objectStored(obj.OID); return stored }():
			// Already here: no actions, and git-lfs skips the transfer.
		case !xet:
			out.Error = &lfsObjectError{Code: http.StatusUnprocessableEntity,
				Message: "this server stores LFS objects with the xet transfer; install git-xet and run `git xet install` to push"}
		default:
			out.Authenticated = true
			out.Actions = map[string]*lfsAction{"upload": upload}
		}
		resp.Objects = append(resp.Objects, out)
	}
}

func (s *Server) fillDownloadBatch(r *http.Request, resp *lfsBatchResponse, req *lfsBatchRequest, repo auth.Repo, base, subject string) {
	resp.Transfer = transferBasic

	var token string
	var expiresIn int64
	if len(req.Objects) > 0 {
		t, exp, err := s.mintToken(auth.ScopeRead, subject, repo)
		if err != nil {
			for _, obj := range req.Objects {
				resp.Objects = append(resp.Objects, lfsBatchObject{OID: obj.OID, Size: obj.Size,
					Error: &lfsObjectError{Code: http.StatusInternalServerError, Message: "mint download token: " + err.Error()}})
			}
			return
		}
		token = t
		expiresIn = int64(exp.Unix() - exp.Add(-s.tokenTTL).Unix())
	}

	for _, obj := range req.Objects {
		out := lfsBatchObject{OID: obj.OID, Size: obj.Size}
		if !isLFSOID(obj.OID) {
			out.Error = &lfsObjectError{Code: http.StatusUnprocessableEntity, Message: "oid must be a lowercase hex SHA-256"}
			resp.Objects = append(resp.Objects, out)
			continue
		}
		size, stored := s.objectStored(obj.OID)
		var missing int
		if stored {
			missing = s.missingXorbCount(r.Context(), obj.OID)
		}
		switch {
		case !stored:
			out.Error = &lfsObjectError{Code: http.StatusNotFound, Message: "object not found on this server (was it pushed?)"}
		case missing > 0:
			out.Error = &lfsObjectError{Code: http.StatusServiceUnavailable,
				Message: "content not yet available on this replica (" + strconv.Itoa(missing) + " xorb(s) still syncing); retry once the folder has synced"}
		case obj.Size != 0 && obj.Size != size:
			out.Error = &lfsObjectError{Code: http.StatusUnprocessableEntity,
				Message: "pointer size " + strconv.FormatInt(obj.Size, 10) + " does not match stored size " + strconv.FormatInt(size, 10)}
		default:
			out.Size = size
			out.Authenticated = true
			out.Actions = map[string]*lfsAction{"download": {
				Href:      base + "/" + repoURLPath(repo) + lfsPathMarker + "/objects/" + obj.OID,
				Header:    map[string]string{"Authorization": "Bearer " + token},
				ExpiresIn: expiresIn,
			}}
		}
		resp.Objects = append(resp.Objects, out)
	}
}
