package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Exercise the read-only verifier against bytes written by the actual ARTEX exporter.
// A body or header serialization change must not silently produce a confirmed finding.
func TestWhitehatReadsNativeEvidenceExport(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("native report contract requires Python 3.10+")
	}
	dir := t.TempDir()
	sum := sha256.Sum256(nil)
	hash := hex.EncodeToString(sum[:])
	blobDir := filepath.Join(dir, "blobs", hash[:2])
	if err := os.MkdirAll(blobDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, hash+".bin"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot := db.TrafficEvidenceSnapshot{
		SourceTrafficID: "1700000001-0001", CapturedAt: 1700000001,
		URL: "https://fixture.test/data", Method: "GET", Status: 200, ContentType: "text/html",
		ReqHead: "GET /data HTTP/1.1\nHost: fixture.test\n", RespHead: "HTTP 200\nContent-Type: text/html\n",
		ReqHash: hash, RespHash: hash,
	}
	snapshot.ID = db.TrafficSnapshotID(snapshot)
	finding := db.DBFinding{ID: 42, Name: "Header policy"}
	finding.TrafficBindings = []db.FindingTrafficBinding{
		{ID: 17, FindingID: finding.ID, SnapshotID: snapshot.ID, Snapshot: snapshot, Role: "proof"},
	}
	archive := filepath.Join(dir, "capture.zip")
	if err := buildFindingsEvidenceZip(archive, []*db.DBFinding{&finding}, dir, time.Unix(1700000001, 0)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	archiveSum := sha256.Sum256(data)
	spec := map[string]any{"schema": "whitehat-report/1", "cases": []any{
		map[string]any{
			"id": "native-export", "revision": "v1", "target": snapshot.URL,
			"control": "https://control.test/data", "window": []int{1700000000, 1700000010},
			"rule": map[string]string{"kind": "http.nosniff", "finding_id": "42", "media_type": "text/html"},
			"runs": []map[string]string{{"id": "first", "collector": "native", "side": "target",
				"revision": "v1", "file": "capture.zip", "sha256": hex.EncodeToString(archiveSum[:])}},
		},
	}}
	body, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "case.json")
	if err := os.WriteFile(file, body, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "output")
	cmd := exec.Command(python, "-m", "whitehat", "report", file, "--out", output)
	cmd.Dir = ".."
	if log, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native evidence verification: %v\n%s", err, log)
	}
	raw, err := os.ReadFile(filepath.Join(output, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(raw, &report); err != nil || report.Counts["observed"] != 1 {
		t.Fatalf("unexpected native report: %v, counts %v", err, report.Counts)
	}
}
