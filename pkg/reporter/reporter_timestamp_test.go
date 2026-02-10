package report

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"veo/pkg/types"
)

func TestGenerateCombinedJSONIncludesResultTimestamp(t *testing.T) {
	ts := time.Date(2026, 1, 22, 20, 22, 22, 0, time.Local)
	dirPages := []types.HTTPResponse{
		{
			URL:        "http://example.com/admin",
			StatusCode: 200,
			Timestamp:  ts,
		},
	}
	fpPages := []types.HTTPResponse{
		{
			URL:        "http://example.com",
			StatusCode: 200,
			Timestamp:  ts,
		},
	}

	jsonStr, err := GenerateCombinedJSON(dirPages, fpPages, nil)
	if err != nil {
		t.Fatalf("GenerateCombinedJSON failed: %v", err)
	}

	var got CombinedAPIResponse
	if err := json.Unmarshal([]byte(jsonStr), &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	want := "2026/01/22 20:22:22"
	if len(got.Dirscan) != 1 || got.Dirscan[0].Timestamp != want {
		t.Fatalf("dirscan timestamp mismatch: %+v", got.Dirscan)
	}
	if len(got.Fingerprint) != 1 || got.Fingerprint[0].Timestamp != want {
		t.Fatalf("fingerprint timestamp mismatch: %+v", got.Fingerprint)
	}
}

func TestGenerateCombinedJSONUsesMatchTimestampWhenNoPage(t *testing.T) {
	ts := time.Date(2026, 1, 22, 20, 22, 22, 0, time.Local)
	matches := []types.FingerprintMatch{
		{
			URL:       "http://example.com",
			RuleName:  "test-rule",
			Timestamp: ts,
		},
	}

	jsonStr, err := GenerateCombinedJSON(nil, nil, matches)
	if err != nil {
		t.Fatalf("GenerateCombinedJSON failed: %v", err)
	}

	var got CombinedAPIResponse
	if err := json.Unmarshal([]byte(jsonStr), &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if len(got.Fingerprint) != 1 {
		t.Fatalf("unexpected fingerprint result count: %d", len(got.Fingerprint))
	}
	if got.Fingerprint[0].Timestamp != "2026/01/22 20:22:22" {
		t.Fatalf("unexpected timestamp: %s", got.Fingerprint[0].Timestamp)
	}
}

func TestRealtimeCSVReporterWritesTimestampColumn(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "result.csv")

	reporter, err := NewRealtimeCSVReporter(outputPath)
	if err != nil {
		t.Fatalf("NewRealtimeCSVReporter failed: %v", err)
	}

	ts := time.Date(2026, 1, 22, 20, 22, 22, 0, time.Local)
	resp := &types.HTTPResponse{
		URL:           "http://example.com",
		StatusCode:    200,
		ContentLength: 123,
		Title:         "example",
		Timestamp:     ts,
	}
	if err := reporter.WriteResponse(resp); err != nil {
		t.Fatalf("WriteResponse failed: %v", err)
	}
	if err := reporter.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	f, err := os.Open(outputPath)
	if err != nil {
		t.Fatalf("open csv failed: %v", err)
	}
	defer f.Close()

	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read csv failed: %v", err)
	}
	if len(rows) < 2 {
		t.Fatalf("unexpected rows: %v", rows)
	}

	if rows[0][0] != "Timestamp" {
		t.Fatalf("unexpected header: %v", rows[0])
	}
	if rows[1][0] != "2026/01/22 20:22:22" {
		t.Fatalf("unexpected timestamp value: %v", rows[1][0])
	}
}
