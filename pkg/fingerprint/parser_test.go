package fingerprint

import (
	"crypto/md5"
	"fmt"
	"testing"
	"time"
	"veo/pkg/types"
)

func TestEvaluateContainsAll(t *testing.T) {
	parser := NewDSLParser()

	tests := []struct {
		name     string
		dsl      string
		body     string
		headers  map[string][]string
		expected bool
	}{
		{
			name:     "match body with all strings",
			dsl:      "contains_all(body, 'foo', 'bar')",
			body:     "this is foo and bar",
			expected: true,
		},
		{
			name:     "fail body missing one string",
			dsl:      "contains_all(body, 'foo', 'baz')",
			body:     "this is foo and bar",
			expected: false,
		},
		{
			name:     "match body case insensitive",
			dsl:      "contains_all(body, 'FOO', 'Bar')",
			body:     "this is foo and bar",
			expected: true,
		},
		{
			name:     "match header",
			dsl:      "contains_all(header, 'X-Test', 'Value')",
			body:     "",
			headers:  map[string][]string{"X-Test": {"Value"}, "Other": {"Header"}},
			expected: true,
		},
		{
			name:     "fail header missing string",
			dsl:      "contains_all(header, 'X-Test', 'Missing')",
			body:     "",
			headers:  map[string][]string{"X-Test": {"Value"}},
			expected: false,
		},
		{
			name:     "verify bug fix: body without 'body' string",
			dsl:      "contains_all(body, 'foo', 'bar')",
			body:     "foo and bar", // Does NOT contain the word "body"
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(map[string][]string)
			if tt.headers != nil {
				headers = make(map[string][]string, len(tt.headers))
				for k, v := range tt.headers {
					if len(v) == 0 {
						continue
					}
					dup := make([]string, len(v))
					copy(dup, v)
					headers[k] = dup
				}
			}

			ctx := &DSLContext{
				Body:    tt.body,
				Headers: headers,
				Response: &types.HTTPResponse{
					Title:  "Test Title",
					Server: "Test Server",
				},
			}
			result := parser.EvaluateDSL(tt.dsl, ctx)
			if result != tt.expected {
				t.Errorf("EvaluateDSL(%q) = %v, want %v", tt.dsl, result, tt.expected)
			}
		})
	}
}

func TestBuildJSONResultIncludesTimestamp(t *testing.T) {
	ts := time.Date(2026, 1, 22, 20, 22, 22, 0, time.Local)
	resp := &HTTPResponse{
		URL:           "http://example.com",
		StatusCode:    200,
		ContentLength: 1,
		ContentType:   "text/html",
		Title:         "example",
		Timestamp:     ts,
	}

	result := buildJSONResult(resp, nil, nil)
	if result.Timestamp != "2026/01/22 20:22:22" {
		t.Fatalf("unexpected timestamp: %s", result.Timestamp)
	}
}

type mockClient struct {
	body       string
	statusCode int
	err        error
}

func (m *mockClient) MakeRequest(rawURL string) (string, int, error) {
	return m.body, m.statusCode, m.err
}

func TestIconCache(t *testing.T) {
	c := NewIconCache()
	client := &mockClient{body: "test_icon_data", statusCode: 200}
	expectedHash := fmt.Sprintf("%x", md5.Sum([]byte("test_icon_data")))

	hash, err := c.GetHash("http://example.com/icon.ico", client)
	if err != nil {
		t.Errorf("GetHash failed: %v", err)
	}
	if hash != expectedHash {
		t.Errorf("Expected hash %s, got %s", expectedHash, hash)
	}

	client.body = "changed_data"
	hash2, err := c.GetHash("http://example.com/icon.ico", client)
	if err != nil {
		t.Errorf("GetHash failed: %v", err)
	}
	if hash2 != expectedHash {
		t.Errorf("Cache miss? Expected %s, got %s", expectedHash, hash2)
	}

	if _, exists := c.GetMatchResult("http://example.com/icon.ico", expectedHash); exists {
		t.Error("Match cache should be empty")
	}

	c.SetMatchResult("http://example.com/icon.ico", expectedHash, true)
	matched, exists := c.GetMatchResult("http://example.com/icon.ico", expectedHash)
	if !exists || !matched {
		t.Error("Match cache failed")
	}

	c.Clear()
	if _, exists := c.GetMatchResult("http://example.com/icon.ico", expectedHash); exists {
		t.Error("Clear failed")
	}
}

func TestDeduplicator(t *testing.T) {
	d := NewDeduplicator()

	url1 := "http://example.com"
	fps1 := []string{"CMS"}
	if !d.ShouldOutput(url1, fps1) {
		t.Error("Expected true for first time output")
	}

	if d.ShouldOutput(url1, fps1) {
		t.Error("Expected false for second time output")
	}

	fps2 := []string{"CMS", "Framework"}
	if !d.ShouldOutput(url1, fps2) {
		t.Error("Expected true for new fingerprints on same URL")
	}

	d.Clear()
	if !d.ShouldOutput(url1, []string{"CMS"}) {
		t.Error("Expected true for first time output")
	}
	if d.ShouldOutput(url1, []string{"CMS", "CMS"}) {
		t.Error("Expected false for duplicated fingerprint names (same logical key)")
	}

	d.Clear()
	if d.Count() != 0 {
		t.Errorf("Expected count 0, got %d", d.Count())
	}
	if !d.ShouldOutput(url1, fps1) {
		t.Error("Expected true after clear")
	}
}
