package fingerprint

import (
	"context"
	"testing"
)

type redirectingFingerprintClient struct {
	calls int
}

func (c *redirectingFingerprintClient) MakeRequest(rawURL string) (string, int, error) {
	c.calls++
	if rawURL == "http://example.com/next" {
		return `<html><script>location.href = "/start";</script></html>`, 200, nil
	}
	return "ok", 200, nil
}

type staticFilterFormatter struct {
	matchCount   int
	noMatchCount int
}

func (f *staticFilterFormatter) FormatMatch(matches []*FingerprintMatch, response *HTTPResponse, tags ...string) {
	f.matchCount++
}

func (f *staticFilterFormatter) FormatNoMatch(response *HTTPResponse) {
	f.noMatchCount++
}

func (f *staticFilterFormatter) ShouldOutput(url string, fingerprintNames []string) bool {
	return true
}

func TestAnalyzeResponseStaticFileDoesNotOutputNoMatch(t *testing.T) {
	engine := NewEngine(nil)
	formatter := &staticFilterFormatter{}
	engine.config.OutputFormatter = formatter

	resp := &HTTPResponse{
		URL:         "https://example.com/jis-web/css/chunk-vendors.4cd41c92.css",
		StatusCode:  200,
		ContentType: "text/css",
		Body:        "body { color: red; }",
	}

	matches := engine.AnalyzeResponseWithClient(resp, nil)
	if len(matches) != 0 {
		t.Fatalf("expected no matches for static file, got %d", len(matches))
	}
	if formatter.matchCount != 0 {
		t.Fatalf("expected no match output for static file, got %d", formatter.matchCount)
	}
	if formatter.noMatchCount != 0 {
		t.Fatalf("expected filtered static file to suppress no-match output, got %d", formatter.noMatchCount)
	}
}

func TestAnalyzeResponseFollowsClientRedirectOnce(t *testing.T) {
	engine := NewEngine(nil)
	engine.config.EnableFiltering = false
	engine.ruleManager.rules["match-ok"] = &FingerprintRule{
		ID:   "match-ok",
		Name: "match-ok",
		DSL:  []string{"contains(body, 'ok')"},
	}
	engine.ruleManager.updateSnapshot()

	client := &redirectingFingerprintClient{}
	resp := &HTTPResponse{
		URL:         "http://example.com/start",
		StatusCode:  200,
		ContentType: "text/html",
		Body:        `<html><script>location.href = "/next";</script></html>`,
	}

	matches := engine.AnalyzeResponseWithClient(resp, client)
	if len(matches) != 0 {
		t.Fatalf("expected no match after single redirect, got %d", len(matches))
	}
	if client.calls != 1 {
		t.Fatalf("expected exactly one client redirect fetch, got %d", client.calls)
	}
}

type failingFingerprintClient struct {
	calls int
}

func (c *failingFingerprintClient) MakeRequest(rawURL string) (string, int, error) {
	c.calls++
	return "", 0, context.DeadlineExceeded
}

func TestExecuteActiveProbingCanDisableTimeoutDrop(t *testing.T) {
	engine := NewEngine(nil)
	engine.config.MaxConcurrency = 1
	engine.SetTimeoutDrop(false, func(string) {
		t.Fatal("timeout drop handler should not be called when disabled")
	})
	engine.ruleManager.rules["path-rule"] = &FingerprintRule{
		ID:    "path-rule",
		Name:  "path-rule",
		DSL:   []string{"contains(body, 'ok')"},
		Paths: []string{"/a", "/b", "/c"},
	}
	engine.ruleManager.updateSnapshot()

	client := &failingFingerprintClient{}
	results, err := engine.ExecuteActiveProbing(context.Background(), "http://example.com", client)
	if err != nil {
		t.Fatalf("ExecuteActiveProbing failed: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no results, got %d", len(results))
	}
	if client.calls != 3 {
		t.Fatalf("drop disabled should process all tasks, calls = %d, want 3", client.calls)
	}
}
