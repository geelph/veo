package cli

import (
	"testing"
	"time"

	"veo/pkg/shared"
)

func TestBuildActiveRequestConfigDefaultTimeout(t *testing.T) {
	cfg := buildActiveRequestConfig(nil, "")
	if cfg.Timeout != shared.DefaultRequestTimeout {
		t.Fatalf("active timeout = %v, want %v", cfg.Timeout, shared.DefaultRequestTimeout)
	}
}

func TestBuildActiveRequestConfigArgsTimeout(t *testing.T) {
	cfg := buildActiveRequestConfig(&CLIArgs{Timeout: 9}, "")
	if cfg.Timeout != 9*time.Second {
		t.Fatalf("active timeout = %v, want 9s", cfg.Timeout)
	}
}
