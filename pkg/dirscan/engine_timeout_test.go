package dirscan

import (
	"testing"
	"time"

	requests "veo/pkg/processor"
	"veo/pkg/shared"
)

func TestEngineDefaultRequestTimeout(t *testing.T) {
	cfg := getDefaultConfig()
	if cfg.RequestTimeout != shared.DefaultRequestTimeout {
		t.Fatalf("default request timeout = %v, want %v", cfg.RequestTimeout, shared.DefaultRequestTimeout)
	}
}

func TestEngineKeepsInjectedProcessorTimeout(t *testing.T) {
	rp := requests.NewRequestProcessor(&requests.RequestConfig{Timeout: 7 * time.Second})
	engine := NewEngine(&EngineConfig{MaxConcurrency: 1})
	engine.SetRequestProcessor(rp)

	got := engine.getOrCreateRequestProcessor().GetConfig().Timeout
	if got != 7*time.Second {
		t.Fatalf("processor timeout = %v, want 7s", got)
	}
}
