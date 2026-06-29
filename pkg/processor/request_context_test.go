package processor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"veo/pkg/shared"
	interfaces "veo/pkg/types"
)

func TestRequestProcessor_ProcessURLsWithContext_CancelStopsEarly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟慢响应，便于观察取消是否能提前停止后续URL处理
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rp := NewRequestProcessor(&RequestConfig{
		Timeout:            2 * time.Second,
		MaxRetries:         0,
		MaxConcurrent:      1,
		FollowRedirect:     false,
		DecompressResponse: true,
	})

	urls := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		urls = append(urls, srv.URL)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// 等待请求开始后再取消，避免测试变成“零请求直接返回”的路径
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_ = rp.ProcessURLsWithContext(ctx, urls)
	elapsed := time.Since(start)

	// 若未能停止派发剩余URL，50*200ms 约等于 10s；取消后应明显更快返回
	if elapsed > 3*time.Second {
		t.Fatalf("expected ProcessURLsWithContext to stop early after cancel; took %v", elapsed)
	}
}

func TestRequestProcessor_GetConfigReturnsCopy(t *testing.T) {
	rp := NewRequestProcessor(&RequestConfig{
		Timeout:       time.Second,
		MaxRetries:    1,
		MaxConcurrent: 5,
		UserAgents:    []string{"ua-a"},
	})

	cfg := rp.GetConfig()
	cfg.Timeout = 9 * time.Second
	cfg.UserAgents[0] = "ua-b"

	got := rp.GetConfig()
	if got.Timeout != time.Second {
		t.Fatalf("GetConfig leaked Timeout mutation: got %v", got.Timeout)
	}
	if len(got.UserAgents) != 1 || got.UserAgents[0] != "ua-a" {
		t.Fatalf("GetConfig leaked UserAgents mutation: got %#v", got.UserAgents)
	}
}

func TestRequestProcessor_UpdateConfigCopiesInput(t *testing.T) {
	rp := NewRequestProcessor(nil)
	cfg := &RequestConfig{
		Timeout:       2 * time.Second,
		MaxRetries:    1,
		MaxConcurrent: 5,
		UserAgents:    []string{"ua-a"},
	}

	rp.UpdateConfig(cfg)
	cfg.Timeout = 9 * time.Second
	cfg.UserAgents[0] = "ua-b"

	got := rp.GetConfig()
	if got.Timeout != 2*time.Second {
		t.Fatalf("UpdateConfig kept caller Timeout pointer: got %v", got.Timeout)
	}
	if len(got.UserAgents) != 1 || got.UserAgents[0] != "ua-a" {
		t.Fatalf("UpdateConfig kept caller UserAgents slice: got %#v", got.UserAgents)
	}
}

func TestRequestProcessor_DefaultTimeout(t *testing.T) {
	cfg := GetDefaultConfig()
	if cfg.Timeout != shared.DefaultRequestTimeout {
		t.Fatalf("default timeout = %v, want %v", cfg.Timeout, shared.DefaultRequestTimeout)
	}

	rp := NewRequestProcessor(&RequestConfig{Timeout: 0})
	if got := rp.EffectiveTimeout(); got != shared.DefaultRequestTimeout {
		t.Fatalf("effective timeout = %v, want %v", got, shared.DefaultRequestTimeout)
	}
}

func TestRequestProcessor_WithTimeoutUsesConfig(t *testing.T) {
	rp := NewRequestProcessor(&RequestConfig{Timeout: 40 * time.Millisecond})

	ctx, cancel := rp.WithTimeout(context.Background())
	defer cancel()

	select {
	case <-ctx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected context to be canceled by processor timeout")
	}
}

func TestRequestProcessor_DropsLateResponseAfterContextDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("late"))
	}))
	defer srv.Close()

	rp := NewRequestProcessor(&RequestConfig{
		Timeout:            time.Second,
		MaxRetries:         0,
		MaxConcurrent:      1,
		DecompressResponse: true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	resp, err := rp.RequestOnceWithHeaders(ctx, srv.URL, nil)
	if resp != nil {
		t.Fatalf("expected late response to be dropped, got %#v", resp)
	}
	if !IsTimeoutError(err) {
		t.Fatalf("expected context timeout error, got %v", err)
	}
}

func TestRequestProcessor_ResultHookCanCancelAfterTimeoutStopLoss(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		time.Sleep(80 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("late"))
	}))
	defer srv.Close()

	rp := NewRequestProcessor(&RequestConfig{
		Timeout:            20 * time.Millisecond,
		MaxRetries:         0,
		MaxConcurrent:      1,
		DecompressResponse: true,
	})

	urls := make([]string, 20)
	for i := range urls {
		urls[i] = srv.URL
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopLoss := shared.NewTimeoutStopLossWithConfig(shared.TimeoutStopLossConfig{MaxConsecutiveTimeouts: 5})
	rp.ProcessURLsWithCallbackAndResultHook(ctx, urls, nil, nil, func(resp *interfaces.HTTPResponse, err error) {
		if resp == nil && stopLoss.Record(err) {
			cancel()
		}
	})

	if got := atomic.LoadInt64(&hits); got >= int64(len(urls)) {
		t.Fatalf("expected stop loss to cancel before all requests, got %d hits", got)
	}
}

func TestRequestProcessor_CloneWithContextRebuildsClientTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rp := NewRequestProcessor(&RequestConfig{
		Timeout:            2 * time.Second,
		MaxRetries:         0,
		MaxConcurrent:      1,
		DecompressResponse: true,
	})

	clone := rp.CloneWithContext("test", 30*time.Millisecond)
	_, err := clone.RequestOnceWithHeaders(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatal("expected cloned processor to use shorter timeout")
	}
	if !IsTimeoutError(err) {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestRequestProcessor_UsesFinalRedirectURL(t *testing.T) {
	finalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			t.Fatalf("unexpected final path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<title>login</title>"))
	}))
	defer finalSrv.Close()

	entrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, finalSrv.URL+"/login", http.StatusFound)
	}))
	defer entrySrv.Close()

	rp := NewRequestProcessor(&RequestConfig{
		Timeout:            2 * time.Second,
		MaxRetries:         0,
		MaxConcurrent:      1,
		FollowRedirect:     true,
		MaxRedirects:       3,
		DecompressResponse: true,
	})
	rp.SetRedirectSameHostOnly(false)

	resp, err := rp.RequestOnceWithHeaders(context.Background(), entrySrv.URL+"/entry", nil)
	if err != nil {
		t.Fatalf("RequestOnceWithHeaders failed: %v", err)
	}
	want := finalSrv.URL + "/login"
	if resp.URL != want {
		t.Fatalf("response URL = %q, want final URL %q", resp.URL, want)
	}
	if _, ok := resp.ResponseHeaders["X-VEO-Final-URL"]; ok {
		t.Fatalf("internal final URL header leaked into response headers")
	}
}
