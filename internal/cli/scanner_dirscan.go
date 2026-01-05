package cli

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"veo/pkg/dirscan"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	requests "veo/pkg/utils/processor"
)

const dirscanTimeoutDropThreshold = 100

type timeoutDropper struct {
	base      requests.StatsUpdater
	threshold int64
	onExceed  func()
	count     int64
	triggered int32
}

func (t *timeoutDropper) IncrementCompletedRequests() {
	if t.base != nil {
		t.base.IncrementCompletedRequests()
	}
}

func (t *timeoutDropper) IncrementTimeouts() {
	if t.base != nil {
		t.base.IncrementTimeouts()
	}
	if t.threshold <= 0 {
		return
	}
	newCount := atomic.AddInt64(&t.count, 1)
	if newCount >= t.threshold && atomic.CompareAndSwapInt32(&t.triggered, 0, 1) {
		if t.onExceed != nil {
			t.onExceed()
		}
	}
}

func (t *timeoutDropper) IncrementErrors() {
	if t.base != nil {
		t.base.IncrementErrors()
	}
}

func (t *timeoutDropper) SetTotalRequests(count int64) {
	if t.base != nil {
		t.base.SetTotalRequests(count)
	}
}

func (t *timeoutDropper) AddTotalRequests(count int64) {
	if t.base != nil {
		t.base.AddTotalRequests(count)
	}
}

func (t *timeoutDropper) IncrementCompletedHosts() {
	if t.base != nil {
		t.base.IncrementCompletedHosts()
	}
}

type wafCancelContext struct {
	context.Context
	reason atomic.Value
}

func (w *wafCancelContext) Value(key interface{}) interface{} {
	if key == dirscan.CancelReasonKey {
		if v := w.reason.Load(); v != nil {
			return v
		}
		return nil
	}
	return w.Context.Value(key)
}

func (w *wafCancelContext) setReason(reason string) {
	w.reason.Store(reason)
}

func (sc *ScanController) runDirscanModule(ctx context.Context, targets []string) ([]interfaces.HTTPResponse, error) {
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext("dirscan")

	originalBatchMode := sc.requestProcessor.IsBatchMode()
	sc.requestProcessor.SetBatchMode(true)
	originalDecompress := true
	originalFollowRedirect := false
	originalMaxRedirects := 0
	if cfg := sc.requestProcessor.GetConfig(); cfg != nil {
		originalDecompress = cfg.DecompressResponse
		originalFollowRedirect = cfg.FollowRedirect
		originalMaxRedirects = cfg.MaxRedirects
		if originalDecompress || originalFollowRedirect || originalMaxRedirects != 0 {
			updated := *cfg
			updated.DecompressResponse = false
			updated.FollowRedirect = false
			updated.MaxRedirects = 0
			sc.requestProcessor.UpdateConfig(&updated)
		}
	}

	defer func() {
		sc.requestProcessor.SetModuleContext(originalContext)
		sc.requestProcessor.SetBatchMode(originalBatchMode)
		if cfg := sc.requestProcessor.GetConfig(); cfg != nil {
			if cfg.DecompressResponse != originalDecompress || cfg.FollowRedirect != originalFollowRedirect || cfg.MaxRedirects != originalMaxRedirects {
				updated := *cfg
				updated.DecompressResponse = originalDecompress
				updated.FollowRedirect = originalFollowRedirect
				updated.MaxRedirects = originalMaxRedirects
				sc.requestProcessor.UpdateConfig(&updated)
			}
		}
	}()

	// 模块启动提示
	dictInfo := "config/dict/common.txt"
	if strings.TrimSpace(sc.wordlistPath) != "" {
		dictInfo = sc.wordlistPath
	}
	// 模块开始前空行，提升可读性
	logger.Infof("Start Dirscan, Loaded Dict: %s", dictInfo)
	validTargets := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		validTargets = append(validTargets, target)
	}

	logger.Debugf("开始目录扫描，目标数量: %d", len(validTargets))

	maxDepth := 0
	if sc.args.DepthSet {
		maxDepth = sc.args.Depth
	}

	if sc.statsDisplay.IsEnabled() {
		if maxDepth <= 0 {
			dictSize := dirscan.GetCommonDictionarySize()
			if dictSize > 0 {
				totalRequests := int64(len(validTargets) * dictSize)
				sc.statsDisplay.EnableManualTotalRequests(totalRequests)
				defer sc.statsDisplay.DisableManualTotalRequests()
			}
		} else {
			sc.statsDisplay.DisableManualTotalRequests()
		}
	}

	reqConfig := sc.requestProcessor.GetConfig()

	var allResults []interfaces.HTTPResponse
	var allResultsMu sync.Mutex
	var firstErr error
	hadSuccess := false

	if len(validTargets) == 0 {
		return allResults, nil
	}

	maxConcurrent := reqConfig.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}

	perTargetConcurrent := maxConcurrent
	if perTargetConcurrent < 1 {
		perTargetConcurrent = 1
	}

	logger.Debugf("目录扫描顺序扫描目标，单目标并发数: %d", perTargetConcurrent)

	for _, target := range validTargets {
		if ctx.Err() != nil {
			break
		}

		currentTarget := target

		workerProcessor := sc.requestProcessor.CloneWithContext("dirscan", 0)
		workerCfg := workerProcessor.GetConfig()
		if workerCfg.MaxConcurrent != perTargetConcurrent {
			workerCfg.MaxConcurrent = perTargetConcurrent
			workerProcessor.UpdateConfig(workerCfg)
		}

		engine := dirscan.NewEngine(&dirscan.EngineConfig{
			MaxConcurrency: perTargetConcurrent,
			RequestTimeout: workerCfg.Timeout,
			ProxyURL:       workerCfg.ProxyURL,
		})
		engine.SetRequestProcessor(workerProcessor)

		baseCtx, baseCancel := context.WithCancel(ctx)
		runCtx := &wafCancelContext{Context: baseCtx}
		cancel := baseCancel

		timeoutTracker := &timeoutDropper{
			base:      workerProcessor.GetStatsUpdater(),
			threshold: dirscanTimeoutDropThreshold,
			onExceed: func() {
				if ctx.Err() != nil {
					return
				}
				runCtx.setReason(dirscan.CancelReasonWAF)
				logger.Warnf("%s 疑似存在WAF，超时已丢弃", currentTarget)
				if cancel != nil {
					cancel()
				}
			},
		}
		workerProcessor.SetStatsUpdater(timeoutTracker)

		layerScanner := func(layerTargets []string, filter *dirscan.ResponseFilter, depth int) ([]interfaces.HTTPResponse, error) {
			tempCollector := dirscan.NewRecursionCollector(layerTargets)

			recursive := depth > 0
			scanResult, err := engine.PerformScanWithFilter(runCtx, tempCollector, recursive, filter)
			if err != nil {
				if runCtx.Err() != nil {
					if reason, ok := runCtx.Value(dirscan.CancelReasonKey).(string); ok && reason == dirscan.CancelReasonWAF {
						return nil, nil
					}
				}
				return nil, err
			}
			if scanResult == nil || scanResult.FilterResult == nil {
				return nil, nil
			}

			validPages := scanResult.FilterResult.ValidPages

			sc.collectedResultsMu.Lock()
			if len(scanResult.FilterResult.PrimaryFilteredPages) > 0 {
				sc.collectedPrimaryFiltered = append(sc.collectedPrimaryFiltered, toValueSlice(scanResult.FilterResult.PrimaryFilteredPages)...)
			}
			if len(scanResult.FilterResult.StatusFilteredPages) > 0 {
				sc.collectedStatusFiltered = append(sc.collectedStatusFiltered, toValueSlice(scanResult.FilterResult.StatusFilteredPages)...)
			}
			sc.collectedResultsMu.Unlock()

			if sc.statsDisplay.IsEnabled() {
				for range layerTargets {
					sc.statsDisplay.IncrementCompletedHosts()
				}
			}

			result := make([]interfaces.HTTPResponse, 0, len(validPages))
			for _, page := range validPages {
				if page != nil {
					result = append(result, *page)
				}
			}

			return result, nil
		}

		targetFilter := dirscan.CreateResponseFilterFromExternal()
		if sc.fingerprintEngine != nil {
			targetFilter.SetFingerprintEngine(sc.fingerprintEngine)
		}
		targetFilter.SetOnValid(func(page *interfaces.HTTPResponse) {
			if page == nil {
				return
			}
			sc.displayedURLsMu.Lock()
			if sc.displayedURLs[page.URL] {
				sc.displayedURLsMu.Unlock()
				return
			}
			sc.displayedURLs[page.URL] = true
			sc.displayedURLsMu.Unlock()

			allResultsMu.Lock()
			allResults = append(allResults, *page)
			allResultsMu.Unlock()

			if sc.realtimeReporter != nil {
				_ = sc.realtimeReporter.WriteResponse(page)
			}
			printHTTPResponseResult(page, sc.showFingerprintSnippet, sc.args.Verbose || sc.args.VeryVerbose)
		})

		_, err := dirscan.RunRecursiveScan(
			runCtx,
			[]string{currentTarget},
			maxDepth,
			layerScanner,
			targetFilter,
		)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			logger.Warnf("目标目录扫描失败: %s, %v", currentTarget, err)
			continue
		}

		hadSuccess = true
	}

	if !hadSuccess && firstErr != nil {
		return nil, firstErr
	}

	return allResults, nil
}
