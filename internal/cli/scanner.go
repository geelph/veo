package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"veo/internal/config"
	"veo/pkg/fingerprint"
	"veo/pkg/logger"
	requests "veo/pkg/processor"
	reporter "veo/pkg/reporter"
	"veo/pkg/stats"
	interfaces "veo/pkg/types"
)

// ScanController 扫描控制器
type ScanController struct {
	args                   *CLIArgs
	config                 *config.Config
	runtimeConfig          *RuntimeConfig
	requestProcessor       *requests.RequestProcessor
	fingerprintEngine      *fingerprint.Engine
	probedHosts            map[string]bool
	probedMutex            sync.RWMutex
	statsDisplay           *stats.StatsDisplay
	showFingerprintSnippet bool
	reportPath             string
	wordlistPath           string
	realtimeReporter       *reporter.RealtimeCSVReporter

	lastDirscanResults     []interfaces.HTTPResponse
	lastFingerprintResults []interfaces.HTTPResponse
	scanStartedAt          time.Time
	scanDuration           time.Duration
	moduleDurations        map[string]time.Duration

	displayedURLs   map[string]bool
	displayedURLsMu sync.Mutex

	collectedPrimaryFiltered []interfaces.HTTPResponse
	collectedStatusFiltered  []interfaces.HTTPResponse
	collectedResultsMu       sync.Mutex

	droppedTargetsMu sync.Mutex
	droppedTargets   map[string]struct{}
}

func NewScanController(args *CLIArgs, cfg *config.Config) *ScanController {
	runtimeConfig := buildRuntimeConfig(args)
	requestConfig := runtimeConfig.Request

	if !args.CheckSimilarOnly {
		logger.Debugf("请求处理器并发数设置为: %d", requestConfig.MaxConcurrent)
		logger.Debugf("请求处理器重试次数设置为: %d", requestConfig.MaxRetries)
		logger.Debugf("请求处理器超时时间设置为: %v", requestConfig.Timeout)
		if requestConfig.ProxyURL != "" {
			logger.Debugf("ActiveScan: 设置请求处理器代理: %s", requestConfig.ProxyURL)
		}
	}

	var fpEngine *fingerprint.Engine
	if !args.CheckSimilarOnly && (args.HasModule(moduleFinger) || args.HasModule(moduleDirscan)) {
		fpEngine = fingerprint.NewEngine(nil)
		if fpEngine != nil {
			if err := fpEngine.LoadRules(fpEngine.GetConfig().RulesPath); err != nil {
				logger.Warnf("Failed to load fingerprint rules, fingerprint detection may return no results: %v", err)
			}
		}
	}

	requestProcessor := requests.NewRequestProcessor(requestConfig)

	if len(args.Modules) == 1 && args.Modules[0] == moduleFinger {
		requestProcessor.SetModuleContext("fingerprint")
	}
	if len(runtimeConfig.Headers) > 0 {
		requestProcessor.SetCustomHeaders(runtimeConfig.Headers)
	}
	if args.Shiro {
		requestProcessor.SetShiroCookieEnabled(true)
	}

	statsDisplay := stats.NewStatsDisplay()
	if args.Stats {
		statsDisplay.Enable()
		requestProcessor.SetStatsUpdater(statsDisplay)
	}

	snippetEnabled := args.VeryVerbose
	ruleEnabled := args.Verbose || args.VeryVerbose

	if fpEngine != nil {
		// 启用snippet捕获(用于报告)
		fpEngine.GetConfig().ShowSnippet = true

		// 创建OutputFormatter并注入到Engine
		var outputFormatter fingerprint.OutputFormatter
		if args.JSONOutput {
			jsonFormatter := fingerprint.NewJSONOutputFormatter()
			jsonFormatter.SetSuppressOutput(true)
			outputFormatter = jsonFormatter
		} else {
			consoleFormatter := fingerprint.NewConsoleOutputFormatter(
				true,           // logMatches
				true,           // showSnippet - 始终捕获
				ruleEnabled,    // showRules
				snippetEnabled, // consoleSnippetEnabled
			)
			outputFormatter = consoleFormatter
		}
		fpEngine.GetConfig().OutputFormatter = outputFormatter
		logger.Debugf("指纹引擎 OutputFormatter 已注入: %T", outputFormatter)
	}

	sc := &ScanController{
		args:                   args,
		config:                 cfg,
		runtimeConfig:          runtimeConfig,
		requestProcessor:       requestProcessor,
		fingerprintEngine:      fpEngine,
		probedHosts:            make(map[string]bool),
		statsDisplay:           statsDisplay,
		showFingerprintSnippet: snippetEnabled,
		reportPath:             strings.TrimSpace(args.Output),
		wordlistPath:           strings.TrimSpace(args.Wordlist),
		moduleDurations:        make(map[string]time.Duration),
		displayedURLs:          make(map[string]bool),
		droppedTargets:         make(map[string]struct{}),
	}
	if sc.fingerprintEngine != nil {
		sc.fingerprintEngine.SetTimeoutDrop(sc.timeoutDropEnabled(), sc.recordDroppedTarget)
	}

	return sc
}

func (sc *ScanController) timeoutDropEnabled() bool {
	if sc.args == nil {
		return true
	}
	return !sc.args.DropSet || sc.args.Drop
}

func (sc *ScanController) recordDroppedTarget(target string) {
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}

	sc.droppedTargetsMu.Lock()
	defer sc.droppedTargetsMu.Unlock()
	if sc.droppedTargets == nil {
		sc.droppedTargets = make(map[string]struct{})
	}
	sc.droppedTargets[target] = struct{}{}
}

func (sc *ScanController) droppedTargetList() []string {
	sc.droppedTargetsMu.Lock()
	defer sc.droppedTargetsMu.Unlock()
	if len(sc.droppedTargets) == 0 {
		return nil
	}

	targets := make([]string, 0, len(sc.droppedTargets))
	for target := range sc.droppedTargets {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets
}

func (sc *ScanController) Run() error {
	if shouldUseRealtimeCSVReport(sc.reportPath) {
		realtimeReporter, err := reporter.NewRealtimeCSVReporter(sc.reportPath)
		if err != nil {
			logger.Warnf("Failed to create realtime CSV report: %v", err)
		} else {
			sc.realtimeReporter = realtimeReporter
			sc.attachRealtimeReporter()
			logger.Infof("Realtime CSV Report: %s", realtimeReporter.Path())
			defer func() {
				if err := realtimeReporter.Close(); err != nil {
					logger.Warnf("Failed to close realtime CSV report: %v", err)
				}
			}()
		}
	}

	return sc.runActiveMode()
}

func (sc *ScanController) runActiveMode() error {
	if sc.args == nil || !sc.args.CheckSimilarOnly {
		logger.Debug("启动主动扫描模式")
	}

	restoreNetworkCheck := prepareTargetParsingNetworkCheck(sc.args)
	targets, err := sc.parseTargets(sc.args.Targets)
	restoreNetworkCheck()
	if err != nil {
		return fmt.Errorf("Target Parse Error: %v", err)
	}

	logger.Debugf("解析到 %d 个目标", len(targets))

	orderedModules := sc.getOptimizedModuleOrder()
	sc.scanStartedAt = time.Now()

	// 信号处理：捕获 Ctrl+C / SIGTERM，通过 ctx 取消让各模块尽快收敛
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	defer close(done)

	stopSignalWatcher := startSignalCancelWatcher(done, cancel)
	defer stopSignalWatcher()

	if sc.args.CheckSimilarOnly {
		targets, _ = sc.checkSimilarTargetsWithReport(ctx, targets)
		for _, target := range targets {
			fmt.Println(target)
		}
		return nil
	}

	if sc.args.CheckSimilar {
		targets, _ = sc.checkSimilarTargetsWithReport(ctx, targets)
	}

	// 打印有效性筛选结果
	if !sc.args.JSONOutput {
		logger.Infof("Available Hosts: %d", len(targets))
	}

	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.SetTotalHosts(int64(len(targets)))
		logger.Debugf("统计显示器：设置总主机数 = %d", len(targets))
	}

	// 同步执行：避免 goroutine 写结果、主流程读结果带来的数据竞争
	allResults, dirscanResults, fingerprintResults := sc.executeModulesSequenceWithContext(ctx, orderedModules, targets)

	return sc.finalizeScan(allResults, dirscanResults, fingerprintResults)
}

func (sc *ScanController) executeModulesSequenceWithContext(ctx context.Context, modules []string, targets []string) ([]interfaces.HTTPResponse, []interfaces.HTTPResponse, []interfaces.HTTPResponse) {
	var allResults []interfaces.HTTPResponse
	var dirResults []interfaces.HTTPResponse
	var fingerprintResults []interfaces.HTTPResponse

	if len(modules) == 0 || len(targets) == 0 {
		return allResults, dirResults, fingerprintResults
	}

	for i, moduleName := range modules {
		// 检查Context是否取消
		select {
		case <-ctx.Done():
			return allResults, dirResults, fingerprintResults
		default:
		}

		logger.Debugf("开始执行模块: %s (%d/%d)", moduleName, i+1, len(modules))

		startedAt := time.Now()
		moduleResults, err := sc.runModuleForTargetsWithContext(ctx, moduleName, targets)
		sc.moduleDurations[moduleName] = time.Since(startedAt)
		if err != nil {
			if sc.args == nil || !sc.args.JSONOutput {
				logger.Errorf("Module %s execution failed: %v", moduleName, err)
			}
			continue
		}

		allResults = append(allResults, moduleResults...)
		switch moduleName {
		case moduleDirscan:
			dirResults = append(dirResults, moduleResults...)
		case moduleFinger:
			fingerprintResults = append(fingerprintResults, moduleResults...)
		}
		logger.Debugf("模块 %s 完成，获得 %d 个结果", moduleName, len(moduleResults))

		if len(modules) > 1 && i < len(modules)-1 && !sc.args.JSONOutput {
			fmt.Println()
		}
	}

	return allResults, dirResults, fingerprintResults
}

func (sc *ScanController) getOptimizedModuleOrder() []string {
	var orderedModules []string

	for _, module := range sc.args.Modules {
		if module == moduleFinger {
			orderedModules = append(orderedModules, module)
			break
		}
	}

	// 然后执行其他模块
	for _, module := range sc.args.Modules {
		if module != moduleFinger {
			orderedModules = append(orderedModules, module)
		}
	}

	return orderedModules
}

func (sc *ScanController) runModuleForTargetsWithContext(ctx context.Context, moduleName string, targets []string) ([]interfaces.HTTPResponse, error) {
	switch moduleName {
	case moduleDirscan:
		return sc.runDirscanModule(ctx, targets)
	case moduleFinger:
		return sc.runFingerprintModuleWithContext(ctx, targets)
	default:
		return nil, fmt.Errorf("unsupported module: %s", moduleName)
	}
}
