//go:build passive

package dirscan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"veo/pkg/logger"
	interfaces "veo/pkg/types"
	"veo/proxy"
)

// ModuleStatus 模块状态
type ModuleStatus int

const (
	ModuleStatusStopped ModuleStatus = iota // 已停止
	ModuleStatusStarted                     // 已启动
	ModuleStatusError                       // 错误状态
)

// DirscanModule 目录扫描模块包装器
type DirscanModule struct {
	addon  *DirscanAddon
	status ModuleStatus
}

// NewDirscanModule 创建目录扫描模块
func NewDirscanModule(col *Collector) (*DirscanModule, error) {
	addon, err := CreateDefaultAddon()
	if err != nil {
		return nil, err
	}

	if col != nil {
		addon.SetCollector(col)
	}

	module := &DirscanModule{
		addon:  addon,
		status: ModuleStatusStopped,
	}

	return module, nil
}

// SetProxy 设置代理
func (dm *DirscanModule) SetProxy(proxyURL string) {
	if dm.addon != nil {
		dm.addon.SetProxy(proxyURL)
	}
}

// Start 启动模块
func (dm *DirscanModule) Start() error {
	if dm.status == ModuleStatusStarted {
		return nil
	}

	dm.addon.Enable()
	dm.status = ModuleStatusStarted
	return nil
}

// Stop 停止模块
func (dm *DirscanModule) Stop() error {
	if dm.status == ModuleStatusStopped {
		logger.Debug("模块已经停止")
		return nil
	}

	dm.addon.Disable()
	dm.status = ModuleStatusStopped
	logger.Debug("模块停止成功")
	return nil
}

// GetAddon 获取addon实例
func (dm *DirscanModule) GetAddon() *DirscanAddon {
	return dm.addon
}

type Collector struct {
	proxy.BaseAddon
	urlMap             map[string]int  // 最终采集的URL访问计数映射
	pendingURLs        map[string]bool // 待处理的URL（已过滤静态资源）
	includeStatusCodes []int           // 需要采集的状态码白名单
	mu                 sync.RWMutex    // 读写锁
	collectionEnabled  bool            // 收集功能是否启用

	cleaner *URLCleaner // URL清理器
}

// NewCollector 创建新的Collector实例
func NewCollector() *Collector {
	logger.Debugf("创建Collector实例")
	return &Collector{
		urlMap:             make(map[string]int),
		pendingURLs:        make(map[string]bool),
		includeStatusCodes: []int{200, 301, 302, 403, 404, 500},
		collectionEnabled:  true,
		cleaner:            NewURLCleaner(),
	}
}

// Requestheaders 处理请求头
func (c *Collector) Requestheaders(f *proxy.Flow) {
	if !c.IsCollectionEnabled() {
		return
	}

	rawURL := f.Request.URL.String()
	if rawURL == "" {
		return
	}

	// 静态资源过滤
	if c.cleaner.IsStaticResource(rawURL) {
		return
	}

	// URL清理
	cleanedURL := c.cleaner.CleanURLParams(rawURL)
	if cleanedURL == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pendingURLs[cleanedURL] {
		return
	}
	c.pendingURLs[cleanedURL] = true
	logger.Debugf("暂存URL: %s", cleanedURL)
}

// Responseheaders 处理响应头
func (c *Collector) Responseheaders(f *proxy.Flow) {
	if !c.IsCollectionEnabled() {
		return
	}

	rawURL := f.Request.URL.String()
	statusCode := f.Response.StatusCode

	cleanedURL := c.cleaner.CleanURLParams(rawURL)
	if cleanedURL == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 必须在Request中见过
	if !c.pendingURLs[cleanedURL] {
		return
	}

	delete(c.pendingURLs, cleanedURL)

	// 检查状态码
	isValidCode := false
	for _, code := range c.includeStatusCodes {
		if code == statusCode {
			isValidCode = true
			break
		}
	}
	if !isValidCode {
		return
	}

	c.urlMap[cleanedURL]++
	if c.urlMap[cleanedURL] == 1 {
		logger.Infof("Record URL: [ %s ]", cleanedURL)
	}
}

func (c *Collector) GetURLCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.urlMap)
}

func (c *Collector) GetURLMap() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(map[string]int, len(c.urlMap))
	for k, v := range c.urlMap {
		result[k] = v
	}
	return result
}

func (c *Collector) ClearURLMap() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.urlMap = make(map[string]int)
	c.pendingURLs = make(map[string]bool)
}

func (c *Collector) EnableCollection() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collectionEnabled = true
}

func (c *Collector) DisableCollection() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collectionEnabled = false
}

func (c *Collector) IsCollectionEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.collectionEnabled
}

type DirscanAddon struct {
	engine    *Engine
	collector *Collector
	enabled   bool
	depth     int // 递归扫描深度
}

// NewDirscanAddon 创建目录扫描插件
func NewDirscanAddon(config *EngineConfig) (*DirscanAddon, error) {
	// 创建引擎
	engine := NewEngine(config)
	collectorInstance := NewCollector()

	addon := &DirscanAddon{
		engine:    engine,
		collector: collectorInstance,
		enabled:   true,
		depth:     0, // 默认深度为0，可通过SetDepth方法修改
	}

	logger.Debug("目录扫描插件初始化完成")
	return addon, nil
}

// CreateDefaultAddon 创建默认配置的目录扫描插件
func CreateDefaultAddon() (*DirscanAddon, error) {
	config := getDefaultConfig()
	return NewDirscanAddon(config)
}

// SetProxy 设置代理
func (da *DirscanAddon) SetProxy(proxyURL string) {
	if da.engine != nil {
		da.engine.SetProxy(proxyURL)
	}
}

// 核心接口方法

// Enable 启用插件
func (da *DirscanAddon) Enable() {
	da.enabled = true
	if da.collector != nil {
		da.collector.EnableCollection()
	}
	logger.Debugf("目录扫描插件已启用")
}

// Disable 禁用插件
func (da *DirscanAddon) Disable() {
	da.enabled = false
	if da.collector != nil {
		da.collector.DisableCollection()
	}
	logger.Debugf("目录扫描插件已禁用")
}

// GetCollectedURLs 获取收集的URL
func (da *DirscanAddon) GetCollectedURLs() []string {
	if da.collector == nil {
		return []string{}
	}

	urlMap := da.collector.GetURLMap()
	urls := make([]string, 0, len(urlMap))
	for url := range urlMap {
		urls = append(urls, url)
	}

	return urls
}

// TriggerScan 触发扫描
func (da *DirscanAddon) TriggerScan() (*ScanResult, error) {
	if !da.enabled {
		return nil, fmt.Errorf("插件未启用")
	}

	if da.collector == nil {
		return nil, fmt.Errorf("collector未初始化")
	}

	// 获取初始收集的URL
	collectedURLs := da.GetCollectedURLs()
	if len(collectedURLs) == 0 {
		return nil, fmt.Errorf("没有收集到URL，无法开始扫描")
	}

	// 暂停采集
	da.collector.DisableCollection()
	defer da.collector.EnableCollection()

	// 获取配置的深度
	depth := da.depth

	// 初始化聚合结果
	finalResult := &ScanResult{
		StartTime:     time.Now(),
		CollectedURLs: collectedURLs,
		Responses:     make([]*interfaces.HTTPResponse, 0),
		FilterResult: &interfaces.FilterResult{
			ValidPages: make([]*interfaces.HTTPResponse, 0),
		},
	}

	// 定义层级扫描器 (用于递归模式)
	scanCtx := context.Background()
	layerScanner := func(layerTargets []string, filter *ResponseFilter, currentDepth int) ([]interfaces.HTTPResponse, error) {
		// 创建临时收集器
		tempCollector := NewRecursionCollector(layerTargets)

		// 执行扫描
		// depth==0：首层扫描应使用非递归URL生成（扫描根目录 + 路径层级）
		// depth>0 ：递归层扫描仅扫描当前目录（不回溯）
		recursive := currentDepth > 0
		scanResult, err := da.engine.PerformScanWithFilter(scanCtx, tempCollector, recursive, filter)
		if err != nil {
			return nil, err
		}
		if scanResult == nil {
			return nil, nil
		}

		// 聚合结果到 finalResult
		if len(scanResult.Responses) > 0 {
			finalResult.Responses = append(finalResult.Responses, scanResult.Responses...)
		}
		if scanResult.FilterResult != nil && len(scanResult.FilterResult.ValidPages) > 0 {
			finalResult.FilterResult.ValidPages = append(finalResult.FilterResult.ValidPages, scanResult.FilterResult.ValidPages...)
		}

		// 更新 Target (以最后一次扫描的为准)
		finalResult.Target = scanResult.Target

		// 返回有效页面供递归逻辑使用
		// 转换指针切片为值切片，以匹配 LayerScanner 接口 (未来建议 LayerScanner 也改为指针)
		validPages := make([]interfaces.HTTPResponse, len(scanResult.FilterResult.ValidPages))
		for i, p := range scanResult.FilterResult.ValidPages {
			if p != nil {
				validPages[i] = *p
			}
		}
		return validPages, nil
	}

	var firstErr error
	hadSuccess := false

	for _, target := range collectedURLs {
		targetFilter := CreateResponseFilterFromExternal()

		_, err := RunRecursiveScan(
			context.Background(),
			[]string{target},
			depth,
			layerScanner,
			targetFilter,
		)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			logger.Warnf("目标目录扫描失败: %s, %v", target, err)
			continue
		}
		hadSuccess = true
	}

	if !hadSuccess && firstErr != nil {
		return nil, firstErr
	}

	// 扫描完成后清空已采集的URL，等待下一轮采集
	da.collector.ClearURLMap()

	finalResult.EndTime = time.Now()
	finalResult.Duration = finalResult.EndTime.Sub(finalResult.StartTime)

	return finalResult, nil
}

// 配置和依赖注入方法

// 控制台设置接口已移除，保持简洁依赖
// SetCollector 注入外部的URL采集器实例，确保与代理侧使用同一实例
//
// 参数:
//   - c: *Collector 外部创建并用于代理拦截的URL采集器
//
// 返回:
//   - 无
//
// 说明:
//   - 在被动代理模式下，代理服务器会将经过的URL写入其注册的Collector实例。
//     若目录扫描插件内部持有不同的Collector实例，将导致“按回车触发扫描”时取不到已采集的URL。
//     通过本方法将外部Collector注入到插件中，可确保两端使用同一个实例，避免“没有收集到URL”的问题。
func (da *DirscanAddon) SetCollector(c *Collector) {
	if c == nil {
		return
	}
	da.collector = c
	logger.Debug("目录扫描插件Collector已注入为外部实例")
}

// 字典预加载方法

// 字典预加载逻辑已经迁移到生成器内部（无须处理）

// SetDepth 设置递归扫描深度
func (da *DirscanAddon) SetDepth(depth int) {
	da.depth = depth
}
