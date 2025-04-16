package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// 工具类型常量
const (
	ToolTypeAnalytics  = "analytics"  // 分析工具
	ToolTypeDebug      = "debug"      // 调试工具  
	ToolTypeBenchmark  = "benchmark"  // 性能测试工具
	ToolTypeSimulator  = "simulator"  // 模拟器
	ToolTypeDeveloper  = "developer"  // 开发者工具
)

// 调试级别常量
const (
	DebugLevelBasic    = 1 // 基础调试信息
	DebugLevelDetailed = 2 // 详细调试信息
	DebugLevelVerbose  = 3 // 完整调试信息
)

// DevToolsConfig 开发者工具链配置
type DevToolsConfig struct {
	DebugMode        bool   // 调试模式
	LogDirectory     string // 日志目录
	DebugLevel       int    // 调试级别(1-3)
	EnableSimulation bool   // 启用模拟
	EnableBenchmark  bool   // 启用性能测试
	EnableAnalytics  bool   // 启用分析
	MaxLogSizeMB     int    // 最大日志大小(MB)
	MaxLogFiles      int    // 最大日志文件数量
	MockNetworkDelay int    // 模拟网络延迟(毫秒)
	StoreTraces      bool   // 存储调用追踪
}

// DevTools 开发者工具链
type DevTools struct {
	config        *DevToolsConfig // 配置
	client        *MobileClient   // 移动客户端引用
	debugger      *Debugger       // 调试器
	simulator     *Simulator      // 模拟器
	profiler      *Profiler       // 性能分析器
	analyticsData *AnalyticsData  // 分析数据
	
	// 工具链状态
	started      bool          // 是否已启动
	lock         sync.RWMutex  // 状态锁
	stopChan     chan struct{} // 停止通道
	wg           sync.WaitGroup // 等待组
	ctx          context.Context // 上下文
	cancel       context.CancelFunc // 取消函数
}

// Debugger 调试器
type Debugger struct {
	isEnabled   bool            // 是否启用
	level       int             // 调试级别
	breakpoints map[string]bool // 断点表
	traces      []TraceEntry    // 调用追踪
	traceLock   sync.RWMutex    // 追踪锁
}

// TraceEntry 追踪条目
type TraceEntry struct {
	Timestamp time.Time     // 时间戳
	Function  string        // 函数名
	Args      []interface{} // 参数
	Result    interface{}   // 结果
	Duration  time.Duration // 持续时间
	Error     string        // 错误信息(如果有)
}

// Simulator 模拟器
type Simulator struct {
	isEnabled    bool           // 是否启用
	mockAccounts []MockAccount  // 模拟账户
	mockBlocks   []*types.Block // 模拟区块
	mockNetwork  *MockNetwork   // 模拟网络
	mockChain    *MockChain     // 模拟链
}

// MockAccount 模拟账户
type MockAccount struct {
	Address    common.Address // 地址
	PrivateKey string         // 私钥(仅用于模拟)
	Balance    *big.Int       // 余额
	Nonce      uint64         // 交易计数
}

// MockNetwork 模拟网络
type MockNetwork struct {
	Latency       int    // 延迟(毫秒)
	PacketLoss    int    // 丢包率(%)
	Bandwidth     int    // 带宽限制(KB/s)
	NetworkType   string // 网络类型(wifi/cellular/none)
	DisconnectAt  int64  // 断开时间(时间戳)
	ReconnectAt   int64  // 重连时间(时间戳)
}

// MockChain 模拟链
type MockChain struct {
	CurrentHeight uint64         // 当前高度
	BlockTime     time.Duration  // 出块时间
	Difficulty    *big.Int       // 难度
}

// Profiler 性能分析器
type Profiler struct {
	isEnabled bool                // 是否启用
	metrics   map[string]Metric   // 度量指标
	metricLock sync.RWMutex       // 指标锁
}

// Metric 度量指标
type Metric struct {
	Name        string        // 指标名称
	Count       int64         // 计数
	TotalTime   time.Duration // 总时间
	MinTime     time.Duration // 最小时间
	MaxTime     time.Duration // 最大时间
	LastUpdated time.Time     // 最后更新时间
}

// AnalyticsData 分析数据
type AnalyticsData struct {
	isEnabled       bool                 // 是否启用
	transactionData map[string]int64     // 交易数据
	callData        map[string]int64     // 调用数据
	resourceData    map[string][]float64 // 资源数据
	dataLock        sync.RWMutex         // 数据锁
}

// NewDevTools 创建新的开发者工具链
func NewDevTools(config *DevToolsConfig, client *MobileClient) (*DevTools, error) {
	if config == nil {
		return nil, errors.New("配置不能为空")
	}
	
	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	
	// 初始化调试器
	debugger := &Debugger{
		isEnabled:   config.DebugMode,
		level:       config.DebugLevel,
		breakpoints: make(map[string]bool),
		traces:      make([]TraceEntry, 0),
	}
	
	// 初始化模拟器
	simulator := &Simulator{
		isEnabled:    config.EnableSimulation,
		mockAccounts: make([]MockAccount, 0),
		mockBlocks:   make([]*types.Block, 0),
		mockNetwork: &MockNetwork{
			Latency:     config.MockNetworkDelay,
			PacketLoss:  0,
			Bandwidth:   1024, // 默认1MB/s
			NetworkType: "wifi",
		},
		mockChain: &MockChain{
			CurrentHeight: 0,
			BlockTime:     15 * time.Second, // 默认15秒出块
			Difficulty:    big.NewInt(1),
		},
	}
	
	// 初始化性能分析器
	profiler := &Profiler{
		isEnabled: config.EnableBenchmark,
		metrics:   make(map[string]Metric),
	}
	
	// 初始化分析数据
	analyticsData := &AnalyticsData{
		isEnabled:       config.EnableAnalytics,
		transactionData: make(map[string]int64),
		callData:        make(map[string]int64),
		resourceData:    make(map[string][]float64),
	}
	
	// 创建开发者工具链
	return &DevTools{
		config:        config,
		client:        client,
		debugger:      debugger,
		simulator:     simulator,
		profiler:      profiler,
		analyticsData: analyticsData,
		stopChan:      make(chan struct{}),
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

// Start 启动开发者工具链
func (dt *DevTools) Start() error {
	dt.lock.Lock()
	defer dt.lock.Unlock()
	
	if dt.started {
		return errors.New("开发者工具链已启动")
	}
	
	// 初始化日志目录
	if dt.config.LogDirectory != "" {
		err := os.MkdirAll(dt.config.LogDirectory, 0755)
		if err != nil {
			return fmt.Errorf("创建日志目录失败: %v", err)
		}
		
		// 配置日志
		setupLogging(dt.config.LogDirectory, dt.config.MaxLogSizeMB, dt.config.MaxLogFiles)
	}
	
	// 启动后台任务
	dt.startBackgroundTasks()
	
	dt.started = true
	
	log.Info("开发者工具链已启动",
		"调试模式", dt.config.DebugMode,
		"调试级别", dt.config.DebugLevel,
		"模拟启用", dt.config.EnableSimulation,
		"性能测试启用", dt.config.EnableBenchmark,
		"分析启用", dt.config.EnableAnalytics)
	
	return nil
}

// 配置日志
func setupLogging(dir string, maxSizeMB, maxFiles int) {
	// 这里仅为示例，实际应根据go-ethereum的日志包进行配置
	log.Root().SetHandler(log.LvlFilterHandler(
		log.LvlDebug,
		log.MultiHandler(
			log.StreamHandler(os.Stderr, log.TerminalFormat(false)),
			log.Must.FileHandler(filepath.Join(dir, "dev_tools.log"), log.JSONFormat()),
		),
	))
}

// Stop 停止开发者工具链
func (dt *DevTools) Stop() error {
	dt.lock.Lock()
	
	if !dt.started {
		dt.lock.Unlock()
		return errors.New("开发者工具链未启动")
	}
	
	dt.lock.Unlock()
	
	// 取消上下文
	dt.cancel()
	
	// 停止后台任务
	close(dt.stopChan)
	dt.wg.Wait()
	
	// 保存分析数据和追踪
	if dt.config.EnableAnalytics {
		dt.saveAnalyticsData()
	}
	
	if dt.config.StoreTraces {
		dt.saveTraces()
	}
	
	dt.lock.Lock()
	dt.started = false
	dt.lock.Unlock()
	
	log.Info("开发者工具链已停止")
	return nil
}

// 保存分析数据
func (dt *DevTools) saveAnalyticsData() {
	if dt.config.LogDirectory == "" {
		return
	}
	
	dt.analyticsData.dataLock.RLock()
	defer dt.analyticsData.dataLock.RUnlock()
	
	// 将分析数据保存到文件
	data := map[string]interface{}{
		"transactions": dt.analyticsData.transactionData,
		"calls":        dt.analyticsData.callData,
		"resources":    dt.analyticsData.resourceData,
		"timestamp":    time.Now().Unix(),
	}
	
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Error("分析数据序列化失败", "错误", err)
		return
	}
	
	filename := filepath.Join(dt.config.LogDirectory, 
		fmt.Sprintf("analytics_%d.json", time.Now().Unix()))
	
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		log.Error("保存分析数据失败", "错误", err)
		return
	}
	
	log.Debug("分析数据已保存", "文件", filename)
}

// 保存追踪
func (dt *DevTools) saveTraces() {
	if dt.config.LogDirectory == "" {
		return
	}
	
	dt.debugger.traceLock.RLock()
	defer dt.debugger.traceLock.RUnlock()
	
	if len(dt.debugger.traces) == 0 {
		return
	}
	
	// 将追踪保存到文件
	jsonData, err := json.MarshalIndent(dt.debugger.traces, "", "  ")
	if err != nil {
		log.Error("追踪序列化失败", "错误", err)
		return
	}
	
	filename := filepath.Join(dt.config.LogDirectory, 
		fmt.Sprintf("traces_%d.json", time.Now().Unix()))
	
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		log.Error("保存追踪失败", "错误", err)
		return
	}
	
	log.Debug("调用追踪已保存", "文件", filename, "记录数", len(dt.debugger.traces))
}

// 启动后台任务
func (dt *DevTools) startBackgroundTasks() {
	if dt.config.EnableSimulation {
		dt.wg.Add(1)
		go dt.runSimulation()
	}
	
	if dt.config.EnableBenchmark {
		dt.wg.Add(1)
		go dt.collectPerformanceMetrics()
	}
	
	if dt.config.EnableAnalytics {
		dt.wg.Add(1)
		go dt.collectAnalytics()
	}
}

// 运行模拟
func (dt *DevTools) runSimulation() {
	defer dt.wg.Done()
	
	ticker := time.NewTicker(dt.simulator.mockChain.BlockTime)
	defer ticker.Stop()
	
	log.Info("区块链模拟器已启动", "出块时间", dt.simulator.mockChain.BlockTime)
	
	for {
		select {
		case <-dt.stopChan:
			return
			
		case <-ticker.C:
			// 模拟新区块
			dt.simulator.mockChain.CurrentHeight++
			
			// 记录模拟区块
			if dt.config.DebugMode && dt.debugger.level >= DebugLevelDetailed {
				log.Debug("模拟生成新区块", "高度", dt.simulator.mockChain.CurrentHeight)
			}
			
			// 模拟网络条件变化
			dt.updateMockNetwork()
		}
	}
}

// 更新模拟网络
func (dt *DevTools) updateMockNetwork() {
	// 模拟网络波动
	now := time.Now().Unix()
	
	// 检查是否需要断开连接
	if dt.simulator.mockNetwork.DisconnectAt > 0 && now >= dt.simulator.mockNetwork.DisconnectAt {
		dt.simulator.mockNetwork.NetworkType = "none"
		dt.simulator.mockNetwork.DisconnectAt = 0
		log.Debug("模拟网络断开连接")
	}
	
	// 检查是否需要重新连接
	if dt.simulator.mockNetwork.ReconnectAt > 0 && now >= dt.simulator.mockNetwork.ReconnectAt {
		dt.simulator.mockNetwork.NetworkType = "wifi"
		dt.simulator.mockNetwork.ReconnectAt = 0
		log.Debug("模拟网络重新连接")
	}
}

// 收集性能度量
func (dt *DevTools) collectPerformanceMetrics() {
	defer dt.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-dt.stopChan:
			return
			
		case <-ticker.C:
			// 收集性能统计信息
			dt.updatePerformanceMetrics()
		}
	}
}

// 更新性能度量
func (dt *DevTools) updatePerformanceMetrics() {
	// 这里仅为示例，实际应从客户端收集真实的性能数据
	
	// 记录当前内存使用
	dt.recordMetric("memory_usage", 100, 0)
	
	// 记录交易处理时间
	dt.recordMetric("tx_processing_time", 10, 150*time.Millisecond)
	
	// 记录区块处理时间
	dt.recordMetric("block_processing_time", 1, 500*time.Millisecond)
}

// 记录度量指标
func (dt *DevTools) recordMetric(name string, count int64, duration time.Duration) {
	dt.profiler.metricLock.Lock()
	defer dt.profiler.metricLock.Unlock()
	
	metric, exists := dt.profiler.metrics[name]
	if !exists {
		metric = Metric{
			Name:    name,
			MinTime: duration,
			MaxTime: duration,
		}
	}
	
	metric.Count += count
	metric.TotalTime += duration
	metric.LastUpdated = time.Now()
	
	if duration < metric.MinTime {
		metric.MinTime = duration
	}
	
	if duration > metric.MaxTime {
		metric.MaxTime = duration
	}
	
	dt.profiler.metrics[name] = metric
}

// 收集分析数据
func (dt *DevTools) collectAnalytics() {
	defer dt.wg.Done()
	
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-dt.stopChan:
			return
			
		case <-ticker.C:
			// 收集资源使用统计
			dt.collectResourceUsage()
		}
	}
}

// 收集资源使用
func (dt *DevTools) collectResourceUsage() {
	if dt.client == nil || dt.client.resourceManager == nil {
		return
	}
	
	// 获取资源状态
	batteryLevel := dt.client.resourceManager.GetBatteryLevel()
	storageAvailable := dt.client.resourceManager.GetAvailableStorage()
	
	// 记录资源数据
	dt.analyticsData.dataLock.Lock()
	defer dt.analyticsData.dataLock.Unlock()
	
	dt.analyticsData.resourceData["battery"] = append(
		dt.analyticsData.resourceData["battery"], 
		float64(batteryLevel))
	
	dt.analyticsData.resourceData["storage"] = append(
		dt.analyticsData.resourceData["storage"], 
		float64(storageAvailable))
	
	// 限制数据点数量
	maxDataPoints := 1440 // 24小时，每分钟一个点
	for key, values := range dt.analyticsData.resourceData {
		if len(values) > maxDataPoints {
			dt.analyticsData.resourceData[key] = values[len(values)-maxDataPoints:]
		}
	}
}

// AddBreakpoint 添加调试断点
func (dt *DevTools) AddBreakpoint(location string) {
	if !dt.config.DebugMode {
		return
	}
	
	dt.debugger.breakpoints[location] = true
	log.Debug("添加断点", "位置", location)
}

// RemoveBreakpoint 移除调试断点
func (dt *DevTools) RemoveBreakpoint(location string) {
	if !dt.config.DebugMode {
		return
	}
	
	delete(dt.debugger.breakpoints, location)
	log.Debug("移除断点", "位置", location)
}

// ListBreakpoints 列出所有断点
func (dt *DevTools) ListBreakpoints() []string {
	if !dt.config.DebugMode {
		return nil
	}
	
	breakpoints := make([]string, 0, len(dt.debugger.breakpoints))
	for location := range dt.debugger.breakpoints {
		breakpoints = append(breakpoints, location)
	}
	
	return breakpoints
}

// TraceFunction 追踪函数调用
func (dt *DevTools) TraceFunction(function string, args []interface{}, callback func() (interface{}, error)) (interface{}, error) {
	if !dt.config.DebugMode || !dt.config.StoreTraces {
		// 如果调试模式关闭或不存储追踪，直接执行回调
		return callback()
	}
	
	// 记录开始时间
	startTime := time.Now()
	
	// 检查是否有断点
	if _, hasBreakpoint := dt.debugger.breakpoints[function]; hasBreakpoint {
		log.Debug("命中断点", "函数", function, "参数", args)
		// 在实际环境中，这里可以暂停执行或通知调试客户端
	}
	
	// 执行函数
	result, err := callback()
	
	// 计算持续时间
	duration := time.Since(startTime)
	
	// 创建追踪记录
	trace := TraceEntry{
		Timestamp: startTime,
		Function:  function,
		Args:      args,
		Result:    result,
		Duration:  duration,
	}
	
	if err != nil {
		trace.Error = err.Error()
	}
	
	// 添加到追踪列表
	dt.debugger.traceLock.Lock()
	dt.debugger.traces = append(dt.debugger.traces, trace)
	dt.debugger.traceLock.Unlock()
	
	// 如果是详细级别，输出日志
	if dt.debugger.level >= DebugLevelDetailed {
		if err != nil {
			log.Debug("函数调用", "函数", function, "持续时间", duration, "错误", err)
		} else {
			log.Debug("函数调用", "函数", function, "持续时间", duration)
		}
	}
	
	return result, err
}

// RecordTransaction 记录交易
func (dt *DevTools) RecordTransaction(txType string) {
	if !dt.config.EnableAnalytics {
		return
	}
	
	dt.analyticsData.dataLock.Lock()
	defer dt.analyticsData.dataLock.Unlock()
	
	dt.analyticsData.transactionData[txType]++
}

// RecordCall 记录调用
func (dt *DevTools) RecordCall(method string) {
	if !dt.config.EnableAnalytics {
		return
	}
	
	dt.analyticsData.dataLock.Lock()
	defer dt.analyticsData.dataLock.Unlock()
	
	dt.analyticsData.callData[method]++
}

// GetTransactionStats 获取交易统计
func (dt *DevTools) GetTransactionStats() map[string]int64 {
	if !dt.config.EnableAnalytics {
		return nil
	}
	
	dt.analyticsData.dataLock.RLock()
	defer dt.analyticsData.dataLock.RUnlock()
	
	// 创建副本
	stats := make(map[string]int64, len(dt.analyticsData.transactionData))
	for k, v := range dt.analyticsData.transactionData {
		stats[k] = v
	}
	
	return stats
}

// GetCallStats 获取调用统计
func (dt *DevTools) GetCallStats() map[string]int64 {
	if !dt.config.EnableAnalytics {
		return nil
	}
	
	dt.analyticsData.dataLock.RLock()
	defer dt.analyticsData.dataLock.RUnlock()
	
	// 创建副本
	stats := make(map[string]int64, len(dt.analyticsData.callData))
	for k, v := range dt.analyticsData.callData {
		stats[k] = v
	}
	
	return stats
}

// GetPerformanceMetrics 获取性能指标
func (dt *DevTools) GetPerformanceMetrics() map[string]Metric {
	if !dt.config.EnableBenchmark {
		return nil
	}
	
	dt.profiler.metricLock.RLock()
	defer dt.profiler.metricLock.RUnlock()
	
	// 创建副本
	metrics := make(map[string]Metric, len(dt.profiler.metrics))
	for k, v := range dt.profiler.metrics {
		metrics[k] = v
	}
	
	return metrics
}

// CreateMockAccounts 创建模拟账户
func (dt *DevTools) CreateMockAccounts(count int) []MockAccount {
	if !dt.config.EnableSimulation {
		return nil
	}
	
	accounts := make([]MockAccount, count)
	for i := 0; i < count; i++ {
		// 生成新的私钥
		privateKey, _ := crypto.GenerateKey()
		address := crypto.PubkeyToAddress(privateKey.PublicKey)
		
		accounts[i] = MockAccount{
			Address:    address,
			PrivateKey: common.Bytes2Hex(crypto.FromECDSA(privateKey)),
			Balance:    big.NewInt(1000000000000000000), // 1 ETH
			Nonce:      0,
		}
	}
	
	dt.simulator.mockAccounts = append(dt.simulator.mockAccounts, accounts...)
	
	log.Debug("创建模拟账户", "数量", count, "总数", len(dt.simulator.mockAccounts))
	
	return accounts
}

// SimulateNetworkCondition 模拟网络条件
func (dt *DevTools) SimulateNetworkCondition(condition string, duration time.Duration) {
	if !dt.config.EnableSimulation {
		return
	}
	
	switch condition {
	case "disconnect":
		// 模拟网络断开
		dt.simulator.mockNetwork.DisconnectAt = time.Now().Unix()
		dt.simulator.mockNetwork.ReconnectAt = time.Now().Add(duration).Unix()
		log.Debug("模拟网络断开", "持续时间", duration)
		
	case "slow":
		// 模拟慢速网络
		prevLatency := dt.simulator.mockNetwork.Latency
		dt.simulator.mockNetwork.Latency = 500 // 500ms延迟
		dt.simulator.mockNetwork.PacketLoss = 5 // 5%丢包率
		
		// 安排恢复
		go func() {
			time.Sleep(duration)
			dt.simulator.mockNetwork.Latency = prevLatency
			dt.simulator.mockNetwork.PacketLoss = 0
			log.Debug("网络条件已恢复")
		}()
		
		log.Debug("模拟慢速网络", "延迟", dt.simulator.mockNetwork.Latency, "持续时间", duration)
		
	case "cellular":
		// 模拟蜂窝网络
		prevType := dt.simulator.mockNetwork.NetworkType
		dt.simulator.mockNetwork.NetworkType = "cellular"
		dt.simulator.mockNetwork.Bandwidth = 256 // 256KB/s
		
		// 安排恢复
		go func() {
			time.Sleep(duration)
			dt.simulator.mockNetwork.NetworkType = prevType
			dt.simulator.mockNetwork.Bandwidth = 1024
			log.Debug("网络类型已恢复")
		}()
		
		log.Debug("模拟蜂窝网络", "带宽", dt.simulator.mockNetwork.Bandwidth, "持续时间", duration)
	}
}

// ExportDebugData 导出调试数据
func (dt *DevTools) ExportDebugData() (string, error) {
	if !dt.config.DebugMode {
		return "", errors.New("调试模式未启用")
	}
	
	// 收集调试数据
	debugData := map[string]interface{}{
		"timestamp":   time.Now(),
		"traces":      dt.debugger.traces,
		"breakpoints": dt.debugger.breakpoints,
	}
	
	// 如果性能分析启用，添加性能数据
	if dt.config.EnableBenchmark {
		debugData["performance"] = dt.profiler.metrics
	}
	
	// 如果分析启用，添加分析数据
	if dt.config.EnableAnalytics {
		debugData["analytics"] = map[string]interface{}{
			"transactions": dt.analyticsData.transactionData,
			"calls":        dt.analyticsData.callData,
			"resources":    dt.analyticsData.resourceData,
		}
	}
	
	// 如果模拟启用，添加模拟状态
	if dt.config.EnableSimulation {
		debugData["simulation"] = map[string]interface{}{
			"network":      dt.simulator.mockNetwork,
			"chain":        dt.simulator.mockChain,
			"accountCount": len(dt.simulator.mockAccounts),
		}
	}
	
	// 序列化为JSON
	jsonData, err := json.MarshalIndent(debugData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化调试数据失败: %v", err)
	}
	
	// 如果设置了日志目录，保存到文件
	if dt.config.LogDirectory != "" {
		filename := filepath.Join(dt.config.LogDirectory, 
			fmt.Sprintf("debug_export_%d.json", time.Now().Unix()))
		
		err = os.WriteFile(filename, jsonData, 0644)
		if err != nil {
			log.Error("保存调试数据失败", "错误", err)
		} else {
			log.Info("调试数据已导出", "文件", filename)
		}
	}
	
	return string(jsonData), nil
}

// GetNetworkSimStatus 获取网络模拟状态
func (dt *DevTools) GetNetworkSimStatus() *MockNetwork {
	if !dt.config.EnableSimulation {
		return nil
	}
	
	return dt.simulator.mockNetwork
}

// GetChainSimStatus 获取链模拟状态
func (dt *DevTools) GetChainSimStatus() *MockChain {
	if !dt.config.EnableSimulation {
		return nil
	}
	
	return dt.simulator.mockChain
}

// ClearTraces 清除调用追踪
func (dt *DevTools) ClearTraces() {
	if !dt.config.DebugMode {
		return
	}
	
	dt.debugger.traceLock.Lock()
	dt.debugger.traces = make([]TraceEntry, 0)
	dt.debugger.traceLock.Unlock()
	
	log.Debug("调用追踪已清除")
}

// SetDebugLevel 设置调试级别
func (dt *DevTools) SetDebugLevel(level int) {
	if !dt.config.DebugMode || level < DebugLevelBasic || level > DebugLevelVerbose {
		return
	}
	
	prevLevel := dt.debugger.level
	dt.debugger.level = level
	
	log.Info("调试级别已更改", "从", prevLevel, "到", level)
}

// GetCurrentStats 获取当前统计信息
func (dt *DevTools) GetCurrentStats() map[string]interface{} {
	stats := make(map[string]interface{})
	
	// 基本信息
	stats["timestamp"] = time.Now().Unix()
	stats["uptime"] = time.Since(dt.client.stats.StartTime).String()
	
	// 模拟状态
	if dt.config.EnableSimulation {
		stats["simulation"] = map[string]interface{}{
			"blockHeight": dt.simulator.mockChain.CurrentHeight,
			"network": map[string]interface{}{
				"type":    dt.simulator.mockNetwork.NetworkType,
				"latency": dt.simulator.mockNetwork.Latency,
			},
		}
	}
	
	// 性能指标
	if dt.config.EnableBenchmark {
		metrics := make(map[string]interface{})
		dt.profiler.metricLock.RLock()
		for name, metric := range dt.profiler.metrics {
			metrics[name] = map[string]interface{}{
				"avg":   metric.TotalTime.Milliseconds() / metric.Count,
				"count": metric.Count,
				"max":   metric.MaxTime.Milliseconds(),
			}
		}
		dt.profiler.metricLock.RUnlock()
		stats["performance"] = metrics
	}
	
	// 分析数据
	if dt.config.EnableAnalytics {
		dt.analyticsData.dataLock.RLock()
		txCount := int64(0)
		for _, count := range dt.analyticsData.transactionData {
			txCount += count
		}
		dt.analyticsData.dataLock.RUnlock()
		stats["transactions"] = txCount
	}
	
	return stats
} 