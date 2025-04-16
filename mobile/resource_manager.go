package mobile

import (
	"fmt"
	"sync"
	"time"
	"sync/atomic"
	"context"
	"errors"
	"runtime"
	"sort"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// 定义资源状态常量
const (
	// 电池电量级别
	BatteryLevelCritical = 10   // 电量极低
	BatteryLevelLow      = 20   // 电量低
	BatteryLevelMedium   = 50   // 电量中等
	BatteryLevelHigh     = 80   // 电量高
	
	// 网络连接类型
	NetworkTypeNone      = 0    // 无连接
	NetworkTypeWiFi      = 1    // WiFi连接
	NetworkTypeMobile    = 2    // 移动数据连接
	NetworkType4G        = 3    // 4G连接
	NetworkType5G        = 4    // 5G连接
	
	// 资源使用模式
	ResourceModeNormal ResourceMode = iota // 正常模式
	ResourceModeLow                        // 低功耗模式
	ResourceModeUltraLow                   // 超低功耗模式
	ResourceModePerformance                // 性能模式
	ResourceModeBalanced                   // 平衡模式
	
	// 资源限制默认值
	DefaultCPULimit      = 50   // 默认CPU使用限制(%)
	DefaultMemoryLimit   = 200  // 默认内存限制(MB)
	DefaultStorageLimit  = 1024 // 默认存储限制(MB)
	DefaultBandwidthLimit = 5   // 默认带宽限制(MB/s)
)

// 资源优化模式 - 新增
const (
	OptimizeModeNone      = "none"      // 不优化
	OptimizeModeAggressive = "aggressive" // 激进优化
	OptimizeModeMedium    = "medium"    // 中等优化
	OptimizeModeLight     = "light"     // 轻度优化
	OptimizeModeBalanced  = "balanced"  // 平衡优化
	OptimizeModeAdaptive  = "adaptive"  // 自适应优化
)

// 资源类型 - 新增
const (
	ResourceTypeBattery = "battery" // 电池资源
	ResourceTypeNetwork = "network" // 网络资源
	ResourceTypeStorage = "storage" // 存储资源
	ResourceTypeCPU     = "cpu"     // CPU资源
	ResourceTypeMemory  = "memory"  // 内存资源
)

// 网络状态常量
const (
	// 原有常量保持不变
	
	// 扩展网络状态常量
	NetworkStateOffline     = "offline"    // 完全离线
	NetworkStateWeak        = "weak"       // 弱网络
	NetworkStateInterrupted = "interrupted" // 网络中断
	NetworkStateUnstable    = "unstable"   // 不稳定
	NetworkStateStable      = "stable"     // 稳定
	NetworkStateExcellent   = "excellent"  // 极佳
)

// 增量同步模式常量
const (
	IncrementalSyncDisabled  = 0 // 禁用增量同步
	IncrementalSyncLight     = 1 // 轻量增量同步
	IncrementalSyncStandard  = 2 // 标准增量同步
	IncrementalSyncAgressive = 3 // 激进增量同步
	IncrementalSyncAdaptive  = 4 // 自适应增量同步
)

// ResourceMode 资源模式
type ResourceMode int

// ResourceMode 常量
const (
	ResourceModeNormal ResourceMode = iota // 正常模式
	ResourceModeLow                        // 低功耗模式
	ResourceModeUltraLow                   // 超低功耗模式
	ResourceModePerformance                // 性能模式
	ResourceModeBalanced                   // 平衡模式
)

// ResourceManager 负责管理移动端资源使用
type ResourceManager struct {
	config *params.MobileResourceConfig // 资源管理配置
	
	// 资源状态
	batteryLevel      int32        // 当前电池电量百分比
	isCharging        int32        // 是否在充电
	networkType       int32        // 网络连接类型
	currentMode       atomic.Value // 资源使用模式 - 修改为使用atomic.Value以避免竞争
	isBackgroundMode  int32        // 是否处于后台模式
	
	// 资源限制
	cpuLimit          int32        // CPU使用限制(%)
	memoryLimit       int32        // 内存限制(MB)
	storageLimit      int32        // 存储限制(MB)
	bandwidthLimit    int32        // 带宽限制(MB/s)
	
	// 资源监控
	cpuUsage          int32        // 当前CPU使用率(%)
	memoryUsage       int32        // 当前内存使用(MB)
	storageUsage      int32        // 当前存储使用(MB)
	bandwidthUsage    int32        // 当前带宽使用(MB/s)
	
	// 性能监控
	syncLatency       int64        // 同步延迟(ms)
	txProcessTime     int64        // 交易处理时间(ms)
	blockProcessTime  int64        // 区块处理时间(ms)
	
	// 资源调整回调
	onResourceAdjusted func()      // 资源调整时回调
	
	// 遥测数据集合
	telemetryEnabled  bool         // 是否启用遥测
	telemetryData     map[string]interface{} // 遥测数据
	telemetryMutex    sync.RWMutex // 遥测数据锁
	
	// 自适应调整
	adaptiveEnabled   bool         // 是否启用自适应调整
	adaptiveTicker    *time.Ticker // 自适应调整定时器
	adaptiveInterval  time.Duration // 自适应调整间隔
	
	// 上下文控制
	ctx               context.Context // 上下文
	cancel            context.CancelFunc // 取消函数
	wg                sync.WaitGroup  // 等待组
	
	// 诊断和调试
	diagnosticMode    bool         // 诊断模式
	debugLog          bool         // 调试日志
	
	// 高级功能
	dataCompressionLevel int32     // 数据压缩级别
	periodicMaintenance  bool      // 定期维护
	lastMaintenanceTime  time.Time // 上次维护时间
	
	// 扩展字段 - 新增
	throttleConfig   *ResourceThrottleConfig // 限流配置
	actions          []*ResourceAction   // 动作历史
	optimizations    map[string]bool     // 已应用优化
	batteryTrend     []int               // 电池趋势
	usageHistory     map[string][]float64 // 使用历史
	criticalAlerts   []string            // 关键告警
	
	// 新增网络弹性字段
	networkCondition   *NetworkCondition // 网络状况
	offlineModeEnabled bool             // 离线模式是否启用
	offlineQueue       []interface{}    // 离线队列
	offlineQueueMutex  sync.RWMutex     // 离线队列互斥锁
	reconnectStrategy  string           // 重连策略
	reconnectAttempts  int              // 重连尝试次数
	reconnectDelay     time.Duration    // 重连延迟
	
	// 新增增量同步字段
	incrementalSync    *IncrementalSyncConfig // 增量同步配置
	syncState          *SyncState           // 同步状态
	syncCheckpoints    map[string][]byte    // 同步检查点
	essentialData      map[string]bool      // 必要数据标记
	dataImportance     map[string]int       // 数据重要性评分
	priorityQueues     map[string][]interface{} // 优先级队列
}

// ResourceConfig 资源配置
type ResourceConfig struct {
	MaxStorageGB      uint64            // 最大存储空间(GB)
	MaxNetworkUsageMB uint64            // 最大网络使用量(MB/小时)
	MaxBatteryUsage   int               // 最大电池使用率(%)
	BatteryAware      bool              // 电池感知
	NetworkAware      bool              // 网络感知
	StorageAware      bool              // 存储感知
	CheckInterval     time.Duration     // 检查间隔
	OptimizeMode      string            // 优化模式 - 新增
	AdaptiveThrottling bool             // 自适应限流 - 新增
	BatteryPreserver  bool              // 电池保护器 - 新增
	DataSaver         bool              // 数据节省器 - 新增
	StorageCompression bool             // 存储压缩 - 新增
	LowPowerMode      bool              // 低功耗模式 - 新增
	SmartScheduling   bool              // 智能调度 - 新增
	ResourceSharing   bool              // 资源共享 - 新增
	PriorityServices  []string          // 优先服务 - 新增
	BackgroundSync    bool              // 后台同步 - 新增
}

// ResourceUsage 资源使用情况
type ResourceUsage struct {
	BatteryLevel      int               // 电池电量(%)
	BatteryCharging   bool              // 是否充电中
	NetworkType       string            // 网络类型
	NetworkUsageMB    float64           // 网络使用量(MB)
	StorageUsedGB     float64           // 已用存储空间(GB)
	StorageTotalGB    float64           // 总存储空间(GB)
	StorageFreeGB     float64           // 可用存储空间(GB)
	CPUUsage          float64           // CPU使用率(%)
	MemoryUsageMB     float64           // 内存使用量(MB)
	LastUpdate        time.Time         // 最后更新时间
	
	// 扩展字段 - 新增
	NetworkSpeed      int               // 网络速度(KB/s)
	NetworkLatency    int               // 网络延迟(ms)
	BatteryTemperature float64          // 电池温度(℃)
	CPUTemperature    float64           // CPU温度(℃)
	BatteryHealth     int               // 电池健康状况(%)
	AvgEnergyUsage    float64           // 平均能耗(mW)
	DataSaverActive   bool              // 数据节省是否激活
	LowPowerActive    bool              // 低功耗是否激活
	OptimizationLevel string            // 优化级别
}

// ResourceAction 资源动作 - 新增
type ResourceAction struct {
	Type              string            // 动作类型
	Target            string            // 目标资源
	Params            map[string]interface{} // 参数
	Priority          int               // 优先级
	Timestamp         time.Time         // 时间戳
	AppliedAt         time.Time         // 应用时间
	Result            string            // 结果
}

// ResourceThrottleConfig 资源限流配置 - 新增
type ResourceThrottleConfig struct {
	MaxConcurrentOperations int        // 最大并发操作
	MaxBandwidthKBps       int        // 最大带宽(KB/s)
	SyncIntervalMultiplier float64    // 同步间隔乘数
	JobThrottlePercent     int        // 作业限流百分比
	CPUThrottlePercent     int        // CPU限流百分比
	BackgroundSyncOnly     bool       // 仅后台同步
	ActiveCoolingEnabled   bool       // 主动冷却启用
	GradualRampUp          bool       // 渐进增长
}

// ResourceListener 资源监听器
type ResourceListener interface {
	OnResourceUpdate(usage ResourceUsage)
	OnResourceCritical(resourceType string, value float64)
}

// NetworkCondition 网络状况 - 新增结构体
type NetworkCondition struct {
	State           string    // 网络状态
	Speed           int       // 速度(KB/s)
	Latency         int       // 延迟(ms)
	StabilityScore  float64   // 稳定性评分(0-1)
	PacketLoss      float64   // 丢包率(%)
	Interrupted     bool      // 是否中断
	LastConnected   time.Time // 最后连接时间
	LastInterrupted time.Time // 最后中断时间
	InterruptCount  int       // 中断次数
}

// IncrementalSyncConfig 增量同步配置 - 新增结构体
type IncrementalSyncConfig struct {
	Enabled         bool      // 是否启用
	Mode            int       // 同步模式
	ChunkSize       int       // 块大小
	PriorityBlocks  []uint64  // 优先区块
	ExcludedData    []string  // 排除数据类型
	OnlyEssential   bool      // 仅同步必要数据
	RetryInterval   time.Duration // 重试间隔
	MaxAttempts     int       // 最大尝试次数
	TimeoutFactor   float64   // 超时因子
	ProgressCallback func(progress float64) // 进度回调
}

// SyncState 同步状态 - 新增结构体
type SyncState struct {
	IsSyncing       bool      // 是否正在同步
	LastSyncTime    time.Time // 最后同步时间
	LastSyncSuccess bool      // 最后同步是否成功
	PendingItems    int       // 待同步项数量
	FailedAttempts  int       // 失败尝试次数
	Checkpoints     map[string]interface{} // 同步检查点
	ResumeData      []byte    // 恢复数据
	Progress        float64   // 进度(0-1)
	SyncMode        string    // 同步模式
	EstimatedTimeLeft time.Duration // 预估剩余时间
}

// NewResourceManager 创建新的资源管理器
func NewResourceManager(config *params.MobileResourceConfig) *ResourceManager {
	if config == nil {
		config = params.DefaultMobileResourceConfig
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	rm := &ResourceManager{
		config:              config,
		batteryLevel:        100,  // 初始假设满电
		isCharging:          1,    // 初始假设在充电
		networkType:         NetworkTypeWiFi, // 初始假设WiFi
		currentMode:         atomic.Value{}, // 初始化为低功耗模式
		isBackgroundMode:    0,    // 初始前台运行
		cpuLimit:            int32(config.MaxCPUUsage),
		memoryLimit:         int32(config.MaxMemoryUsage),
		storageLimit:        int32(config.MaxStorageUsage),
		bandwidthLimit:      10,   // 默认10MB/s
		telemetryEnabled:    false,
		telemetryData:       make(map[string]interface{}),
		adaptiveEnabled:     config.AdaptiveResourceAllocation,
		adaptiveInterval:    30 * time.Second, // 默认30秒调整一次
		ctx:                 ctx,
		cancel:              cancel,
		diagnosticMode:      false,
		debugLog:            false,
		dataCompressionLevel: int32(config.DataCompressionLevel),
		periodicMaintenance: config.PeriodicMaintenance,
		lastMaintenanceTime: time.Now(),
		throttleConfig:      &ResourceThrottleConfig{
			MaxConcurrentOperations: 5,
			MaxBandwidthKBps:       1000,
			SyncIntervalMultiplier:  1.0,
			JobThrottlePercent:      0,
			CPUThrottlePercent:      0,
			BackgroundSyncOnly:     false,
			ActiveCoolingEnabled:   false,
			GradualRampUp:          true,
		},
		actions:           make([]*ResourceAction, 0),
		optimizations:     make(map[string]bool),
		batteryTrend:      make([]int, 0),
		usageHistory:      make(map[string][]float64),
		criticalAlerts:    make([]string, 0),
		networkCondition:   nil,
		offlineModeEnabled: false,
		offlineQueue:       make([]interface{}, 0),
		incrementalSync:    nil,
		syncState:          nil,
		syncCheckpoints:    make(map[string][]byte),
		essentialData:      make(map[string]bool),
		dataImportance:     make(map[string]int),
		priorityQueues:     make(map[string][]interface{}),
	}
	
	// 初始化atomic.Value
	rm.currentMode.Store(ResourceModeLow) // 默认为低功耗模式
	
	// 启动自适应调整
	if rm.adaptiveEnabled {
		rm.startAdaptiveAdjustment()
	}
	
	return rm
}

// Start 启动资源管理器
func (rm *ResourceManager) Start() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	// 初始化检查定时器
	rm.checkTicker = time.NewTicker(rm.config.CheckInterval)
	
	// 启动资源检查任务
	rm.wg.Add(1)
	go rm.resourceCheckLoop()
	
	// 初始化资源
	rm.initializeResourceUsage()
	
	// 应用初始优化
	rm.applyInitialOptimizations()
	
	log.Info("移动端资源管理器已启动", "模式", rm.GetResourceMode())
}

// Stop 停止资源管理器
func (rm *ResourceManager) Stop() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	if rm.checkTicker != nil {
		rm.checkTicker.Stop()
	}
	
	// 取消上下文
	rm.cancel()
	
	// 等待所有任务结束
	rm.wg.Wait()
	
	log.Info("移动端资源管理器已停止")
}

// SetBatteryLevel 设置电池电量
func (rm *ResourceManager) SetBatteryLevel(level int) {
	atomic.StoreInt32(&rm.batteryLevel, int32(level))
	
	// 低电量检查并优化资源使用
	if level <= int(rm.config.LowBatteryThreshold) && rm.config.BatteryOptimizationMode {
		rm.switchToLowPowerMode()
		log.Info("检测到低电量，切换到低功耗模式", "电量", level)
	}
}

// SetCharging 设置充电状态
func (rm *ResourceManager) SetCharging(charging bool) {
	if charging {
		atomic.StoreInt32(&rm.isCharging, 1)
	} else {
		atomic.StoreInt32(&rm.isCharging, 0)
	}
	
	// 调整资源策略
	rm.adjustResourceLimits()
}

// SetNetworkType 设置网络连接类型
func (rm *ResourceManager) SetNetworkType(networkType int) {
	atomic.StoreInt32(&rm.networkType, int32(networkType))
	
	// 网络感知资源调整
	if rm.config.NetworkTypeAwareness {
		rm.adjustNetworkResources(networkType)
	}
}

// SetBackgroundMode 设置应用运行模式（前台/后台）
func (rm *ResourceManager) SetBackgroundMode(background bool) {
	if background {
		atomic.StoreInt32(&rm.isBackgroundMode, 1)
		if rm.config.BackgroundModeEnabled {
			// 后台模式资源限制
			rm.limitBackgroundResources()
		}
	} else {
		atomic.StoreInt32(&rm.isBackgroundMode, 0)
		// 恢复正常资源使用
		rm.adjustResourceLimits()
	}
}

// GetBatteryLevel 获取当前电池电量
func (rm *ResourceManager) GetBatteryLevel() int {
	return int(atomic.LoadInt32(&rm.batteryLevel))
}

// IsCharging 检查是否在充电
func (rm *ResourceManager) IsCharging() bool {
	return atomic.LoadInt32(&rm.isCharging) == 1
}

// GetNetworkType 获取当前网络类型
func (rm *ResourceManager) GetNetworkType() int {
	return int(atomic.LoadInt32(&rm.networkType))
}

// IsBackgroundMode 检查是否处于后台模式
func (rm *ResourceManager) IsBackgroundMode() bool {
	return atomic.LoadInt32(&rm.isBackgroundMode) == 1
}

// GetResourceMode 获取当前资源模式
func (rm *ResourceManager) GetResourceMode() ResourceMode {
	// 使用Load方法安全地读取currentMode
	mode := rm.currentMode.Load()
	if mode == nil {
		return ResourceModeLow // 默认为低功耗模式
	}
	if mode, ok := mode.(ResourceMode); ok {
		return mode
	}
	log.Error("资源模式类型断言失败")
	return ResourceModeLow // 默认为低功耗模式
}

// SetResourceMode 设置资源模式
func (rm *ResourceManager) SetResourceMode(mode ResourceMode) {
	// 使用Store方法安全地更新currentMode
	rm.currentMode.Store(mode)
	
	// 根据新模式调整资源
	rm.adjustResourceLimits()
	
	if rm.onResourceAdjusted != nil {
		rm.onResourceAdjusted()
	}
}

// EnableTelemetry 启用遥测数据收集
func (rm *ResourceManager) EnableTelemetry(enabled bool) {
	rm.telemetryMutex.Lock()
	defer rm.telemetryMutex.Unlock()
	
	rm.telemetryEnabled = enabled
}

// SetDiagnosticMode 设置诊断模式
func (rm *ResourceManager) SetDiagnosticMode(enabled bool) {
	rm.diagnosticMode = enabled
	rm.debugLog = enabled
	
	if enabled {
		log.Info("诊断模式已启用，性能监控和日志记录增强")
	} else {
		log.Info("诊断模式已禁用")
	}
}

// SetPerformanceMetric 设置性能指标
func (rm *ResourceManager) SetPerformanceMetric(metricName string, value int64) {
	switch metricName {
	case "syncLatency":
		atomic.StoreInt64(&rm.syncLatency, value)
	case "txProcessTime":
		atomic.StoreInt64(&rm.txProcessTime, value)
	case "blockProcessTime":
		atomic.StoreInt64(&rm.blockProcessTime, value)
	default:
		rm.telemetryMutex.Lock()
		if rm.telemetryEnabled {
			rm.telemetryData[metricName] = value
		}
		rm.telemetryMutex.Unlock()
	}
}

// GetResourceUsage 获取当前资源使用情况
func (rm *ResourceManager) GetResourceUsage() map[string]int {
	usage := make(map[string]int)
	usage["cpuUsage"] = int(atomic.LoadInt32(&rm.cpuUsage))
	usage["memoryUsage"] = int(atomic.LoadInt32(&rm.memoryUsage))
	usage["storageUsage"] = int(atomic.LoadInt32(&rm.storageUsage))
	usage["bandwidthUsage"] = int(atomic.LoadInt32(&rm.bandwidthUsage))
	return usage
}

// GetPerformanceMetrics 获取性能指标
func (rm *ResourceManager) GetPerformanceMetrics() map[string]int64 {
	metrics := make(map[string]int64)
	metrics["syncLatency"] = atomic.LoadInt64(&rm.syncLatency)
	metrics["txProcessTime"] = atomic.LoadInt64(&rm.txProcessTime)
	metrics["blockProcessTime"] = atomic.LoadInt64(&rm.blockProcessTime)
	
	rm.telemetryMutex.RLock()
	defer rm.telemetryMutex.RUnlock()
	
	// 添加其他遥测数据
	if rm.telemetryEnabled {
		for k, v := range rm.telemetryData {
			if val, ok := v.(int64); ok {
				metrics[k] = val
			}
		}
	}
	
	return metrics
}

// SetOnResourceAdjusted 设置资源调整回调
func (rm *ResourceManager) SetOnResourceAdjusted(callback func()) {
	rm.onResourceAdjusted = callback
}

// GetCompressLevel 获取当前数据压缩级别
func (rm *ResourceManager) GetCompressLevel() int {
	return int(atomic.LoadInt32(&rm.dataCompressionLevel))
}

// SetCompressLevel 设置数据压缩级别
func (rm *ResourceManager) SetCompressLevel(level int) {
	if level < 1 {
		level = 1
	} else if level > 9 {
		level = 9
	}
	atomic.StoreInt32(&rm.dataCompressionLevel, int32(level))
}

// GetResourceLimits 获取当前资源限制
func (rm *ResourceManager) GetResourceLimits() map[string]int {
	limits := make(map[string]int)
	limits["cpuLimit"] = int(atomic.LoadInt32(&rm.cpuLimit))
	limits["memoryLimit"] = int(atomic.LoadInt32(&rm.memoryLimit))
	limits["storageLimit"] = int(atomic.LoadInt32(&rm.storageLimit))
	limits["bandwidthLimit"] = int(atomic.LoadInt32(&rm.bandwidthLimit))
	return limits
}

// CollectTelemetry 收集遥测数据
func (rm *ResourceManager) CollectTelemetry() map[string]interface{} {
	if !rm.telemetryEnabled {
		return nil
	}
	
	rm.telemetryMutex.RLock()
	defer rm.telemetryMutex.RUnlock()
	
	// 创建遥测数据副本
	telemetry := make(map[string]interface{})
	for k, v := range rm.telemetryData {
		telemetry[k] = v
	}
	
	// 添加资源使用数据
	telemetry["batteryLevel"] = rm.GetBatteryLevel()
	telemetry["isCharging"] = rm.IsCharging()
	telemetry["networkType"] = rm.GetNetworkType()
	telemetry["cpuUsage"] = atomic.LoadInt32(&rm.cpuUsage)
	telemetry["memoryUsage"] = atomic.LoadInt32(&rm.memoryUsage)
	telemetry["storageUsage"] = atomic.LoadInt32(&rm.storageUsage)
	telemetry["bandwidthUsage"] = atomic.LoadInt32(&rm.bandwidthUsage)
	telemetry["syncLatency"] = atomic.LoadInt64(&rm.syncLatency)
	telemetry["blockProcessTime"] = atomic.LoadInt64(&rm.blockProcessTime)
	telemetry["resourceMode"] = rm.GetResourceMode()
	
	return telemetry
}

// TriggerMaintenance 手动触发维护操作
func (rm *ResourceManager) TriggerMaintenance() {
	if !rm.periodicMaintenance {
		return
	}
	
	go rm.performMaintenance()
}

// ShouldSyncNow 根据当前条件决定是否应该立即同步
func (rm *ResourceManager) ShouldSyncNow() bool {
	// 如果电量极低且未充电，不建议同步
	if rm.GetBatteryLevel() < BatteryLevelCritical && !rm.IsCharging() {
		return false
	}
	
	// 如果无网络连接，不能同步
	if rm.GetNetworkType() == NetworkTypeNone {
		return false
	}
	
	// 如果在移动网络且启用了数据节省模式，不建议同步
	if rm.GetNetworkType() == NetworkTypeMobile && rm.config.DataSavingMode {
		return false
	}
	
	return true
}

// GetSyncFrequency 获取当前推荐的同步频率
func (rm *ResourceManager) GetSyncFrequency() int {
	isCharging := rm.IsCharging()
	batteryLevel := rm.GetBatteryLevel()
	networkType := rm.GetNetworkType()
	
	// 在充电状态
	if isCharging {
		return rm.config.SyncFrequencyOnCharging
	}
	
	// 低电量状态
	if batteryLevel <= int(rm.config.LowBatteryThreshold) {
		return 60 // 低电量时1小时同步一次
	}
	
	// 网络状态考量
	if networkType == NetworkTypeWiFi {
		return rm.config.SyncFrequencyOnCharging * 2 // WiFi下同步频率较高但不如充电
	}
	
	// 默认返回电池模式下的同步频率
	return rm.config.SyncFrequencyOnBattery
}

// 内部方法 - 监控资源使用
func (rm *ResourceManager) monitorResources() {
	defer rm.wg.Done()
	
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// 更新CPU使用率
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			
			// 内存使用(MB)
			memUsageMB := int32(m.Alloc / 1024 / 1024)
			atomic.StoreInt32(&rm.memoryUsage, memUsageMB)
			
			// CPU使用率估算 (这里是简化模拟，实际需要通过CGO调用系统API)
			// 在真实实现中应该通过平台特定API获取
			cpuUsage := int32(30) // 假设值
			atomic.StoreInt32(&rm.cpuUsage, cpuUsage)
			
			// 存储使用估算 (同样需要平台特定实现)
			// 在真实实现中应该计算链数据目录的实际大小
			storageUsage := int32(500) // 假设值
			atomic.StoreInt32(&rm.storageUsage, storageUsage)
			
			// 检查资源是否超限
			if memUsageMB > rm.memoryLimit {
				log.Warn("内存使用超过限制", "当前", memUsageMB, "限制", rm.memoryLimit)
				rm.triggerMemoryOptimization()
			}
			
			// 记录资源使用到遥测
			if rm.telemetryEnabled {
				rm.telemetryMutex.Lock()
				rm.telemetryData["memoryUsage"] = memUsageMB
				rm.telemetryData["cpuUsage"] = cpuUsage
				rm.telemetryData["storageUsage"] = storageUsage
				rm.telemetryMutex.Unlock()
			}
			
			// 诊断日志
			if rm.debugLog {
				log.Debug("资源使用统计", 
					"内存(MB)", memUsageMB, 
					"CPU(%)", cpuUsage,
					"存储(MB)", storageUsage,
					"电量(%)", rm.GetBatteryLevel(),
					"充电", rm.IsCharging())
			}
			
		case <-rm.ctx.Done():
			return
		}
	}
}

// 内部方法 - 监控性能
func (rm *ResourceManager) monitorPerformance() {
	defer rm.wg.Done()
	
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// 记录当前性能指标
			syncLatency := atomic.LoadInt64(&rm.syncLatency)
			txProcessTime := atomic.LoadInt64(&rm.txProcessTime)
			blockProcessTime := atomic.LoadInt64(&rm.blockProcessTime)
			
			// 如果性能过低，尝试优化
			if syncLatency > 5000 && rm.adaptiveEnabled { // 如果同步延迟超过5秒
				log.Warn("检测到同步延迟过高，尝试优化", "延迟(ms)", syncLatency)
				rm.optimizeForSync()
			}
			
			// 诊断模式下记录详细日志
			if rm.diagnosticMode {
				log.Info("性能监控", 
					"同步延迟(ms)", syncLatency,
					"交易处理(ms)", txProcessTime,
					"区块处理(ms)", blockProcessTime)
			}
			
		case <-rm.ctx.Done():
			return
		}
	}
}

// 内部方法 - 定期维护
func (rm *ResourceManager) maintenanceRoutine() {
	defer rm.wg.Done()
	
	// 每6小时执行一次维护
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			rm.performMaintenance()
			
		case <-rm.ctx.Done():
			return
		}
	}
}

// 内部方法 - 执行维护操作
func (rm *ResourceManager) performMaintenance() {
	// 只有在非低电量或充电状态下执行维护
	if rm.GetBatteryLevel() < BatteryLevelLow && !rm.IsCharging() {
		log.Info("跳过维护操作：电量过低且未充电")
		return
	}
	
	log.Info("执行定期维护操作")
	
	// 记录维护开始时间
	startTime := time.Now()
	
	// 在此处执行维护操作：
	// 1. 强制垃圾回收
	runtime.GC()
	
	// 2. 释放未使用内存
	debug.FreeOSMemory()
	
	// 3. 其他维护操作
	// ...
	
	// 更新最后维护时间
	rm.lastMaintenanceTime = time.Now()
	
	// 记录维护操作耗时
	duration := time.Since(startTime)
	log.Info("维护操作完成", "耗时", duration)
	
	// 记录到遥测
	if rm.telemetryEnabled {
		rm.telemetryMutex.Lock()
		rm.telemetryData["lastMaintenanceTime"] = rm.lastMaintenanceTime.Unix()
		rm.telemetryData["maintenanceDuration"] = duration.Milliseconds()
		rm.telemetryMutex.Unlock()
	}
}

// 内部方法 - 切换到低功耗模式
func (rm *ResourceManager) switchToLowPowerMode() {
	// 使用SetResourceMode方法安全地更新资源模式
	rm.SetResourceMode(ResourceModeLow)
	
	// 降低资源限制
	atomic.StoreInt32(&rm.cpuLimit, 30)
	atomic.StoreInt32(&rm.memoryLimit, 150)
	atomic.StoreInt32(&rm.bandwidthLimit, 2)
	
	// 提高压缩级别以节省资源
	atomic.StoreInt32(&rm.dataCompressionLevel, 9)
	
	// 通知回调
	if rm.onResourceAdjusted != nil {
		rm.onResourceAdjusted()
	}
	
	log.Info("已切换到低功耗模式")
}

// 内部方法 - 根据资源模式调整资源限制
func (rm *ResourceManager) adjustResourceLimits() {
	mode := rm.GetResourceMode()
	
	switch mode {
	case ResourceModeNormal:
		atomic.StoreInt32(&rm.cpuLimit, 30)
		atomic.StoreInt32(&rm.memoryLimit, 150)
		atomic.StoreInt32(&rm.bandwidthLimit, 2)
		atomic.StoreInt32(&rm.dataCompressionLevel, 9)
	case ResourceModeLow:
		atomic.StoreInt32(&rm.cpuLimit, 30)
		atomic.StoreInt32(&rm.memoryLimit, 150)
		atomic.StoreInt32(&rm.bandwidthLimit, 2)
		atomic.StoreInt32(&rm.dataCompressionLevel, 9)
	case ResourceModeUltraLow:
		atomic.StoreInt32(&rm.cpuLimit, 30)
		atomic.StoreInt32(&rm.memoryLimit, 150)
		atomic.StoreInt32(&rm.bandwidthLimit, 2)
		atomic.StoreInt32(&rm.dataCompressionLevel, 9)
	case ResourceModePerformance:
		atomic.StoreInt32(&rm.cpuLimit, 80)
		atomic.StoreInt32(&rm.memoryLimit, 300)
		atomic.StoreInt32(&rm.bandwidthLimit, 10)
		atomic.StoreInt32(&rm.dataCompressionLevel, 5)
	case ResourceModeBalanced:
		atomic.StoreInt32(&rm.cpuLimit, int32(rm.config.MaxCPUUsage))
		atomic.StoreInt32(&rm.memoryLimit, int32(rm.config.MaxMemoryUsage))
		atomic.StoreInt32(&rm.bandwidthLimit, 5)
		atomic.StoreInt32(&rm.dataCompressionLevel, 7)
	}
	
	// 如果在充电，提高资源限制
	if rm.IsCharging() {
		cpuLimit := atomic.LoadInt32(&rm.cpuLimit)
		memoryLimit := atomic.LoadInt32(&rm.memoryLimit)
		
		atomic.StoreInt32(&rm.cpuLimit, int32(float32(cpuLimit)*1.5))
		atomic.StoreInt32(&rm.memoryLimit, int32(float32(memoryLimit)*1.2))
	}
	
	// 通知回调
	if rm.onResourceAdjusted != nil {
		rm.onResourceAdjusted()
	}
}

// 内部方法 - 基于网络类型调整资源
func (rm *ResourceManager) adjustNetworkResources(networkType int) {
	switch networkType {
	case NetworkTypeNone:
		// 无网络时限制带宽使用为0
		atomic.StoreInt32(&rm.bandwidthLimit, 0)
	case NetworkTypeMobile:
		// 移动网络下限制带宽
		if rm.config.DataSavingMode {
			atomic.StoreInt32(&rm.bandwidthLimit, 1)
		} else {
			atomic.StoreInt32(&rm.bandwidthLimit, 3)
		}
	case NetworkType4G:
		// 4G网络
		if rm.config.DataSavingMode {
			atomic.StoreInt32(&rm.bandwidthLimit, 2)
		} else {
			atomic.StoreInt32(&rm.bandwidthLimit, 5)
		}
	case NetworkType5G:
		// 5G网络
		if rm.config.DataSavingMode {
			atomic.StoreInt32(&rm.bandwidthLimit, 5)
		} else {
			atomic.StoreInt32(&rm.bandwidthLimit, 10)
		}
	case NetworkTypeWiFi:
		// WiFi网络下放宽带宽限制
		atomic.StoreInt32(&rm.bandwidthLimit, 20)
	}
	
	// 通知回调
	if rm.onResourceAdjusted != nil {
		rm.onResourceAdjusted()
	}
}

// 内部方法 - 限制后台运行资源
func (rm *ResourceManager) limitBackgroundResources() {
	// 记录当前限制以便恢复
	currentCPULimit := atomic.LoadInt32(&rm.cpuLimit)
	currentMemoryLimit := atomic.LoadInt32(&rm.memoryLimit)
	currentBandwidthLimit := atomic.LoadInt32(&rm.bandwidthLimit)
	
	// 后台模式下降低资源限制
	atomic.StoreInt32(&rm.cpuLimit, currentCPULimit/2)
	atomic.StoreInt32(&rm.memoryLimit, currentMemoryLimit/2)
	atomic.StoreInt32(&rm.bandwidthLimit, currentBandwidthLimit/2)
	
	log.Info("应用进入后台模式，资源限制已调整")
	
	// 通知回调
	if rm.onResourceAdjusted != nil {
		rm.onResourceAdjusted()
	}
}

// 内部方法 - 启动自适应资源调整
func (rm *ResourceManager) startAdaptiveAdjustment() {
	rm.adaptiveTicker = time.NewTicker(rm.adaptiveInterval)
	
	rm.wg.Add(1)
	go func() {
		defer rm.wg.Done()
		
		for {
			select {
			case <-rm.adaptiveTicker.C:
				rm.performAdaptiveAdjustment()
			case <-rm.ctx.Done():
				return
			}
		}
	}()
	
	log.Info("自适应资源调整已启动", "间隔", rm.adaptiveInterval)
}

// 内部方法 - 执行自适应资源调整
func (rm *ResourceManager) performAdaptiveAdjustment() {
	// 收集当前资源使用情况
	cpuUsage := atomic.LoadInt32(&rm.cpuUsage)
	memoryUsage := atomic.LoadInt32(&rm.memoryUsage)
	cpuLimit := atomic.LoadInt32(&rm.cpuLimit)
	memoryLimit := atomic.LoadInt32(&rm.memoryLimit)
	
	// 获取当前电池和网络状态
	batteryLevel := rm.GetBatteryLevel()
	isCharging := rm.IsCharging()
	networkType := rm.GetNetworkType()
	
	// 资源使用率计算
	cpuUtilization := float32(cpuUsage) / float32(cpuLimit)
	memoryUtilization := float32(memoryUsage) / float32(memoryLimit)
	
	// 调整逻辑
	if rm.diagnosticMode {
		log.Debug("自适应调整数据", 
			"CPU使用率", cpuUtilization,
			"内存使用率", memoryUtilization,
			"电量", batteryLevel,
			"充电", isCharging,
			"网络", networkType)
	}
	
	// 基于使用率调整
	if cpuUtilization > 0.9 {
		// CPU使用率过高
		if isCharging || batteryLevel > BatteryLevelMedium {
			// 如果在充电或电量充足，提高CPU限制
			atomic.StoreInt32(&rm.cpuLimit, int32(float32(cpuLimit)*1.2))
		} else {
			// 否则考虑降低其他资源来平衡
			atomic.StoreInt32(&rm.bandwidthLimit, atomic.LoadInt32(&rm.bandwidthLimit)*0.8)
		}
	} else if cpuUtilization < 0.3 {
		// CPU使用率很低，可以降低限制
		atomic.StoreInt32(&rm.cpuLimit, int32(float32(cpuLimit)*0.9))
	}
	
	if memoryUtilization > 0.9 {
		// 内存使用率过高
		if isCharging || batteryLevel > BatteryLevelMedium {
			// 如果在充电或电量充足，提高内存限制
			atomic.StoreInt32(&rm.memoryLimit, int32(float32(memoryLimit)*1.2))
		} else {
			// 触发内存优化
			rm.triggerMemoryOptimization()
		}
	} else if memoryUtilization < 0.5 {
		// 内存使用率很低，可以降低限制
		atomic.StoreInt32(&rm.memoryLimit, int32(float32(memoryLimit)*0.9))
	}
	
	// 基于剩余电量调整
	if batteryLevel < BatteryLevelLow && !isCharging {
		// 电量低且未充电，进入节能模式
		rm.switchToLowPowerMode()
	} else if batteryLevel > BatteryLevelHigh || isCharging {
		// 电量充足或正在充电，可以提高资源限制
		if rm.GetResourceMode() == ResourceModeNormal {
			// 从正常模式切换到平衡模式
			rm.SetResourceMode(ResourceModeBalanced)
		}
	}
	
	// 网络状态变化处理
	if networkType == NetworkTypeNone || 
		(networkType == NetworkTypeMobile && rm.config.DataSavingMode) {
		// 无网络或移动数据模式下降低网络活动
		atomic.StoreInt32(&rm.bandwidthLimit, 1)
	}
	
	// 如果有任何调整，通知回调
	if rm.onResourceAdjusted != nil {
		rm.onResourceAdjusted()
	}
}

// 内部方法 - 触发内存优化
func (rm *ResourceManager) triggerMemoryOptimization() {
	log.Info("触发内存优化")
	
	// 强制垃圾回收
	runtime.GC()
	
	// 在真实实现中，这里可以添加更多内存优化策略，如：
	// - 清理缓存
	// - 释放非必要资源
	// - 减少预取数据量
	// 等等
}

// 内部方法 - 同步性能优化
func (rm *ResourceManager) optimizeForSync() {
	// 增加同步资源分配
	currentMode := rm.GetResourceMode()
	
	// 仅当未处于高性能模式时才提升
	if currentMode != ResourceModePerformance {
		// 短暂切换到高性能模式以提升同步速度
		previousMode := currentMode
		rm.SetResourceMode(ResourceModePerformance)
		
		// 如果电量允许，维持高性能模式一段时间
		if rm.GetBatteryLevel() > BatteryLevelLow || rm.IsCharging() {
			go func() {
				// 高性能模式持续2分钟
				time.Sleep(2 * time.Minute)
				// 恢复之前的模式
				rm.SetResourceMode(previousMode)
			}()
		} else {
			// 电量较低时，只维持高性能30秒
			go func() {
				time.Sleep(30 * time.Second)
				rm.SetResourceMode(previousMode)
			}()
		}
	}
}

// Helper functions for testing and simulation

// getStorageTotal 获取总存储空间
func getStorageTotal() uint64 {
	// 实际实现应调用系统API
	return 64 * 1024 * 1024 * 1024 // 64GB
}

// getStorageUsed 获取已使用存储空间
func getStorageUsed() uint64 {
	// 实际实现应调用系统API
	return 32 * 1024 * 1024 * 1024 // 32GB
}

// getMemoryTotal 获取总内存
func getMemoryTotal() uint64 {
	// 实际实现应调用系统API
	return 8 * 1024 * 1024 * 1024 // 8GB
}

// getBatteryLevel 获取电池电量
func getBatteryLevel() int {
	// 实际实现应调用系统API
	return 50 // 50%
}

// isBatteryCharging 检查是否正在充电
func isBatteryCharging() bool {
	// 实际实现应调用系统API
	return false
}

// getNetworkType 获取网络类型
func getNetworkType() string {
	// 实际实现应调用系统API
	return "wifi"
}

// getNetworkSpeed 获取网络速度
func getNetworkSpeed() uint64 {
	// 实际实现应调用系统API
	return 10 * 1024 * 1024 // 10MB/s
}

// getCpuUsage 获取CPU使用率
func getCpuUsage() float64 {
	// 实际实现应调用系统API
	return 30.0 // 30%
}

// getMemoryUsage 获取内存使用量
func getMemoryUsage() uint64 {
	// 实际实现应调用系统API
	return 4 * 1024 * 1024 * 1024 // 4GB
}

// formatByteSize 格式化字节大小为人类可读形式
func formatByteSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// resourceCheckLoop 资源检查循环
func (rm *ResourceManager) resourceCheckLoop() {
	defer rm.wg.Done()
	
	// 默认检查间隔
	defaultInterval := rm.config.CheckInterval
	// 电池状态检查计数器
	batteryCheckCount := 0
	
	for {
		select {
		case <-rm.ctx.Done():
			return
			
		case <-rm.checkTicker.C:
			// 更新资源使用情况
			if err := rm.updateResourceUsage(); err != nil {
				log.Error("更新资源使用情况失败", "错误", err)
				continue
			}
			
			// 检查资源阈值并优化
			rm.checkAndOptimizeResources()
			
			// 动态调整采样间隔（每5次检查调整一次）
			batteryCheckCount++
			if batteryCheckCount >= 5 {
				batteryCheckCount = 0
				
				// 根据充电状态和电池电量动态调整检查间隔
				isCharging := rm.IsCharging()
				batteryLevel := rm.GetBatteryLevel()
				
				var newInterval time.Duration
				
				if isCharging {
					// 充电时使用默认间隔
					newInterval = defaultInterval
				} else if batteryLevel < BatteryLevelLow {
					// 低电量时，降低采样频率，延长间隔
					newInterval = defaultInterval * 3
				} else if batteryLevel < BatteryLevelMedium {
					// 中等电量，稍微延长间隔
					newInterval = defaultInterval * 2
				} else {
					// 电量充足，使用默认间隔
					newInterval = defaultInterval
				}
				
				// 只有在间隔发生变化时才更新定时器
				if rm.checkTicker.Reset(newInterval) {
					log.Debug("调整资源检查间隔", 
						"电量", batteryLevel, 
						"充电", isCharging, 
						"新间隔", newInterval.String())
				}
			}
		}
	}
}

// initializeResourceUsage 初始化资源使用情况
func (rm *ResourceManager) initializeResourceUsage() {
	// 获取初始资源使用情况
	usage, err := rm.queryResourceUsage()
	if err != nil {
		log.Warn("查询初始资源使用情况失败", "错误", err)
		return
	}
	
	rm.mu.Lock()
	rm.usage = usage
	rm.mu.Unlock()
	
	// 添加到历史记录
	rm.addToUsageHistory("battery", float64(usage.BatteryLevel))
	rm.addToUsageHistory("storage", usage.StorageFreeGB)
	rm.addToUsageHistory("network", usage.NetworkUsageMB)
	
	// 通知监听器
	rm.notifyResourceListeners(usage)
	
	log.Debug("资源使用情况已初始化", 
		"电池", usage.BatteryLevel,
		"存储", fmt.Sprintf("%.2f/%.2f GB", usage.StorageUsedGB, usage.StorageTotalGB),
		"网络", fmt.Sprintf("%.2f MB", usage.NetworkUsageMB))
}

// applyInitialOptimizations 应用初始优化
func (rm *ResourceManager) applyInitialOptimizations() {
	// 根据设备状态应用初始优化
	
	// 如果电量低，应用电池优化
	if rm.usage.BatteryLevel < BatteryLevelModerate && !rm.usage.BatteryCharging {
		rm.applyBatteryOptimizations()
	}
	
	// 如果网络类型是移动网络，应用网络优化
	if rm.usage.NetworkType == "cellular" && rm.config.DataSaver {
		rm.applyNetworkOptimizations()
	}
	
	// 如果存储空间不足，应用存储优化
	if rm.usage.StorageFreeGB < float64(StorageThresholdModerate)/1024.0 {
		rm.applyStorageOptimizations()
	}
	
	// 记录初始优化动作
	action := &ResourceAction{
		Type:      "initial_optimization",
		Target:    "all",
		Params:    map[string]interface{}{"mode": rm.config.OptimizeMode},
		Priority:  10,
		Timestamp: time.Now(),
		AppliedAt: time.Now(),
		Result:    "applied",
	}
	
	rm.mu.Lock()
	rm.actions = append(rm.actions, action)
	rm.mu.Unlock()
}

// addToUsageHistory 添加到使用历史
func (rm *ResourceManager) addToUsageHistory(resourceType string, value float64) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	// 限制历史记录长度
	maxHistory := 100
	history := rm.usageHistory[resourceType]
	
	if len(history) >= maxHistory {
		// 移除最旧的记录
		history = history[1:]
	}
	
	// 添加新记录
	history = append(history, value)
	rm.usageHistory[resourceType] = history
}

// updateResourceUsage 更新资源使用情况
func (rm *ResourceManager) updateResourceUsage() error {
	// 获取资源使用情况
	usage, err := rm.queryResourceUsage()
	if err != nil {
		return err
	}
	
	// 更新网络状况
	rm.updateNetworkCondition(usage)
	
	// 更新同步状态
	rm.updateSyncState(usage)
	
	// 根据资源使用情况进行优化
	rm.checkAndOptimizeResources()
	
	// 通知资源监听器
	rm.notifyResourceListeners(usage)
	
	return nil
}

// queryResourceUsage 查询资源使用情况
func (rm *ResourceManager) queryResourceUsage() (ResourceUsage, error) {
	// 在实际实现中，这里应该查询设备的真实资源使用情况
	// 这里仅作为示例实现
	
	usage := ResourceUsage{
		LastUpdate: time.Now(),
	}
	
	// 模拟电池状态
	if rm.config.BatteryAware {
		usage.BatteryLevel = 60 // 模拟60%电量
		usage.BatteryCharging = false
		usage.BatteryTemperature = 32.5 // 32.5℃
		usage.BatteryHealth = 90 // 90%健康
		usage.AvgEnergyUsage = 250 // 250mW
	}
	
	// 模拟网络状态
	if rm.config.NetworkAware {
		usage.NetworkType = "wifi" // 模拟Wi-Fi网络
		usage.NetworkUsageMB = 150.5 // 模拟已使用150.5MB
		usage.NetworkSpeed = 2000 // 2000KB/s
		usage.NetworkLatency = 50 // 50ms
	}
	
	// 模拟存储状态
	if rm.config.StorageAware {
		usage.StorageTotalGB = float64(rm.config.MaxStorageGB)
		usage.StorageUsedGB = 10.5 // 模拟已使用10.5GB
		usage.StorageFreeGB = usage.StorageTotalGB - usage.StorageUsedGB
	}
	
	// 模拟CPU和内存状态
	usage.CPUUsage = 25.0 // 25% CPU使用率
	usage.MemoryUsageMB = 1024.0 // 1024MB内存使用
	usage.CPUTemperature = 45.0 // 45℃
	
	// 功能状态
	usage.DataSaverActive = rm.config.DataSaver
	usage.LowPowerActive = rm.config.LowPowerMode
	usage.OptimizationLevel = rm.config.OptimizeMode
	
	return usage, nil
}

// checkAndOptimizeResources 检查并优化资源
func (rm *ResourceManager) checkAndOptimizeResources() {
	rm.mu.RLock()
	usage := rm.usage
	rm.mu.RUnlock()
	
	// 检查并处理电池
	if rm.config.BatteryAware {
		rm.checkBattery(usage)
	}
	
	// 检查并处理网络
	if rm.config.NetworkAware {
		rm.checkNetwork(usage)
	}
	
	// 检查并处理存储
	if rm.config.StorageAware {
		rm.checkStorage(usage)
	}
	
	// 应用自适应优化
	if rm.config.OptimizeMode == OptimizeModeAdaptive {
		rm.applyAdaptiveOptimizations(usage)
	}
}

// checkBattery 检查电池
func (rm *ResourceManager) checkBattery(usage ResourceUsage) {
	// 如果正在充电，略过电池检查
	if usage.BatteryCharging {
		// 如果有电池优化，取消它们
		if rm.shouldDisableBatteryOptimizations() {
			rm.disableBatteryOptimizations()
		}
		return
	}
	
	// 检查电池电量
	if usage.BatteryLevel <= BatteryLevelCritical {
		// 电量严重不足
		log.Warn("电池电量严重不足", "电量", usage.BatteryLevel)
		rm.notifyResourceCritical(ResourceTypeBattery, float64(usage.BatteryLevel))
		
		// 应用激进的电池优化
		if !rm.optimizations["battery_critical"] {
			rm.applyAggressiveBatteryOptimizations()
		}
	} else if usage.BatteryLevel <= BatteryLevelLow {
		// 电量不足
		log.Info("电池电量不足", "电量", usage.BatteryLevel)
		
		// 应用电池优化
		if !rm.optimizations["battery_low"] {
			rm.applyBatteryOptimizations()
		}
	} else if usage.BatteryLevel >= BatteryLevelHigh {
		// 电量充足，可以取消一些优化
		if rm.shouldDisableBatteryOptimizations() {
			rm.disableBatteryOptimizations()
		}
	}
	
	// 检查电池温度过高
	if usage.BatteryTemperature > 45.0 {
		log.Warn("电池温度过高", "温度", usage.BatteryTemperature)
		
		// 应用降温优化
		if !rm.optimizations["cooling"] {
			rm.applyCoolingOptimizations()
		}
	}
}

// checkNetwork 检查网络
func (rm *ResourceManager) checkNetwork(usage ResourceUsage) {
	// 根据网络类型应用不同的策略
	if usage.NetworkType == "cellular" {
		// 蜂窝网络，应用数据节省
		if rm.config.DataSaver && !rm.optimizations["data_saver"] {
			rm.applyNetworkOptimizations()
		}
		
		// 检查网络使用量是否接近限制
		if usage.NetworkUsageMB >= float64(rm.config.MaxNetworkUsageMB)*0.8 {
			log.Warn("网络使用量接近限制", 
				"使用量", usage.NetworkUsageMB, 
				"限制", rm.config.MaxNetworkUsageMB)
			
			// 应用更严格的网络限制
			if !rm.optimizations["network_limit"] {
				rm.applyNetworkLimitOptimizations()
			}
		}
	} else if usage.NetworkType == "wifi" {
		// WiFi网络，可以放宽一些限制
		if rm.optimizations["data_saver"] && rm.shouldDisableNetworkOptimizations() {
			rm.disableNetworkOptimizations()
		}
	}
	
	// 检查网络速度和延迟
	if usage.NetworkSpeed < 200 || usage.NetworkLatency > 300 {
		log.Info("网络质量不佳", 
			"速度", usage.NetworkSpeed, 
			"延迟", usage.NetworkLatency)
		
		// 应用弱网优化
		if !rm.optimizations["weak_network"] {
			rm.applyWeakNetworkOptimizations()
		}
	}
}

// checkStorage 检查存储
func (rm *ResourceManager) checkStorage(usage ResourceUsage) {
	// 计算存储使用百分比
	storageUsedPercent := (usage.StorageUsedGB / usage.StorageTotalGB) * 100
	
	// 检查存储使用情况
	if usage.StorageFreeGB < float64(StorageThresholdCritical)/1024.0 {
		// 存储严重不足
		log.Warn("存储空间严重不足", 
			"可用", usage.StorageFreeGB, 
			"总量", usage.StorageTotalGB,
			"使用率", storageUsedPercent)
		
		rm.notifyResourceCritical(ResourceTypeStorage, usage.StorageFreeGB)
		
		// 应用激进的存储优化
		if !rm.optimizations["storage_critical"] {
			rm.applyAggressiveStorageOptimizations()
		}
	} else if usage.StorageFreeGB < float64(StorageThresholdLow)/1024.0 {
		// 存储不足
		log.Info("存储空间不足", 
			"可用", usage.StorageFreeGB, 
			"总量", usage.StorageTotalGB,
			"使用率", storageUsedPercent)
		
		// 应用存储优化
		if !rm.optimizations["storage_low"] {
			rm.applyStorageOptimizations()
		}
	} else if storageUsedPercent < 60 {
		// 存储充足，可以取消一些优化
		if rm.shouldDisableStorageOptimizations() {
			rm.disableStorageOptimizations()
		}
	}
}

// applyAdaptiveOptimizations 应用自适应优化
func (rm *ResourceManager) applyAdaptiveOptimizations(usage ResourceUsage) {
	// 综合考虑多个因素进行自适应优化
	
	// 计算资源状况得分 (0-100)
	batteryScore := usage.BatteryLevel
	if usage.BatteryCharging {
		batteryScore += 20 // 充电中加分
	}
	
	storageScore := int((usage.StorageFreeGB / usage.StorageTotalGB) * 100)
	
	networkScore := 100
	if usage.NetworkType == "cellular" {
		networkScore = 60 // 蜂窝网络降分
	}
	if usage.NetworkSpeed < 500 {
		networkScore -= 20 // 低速网络降分
	}
	
	// 计算总分 (0-100)
	totalScore := (batteryScore + storageScore + networkScore) / 3
	
	// 根据总分应用不同级别的优化
	if totalScore < 30 {
		// 资源严重受限，应用激进优化
		rm.applyAggressiveOptimizations()
	} else if totalScore < 50 {
		// 资源受限，应用中等优化
		rm.applyMediumOptimizations()
	} else if totalScore < 70 {
		// 资源一般，应用轻度优化
		rm.applyLightOptimizations()
	} else {
		// 资源充足，可以取消一些优化
		rm.applyBalancedOptimizations()
	}
	
	// 更新当前优化级别
	rm.mu.Lock()
	rm.usage.OptimizationLevel = fmt.Sprintf("adaptive_%d", totalScore)
	rm.mu.Unlock()
	
	log.Debug("应用自适应优化", 
		"电池分", batteryScore, 
		"存储分", storageScore, 
		"网络分", networkScore, 
		"总分", totalScore)
}

// applyBatteryOptimizations 应用电池优化
func (rm *ResourceManager) applyBatteryOptimizations() {
	log.Info("应用电池优化")
	
	// 开启低功耗模式
	rm.config.LowPowerMode = true
	
	// 调整同步频率
	rm.throttleConfig.SyncIntervalMultiplier = 2.0
	
	// 限制带宽使用
	rm.throttleConfig.MaxBandwidthKBps = 500
	
	// 限制并发操作
	rm.throttleConfig.MaxConcurrentOperations = 2
	
	// 记录优化动作
	action := &ResourceAction{
		Type:      "optimization",
		Target:    ResourceTypeBattery,
		Params:    map[string]interface{}{"mode": "battery_save"},
		Priority:  5,
		Timestamp: time.Now(),
		AppliedAt: time.Now(),
		Result:    "applied",
	}
	
	rm.mu.Lock()
	rm.optimizations["battery_low"] = true
	rm.actions = append(rm.actions, action)
	rm.mu.Unlock()
}

// applyAggressiveBatteryOptimizations 应用激进电池优化
func (rm *ResourceManager) applyAggressiveBatteryOptimizations() {
	log.Warn("应用激进电池优化")
	
	// 开启最大低功耗模式
	rm.config.LowPowerMode = true
	
	// 极大延长同步间隔
	rm.throttleConfig.SyncIntervalMultiplier = 5.0
	
	// 严格限制带宽
	rm.throttleConfig.MaxBandwidthKBps = 100
	
	// 最小化并发操作
	rm.throttleConfig.MaxConcurrentOperations = 1
	
	// 仅在后台同步
	rm.throttleConfig.BackgroundSyncOnly = true
	
	// 减少CPU使用
	rm.throttleConfig.CPUThrottlePercent = 50
	
	// 记录优化动作
	action := &ResourceAction{
		Type:      "optimization",
		Target:    ResourceTypeBattery,
		Params:    map[string]interface{}{"mode": "battery_critical"},
		Priority:  10,
		Timestamp: time.Now(),
		AppliedAt: time.Now(),
		Result:    "applied",
	}
	
	rm.mu.Lock()
	rm.optimizations["battery_critical"] = true
	rm.actions = append(rm.actions, action)
	rm.mu.Unlock()
}

// disableBatteryOptimizations 禁用电池优化
func (rm *ResourceManager) disableBatteryOptimizations() {
	log.Info("禁用电池优化")
	
	// 关闭低功耗模式
	rm.config.LowPowerMode = false
	
	// 恢复正常同步间隔
	rm.throttleConfig.SyncIntervalMultiplier = 1.0
	
	// 恢复带宽限制
	rm.throttleConfig.MaxBandwidthKBps = 1000
	
	// 恢复并发操作
	rm.throttleConfig.MaxConcurrentOperations = 5
	
	// 恢复后台同步
	rm.throttleConfig.BackgroundSyncOnly = false
	
	// 记录优化动作
	action := &ResourceAction{
		Type:      "optimization",
		Target:    ResourceTypeBattery,
		Params:    map[string]interface{}{"mode": "normal"},
		Priority:  5,
		Timestamp: time.Now(),
		AppliedAt: time.Now(),
		Result:    "disabled",
	}
	
	rm.mu.Lock()
	rm.optimizations["battery_low"] = false
	rm.optimizations["battery_critical"] = false
	rm.actions = append(rm.actions, action)
	rm.mu.Unlock()
}

// 其他优化方法实现 (为简洁起见省略)

// notifyResourceListeners 通知资源监听器
func (rm *ResourceManager) notifyResourceListeners(usage ResourceUsage) {
	for _, listener := range rm.resourceListeners {
		if listener != nil {
			go listener.OnResourceUpdate(usage)
		}
	}
}

// notifyResourceCritical 通知资源危急
func (rm *ResourceManager) notifyResourceCritical(resourceType string, value float64) {
	// 添加到关键告警
	rm.mu.Lock()
	alertMsg := fmt.Sprintf("%s: %.2f at %s", resourceType, value, time.Now().Format(time.RFC3339))
	rm.criticalAlerts = append(rm.criticalAlerts, alertMsg)
	// 保留最新的10条
	if len(rm.criticalAlerts) > 10 {
		rm.criticalAlerts = rm.criticalAlerts[len(rm.criticalAlerts)-10:]
	}
	rm.mu.Unlock()
	
	// 通知监听器
	for _, listener := range rm.resourceListeners {
		if listener != nil {
			go listener.OnResourceCritical(resourceType, value)
		}
	}
}

// AddResourceListener 添加资源监听器
func (rm *ResourceManager) AddResourceListener(listener ResourceListener) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.resourceListeners = append(rm.resourceListeners, listener)
	log.Debug("已添加资源监听器", "总数", len(rm.resourceListeners))
}

// RemoveResourceListener 移除资源监听器
func (rm *ResourceManager) RemoveResourceListener(listener ResourceListener) bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	for i, l := range rm.resourceListeners {
		if l == listener {
			// 移除此监听器
			rm.resourceListeners = append(rm.resourceListeners[:i], rm.resourceListeners[i+1:]...)
			log.Debug("已移除资源监听器", "总数", len(rm.resourceListeners))
			return true
		}
	}
	
	return false
}

// GetResourceUsage 获取资源使用情况
func (rm *ResourceManager) GetResourceUsage() ResourceUsage {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.usage
}

// GetResourceStats 获取资源统计信息
func (rm *ResourceManager) GetResourceStats() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	// 准备统计信息
	stats := make(map[string]interface{})
	
	// 基本信息
	stats["battery_level"] = rm.usage.BatteryLevel
	stats["battery_charging"] = rm.usage.BatteryCharging
	stats["storage_used_gb"] = rm.usage.StorageUsedGB
	stats["storage_total_gb"] = rm.usage.StorageTotalGB
	stats["storage_free_gb"] = rm.usage.StorageFreeGB
	stats["network_type"] = rm.usage.NetworkType
	stats["network_usage_mb"] = rm.usage.NetworkUsageMB
	
	// 扩展信息
	stats["cpu_usage"] = rm.usage.CPUUsage
	stats["memory_usage_mb"] = rm.usage.MemoryUsageMB
	stats["battery_temperature"] = rm.usage.BatteryTemperature
	stats["cpu_temperature"] = rm.usage.CPUTemperature
	stats["network_speed"] = rm.usage.NetworkSpeed
	stats["network_latency"] = rm.usage.NetworkLatency
	
	// 优化状态
	stats["low_power_mode"] = rm.config.LowPowerMode
	stats["data_saver"] = rm.config.DataSaver
	stats["optimization_mode"] = rm.config.OptimizeMode
	stats["optimization_level"] = rm.usage.OptimizationLevel
	
	// 优化计数
	activatedOpts := 0
	for _, active := range rm.optimizations {
		if active {
			activatedOpts++
		}
	}
	stats["active_optimizations"] = activatedOpts
	
	// 电池趋势
	if len(rm.batteryTrend) > 0 {
		var sum int
		for _, t := range rm.batteryTrend {
			sum += t
		}
		avgTrend := float64(sum) / float64(len(rm.batteryTrend))
		stats["battery_trend"] = avgTrend
	}
	
	// 告警信息
	stats["critical_alerts"] = len(rm.criticalAlerts)
	
	return stats
}

// shouldDisableBatteryOptimizations 是否应该禁用电池优化
func (rm *ResourceManager) shouldDisableBatteryOptimizations() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	// 如果正在充电或电量充足
	return rm.usage.BatteryCharging || rm.usage.BatteryLevel >= BatteryLevelHigh
}

// shouldDisableNetworkOptimizations 是否应该禁用网络优化
func (rm *ResourceManager) shouldDisableNetworkOptimizations() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	// 如果是WiFi网络且质量良好
	return rm.usage.NetworkType == "wifi" && rm.usage.NetworkSpeed > 1000 && rm.usage.NetworkLatency < 100
}

// shouldDisableStorageOptimizations 是否应该禁用存储优化
func (rm *ResourceManager) shouldDisableStorageOptimizations() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	// 如果存储空间充足
	storageUsedPercent := (rm.usage.StorageUsedGB / rm.usage.StorageTotalGB) * 100
	return storageUsedPercent < 60
}

// 优化方法 (为了简洁，仅提供接口，不实现详细逻辑)
func (rm *ResourceManager) applyAggressiveOptimizations() {}
func (rm *ResourceManager) applyMediumOptimizations() {}
func (rm *ResourceManager) applyLightOptimizations() {}
func (rm *ResourceManager) applyBalancedOptimizations() {}
func (rm *ResourceManager) applyNetworkOptimizations() {}
func (rm *ResourceManager) applyNetworkLimitOptimizations() {}
func (rm *ResourceManager) disableNetworkOptimizations() {}
func (rm *ResourceManager) applyWeakNetworkOptimizations() {}
func (rm *ResourceManager) applyStorageOptimizations() {}
func (rm *ResourceManager) applyAggressiveStorageOptimizations() {}
func (rm *ResourceManager) disableStorageOptimizations() {}
func (rm *ResourceManager) applyCoolingOptimizations() {}

// 新增updateNetworkCondition方法
func (rm *ResourceManager) updateNetworkCondition(usage ResourceUsage) {
	// 初始化网络状况对象
	if rm.networkCondition == nil {
		rm.networkCondition = &NetworkCondition{
			State:          NetworkStateStable,
			LastConnected:  time.Now(),
			StabilityScore: 1.0,
		}
	}
	
	// 获取当前网络类型
	networkType := atomic.LoadInt32(&rm.networkType)
	
	// 更新网络速度和延迟
	rm.networkCondition.Speed = usage.NetworkSpeed
	rm.networkCondition.Latency = usage.NetworkLatency
	
	// 判断网络状态
	switch {
	case networkType == NetworkTypeNone:
		// 离线状态
		rm.networkCondition.State = NetworkStateOffline
		rm.networkCondition.Interrupted = true
		rm.networkCondition.LastInterrupted = time.Now()
		rm.networkCondition.InterruptCount++
		
	case usage.NetworkSpeed <= 10: // 10KB/s以下认为是弱网络
		rm.networkCondition.State = NetworkStateWeak
		rm.networkCondition.StabilityScore = 0.3
		
	case usage.NetworkLatency >= 500: // 延迟超过500ms认为不稳定
		rm.networkCondition.State = NetworkStateUnstable
		rm.networkCondition.StabilityScore = 0.5
		
	case networkType == NetworkTypeWiFi && usage.NetworkSpeed > 200:
		rm.networkCondition.State = NetworkStateExcellent
		rm.networkCondition.StabilityScore = 1.0
		rm.networkCondition.Interrupted = false
		rm.networkCondition.LastConnected = time.Now()
		
	default:
		rm.networkCondition.State = NetworkStateStable
		rm.networkCondition.StabilityScore = 0.8
		rm.networkCondition.Interrupted = false
		rm.networkCondition.LastConnected = time.Now()
	}
	
	// 如果网络状态发生变化，应用相应的优化策略
	if rm.networkCondition.State == NetworkStateOffline || 
	   rm.networkCondition.State == NetworkStateWeak {
		rm.enableOfflineMode(true)
		rm.applyWeakNetworkOptimizations()
	} else if rm.offlineModeEnabled {
		// 如果之前处于离线模式，现在网络恢复，则同步离线数据
		rm.syncOfflineData()
		rm.enableOfflineMode(false)
	}
	
	// 添加网络状态到遥测数据
	if rm.telemetryEnabled {
		rm.telemetryMutex.Lock()
		rm.telemetryData["network_state"] = rm.networkCondition.State
		rm.telemetryData["network_stability"] = rm.networkCondition.StabilityScore
		rm.telemetryData["network_interrupts"] = rm.networkCondition.InterruptCount
		rm.telemetryMutex.Unlock()
	}
}

// 启用或禁用离线模式
func (rm *ResourceManager) enableOfflineMode(enable bool) {
	if rm.offlineModeEnabled == enable {
		return // 状态未变，无需操作
	}
	
	rm.offlineModeEnabled = enable
	
	if enable {
		log.Info("启用离线模式")
		
		// 记录操作到资源动作历史
		rm.recordResourceAction("enable", "offline_mode", map[string]interface{}{
			"reason": rm.networkCondition.State,
		})
		
		// 如果支持增量同步，创建同步检查点
		if rm.incrementalSync != nil && rm.incrementalSync.Enabled {
			rm.createSyncCheckpoint()
		}
	} else {
		log.Info("禁用离线模式")
		
		// 记录操作到资源动作历史
		rm.recordResourceAction("disable", "offline_mode", map[string]interface{}{
			"duration_minutes": time.Since(rm.networkCondition.LastInterrupted).Minutes(),
		})
	}
}

// 同步离线数据
func (rm *ResourceManager) syncOfflineData() {
	if len(rm.offlineQueue) == 0 {
		return // 没有离线数据需要同步
	}
	
	log.Info("开始同步离线数据", "项目数量", len(rm.offlineQueue))
	
	// 记录操作到资源动作历史
	rm.recordResourceAction("sync", "offline_data", map[string]interface{}{
		"items": len(rm.offlineQueue),
	})
	
	// 在实际实现中，这里应该处理离线队列中的数据
	// 例如将交易广播到网络，同步本地状态等
	
	// 清空离线队列
	rm.offlineQueueMutex.Lock()
	rm.offlineQueue = make([]interface{}, 0)
	rm.offlineQueueMutex.Unlock()
}

// 记录资源管理动作
func (rm *ResourceManager) recordResourceAction(actionType, target string, params map[string]interface{}) {
	action := &ResourceAction{
		Type:      actionType,
		Target:    target,
		Params:    params,
		Timestamp: time.Now(),
		AppliedAt: time.Now(),
	}
	
	rm.actions = append(rm.actions, action)
	
	// 限制历史记录大小
	if len(rm.actions) > 100 {
		rm.actions = rm.actions[len(rm.actions)-100:]
	}
}

// 更新同步状态
func (rm *ResourceManager) updateSyncState(usage ResourceUsage) {
	if rm.syncState == nil {
		rm.syncState = &SyncState{
			IsSyncing:      false,
			LastSyncTime:   time.Time{},
			Checkpoints:    make(map[string]interface{}),
			SyncMode:       "full",
		}
	}
	
	// 更新同步模式
	if rm.incrementalSync != nil && rm.incrementalSync.Enabled {
		switch rm.incrementalSync.Mode {
		case IncrementalSyncLight:
			rm.syncState.SyncMode = "incremental_light"
		case IncrementalSyncStandard:
			rm.syncState.SyncMode = "incremental_standard"
		case IncrementalSyncAgressive:
			rm.syncState.SyncMode = "incremental_aggressive"
		case IncrementalSyncAdaptive:
			rm.syncState.SyncMode = "incremental_adaptive"
		default:
			rm.syncState.SyncMode = "incremental"
		}
	} else {
		rm.syncState.SyncMode = "full"
	}
	
	// 根据网络状况调整同步策略
	if rm.networkCondition != nil {
		switch rm.networkCondition.State {
		case NetworkStateOffline:
			rm.syncState.IsSyncing = false
		case NetworkStateWeak:
			// 弱网络下启用特殊同步模式
			if rm.incrementalSync != nil && rm.incrementalSync.Enabled {
				rm.syncState.SyncMode = "incremental_minimal"
				rm.incrementalSync.OnlyEssential = true
				rm.incrementalSync.ChunkSize = rm.incrementalSync.ChunkSize / 2 // 减小块大小
			}
		case NetworkStateUnstable:
			// 不稳定网络下使用更保守的超时设置
			if rm.incrementalSync != nil && rm.incrementalSync.Enabled {
				rm.incrementalSync.TimeoutFactor = 2.0 // 增加超时时间
				rm.incrementalSync.RetryInterval = rm.incrementalSync.RetryInterval * 2 // 增加重试间隔
			}
		}
	}
}

// 创建同步检查点
func (rm *ResourceManager) createSyncCheckpoint() error {
	if rm.syncCheckpoints == nil {
		rm.syncCheckpoints = make(map[string][]byte)
	}
	
	// 生成检查点ID
	checkpointID := fmt.Sprintf("checkpoint_%d", time.Now().Unix())
	
	// 在实际实现中，这里应该捕获当前同步状态
	// 例如当前区块高度、账户状态等
	
	// 模拟创建检查点数据
	checkpointData := []byte("checkpoint_data")
	
	rm.syncCheckpoints[checkpointID] = checkpointData
	
	// 更新同步状态
	if rm.syncState != nil {
		rm.syncState.Checkpoints[checkpointID] = time.Now()
	}
	
	log.Info("创建同步检查点", "ID", checkpointID)
	
	return nil
}

// 从检查点恢复同步
func (rm *ResourceManager) resumeSyncFromCheckpoint(checkpointID string) error {
	if rm.syncCheckpoints == nil {
		return errors.New("没有可用的同步检查点")
	}
	
	checkpointData, exists := rm.syncCheckpoints[checkpointID]
	if !exists {
		return fmt.Errorf("找不到检查点: %s", checkpointID)
	}
	
	// 在实际实现中，这里应该使用检查点数据恢复同步状态
	
	// 更新同步状态
	if rm.syncState != nil {
		rm.syncState.ResumeData = checkpointData
		rm.syncState.IsSyncing = true
	}
	
	log.Info("从检查点恢复同步", "ID", checkpointID)
	
	return nil
}

// 实现增量同步
func (rm *ResourceManager) startIncrementalSync(targetHeight uint64) error {
	if rm.incrementalSync == nil || !rm.incrementalSync.Enabled {
		return errors.New("增量同步未启用")
	}
	
	// 如果已经在同步中，返回错误
	if rm.syncState != nil && rm.syncState.IsSyncing {
		return errors.New("同步已在进行中")
	}
	
	// 初始化同步状态
	rm.syncState = &SyncState{
		IsSyncing:      true,
		LastSyncTime:   time.Now(),
		LastSyncSuccess: false,
		PendingItems:   int(targetHeight), // 简化实现，实际应计算差异
		FailedAttempts: 0,
		Checkpoints:    make(map[string]interface{}),
		Progress:       0,
		SyncMode:       "incremental",
	}
	
	// 记录操作到资源动作历史
	rm.recordResourceAction("start", "incremental_sync", map[string]interface{}{
		"target_height": targetHeight,
		"mode":          rm.incrementalSync.Mode,
	})
	
	// 这里启动增量同步的实际逻辑
	// 在实际实现中，应该异步执行
	go rm.performIncrementalSync(targetHeight)
	
	return nil
}

// 执行增量同步
func (rm *ResourceManager) performIncrementalSync(targetHeight uint64) {
	// 实际同步逻辑
	totalItems := rm.syncState.PendingItems
	processedItems := 0
	
	// 根据网络状况调整同步参数
	chunkSize := rm.incrementalSync.ChunkSize
	if rm.networkCondition != nil && rm.networkCondition.State == NetworkStateWeak {
		chunkSize = chunkSize / 2 // 弱网络下减小块大小
	}
	
	// 模拟同步进度
	for processedItems < totalItems {
		// 检查是否应该停止同步
		if rm.ctx.Err() != nil || !rm.syncState.IsSyncing {
			break
		}
		
		// 检查网络状态
		if rm.networkCondition != nil && rm.networkCondition.State == NetworkStateOffline {
			// 网络离线，暂停同步并创建检查点
			rm.createSyncCheckpoint()
			rm.syncState.IsSyncing = false
			log.Warn("网络离线，暂停增量同步")
			return
		}
		
		// 模拟处理一批数据
		itemsToProcess := min(chunkSize, totalItems-processedItems)
		processedItems += itemsToProcess
		
		// 更新进度
		rm.syncState.Progress = float64(processedItems) / float64(totalItems)
		rm.syncState.EstimatedTimeLeft = time.Duration(float64(time.Second) * float64(totalItems-processedItems) / float64(itemsToProcess))
		
		// 如果有进度回调，通知进度
		if rm.incrementalSync.ProgressCallback != nil {
			rm.incrementalSync.ProgressCallback(rm.syncState.Progress)
		}
		
		// 模拟同步延迟
		time.Sleep(100 * time.Millisecond)
	}
	
	// 同步完成
	rm.syncState.IsSyncing = false
	rm.syncState.LastSyncTime = time.Now()
	rm.syncState.LastSyncSuccess = true
	rm.syncState.Progress = 1.0
	
	log.Info("增量同步完成", "耗时", time.Since(rm.syncState.LastSyncTime))
	
	// 记录操作到资源动作历史
	rm.recordResourceAction("complete", "incremental_sync", map[string]interface{}{
		"duration":      time.Since(rm.syncState.LastSyncTime).Seconds(),
		"items_synced":  processedItems,
		"target_height": targetHeight,
	})
}

// 辅助函数：取两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 获取网络状态
func (rm *ResourceManager) GetNetworkState() string {
	if rm.networkCondition == nil {
		return NetworkStateStable // 默认为稳定状态
	}
	return rm.networkCondition.State
}

// 获取同步状态
func (rm *ResourceManager) GetSyncState() *SyncState {
	return rm.syncState
}

// 设置增量同步配置
func (rm *ResourceManager) SetIncrementalSyncConfig(config *IncrementalSyncConfig) {
	rm.incrementalSync = config
	
	// 记录操作到资源动作历史
	rm.recordResourceAction("set", "incremental_sync_config", map[string]interface{}{
		"enabled": config.Enabled,
		"mode":    config.Mode,
	})
}

// 增强applyWeakNetworkOptimizations方法
func (rm *ResourceManager) applyWeakNetworkOptimizations() {
	log.Info("应用弱网络优化")
	
	// 记录操作到资源动作历史
	rm.recordResourceAction("apply", "weak_network_optimization", nil)
	
	// 激活增量同步
	if rm.incrementalSync != nil {
		rm.incrementalSync.Enabled = true
		rm.incrementalSync.Mode = IncrementalSyncLight
		rm.incrementalSync.OnlyEssential = true
		rm.incrementalSync.ChunkSize = 50 // 减小块大小
		rm.incrementalSync.RetryInterval = 30 * time.Second // 增加重试间隔
		rm.incrementalSync.MaxAttempts = 5 // 减少最大尝试次数
	}
	
	// 减少带宽使用
	atomic.StoreInt32(&rm.bandwidthLimit, 50) // 限制带宽到50KB/s
	
	// 提高压缩级别
	atomic.StoreInt32(&rm.dataCompressionLevel, 9) // 最高压缩级别
	
	// 禁用非必要的网络活动
	
	// 调整同步频率
	// 降低更新频率
	
	// 如果已启用遥测，将其设置为批量发送模式
	
	// 标记优化已应用
	rm.optimizations["weak_network"] = true
}