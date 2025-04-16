// mobile/light_sync.go - 移动设备轻量级同步和验证模块

package mobile

import (
	"context"
	"math/big"
	"sort"
	"sync"
	"time"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
)

// LightSyncConfig 轻量级同步配置
type LightSyncConfig struct {
	// 基本设置
	HeadersOnly           bool            // 仅同步区块头
	SkipStateSync         bool            // 跳过状态同步
	VerifyHeaders         bool            // 验证区块头
	MaxHeaderFetch        int             // 每批次最大区块头获取数量
	SyncInterval          time.Duration   // 同步间隔
	RetryInterval         time.Duration   // 重试间隔
	MaxRetries            int             // 最大重试次数
	
	// 优化设置
	PriorityBlocks        []uint64        // 优先同步的区块
	TrustedMode           bool            // 信任模式（减少验证）
	CacheTTL              time.Duration   // 缓存有效期
	MaxCacheSize          int             // 最大缓存大小(MB)
	
	// 移动设备特定设置
	BatteryAware          bool            // 电池感知
	NetworkAware          bool            // 网络感知
	LowBatteryThreshold   int             // 低电量阈值
	WeakNetworkThreshold  int             // 弱网阈值
	BackgroundModeFactor  float64         // 后台模式因子(降低同步频率)
	
	// 高级设置
	TrustedCheckpoints    map[uint64]common.Hash // 信任的检查点
	DisableSnapshots      bool            // 禁用快照
	StatelessVerification bool            // 无状态验证
	
	// 新增移动设备优化设置
	PowerSavingMode       bool            // 省电模式
	PowerSavingThreshold  int             // 省电模式阈值
	AggressivePowerSaving bool            // 激进省电模式
	DataSavingMode        bool            // 数据节省模式
	ChunkSize             int             // 数据块大小
	AdaptiveSync          bool            // 自适应同步
	MinSyncInterval       time.Duration   // 最小同步间隔
	MaxSyncInterval       time.Duration   // 最大同步间隔
	DynamicVerification   bool            // 动态验证级别
	SmartCaching          bool            // 智能缓存
	PreferredNetworkTypes []int           // 首选网络类型
	TEEVerification       bool            // TEE验证
	OfflineTolerance      time.Duration   // 离线容忍时间
	LightProofVerification bool           // 轻量证明验证
	CompactDataStorage    bool            // 压缩数据存储
	
	// 新增网络中断保护
	NetworkResilienceEnabled bool          // 网络弹性开关
	MaxOfflineQueueSize     int           // 最大离线队列大小
	OfflineExpiryTime       time.Duration // 离线过期时间
	ReconnectStrategy       string        // 重连策略
	P2PFallbackEnabled      bool          // P2P回退开关
	AutoModeSwitch          bool          // 自动模式切换
}

// LightSyncStats 轻量级同步统计
type LightSyncStats struct {
	LastSyncTime          time.Time       // 最后同步时间
	CurrentHeight         uint64          // 当前高度
	HighestBlockSeen      uint64          // 看到的最高区块
	TotalHeadersProcessed uint64          // 处理的区块头总数
	VerificationTime      time.Duration   // 验证耗时
	SyncTime              time.Duration   // 同步耗时
	Retries               int             // 重试次数
	NetworkLatency        time.Duration   // 网络延迟
	CacheHitRate          float64         // 缓存命中率
	BatteryImpact         float64         // 电池影响评估(0-1)
	DataUsage             int64           // 数据使用量(字节)
	
	// 新增统计字段
	OfflineTime           time.Duration   // 离线时间
	PowerSavingTime       time.Duration   // 省电模式时间
	DataSavedBytes        int64           // 节省的数据量
	VerificationLevel     int             // 当前验证级别
	FailedVerifications   int             // 失败验证次数
	SuccessfulPeerSyncs   int             // 成功的对等同步次数
	LastNetworkType       string          // 最后网络类型
	BatteryUsage          float64         // 电池使用量估计
	TrustedSyncs          int             // 信任模式同步次数
	FullVerificationSyncs int             // 完全验证同步次数
	PendingOfflineActions int             // 等待的离线动作
	P2PSyncCount          int             // P2P同步次数
	TEEVerificationCount  int             // TEE验证次数
}

// LightSyncMode 同步模式
type LightSyncMode int

const (
	// 同步模式常量
	LightSyncModeFull     LightSyncMode = iota // 完整同步
	LightSyncModeHeaders                       // 仅区块头
	LightSyncModePriority                      // 优先区块
	LightSyncModeMinimal                       // 最小化同步
	LightSyncModeOffline                       // 离线模式（新增）
	LightSyncModePower                         // 省电模式（新增）
	LightSyncModeUltraLight                    // 超轻量模式（新增）
	LightSyncModeAdaptive                      // 自适应模式（新增）
)

// VerificationLevel 验证级别
type VerificationLevel int

const (
	// 验证级别常量
	VerificationLevelNone     VerificationLevel = iota // 无验证
	VerificationLevelMinimal                          // 最小验证
	VerificationLevelLight                            // 轻量验证
	VerificationLevelStandard                         // 标准验证
	VerificationLevelFull                             // 完全验证
	VerificationLevelTEE                              // TEE验证
)

// LightSyncPerformanceMetrics 性能指标 - 新增
type LightSyncPerformanceMetrics struct {
	CPUUsage            float64         // CPU使用率
	MemoryUsage         int64           // 内存使用量（字节）
	BatteryDrain        float64         // 电池消耗（%/小时）
	NetworkBandwidth    int64           // 网络带宽使用（字节/秒）
	LatencyMs           int             // 延迟（毫秒）
	ProcessingTimeMs    int64           // 处理时间（毫秒）
	VerificationTimeMs  int64           // 验证时间（毫秒）
	CacheEfficiency     float64         // 缓存效率（0-1）
	TotalOperations     int             // 总操作数
	FailedOperations    int             // 失败操作数
	LastMeasureTime     time.Time       // 最后测量时间
	BlocksPerSecond     float64         // 每秒处理区块数
}

// OfflineQueueItem 离线队列项 - 新增
type OfflineQueueItem struct {
	Type           string          // 类型（如"tx", "block", "header"）
	Data           interface{}     // 数据
	Priority       int             // 优先级（1-5，5最高）
	Timestamp      time.Time       // 时间戳
	ExpiryTime     time.Time       // 过期时间
	Attempts       int             // 尝试次数
	LastAttempt    time.Time       // 最后尝试时间
	Size           int             // 大致大小（字节）
	Hash           common.Hash     // 唯一哈希
}

// LightSync 轻量级同步管理器
type LightSync struct {
	config            *LightSyncConfig      // 配置
	stats             *LightSyncStats       // 统计信息
	currentMode       LightSyncMode         // 当前同步模式
	resourceManager   *ResourceManager      // 资源管理器
	
	// 缓存
	headerCache       map[uint64]*types.Header // 区块头缓存
	receiptCache      map[common.Hash][]*types.Receipt // 收据缓存
	cacheSize         int                    // 当前缓存大小
	
	// 控制
	mu                sync.RWMutex           // 互斥锁
	ctx               context.Context        // 上下文
	cancel            context.CancelFunc     // 取消函数
	wg                sync.WaitGroup         // 等待组
	
	// 事件
	headerCh          chan *types.Header     // 区块头通道
	headerSub         event.Subscription     // 区块头订阅
	
	// 状态
	syncing           bool                   // 是否正在同步
	stopped           bool                   // 是否已停止
	
	// 链操作接口
	chainAdapter      ChainAdapter           // 区块链适配器
	
	// 新增字段 - 移动设备优化
	verificationLevel VerificationLevel     // 当前验证级别
	powerSavingActive bool                  // 省电模式是否激活
	dataSavingActive  bool                  // 数据节省是否激活
	batteryLevel      int                   // 当前电池电量
	isCharging        bool                  // 是否正在充电
	networkType       int                   // 网络类型
	metrics           *LightSyncPerformanceMetrics // 性能指标
	adaptiveInterval  time.Duration         // 自适应同步间隔
	offlineQueue      []*OfflineQueueItem   // 离线队列
	networkResilience *NetworkResilience    // 网络弹性管理
	lastNetworkState  string                // 最后网络状态
	lastBatteryUpdate time.Time             // 最后电池更新时间
	teeHelper         *TEEHelper            // TEE助手
	syncTicker        *time.Ticker          // 同步定时器
	adaptiveTicker    *time.Ticker          // 自适应定时器
	maintenanceTicker *time.Ticker          // 维护定时器
	compressor        *DataCompressor       // 数据压缩器
	priorityManager   *PriorityManager      // 优先级管理器
	modeHistory       []modeHistoryEntry    // 模式历史
}

// modeHistoryEntry 模式历史条目 - 新增
type modeHistoryEntry struct {
	Mode      LightSyncMode // 同步模式
	Timestamp time.Time     // 时间戳
	Reason    string        // 变更原因
	BatteryLevel int        // 电池电量
	NetworkType int         // 网络类型
}

// TEEHelper TEE助手 - 新增
type TEEHelper struct {
	enabled        bool         // 是否启用
	available      bool         // 是否可用
	verifyHeader   func(*types.Header) bool // 验证区块头
	verifyReceipt  func(*types.Receipt) bool // 验证收据
	verifyState    func([]byte) bool // 验证状态
	secureStorage  map[string][]byte // 安全存储
	mu             sync.RWMutex     // 互斥锁
}

// DataCompressor 数据压缩器 - 新增
type DataCompressor struct {
	enabled         bool        // 是否启用
	level           int         // 压缩级别(1-9)
	totalCompressed int64       // 已压缩总量
	totalOriginal   int64       // 原始总量
	autoLevel       bool        // 自动级别
}

// PriorityManager 优先级管理器 - 新增
type PriorityManager struct {
	enabled          bool        // 是否启用
	queues           map[int][]interface{} // 优先级队列
	maxQueueSize     int         // 最大队列大小
	priorityStrategy string      // 优先级策略
}

// NewLightSync 创建新的轻量级同步管理器
func NewLightSync(ctx context.Context, config *LightSyncConfig, resourceManager *ResourceManager) *LightSync {
	ctx, cancel := context.WithCancel(ctx)
	
	// 默认配置确保
	if config.MaxHeaderFetch == 0 {
		config.MaxHeaderFetch = 64 // 默认值
	}
	if config.SyncInterval == 0 {
		config.SyncInterval = 15 * time.Second // 默认值
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3 // 默认值
	}
	// 新增默认配置
	if config.ChunkSize == 0 {
		config.ChunkSize = 1024 * 8 // 默认8KB
	}
	if config.MinSyncInterval == 0 {
		config.MinSyncInterval = 5 * time.Second // 最小5秒
	}
	if config.MaxSyncInterval == 0 {
		config.MaxSyncInterval = 5 * time.Minute // 最大5分钟
	}
	if config.MaxOfflineQueueSize == 0 {
		config.MaxOfflineQueueSize = 1000 // 默认1000项
	}
	if config.OfflineExpiryTime == 0 {
		config.OfflineExpiryTime = 24 * time.Hour // 默认24小时
	}
	
	// 创建同步管理器
	sync := &LightSync{
		config:          config,
		stats:           &LightSyncStats{},
		currentMode:     LightSyncModeFull, // 默认完整同步
		resourceManager: resourceManager,
		headerCache:     make(map[uint64]*types.Header),
		receiptCache:    make(map[common.Hash][]*types.Receipt),
		ctx:             ctx,
		cancel:          cancel,
		headerCh:        make(chan *types.Header, 100),
		verificationLevel: VerificationLevelStandard, // 默认标准验证
		adaptiveInterval: config.SyncInterval, // 初始使用配置的间隔
		metrics:         &LightSyncPerformanceMetrics{
			LastMeasureTime: time.Now(),
		},
		offlineQueue:    make([]*OfflineQueueItem, 0),
		teeHelper:       &TEEHelper{
			enabled:   config.TEEVerification,
			secureStorage: make(map[string][]byte),
		},
		compressor:      &DataCompressor{
			enabled: config.CompactDataStorage,
			level:   5, // 默认中等压缩
		},
		priorityManager: &PriorityManager{
			enabled:      true,
			queues:       make(map[int][]interface{}),
			maxQueueSize: 1000,
			priorityStrategy: "weight", // 权重策略
		},
		modeHistory:     make([]modeHistoryEntry, 0),
	}
	
	// 根据电池和网络状态选择初始同步模式
	sync.adjustSyncMode()
	
	// 初始化TEE
	if config.TEEVerification {
		sync.initializeTEE()
	}
	
	// 记录初始模式
	sync.recordModeChange("initial")
	
	return sync
}

// initializeTEE 初始化TEE环境 - 新增
func (ls *LightSync) initializeTEE() {
	// 检查设备是否支持TEE
	ls.teeHelper.available = checkTEEAvailability()
	if !ls.teeHelper.available {
		log.Warn("设备不支持TEE功能，降级到标准验证")
		ls.verificationLevel = VerificationLevelStandard
		return
	}
	
	// 初始化TEE功能
	ls.teeHelper.verifyHeader = func(header *types.Header) bool {
		// 在TEE环境中验证区块头
		// 实际实现应该在TEE安全环境中进行
		return true
	}
	
	ls.teeHelper.verifyReceipt = func(receipt *types.Receipt) bool {
		// 在TEE环境中验证收据
		return true
	}
	
	ls.teeHelper.verifyState = func(state []byte) bool {
		// 在TEE环境中验证状态
		return true
	}
	
	log.Info("TEE环境初始化完成")
}

// checkTEEAvailability 检查TEE可用性 - 新增
func checkTEEAvailability() bool {
	// 实际实现应检查设备是否支持TEE
	// 如：ARM TrustZone, Intel SGX等
	// 此处简化实现
	return true
}

// 设置区块链适配器
func (ls *LightSync) SetChainAdapter(adapter ChainAdapter) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.chainAdapter = adapter
}

// Start 启动同步
func (ls *LightSync) Start() error {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	
	if ls.syncing {
		return nil // 已经在同步中
	}
	
	// 初始化状态
	ls.syncing = true
	ls.stopped = false
	
	// 设置资源限制
	if ls.resourceManager != nil {
		// 根据同步模式调整资源使用
		ls.resourceManager.optimizeForSync()
	}
	
	// 启动同步定时器
	ls.syncTicker = time.NewTicker(ls.adaptiveInterval)
	
	// 如果启用自适应同步，启动自适应定时器
	if ls.config.AdaptiveSync {
		ls.adaptiveTicker = time.NewTicker(1 * time.Minute)
		ls.wg.Add(1)
		go ls.adaptiveSyncLoop()
	}
	
	// 启动维护定时器
	ls.maintenanceTicker = time.NewTicker(10 * time.Minute)
	ls.wg.Add(1)
	go ls.maintenanceLoop()
	
	// 启动同步任务
	ls.wg.Add(1)
	go ls.syncLoop()
	
	// 启动缓存管理
	ls.wg.Add(1)
	go ls.cacheManager()
	
	// 启动离线队列处理
	if ls.config.NetworkResilienceEnabled {
		ls.wg.Add(1)
		go ls.offlineQueueProcessor()
	}
	
	// 启动性能监控
	ls.wg.Add(1)
	go ls.monitorPerformance()
	
	log.Info("轻量级同步已启动", 
		"模式", ls.currentMode, 
		"验证级别", ls.verificationLevel,
		"自适应", ls.config.AdaptiveSync)
	return nil
}

// 自适应同步循环 - 新增
func (ls *LightSync) adaptiveSyncLoop() {
	defer ls.wg.Done()
	defer ls.adaptiveTicker.Stop()
	
	for {
		select {
		case <-ls.ctx.Done():
			return
		case <-ls.adaptiveTicker.C:
			ls.adjustSyncParameters()
		}
	}
}

// 维护循环 - 新增
func (ls *LightSync) maintenanceLoop() {
	defer ls.wg.Done()
	defer ls.maintenanceTicker.Stop()
	
	for {
		select {
		case <-ls.ctx.Done():
			return
		case <-ls.maintenanceTicker.C:
			ls.performMaintenance()
		}
	}
}

// 性能监控 - 新增
func (ls *LightSync) monitorPerformance() {
	defer ls.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ls.ctx.Done():
			return
		case <-ticker.C:
			ls.updatePerformanceMetrics()
		}
	}
}

// 更新性能指标 - 新增
func (ls *LightSync) updatePerformanceMetrics() {
	now := time.Now()
	
	// 更新性能指标
	metrics := ls.metrics
	metrics.LastMeasureTime = now
	
	// 获取资源使用情况
	if ls.resourceManager != nil {
		resources := ls.resourceManager.GetResourceUsage()
		if cpu, ok := resources["cpu"]; ok {
			metrics.CPUUsage = float64(cpu)
		}
		if memory, ok := resources["memory"]; ok {
			metrics.MemoryUsage = int64(memory) * 1024 * 1024 // 转换为字节
		}
		
		// 获取电池消耗率
		battery := ls.resourceManager.GetResourceStats()
		if drain, ok := battery["battery_drain_rate"]; ok {
			if drainFloat, ok := drain.(float64); ok {
				metrics.BatteryDrain = drainFloat
			}
		}
	}
	
	// 更新统计信息
	ls.mu.Lock()
	ls.stats.BatteryImpact = metrics.BatteryDrain
	if metrics.VerificationTimeMs > 0 {
		ls.stats.VerificationTime = time.Duration(metrics.VerificationTimeMs) * time.Millisecond
	}
	ls.mu.Unlock()
}

// 调整同步参数 - 新增
func (ls *LightSync) adjustSyncParameters() {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	
	// 获取最新电池状态
	if ls.resourceManager != nil {
		ls.batteryLevel = ls.resourceManager.GetBatteryLevel()
		ls.isCharging = ls.resourceManager.IsCharging()
		ls.networkType = ls.resourceManager.GetNetworkType()
	}
	
	// 根据电池电量调整同步间隔
	if !ls.isCharging && ls.batteryLevel < ls.config.PowerSavingThreshold {
		// 低电量模式：增加同步间隔，减少同步频率
		newInterval := ls.adaptiveInterval * 2
		if newInterval > ls.config.MaxSyncInterval {
			newInterval = ls.config.MaxSyncInterval
		}
		ls.adaptiveInterval = newInterval
		
		// 激活省电模式
		if !ls.powerSavingActive && ls.batteryLevel < ls.config.PowerSavingThreshold {
			ls.powerSavingActive = true
			ls.recordModeChange("battery_low")
			log.Info("已激活省电模式", "电池", ls.batteryLevel, "同步间隔", ls.adaptiveInterval)
		}
	} else if ls.isCharging || ls.batteryLevel > ls.config.PowerSavingThreshold*1.5 {
		// 充电或电量充足：减少同步间隔
		newInterval := ls.adaptiveInterval / 1.5
		if newInterval < ls.config.MinSyncInterval {
			newInterval = ls.config.MinSyncInterval
		}
		ls.adaptiveInterval = newInterval
		
		// 停用省电模式
		if ls.powerSavingActive {
			ls.powerSavingActive = false
			ls.recordModeChange("battery_recovered")
			log.Info("已停用省电模式", "电池", ls.batteryLevel, "同步间隔", ls.adaptiveInterval)
		}
	}
	
	// 更新同步定时器
	if ls.syncTicker != nil {
		ls.syncTicker.Reset(ls.adaptiveInterval)
	}
	
	// 调整验证级别
	ls.adjustVerificationLevel()
}

// 调整验证级别 - 新增
func (ls *LightSync) adjustVerificationLevel() {
	if !ls.config.DynamicVerification {
		return
	}
	
	// 根据电池和网络情况调整验证级别
	oldLevel := ls.verificationLevel
	
	if ls.config.TEEVerification && ls.teeHelper.available {
		// 优先使用TEE验证
		ls.verificationLevel = VerificationLevelTEE
	} else if ls.isCharging || ls.batteryLevel > 70 {
		// 充电或电量充足：使用完全验证
		ls.verificationLevel = VerificationLevelFull
	} else if ls.batteryLevel > 40 {
		// 电量中等：使用标准验证
		ls.verificationLevel = VerificationLevelStandard
	} else if ls.batteryLevel > 20 {
		// 电量较低：使用轻量验证
		ls.verificationLevel = VerificationLevelLight
	} else {
		// 电量极低：使用最小验证
		ls.verificationLevel = VerificationLevelMinimal
	}
	
	// 如果验证级别变化，记录日志
	if oldLevel != ls.verificationLevel {
		log.Info("同步验证级别已调整", 
			"原级别", oldLevel, 
			"新级别", ls.verificationLevel, 
			"电池", ls.batteryLevel, 
			"充电", ls.isCharging)
		ls.recordModeChange("verification_adjust")
	}
}

// 记录模式变更 - 新增
func (ls *LightSync) recordModeChange(reason string) {
	entry := modeHistoryEntry{
		Mode:         ls.currentMode,
		Timestamp:    time.Now(),
		Reason:       reason,
		BatteryLevel: ls.batteryLevel,
		NetworkType:  ls.networkType,
	}
	ls.modeHistory = append(ls.modeHistory, entry)
	
	// 限制历史记录大小
	if len(ls.modeHistory) > 100 {
		ls.modeHistory = ls.modeHistory[len(ls.modeHistory)-100:]
	}
}

// 执行维护任务 - 新增
func (ls *LightSync) performMaintenance() {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	
	// 清理过期缓存
	ls.cleanupCache()
	
	// 清理过期离线队列项
	ls.cleanupOfflineQueue()
	
	// 优化存储
	if ls.config.CompactDataStorage {
		ls.compactStorage()
	}
	
	// 更新统计信息
	ls.updateStats()
	
	log.Debug("同步维护任务已完成", 
		"缓存大小", ls.cacheSize, 
		"离线队列", len(ls.offlineQueue))
}

// 清理离线队列 - 新增
func (ls *LightSync) cleanupOfflineQueue() {
	now := time.Now()
	var newQueue []*OfflineQueueItem
	
	for _, item := range ls.offlineQueue {
		if now.Before(item.ExpiryTime) {
			newQueue = append(newQueue, item)
		}
	}
	
	expiredCount := len(ls.offlineQueue) - len(newQueue)
	if expiredCount > 0 {
		log.Debug("已清理过期离线队列项", "数量", expiredCount)
	}
	
	ls.offlineQueue = newQueue
}

// 压缩存储 - 新增
func (ls *LightSync) compactStorage() {
	// 实现存储压缩逻辑
	log.Debug("存储压缩已执行")
}

// 离线队列处理器 - 新增
func (ls *LightSync) offlineQueueProcessor() {
	defer ls.wg.Done()
	
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ls.ctx.Done():
			return
		case <-ticker.C:
			// 检查网络是否恢复
			if ls.isNetworkAvailable() {
				ls.processOfflineQueue()
			}
		}
	}
}

// 处理离线队列 - 新增
func (ls *LightSync) processOfflineQueue() {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	
	if len(ls.offlineQueue) == 0 {
		return
	}
	
	log.Info("开始处理离线队列", "项目数", len(ls.offlineQueue))
	
	// 按优先级排序
	sort.Slice(ls.offlineQueue, func(i, j int) bool {
		return ls.offlineQueue[i].Priority > ls.offlineQueue[j].Priority
	})
	
	// 处理队列（最多处理50项，避免过载）
	processLimit := 50
	if len(ls.offlineQueue) < processLimit {
		processLimit = len(ls.offlineQueue)
	}
	
	var remainingItems []*OfflineQueueItem
	
	for i, item := range ls.offlineQueue {
		if i >= processLimit {
			remainingItems = append(remainingItems, item)
			continue
		}
		
		// 尝试处理项目
		success := ls.processOfflineItem(item)
		if !success {
			// 记录尝试并返回队列
			item.Attempts++
			item.LastAttempt = time.Now()
			
			// 检查是否超过最大尝试次数
			if item.Attempts < ls.config.MaxRetries {
				remainingItems = append(remainingItems, item)
			} else {
				log.Warn("离线项目超过最大尝试次数，丢弃", 
					"类型", item.Type, 
					"哈希", item.Hash, 
					"尝试", item.Attempts)
			}
		} else {
			log.Debug("成功处理离线项目", 
				"类型", item.Type, 
				"哈希", item.Hash)
		}
	}
	
	ls.offlineQueue = remainingItems
	ls.stats.PendingOfflineActions = len(ls.offlineQueue)
	
	log.Info("离线队列处理完成", 
		"处理数", processLimit, 
		"剩余", len(ls.offlineQueue))
}

// 处理单个离线项目 - 新增
func (ls *LightSync) processOfflineItem(item *OfflineQueueItem) bool {
	// 根据类型处理不同项目
	switch item.Type {
	case "header":
		if header, ok := item.Data.(*types.Header); ok {
			ls.processNewHeader(header)
			return true
		}
	case "tx":
		// 处理交易
		return true
	case "block":
		// 处理区块
		return true
	}
	return false
}

// 检查网络可用性 - 新增
func (ls *LightSync) isNetworkAvailable() bool {
	// 通过资源管理器检查网络状态
	if ls.resourceManager != nil && ls.resourceManager.GetNetworkType() != NetworkTypeNone {
		return true
	}
	
	// 如果有网络弹性管理器，检查其状态
	if ls.networkResilience != nil {
		state := ls.networkResilience.GetNetworkState()
		return state != NetworkStateOffline && state != NetworkStateInterrupted
	}
	
	return true // 默认假设网络可用
}

// 更新统计信息 - 新增
func (ls *LightSync) updateStats() {
	now := time.Now()
	stats := ls.stats
	
	if ls.powerSavingActive {
		// 更新省电模式时间
		if !stats.LastSyncTime.IsZero() {
			stats.PowerSavingTime += now.Sub(stats.LastSyncTime)
		}
	}
	
	// 更新TEE验证计数
	if ls.verificationLevel == VerificationLevelTEE {
		stats.TEEVerificationCount++
	}
	
	// 更新验证级别
	stats.VerificationLevel = int(ls.verificationLevel)
	
	// 更新离线动作数
	stats.PendingOfflineActions = len(ls.offlineQueue)
}

// 向离线队列添加项目 - 新增
func (ls *LightSync) addToOfflineQueue(itemType string, data interface{}, priority int, hash common.Hash) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	
	// 检查队列是否已满
	if len(ls.offlineQueue) >= ls.config.MaxOfflineQueueSize {
		// 移除最低优先级项目
		lowestIdx := 0
		lowestPriority := 6 // 高于可能的最高优先级
		
		for i, item := range ls.offlineQueue {
			if item.Priority < lowestPriority {
				lowestPriority = item.Priority
				lowestIdx = i
			}
		}
		
		// 如果新项目优先级更高，替换最低优先级项
		if priority > lowestPriority {
			log.Debug("离线队列已满，替换低优先级项目", 
				"移除类型", ls.offlineQueue[lowestIdx].Type,
				"移除优先级", lowestPriority,
				"新类型", itemType,
				"新优先级", priority)
			
			// 移除最低优先级项
			ls.offlineQueue = append(ls.offlineQueue[:lowestIdx], ls.offlineQueue[lowestIdx+1:]...)
		} else {
			log.Debug("离线队列已满，丢弃新项目", 
				"类型", itemType, 
				"优先级", priority)
			return
		}
	}
	
	// 创建新的队列项
	item := &OfflineQueueItem{
		Type:        itemType,
		Data:        data,
		Priority:    priority,
		Timestamp:   time.Now(),
		ExpiryTime:  time.Now().Add(ls.config.OfflineExpiryTime),
		Hash:        hash,
	}
	
	// 如果可以估计大小，设置大小
	switch data.(type) {
	case *types.Header:
		item.Size = 500 // 估计大小
	case *types.Transaction:
		item.Size = 300 // 估计大小
	case *types.Block:
		item.Size = 5000 // 估计大小
	}
	
	// 添加到队列
	ls.offlineQueue = append(ls.offlineQueue, item)
	ls.stats.PendingOfflineActions = len(ls.offlineQueue)
	
	log.Debug("项目已添加到离线队列", 
		"类型", itemType, 
		"哈希", hash.Hex()[:10], 
		"优先级", priority)
}

// 同步循环
func (ls *LightSync) syncLoop() {
	defer ls.wg.Done()
	
	// 根据配置设置定时器
	interval := ls.config.SyncInterval
	if interval == 0 {
		interval = 15 * time.Second // 默认15秒
	}
	
	syncTicker := time.NewTicker(interval)
	defer syncTicker.Stop()
	
	// 立即执行一次同步
	ls.performSync()
	
	for {
		select {
		case <-ls.ctx.Done():
			return
		case <-syncTicker.C:
			// 调整同步模式
			ls.adjustSyncMode()
			
			// 如果设备状态不适合同步，则跳过本次同步
			if !ls.shouldSync() {
				continue
			}
			
			// 执行同步
			ls.performSync()
		case header := <-ls.headerCh:
			// 处理新区块头
			ls.processNewHeader(header)
		}
	}
}

// 执行同步
func (ls *LightSync) performSync() {
	ls.mu.Lock()
	if !ls.syncing {
		ls.mu.Unlock()
		return
	}
	ls.mu.Unlock()
	
	startTime := time.Now()
	
	// 记录同步开始
	log.Debug("开始同步", "模式", ls.currentMode)
	
	// 根据同步模式执行不同的同步逻辑
	var err error
	switch ls.currentMode {
	case LightSyncModeFull:
		err = ls.fullSync()
	case LightSyncModeHeaders:
		err = ls.headersSync()
	case LightSyncModePriority:
		err = ls.prioritySync()
	case LightSyncModeMinimal:
		err = ls.minimalSync()
	}
	
	syncDuration := time.Since(startTime)
	
	ls.mu.Lock()
	ls.stats.LastSyncTime = time.Now()
	ls.stats.SyncTime = syncDuration
	ls.mu.Unlock()
	
	// 记录同步结果
	if err != nil {
		log.Warn("同步失败", "错误", err, "耗时", syncDuration)
	} else {
		log.Debug("同步完成", "耗时", syncDuration)
	}
}

// 完整同步模式
func (ls *LightSync) fullSync() error {
	// 实现完整同步逻辑
	// 1. 同步区块头
	// 2. 同步区块体
	// 3. 处理交易
	// 4. 可选地同步状态
	
	// 示例实现
	if ls.chainAdapter == nil {
		return nil
	}
	
	// 获取当前区块高度
	currentHeight := ls.stats.CurrentHeight
	
	// 获取远程节点的区块高度
	isConnected := ls.chainAdapter.IsConnected()
	if !isConnected {
		return nil
	}
	
	return nil
}

// 仅区块头同步模式
func (ls *LightSync) headersSync() error {
	// 实现仅区块头的同步逻辑
	return nil
}

// 优先区块同步模式
func (ls *LightSync) prioritySync() error {
	// 实现优先区块的同步逻辑
	return nil
}

// 最小化同步模式
func (ls *LightSync) minimalSync() error {
	// 实现最小化的同步逻辑
	return nil
}

// 处理新区块头
func (ls *LightSync) processNewHeader(header *types.Header) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	
	// 更新统计信息
	ls.stats.TotalHeadersProcessed++
	
	// 如果是更高的区块，更新记录
	if header.Number.Uint64() > ls.stats.HighestBlockSeen {
		ls.stats.HighestBlockSeen = header.Number.Uint64()
	}
	
	// 添加到缓存
	ls.headerCache[header.Number.Uint64()] = header
	
	// 更新缓存大小
	ls.updateCacheSize()
}

// 调整同步模式
func (ls *LightSync) adjustSyncMode() {
	// 如果没有资源管理器，保持当前模式
	if ls.resourceManager == nil {
		return
	}
	
	// 获取资源状态
	batteryLevel := ls.resourceManager.GetBatteryLevel()
	isCharging := ls.resourceManager.IsCharging()
	networkType := ls.resourceManager.GetNetworkType()
	isBackground := ls.resourceManager.IsBackgroundMode()
	
	// 根据设备状态调整同步模式
	switch {
	case isCharging && networkType == NetworkTypeWifi:
		// 充电 + WiFi: 完整同步
		ls.setMode(LightSyncModeFull)
		
	case batteryLevel <= ls.config.LowBatteryThreshold && !isCharging:
		// 低电量且不在充电: 最小化同步
		ls.setMode(LightSyncModeMinimal)
		
	case networkType == NetworkTypeMobile || networkType == NetworkTypeWeak:
		// 移动网络或弱网: 仅区块头
		ls.setMode(LightSyncModeHeaders)
		
	case isBackground:
		// 后台模式: 优先区块同步
		ls.setMode(LightSyncModePriority)
		
	default:
		// 其他情况: 完整同步
		ls.setMode(LightSyncModeFull)
	}
}

// 设置同步模式
func (ls *LightSync) setMode(mode LightSyncMode) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	
	// 如果模式没变，不做任何事
	if ls.currentMode == mode {
		return
	}
	
	oldMode := ls.currentMode
	ls.currentMode = mode
	
	log.Info("同步模式已更改", "从", oldMode, "到", mode)
}

// 缓存管理器
func (ls *LightSync) cacheManager() {
	defer ls.wg.Done()
	
	// 缓存清理时间间隔
	cleanupInterval := ls.config.CacheTTL
	if cleanupInterval == 0 {
		cleanupInterval = 30 * time.Minute // 默认30分钟
	}
	
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ls.ctx.Done():
			return
		case <-ticker.C:
			ls.cleanupCache()
		}
	}
}

// 清理过期缓存
func (ls *LightSync) cleanupCache() {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	
	// 获取当前高度
	currentHeight := ls.stats.CurrentHeight
	
	// 清理太旧的区块头缓存
	for height, _ := range ls.headerCache {
		// 保留最近的区块头 (例如保留最近10000个区块头)
		if height+10000 < currentHeight {
			delete(ls.headerCache, height)
		}
	}
	
	// 更新缓存大小
	ls.updateCacheSize()
}

// 更新缓存大小(粗略估计)
func (ls *LightSync) updateCacheSize() {
	// 简单估计: 每个区块头约500字节，每个收据约200字节
	headerSize := len(ls.headerCache) * 500
	
	receiptSize := 0
	for _, receipts := range ls.receiptCache {
		receiptSize += len(receipts) * 200
	}
	
	ls.cacheSize = (headerSize + receiptSize) / (1024 * 1024) // 转为MB
	
	// 如果超过最大缓存大小，触发清理
	if ls.config.MaxCacheSize > 0 && ls.cacheSize > ls.config.MaxCacheSize {
		ls.reduceCache()
	}
}

// 减少缓存大小
func (ls *LightSync) reduceCache() {
	// 简单策略: 清理一半的旧区块头
	if len(ls.headerCache) > 0 {
		// 收集所有高度并排序
		heights := make([]uint64, 0, len(ls.headerCache))
		for height := range ls.headerCache {
			heights = append(heights, height)
		}
		
		// 排序
		sort.Slice(heights, func(i, j int) bool {
			return heights[i] < heights[j]
		})
		
		// 删除前一半的旧区块头
		deleteCount := len(heights) / 2
		for i := 0; i < deleteCount; i++ {
			delete(ls.headerCache, heights[i])
		}
	}
 
	// 清理收据缓存
	// 这里可以实现更复杂的策略，例如基于使用频率或最近访问时间
	if len(ls.receiptCache) > 10 {
		// 简单示例：保留最多10个收据
		count := 0
		for hash := range ls.receiptCache {
			if count > 10 {
				delete(ls.receiptCache, hash)
			}
			count++
		}
	}
}

// 判断当前是否应该同步
func (ls *LightSync) shouldSync() bool {
	// 如果配置不允许电池感知，总是同步
	if !ls.config.BatteryAware {
		return true
	}
	
	// 检查电池状态
	if ls.resourceManager != nil {
		batteryLevel := ls.resourceManager.GetBatteryLevel()
		isCharging := ls.resourceManager.IsCharging()
		
		// 如果电量极低且未充电，跳过同步
		if batteryLevel < 5 && !isCharging {
			log.Debug("电量极低，跳过同步", "电量", batteryLevel)
			return false
		}
		
		// 低电量时降低同步频率
		if batteryLevel < ls.config.LowBatteryThreshold && !isCharging {
			// 使用随机跳过部分同步周期
			randVal := rand.Float64()
			if randVal < 0.7 { // 70%的概率跳过
				log.Debug("电量低，随机跳过同步", "电量", batteryLevel)
				return false
			}
		}
		
		// 检查网络状态
		if ls.config.NetworkAware {
			networkType := ls.resourceManager.GetNetworkType()
			
			// 无网络时跳过同步
			if networkType == NetworkTypeNone {
				log.Debug("无网络连接，跳过同步")
				return false
			}
			
			// 移动网络且数据节省模式开启时，降低同步频率
			if networkType == NetworkTypeMobile && ls.config.DataSavingEnabled {
				// 随机跳过部分同步
				randVal := rand.Float64()
				if randVal < 0.5 { // 50%的概率跳过
					log.Debug("移动网络节省数据，跳过同步")
					return false
				}
			}
		}
		
		// 后台模式降低同步频率
		if ls.resourceManager.IsBackgroundMode() && ls.config.BackgroundModeFactor > 0 {
			// 使用时间戳来确保一致性
			timestamp := time.Now().Unix()
			skipFactor := ls.config.BackgroundModeFactor
			
			// 每 BackgroundModeFactor 个同步周期才执行一次
			if timestamp%(int64(skipFactor*10)) > 10 {
				log.Debug("后台模式，跳过同步")
				return false
			}
		}
	}
	
	return true
}

// GetSyncStats 获取同步统计信息
func (ls *LightSync) GetSyncStats() *LightSyncStats {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	
	// 返回统计信息的副本
	statsCopy := *ls.stats
	return &statsCopy
}

// GetCurrentMode 获取当前同步模式
func (ls *LightSync) GetCurrentMode() LightSyncMode {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	
	return ls.currentMode
}

// IsSyncing 检查是否正在同步
func (ls *LightSync) IsSyncing() bool {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	
	return ls.syncing
}

// GetCacheSize 获取当前缓存大小(MB)
func (ls *LightSync) GetCacheSize() int {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	
	return ls.cacheSize
}

// SetConfig 更新配置
func (ls *LightSync) SetConfig(config *LightSyncConfig) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	
	ls.config = config
	
	// 重新调整同步模式
	ls.adjustSyncMode()
} 