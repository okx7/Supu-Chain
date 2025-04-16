package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"math/big"
	"sort"
	"sync"
	"time"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/hashicorp/golang-lru"
)

// 网络状态常量
const (
	NetworkStateUnknown   = "unknown"    // 未知状态
	NetworkStateOffline   = "offline"    // 离线状态
	NetworkStateWeak      = "weak"       // 弱网状态
	NetworkStateNormal    = "normal"     // 正常状态
	NetworkStateStrong    = "strong"     // 强网状态
)

// 网络类型常量
const (
	NetworkTypeUnknown    = "unknown"    // 未知网络
	NetworkTypeWifi       = "wifi"       // WiFi网络
	NetworkTypeCellular   = "cellular"   // 蜂窝网络
	NetworkTypeEthernet   = "ethernet"   // 以太网
	NetworkTypeBluetooth  = "bluetooth"  // 蓝牙网络
	NetworkTypeP2P        = "p2p"        // P2P网络
	NetworkTypeSimulated  = "simulated"  // 模拟网络
)

// 交易优先级常量
const (
	TxPriorityLow     = 1 // 低优先级
	TxPriorityNormal  = 2 // 正常优先级
	TxPriorityHigh    = 3 // 高优先级
	TxPriorityCritical = 4 // 关键优先级
)

// 数据传输策略常量
const (
	TransferPolicyRealtime = "realtime" // 实时策略 - 不缓存，立即发送
	TransferPolicyBatched  = "batched"  // 批量策略 - 缓存并批量发送
	TransferPolicyDeferred = "deferred" // 延迟策略 - 等待良好网络再发送
	TransferPolicyAdaptive = "adaptive" // 自适应策略 - 根据网络状况调整
)

// 错误处理策略常量
const (
	ErrorPolicyFail     = "fail"    // 失败策略 - 遇到错误立即失败
	ErrorPolicyRetry    = "retry"   // 重试策略 - 遇到错误自动重试
	ErrorPolicyDegrade  = "degrade" // 降级策略 - 降级服务，使用本地缓存
	ErrorPolicyIgnore   = "ignore"  // 忽略策略 - 忽略错误，继续执行
)

// 本地P2P连接类型常量 - 新增
const (
	LocalP2PTypeNone      = "none"      // 无本地P2P
	LocalP2PTypeBluetooth = "bluetooth" // 蓝牙连接
	LocalP2PTypeWifiDirect = "wifi_direct" // WiFi直连
	LocalP2PTypeLAN       = "lan"       // 局域网
	LocalP2PTypeHybrid    = "hybrid"    // 混合模式
)

// 消息类型常量
const (
	MessageTypeUnknown       = 0    // 未知消息类型
	MessageTypeBlockRequest  = 1    // 区块请求
	MessageTypeBlockResponse = 2    // 区块响应
	MessageTypeTxRequest     = 3    // 交易请求
	MessageTypeTxResponse    = 4    // 交易响应
	MessageTypeSync          = 5    // 同步消息
	MessageTypeControl       = 6    // 控制消息
	MessageTypeDiscovery     = 7    // 发现消息
	MessageTypeHeartbeat     = 8    // 心跳消息
	MessageTypeStateRequest  = 9    // 状态请求
	MessageTypeStateResponse = 10   // 状态响应
	MessageTypeMaxValid      = 10   // 最大有效消息类型
)

// VALID_MESSAGE_TYPES 有效消息类型集合 - 使用常量数组提升可维护性
var VALID_MESSAGE_TYPES = []uint8{
	MessageTypeBlockRequest,
	MessageTypeBlockResponse,
	MessageTypeTxRequest,
	MessageTypeTxResponse,
	MessageTypeSync,
	MessageTypeControl,
	MessageTypeDiscovery,
	MessageTypeHeartbeat,
	MessageTypeStateRequest,
	MessageTypeStateResponse,
}

// 动态生成消息类型映射，提高查询效率
var validMessageTypes = func() map[uint8]bool {
	types := make(map[uint8]bool)
	for _, t := range VALID_MESSAGE_TYPES {
		types[t] = true
	}
	return types
}()

// 添加重试策略常量
const (
	RetryStrategyImmediate = "immediate" // 立即重试
	RetryStrategyExponential = "exponential" // 指数退避
	RetryStrategyLinear = "linear" // 线性增长
	RetryStrategyFixedInterval = "fixed" // 固定间隔
)

// NetworkResilienceConfig 网络弹性配置
type NetworkResilienceConfig struct {
	// 基本配置
	NetworkAwareness      bool          // 网络感知
	OfflineMode           bool          // 离线模式
	WeakNetworkTolerance  bool          // 弱网容忍
	AutoReconnect         bool          // 自动重连
	ReconnectInterval     time.Duration // 重连间隔
	
	// 优化配置
	DataCompressionLevel  int           // 数据压缩级别(0-9)
	BatchingEnabled       bool          // 批处理启用
	BatchSize             int           // 批处理大小
	BatchInterval         time.Duration // 批处理间隔
	
	// 高级配置
	AdaptiveTimeout       bool          // 自适应超时
	MinTimeout            time.Duration // 最小超时
	MaxTimeout            time.Duration // 最大超时
	TimeoutMultiplier     float64       // 超时乘数
	
	// 断点续传
	ResumeDownload        bool          // 断点续传
	ChunkSize             int           // 分片大小
	MaxConcurrentChunks   int           // 最大并发分片
	
	// 优先级和调度
	PrioritizedSyncing    bool          // 优先级同步
	LowPriorityDataTypes  []string      // 低优先级数据类型
	HighPriorityDataTypes []string      // 高优先级数据类型
	
	// 弱网优化
	DeltaSyncEnabled      bool          // 增量同步
	DiffCompressionEnabled bool         // 差异压缩
	MinUpdateInterval     time.Duration // 最小更新间隔
	
	// 故障转移
	FailoverStrategy      string        // 故障转移策略
	MaxFailoverAttempts   int           // 最大故障转移尝试
	FailoverNodes         []string      // 故障转移节点
	
	// 缓存策略
	CacheTTL              time.Duration // 缓存生存时间
	MaxCacheSize          int           // 最大缓存大小(MB)
	StaleDataPolicy       string        // 过期数据策略

	// 本地P2P配置 - 新增
	LocalP2PEnabled    bool             // 启用本地P2P
	LocalP2PConfig     *LocalP2PConfig  // 本地P2P配置
}

// NetworkStats 网络统计
type NetworkStats struct {
	State               string        // 当前网络状态
	Type                string        // 网络类型
	LatencyMs           int           // 延迟(毫秒)
	DownloadSpeedKBps   int           // 下载速度(KB/s)
	UploadSpeedKBps     int           // 上传速度(KB/s)
	PacketLoss          float64       // 丢包率(%)
	LastStateChange     time.Time     // 最后状态变化时间
	ConnectionUptime    time.Duration // 连接持续时间
	ReconnectCount      int           // 重连次数
	LastReconnectTime   time.Time     // 最后重连时间
	FailedTxCount       int           // 失败交易数
	DeferredTxCount     int           // 延迟交易数
	SuccessfulTxCount   int           // 成功交易数
	CompressedDataSent  int64         // 压缩数据发送量(字节)
	RawDataSent         int64         // 原始数据发送量(字节)
	CompressionRatio    float64       // 压缩比
}

// PendingTransaction 待处理交易
type PendingTransaction struct {
	TxHash           common.Hash    // 交易哈希
	Tx               *types.Transaction // 交易
	SubmitTime       time.Time     // 提交时间
	Priority         int           // 优先级
	Attempts         int           // 尝试次数
	LastAttempt      time.Time     // 最后尝试时间
	Status           string        // 状态
	Error            string        // 错误信息
	TransferPolicy   string        // 传输策略
	DataSize         int           // 数据大小(字节)
}

// ResumeDownloadInfo 断点续传信息
type ResumeDownloadInfo struct {
	ResourceID       string        // 资源ID
	ResourceType     string        // 资源类型
	URL              string        // 资源URL
	TotalSize        int64         // 总大小
	DownloadedSize   int64         // 已下载大小
	StartTime        time.Time     // 开始时间
	LastUpdate       time.Time     // 最后更新时间
	ChunkStatus      map[int]bool  // 分片状态
	Status           string        // 状态
	Error            string        // 错误信息
}

// BatchOperation 批量操作
type BatchOperation struct {
	BatchID          string        // 批次ID
	Operations       []interface{} // 操作列表
	CreateTime       time.Time     // 创建时间
	ScheduledTime    time.Time     // 计划执行时间
	Status           string        // 状态
	Priority         int           // 优先级
}

// LocalPeerInfo 本地对等节点信息 - 新增
type LocalPeerInfo struct {
	PeerID         string         // 对等节点ID
	DeviceID       string         // 设备ID
	DeviceName     string         // 设备名称
	ConnectionType string         // 连接类型
	Address        string         // 地址
	ConnectedAt    time.Time      // 连接时间
	LastSeen       time.Time      // 最后见到时间
	Latency        time.Duration  // 延迟
	IsActive       bool           // 是否活跃
	Capabilities   []string       // 能力
	TxRelayEnabled bool           // 交易中继启用
	DataRelayEnabled bool         // 数据中继启用
}

// LocalP2PConfig 本地P2P配置 - 新增
type LocalP2PConfig struct {
	Enabled            bool         // 是否启用
	ConnectionTypes    []string     // 连接类型
	MaxPeers           int          // 最大对等节点数
	DiscoveryInterval  time.Duration // 发现间隔
	HeartbeatInterval  time.Duration // 心跳间隔
	TxRelay            bool         // 交易中继
	StateSync          bool         // 状态同步
	DataRelay          bool         // 数据中继
	AutoConnect        bool         // 自动连接
	TrustedPeersOnly   bool         // 仅可信节点
	TrustedPeers       []string     // 可信节点列表
	BlacklistedPeers   []string     // 黑名单节点列表
	EncryptionEnabled  bool         // 加密启用
	CompressionEnabled bool         // 压缩启用
	BandwidthLimit     int          // 带宽限制(KB/s)
	KeepAliveTimeout   time.Duration // 保活超时
}

// NetworkResilience 网络弹性
type NetworkResilience struct {
	config           *NetworkResilienceConfig // 配置
	stats            NetworkStats       // 统计信息
	pendingTxs       map[common.Hash]*PendingTransaction // 待处理交易
	pendingBatches   map[string]*BatchOperation // 待处理批次
	resumeDownloads  map[string]*ResumeDownloadInfo // 断点续传
	
	// 状态
	currentState      string           // 当前状态
	currentTimeout    time.Duration    // 当前超时
	
	// 缓存
	dataCache         map[string][]byte // 数据缓存
	txCache           map[common.Hash]*types.Transaction // 交易缓存
	
	// 控制
	mu               sync.RWMutex      // 互斥锁
	ctx              context.Context   // 上下文
	cancel           context.CancelFunc // 取消函数
	wg               sync.WaitGroup    // 等待组
	
	// 回调
	stateChangeCallback func(oldState, newState string) // 状态变更回调
	txCallback          func(txHash common.Hash, status string, err error) // 交易回调

	// 本地P2P相关 - 新增
	localPeers        map[string]*LocalPeerInfo // 本地对等节点
	relayTxs          map[common.Hash]time.Time // 中继交易
	relayData         map[string][]byte         // 中继数据
	discoveryTicker   *time.Ticker     // 发现定时器
	heartbeatTicker   *time.Ticker     // 心跳定时器
	localP2PActive    bool             // 本地P2P是否活跃
	
	// 链适配器 - 新增
	chainAdapter      ChainAdapter     // 链适配器
	
	// 重试控制
	syncRetryContext    *RetryContext   // 同步重试上下文
	reconnectRetryContext *RetryContext // 重连重试上下文
	retryTasks           map[string]*RetryContext // 各任务的重试上下文
}

// RetryContext 重试上下文结构体
type RetryContext struct {
	startTime      time.Time     // 开始时间
	attempt        int           // 当前尝试次数
	maxAttempts    int           // 最大尝试次数
	initialDelay   time.Duration // 初始延迟
	maxDelay       time.Duration // 最大延迟
	strategy       string        // 重试策略
	isActive       bool          // 是否激活
	lastRetryTime  time.Time     // 上次重试时间
	nextRetryTime  time.Time     // 下次重试时间
}

// NewRetryContext 创建重试上下文
func NewRetryContext(maxAttempts int, initialDelay, maxDelay time.Duration, strategy string) *RetryContext {
	return &RetryContext{
		startTime:     time.Now(),
		attempt:       0,
		maxAttempts:   maxAttempts,
		initialDelay:  initialDelay,
		maxDelay:      maxDelay,
		strategy:      strategy,
		isActive:      true,
		lastRetryTime: time.Time{},
		nextRetryTime: time.Now(),
	}
}

// CalculateNextRetryDelay 计算下次重试延迟
func (rc *RetryContext) CalculateNextRetryDelay() time.Duration {
	rc.attempt++
	
	if rc.attempt > rc.maxAttempts {
		return 0 // 超过最大重试次数
	}
	
	var delay time.Duration
	
	switch rc.strategy {
	case RetryStrategyImmediate:
		delay = 0
	
	case RetryStrategyExponential:
		// 指数退避: initialDelay * (2^attempt)
		delaySeconds := float64(rc.initialDelay.Seconds()) * math.Pow(2, float64(rc.attempt-1))
		delay = time.Duration(delaySeconds) * time.Second
		
		// 添加一些随机性避免雪崩重试 (±20%)
		jitter := rand.Float64()*0.4 - 0.2 // -20% 到 +20%
		delay = time.Duration(float64(delay) * (1 + jitter))
		
		// 确保指数退避不会超过最大延迟，防止过长等待
		if delay > rc.maxDelay {
			delay = rc.maxDelay
			log.Debug("指数退避延迟超过最大值，已限制", 
				"原始延迟", time.Duration(delaySeconds)*time.Second,
				"限制后延迟", delay,
				"尝试次数", rc.attempt)
		}
	
	case RetryStrategyLinear:
		// 线性增长: initialDelay * attempt
		delay = rc.initialDelay * time.Duration(rc.attempt)
	
	case RetryStrategyFixedInterval:
		// 固定间隔
		delay = rc.initialDelay
	
	default:
		// 默认使用指数退避
		delaySeconds := float64(rc.initialDelay.Seconds()) * math.Pow(2, float64(rc.attempt-1))
		delay = time.Duration(delaySeconds) * time.Second
	}
	
	// 限制最大延迟（此检查保留，以确保所有策略都受到限制）
	if delay > rc.maxDelay {
		delay = rc.maxDelay
	}
	
	// 更新重试状态
	rc.lastRetryTime = time.Now()
	rc.nextRetryTime = rc.lastRetryTime.Add(delay)
	
	return delay
}

// IsRetryAllowed 检查是否允许重试
func (rc *RetryContext) IsRetryAllowed() bool {
	return rc.isActive && rc.attempt < rc.maxAttempts
}

// NewNetworkResilience 创建新的网络弹性
func NewNetworkResilience(ctx context.Context, config *NetworkResilienceConfig) *NetworkResilience {
	if config == nil {
		config = DefaultNetworkResilienceConfig()
	}
	
	ctx, cancel := context.WithCancel(ctx)
	
	// 创建重试上下文
	syncRetryContext := NewRetryContext(
		10, // 最大尝试次数
		2 * time.Second, // 初始延迟
		5 * time.Minute, // 最大延迟
		RetryStrategyExponential, // 使用指数退避策略
	)
	
	reconnectRetryContext := NewRetryContext(
		20, // 最大尝试次数
		1 * time.Second, // 初始延迟
		30 * time.Minute, // 最大延迟
		RetryStrategyExponential, // 使用指数退避策略
	)
	
	nr := &NetworkResilience{
		config:           config,
		stats:            NetworkStats{},
		pendingTxs:       make(map[common.Hash]*PendingTransaction),
		pendingBatches:   make(map[string]*BatchOperation),
		resumeDownloads:  make(map[string]*ResumeDownloadInfo),
		
		currentState:      NetworkStateNormal,
		currentTimeout:    config.DefaultTimeout,
		
		dataCache:         make(map[string][]byte),
		txCache:           make(map[common.Hash]*types.Transaction),
		
		ctx:              ctx,
		cancel:           cancel,
		
		localPeers:        make(map[string]*LocalPeerInfo),
		relayTxs:          make(map[common.Hash]time.Time),
		relayData:         make(map[string][]byte),
		localP2PActive:    false,
		
		syncRetryContext: syncRetryContext,
		reconnectRetryContext: reconnectRetryContext,
		retryTasks: make(map[string]*RetryContext),
	}
	
	// 初始化网络监控
	nr.startNetworkMonitoring()
	
	// 如果启用本地P2P，则初始化P2P功能
	if config.LocalP2PEnabled {
		nr.initLocalP2P()
	}
	
	// 启动后台处理任务
	nr.startBackgroundTasks()
	
	return nr
}

// Start 启动网络弹性
func (nr *NetworkResilience) Start() error {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	// 启动网络监控
	nr.wg.Add(1)
	go nr.monitorNetwork()
	
	// 启动批处理任务
	if nr.config.BatchingEnabled {
		nr.wg.Add(1)
		go nr.batchProcessor()
	}
	
	// 启动超时调整任务
	if nr.config.AdaptiveTimeout {
		nr.wg.Add(1)
		go nr.timeoutAdjuster()
	}
	
	// 启动交易管理任务
	nr.wg.Add(1)
	go nr.txManagerTask()
	
	// 启动缓存清理任务
	nr.wg.Add(1)
	go nr.cacheCleanupTask()

	// 启动本地P2P
	if nr.config.LocalP2PEnabled && nr.config.LocalP2PConfig != nil && nr.config.LocalP2PConfig.Enabled {
		nr.wg.Add(1)
		go nr.runLocalP2P()
	}
	
	log.Info("网络弹性优化器已启动")
	return nil
}

// Stop 停止网络弹性
func (nr *NetworkResilience) Stop() error {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	// 取消上下文
	nr.cancel()
	
	// 等待所有任务结束
	nr.wg.Wait()
	
	log.Info("网络弹性优化器已停止")
	return nil
}

// 监控网络状态
func (nr *NetworkResilience) monitorNetwork() {
	defer nr.wg.Done()
	
	// 初始探测间隔
	probeInterval := 5 * time.Second
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-nr.ctx.Done():
			return
			
		case <-ticker.C:
			// 检测网络状态
			state, networkType, stats := nr.probeNetworkState()
			
			nr.mu.Lock()
			// 更新网络统计信息
			nr.stats.State = state
			nr.stats.Type = networkType
			nr.stats.LatencyMs = stats.latencyMs
			nr.stats.PacketLoss = stats.packetLoss
			nr.stats.DownloadSpeedKBps = stats.downloadSpeedKBps
			nr.stats.UploadSpeedKBps = stats.uploadSpeedKBps
			
			// 如果状态有变化
			if nr.currentState != state {
				oldState := nr.currentState
				nr.currentState = state
				nr.stats.LastStateChange = time.Now()
				
				// 调用状态变更回调
				if nr.stateChangeCallback != nil {
					go nr.stateChangeCallback(oldState, state)
				}
				
				// 根据网络状态调整探测间隔
				switch state {
				case NetworkStateOffline:
					probeInterval = 10 * time.Second // 离线时减少探测频率
				case NetworkStateWeak:
					probeInterval = 7 * time.Second // 弱网时稍微减少探测频率
				case NetworkStateNormal, NetworkStateStrong:
					probeInterval = 5 * time.Second // 正常或强网络时使用标准探测频率
				}
				
				// 网络恢复时执行操作
				if (oldState == NetworkStateOffline || oldState == NetworkStateWeak) &&
					(state == NetworkStateNormal || state == NetworkStateStrong) {
					go nr.onNetworkRecovered()
				}
				
				// 网络断开时执行操作
				if oldState != NetworkStateOffline && state == NetworkStateOffline {
					go nr.onNetworkDisconnected()
				}
				
				// 更新ticker间隔
				ticker.Reset(probeInterval)
				
				log.Info("网络状态变更", 
					"从", oldState, 
					"到", state, 
					"类型", networkType,
					"延迟", stats.latencyMs, "ms")
			}
			nr.mu.Unlock()
		}
	}
}

// 网络状态探测结果
type networkProbeResult struct {
	latencyMs           int       // 延迟(毫秒)
	packetLoss          float64   // 丢包率(%)
	downloadSpeedKBps   int       // 下载速度(KB/s)
	uploadSpeedKBps     int       // 上传速度(KB/s)
}

// 探测网络状态
func (nr *NetworkResilience) probeNetworkState() (string, string, networkProbeResult) {
	// 在实际实现中，这里应该进行真实的网络探测
	// 这里仅作为示例实现
	
	// 模拟网络探测结果
	result := networkProbeResult{
		latencyMs: 50,           // 模拟50ms延迟
		packetLoss: 0.1,         // 模拟0.1%丢包率
		downloadSpeedKBps: 1000, // 模拟1000KB/s下载速度
		uploadSpeedKBps: 500,    // 模拟500KB/s上传速度
	}
	
	// 确定网络类型(这里简化为随机)
	networkType := NetworkTypeWifi
	
	// 根据延迟和丢包率确定网络状态
	var state string
	if result.latencyMs < 0 { // 无法连接
		state = NetworkStateOffline
	} else if result.latencyMs > 200 || result.packetLoss > 5 {
		state = NetworkStateWeak
	} else if result.latencyMs > 100 || result.packetLoss > 1 {
		state = NetworkStateNormal
	} else {
		state = NetworkStateStrong
	}
	
	return state, networkType, result
}

// 网络恢复处理
func (nr *NetworkResilience) onNetworkRecovered() {
	nr.mu.Lock()
	
	// 记录重连
	nr.stats.ReconnectCount++
	nr.stats.LastReconnectTime = time.Now()
	
	// 处理所有待处理的交易
	pendingTxCount := len(nr.pendingTxs)
	nr.mu.Unlock()
	
	log.Info("网络已恢复", "待处理交易", pendingTxCount)
	
	// 发送所有待处理的交易
	if pendingTxCount > 0 {
		go nr.processPendingTransactions()
	}
	
	// 恢复所有中断的下载
	if len(nr.resumeDownloads) > 0 {
		go nr.resumeAllDownloads()
	}
	
	// 处理所有待处理的批量操作
	if len(nr.pendingBatches) > 0 {
		go nr.processPendingBatches()
	}
}

// 网络断开处理
func (nr *NetworkResilience) onNetworkDisconnected() {
	log.Info("网络已断开，进入离线模式")
	
	// 保存所有待处理交易到本地
	nr.saveAllPendingTransactions()
	
	// 启动本地P2P（如果未启动）
	if nr.config.LocalP2PEnabled && nr.config.LocalP2PConfig != nil {
		nr.mu.RLock()
		isActive := nr.localP2PActive
		nr.mu.RUnlock()
		
		if !isActive {
			go nr.runLocalP2P()
		} else {
			// 如果已经启动，增加发现频率
			nr.discoveryTicker.Reset(nr.config.LocalP2PConfig.DiscoveryInterval / 2)
		}
	}
	
	// 尝试故障转移
	nr.tryFailover()
	
	// 使用重试策略来重连，而不是立即重连
	delay := nr.reconnectRetryContext.CalculateNextRetryDelay()
	if delay > 0 {
		log.Info("计划网络重连尝试", 
			"尝试次数", nr.reconnectRetryContext.attempt,
			"延迟", delay,
			"下次尝试时间", nr.reconnectRetryContext.nextRetryTime)
			
		time.AfterFunc(delay, func() {
			// 检查是否已关闭
			select {
			case <-nr.ctx.Done():
				return
			default:
				// 尝试重新连接网络
				nr.tryReconnect()
			}
		})
	}
}

// 尝试故障转移
func (nr *NetworkResilience) tryFailover() {
	// 在实际实现中，这里应该尝试连接故障转移节点
	// 这里仅作为示例实现
	log.Info("尝试故障转移", "节点数", len(nr.config.FailoverNodes))
}

// 尝试重新连接网络
func (nr *NetworkResilience) tryReconnect() {
	// 在实际实现中，这里应该尝试网络重连
	log.Info("尝试重新连接网络")
	
	// 模拟重连结果（成功或失败）
	reconnectSuccess := rand.Intn(2) == 0
	
	if reconnectSuccess {
		nr.mu.Lock()
		nr.currentState = NetworkStateNormal
		nr.mu.Unlock()
		
		// 重置重连重试上下文
		nr.reconnectRetryContext = NewRetryContext(
			20, // 最大尝试次数
			1 * time.Second, // 初始延迟
			30 * time.Minute, // 最大延迟
			RetryStrategyExponential, // 使用指数退避策略
		)
		
		// 调用网络恢复处理
		go nr.onNetworkRecovered()
	} else {
		log.Warn("网络重连失败")
		// 使用重试策略继续尝试
		delay := nr.reconnectRetryContext.CalculateNextRetryDelay()
		if delay > 0 {
			log.Info("计划下次网络重连尝试", 
				"尝试次数", nr.reconnectRetryContext.attempt,
				"延迟", delay,
				"下次尝试时间", nr.reconnectRetryContext.nextRetryTime)
				
			time.AfterFunc(delay, func() {
				// 检查是否已关闭
				select {
				case <-nr.ctx.Done():
					return
				default:
					// 再次尝试重连
					nr.tryReconnect()
				}
			})
		} else {
			log.Error("网络重连尝试次数已达上限，放弃重连")
		}
	}
}

// 批处理任务
func (nr *NetworkResilience) batchProcessor() {
	defer nr.wg.Done()
	
	ticker := time.NewTicker(nr.config.BatchInterval)
	defer ticker.Stop()
	
	for {
		
		select {
		case <-nr.ctx.Done():
			return
			
		case <-ticker.C:
			nr.processPendingBatches()
		}
	}
}

// 处理待处理的批量操作
func (nr *NetworkResilience) processPendingBatches() {
	nr.mu.Lock()
	
	// 如果离线或弱网状态，根据策略决定是否处理
	if nr.currentState == NetworkStateOffline {
		if !nr.config.OfflineMode {
			nr.mu.Unlock()
			return
		}
	} else if nr.currentState == NetworkStateWeak {
		if !nr.config.WeakNetworkTolerance {
			nr.mu.Unlock()
			return
		}
	}
	
	// 复制待处理批次，避免长时间持有锁
	batches := make([]*BatchOperation, 0, len(nr.pendingBatches))
	for _, batch := range nr.pendingBatches {
		batches = append(batches, batch)
	}
	nr.mu.Unlock()
	
	// 按优先级排序批次
	sort.Slice(batches, func(i, j int) bool {
		return batches[i].Priority > batches[j].Priority
	})
	
	// 处理批次
	for _, batch := range batches {
		// 在实际实现中，这里应该处理批次中的所有操作
		// 这里仅作为示例实现
		log.Debug("处理批次", "批次ID", batch.BatchID, "操作数", len(batch.Operations))
		
		// 标记批次为已处理
		nr.mu.Lock()
		delete(nr.pendingBatches, batch.BatchID)
		nr.mu.Unlock()
	}
}

// 超时调整任务
func (nr *NetworkResilience) timeoutAdjuster() {
	defer nr.wg.Done()
	
	// 每5分钟调整一次超时
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-nr.ctx.Done():
			return
			
		case <-ticker.C:
			nr.adjustTimeout()
		}
	}
}

// 调整超时
func (nr *NetworkResilience) adjustTimeout() {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	// 根据网络状态调整超时
	switch nr.currentState {
	case NetworkStateOffline:
		// 离线状态使用最大超时
		nr.currentTimeout = nr.config.MaxTimeout
	case NetworkStateWeak:
		// 弱网状态使用较大超时
		nr.currentTimeout = min(nr.currentTimeout*time.Duration(nr.config.TimeoutMultiplier), nr.config.MaxTimeout)
	case NetworkStateNormal:
		// 正常状态使用默认超时
		baseTimeout := (nr.config.MinTimeout + nr.config.MaxTimeout) / 2
		nr.currentTimeout = max(min(nr.currentTimeout, baseTimeout), nr.config.MinTimeout)
	case NetworkStateStrong:
		// 强网络状态使用最小超时
		nr.currentTimeout = nr.config.MinTimeout
	}
	
	log.Debug("调整超时", "新超时", nr.currentTimeout, "网络状态", nr.currentState)
}

// 交易管理任务
func (nr *NetworkResilience) txManagerTask() {
	defer nr.wg.Done()
	
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-nr.ctx.Done():
			return
			
		case <-ticker.C:
			nr.managePendingTransactions()
		}
	}
}

// 管理待处理交易
func (nr *NetworkResilience) managePendingTransactions() {
	nr.mu.Lock()
	
	// 如果没有待处理交易，直接返回
	if len(nr.pendingTxs) == 0 {
		nr.mu.Unlock()
		return
	}
	
	now := time.Now()
	
	// 检查是否有过期的交易
	expiredHashes := make([]common.Hash, 0)
	for hash, tx := range nr.pendingTxs {
		// 交易超过1小时视为过期
		if now.Sub(tx.SubmitTime) > 1*time.Hour {
			expiredHashes = append(expiredHashes, hash)
		}
	}
	
	// 处理过期的交易
	for _, hash := range expiredHashes {
		tx := nr.pendingTxs[hash]
		delete(nr.pendingTxs, hash)
		
		// 调用回调函数
		if nr.txCallback != nil {
			go nr.txCallback(hash, "expired", errors.New("交易超时"))
		}
		
		log.Warn("交易已过期", "哈希", hash.Hex(), "提交时间", tx.SubmitTime)
	}
	
	// 如果当前网络状态良好，触发交易处理
	if nr.currentState == NetworkStateNormal || nr.currentState == NetworkStateStrong {
		// 复制待处理交易，避免长时间持有锁
		pendingTxs := make([]*PendingTransaction, 0, len(nr.pendingTxs))
		for _, tx := range nr.pendingTxs {
			pendingTxs = append(pendingTxs, tx)
		}
		nr.mu.Unlock()
		
		// 按优先级排序
		sort.Slice(pendingTxs, func(i, j int) bool {
			return pendingTxs[i].Priority > pendingTxs[j].Priority
		})
		
		// 处理待处理交易
		for _, ptx := range pendingTxs {
			nr.processSingleTransaction(ptx)
		}
	} else {
		nr.mu.Unlock()
	}
}

// 处理单个交易
func (nr *NetworkResilience) processSingleTransaction(ptx *PendingTransaction) {
	// 在实际实现中，这里应该将交易发送到区块链网络
	// 这里仅作为示例实现
	
	// 模拟交易发送
	success := true // 模拟发送成功
	
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	// 更新交易状态
	ptx.Attempts++
	ptx.LastAttempt = time.Now()
	
	if success {
		// 交易发送成功
		ptx.Status = "success"
		
		// 从待处理交易中删除
		delete(nr.pendingTxs, ptx.TxHash)
		
		// 增加成功交易计数
		nr.stats.SuccessfulTxCount++
		
		// 调用回调函数
		if nr.txCallback != nil {
			go nr.txCallback(ptx.TxHash, "success", nil)
		}
		
		log.Info("交易发送成功", "哈希", ptx.TxHash.Hex(), "尝试次数", ptx.Attempts)
	} else {
		// 交易发送失败
		ptx.Status = "failed"
		ptx.Error = "发送失败"
		
		// 增加失败交易计数
		nr.stats.FailedTxCount++
		
		// 检查是否需要重试
		if ptx.Attempts < 3 { // 最多重试3次
			ptx.Status = "pending" // 重设为待处理状态
		} else {
			// 从待处理交易中删除
			delete(nr.pendingTxs, ptx.TxHash)
			
			// 调用回调函数
			if nr.txCallback != nil {
				go nr.txCallback(ptx.TxHash, "failed", errors.New(ptx.Error))
			}
		}
		
		log.Warn("交易发送失败", "哈希", ptx.TxHash.Hex(), "尝试次数", ptx.Attempts)
	}
}

// 处理所有待处理交易
func (nr *NetworkResilience) processPendingTransactions() {
	nr.mu.Lock()
	
	// 复制待处理交易，避免长时间持有锁
	pendingTxs := make([]*PendingTransaction, 0, len(nr.pendingTxs))
	for _, tx := range nr.pendingTxs {
		pendingTxs = append(pendingTxs, tx)
	}
	nr.mu.Unlock()
	
	// 按优先级排序
	sort.Slice(pendingTxs, func(i, j int) bool {
		return pendingTxs[i].Priority > pendingTxs[j].Priority
	})
	
	// 处理所有待处理交易
	for _, ptx := range pendingTxs {
		nr.processSingleTransaction(ptx)
		
		// 避免过快发送，给网络一些缓冲时间
		time.Sleep(100 * time.Millisecond)
	}
}

// 恢复所有下载
func (nr *NetworkResilience) resumeAllDownloads() {
	nr.mu.Lock()
	
	// 复制下载信息，避免长时间持有锁
	downloads := make([]*ResumeDownloadInfo, 0, len(nr.resumeDownloads))
	for _, dl := range nr.resumeDownloads {
		downloads = append(downloads, dl)
	}
	nr.mu.Unlock()
	
	// 恢复所有下载
	for _, dl := range downloads {
		// 在实际实现中，这里应该恢复下载
		// 这里仅作为示例实现
		log.Info("恢复下载", "资源ID", dl.ResourceID, "类型", dl.ResourceType, "已下载", dl.DownloadedSize, "总大小", dl.TotalSize)
		
		// 更新下载状态
		dl.Status = "downloading"
		dl.LastUpdate = time.Now()
	}
}

// 缓存清理任务
func (nr *NetworkResilience) cacheCleanupTask() {
	defer nr.wg.Done()
	
	// 每小时清理一次缓存
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-nr.ctx.Done():
			return
			
		case <-ticker.C:
			nr.cleanupCache()
		}
	}
}

// 清理缓存
func (nr *NetworkResilience) cleanupCache() {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	now := time.Now()
	
	// 清理数据缓存
	for key := range nr.dataCache {
		// 在实际实现中，这里应该检查缓存项的创建时间
		// 这里简化处理，随机删除一些缓存项
		if rand.Intn(10) < 3 { // 30%概率删除
			delete(nr.dataCache, key)
		}
	}
	
	// 清理交易缓存
	for hash, tx := range nr.txCache {
		// 清理超过1天的交易缓存
		if tx.Time().Add(24 * time.Hour).Before(now) {
			delete(nr.txCache, hash)
		}
	}
	
	log.Debug("缓存已清理", 
		"数据缓存", len(nr.dataCache), 
		"交易缓存", len(nr.txCache))
}

// SubmitTransaction 提交交易
func (nr *NetworkResilience) SubmitTransaction(tx *types.Transaction, priority int) (common.Hash, error) {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	hash := tx.Hash()
	
	// 检查交易是否已存在
	if _, exists := nr.pendingTxs[hash]; exists {
		return hash, errors.New("交易已存在")
	}
	
	// 创建待处理交易
	ptx := &PendingTransaction{
		TxHash:        hash,
		Tx:            tx,
		SubmitTime:    time.Now(),
		Priority:      priority,
		Attempts:      0,
		Status:        "pending",
		DataSize:      estimateTxSize(tx),
	}
	
	// 根据网络状态和优先级决定传输策略
	if nr.currentState == NetworkStateOffline {
		// 离线状态，延迟处理
		ptx.TransferPolicy = TransferPolicyDeferred
		nr.stats.DeferredTxCount++
	} else if nr.currentState == NetworkStateWeak && priority < TxPriorityCritical {
		// 弱网状态，非关键交易批量处理
		ptx.TransferPolicy = TransferPolicyBatched
	} else {
		// 正常状态或关键交易，立即处理
		ptx.TransferPolicy = TransferPolicyRealtime
	}
	
	// 添加到待处理交易
	nr.pendingTxs[hash] = ptx
	
	// 添加到交易缓存
	nr.txCache[hash] = tx
	
	log.Info("提交交易", 
		"哈希", hash.Hex(), 
		"优先级", priority, 
		"传输策略", ptx.TransferPolicy,
		"网络状态", nr.currentState)
	
	// 如果是实时策略且网络状态良好，立即处理
	if ptx.TransferPolicy == TransferPolicyRealtime && 
		(nr.currentState == NetworkStateNormal || nr.currentState == NetworkStateStrong) {
		go nr.processSingleTransaction(ptx)
		return hash, nil
	}
	
	// 如果是批量策略，添加到批次
	if ptx.TransferPolicy == TransferPolicyBatched && nr.config.BatchingEnabled {
		// 查找或创建合适的批次
		batchID := fmt.Sprintf("batch-%d", time.Now().Unix()/int64(nr.config.BatchInterval.Seconds()))
		var batch *BatchOperation
		
		if b, exists := nr.pendingBatches[batchID]; exists {
			batch = b
		} else {
			batch = &BatchOperation{
				BatchID:       batchID,
				Operations:    make([]interface{}, 0),
				CreateTime:    time.Now(),
				ScheduledTime: time.Now().Add(nr.config.BatchInterval),
				Status:        "pending",
				Priority:      priority,
			}
			nr.pendingBatches[batchID] = batch
		}
		
		// 添加交易到批次
		batch.Operations = append(batch.Operations, ptx)
		
		// 更新批次优先级
		if priority > batch.Priority {
			batch.Priority = priority
		}
	}
	
	return hash, nil
}

// SetStateChangeCallback 设置状态变更回调
func (nr *NetworkResilience) SetStateChangeCallback(callback func(oldState, newState string)) {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	nr.stateChangeCallback = callback
}

// SetTxCallback 设置交易回调
func (nr *NetworkResilience) SetTxCallback(callback func(txHash common.Hash, status string, err error)) {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	nr.txCallback = callback
}

// GetNetworkStats 获取网络统计
func (nr *NetworkResilience) GetNetworkStats() NetworkStats {
	nr.mu.RLock()
	defer nr.mu.RUnlock()
	
	// 返回副本
	stats := nr.stats
	stats.ConnectionUptime = time.Since(nr.stats.LastStateChange)
	
	return stats
}

// GetCurrentTimeout 获取当前超时
func (nr *NetworkResilience) GetCurrentTimeout() time.Duration {
	nr.mu.RLock()
	defer nr.mu.RUnlock()
	
	return nr.currentTimeout
}

// GetPendingTransactionCount 获取待处理交易数量
func (nr *NetworkResilience) GetPendingTransactionCount() int {
	nr.mu.RLock()
	defer nr.mu.RUnlock()
	
	return len(nr.pendingTxs)
}

// CacheData 缓存数据
func (nr *NetworkResilience) CacheData(key string, data []byte) {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	// 压缩数据
	compressed := compressData(data, nr.config.DataCompressionLevel)
	
	// 存储压缩后的数据
	nr.dataCache[key] = compressed
}

// GetCachedData 获取缓存数据
func (nr *NetworkResilience) GetCachedData(key string) ([]byte, bool) {
	nr.mu.RLock()
	defer nr.mu.RUnlock()
	
	data, exists := nr.dataCache[key]
	if !exists {
		return nil, false
	}
	
	// 解压数据
	decompressed := decompressData(data)
	
	return decompressed, true
}

// StartResumeDownload 启动断点续传下载
func (nr *NetworkResilience) StartResumeDownload(resourceID, resourceType, url string, totalSize int64) (*ResumeDownloadInfo, error) {
	if !nr.config.ResumeDownload {
		return nil, errors.New("断点续传未启用")
	}
	
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	// 检查是否已存在该下载
	if dl, exists := nr.resumeDownloads[resourceID]; exists {
		return dl, nil
	}
	
	// 创建下载信息
	dl := &ResumeDownloadInfo{
		ResourceID:     resourceID,
		ResourceType:   resourceType,
		URL:            url,
		TotalSize:      totalSize,
		DownloadedSize: 0,
		StartTime:      time.Now(),
		LastUpdate:     time.Now(),
		ChunkStatus:    make(map[int]bool),
		Status:         "started",
	}
	
	// 添加到下载映射
	nr.resumeDownloads[resourceID] = dl
	
	log.Info("启动断点续传下载", 
		"资源ID", resourceID, 
		"类型", resourceType, 
		"大小", totalSize)
	
	return dl, nil
}

// UpdateDownloadProgress 更新下载进度
func (nr *NetworkResilience) UpdateDownloadProgress(resourceID string, chunkIndex int, chunkSize int64) error {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	// 检查下载是否存在
	dl, exists := nr.resumeDownloads[resourceID]
	if !exists {
		return fmt.Errorf("下载 %s 不存在", resourceID)
	}
	
	// 更新分片状态
	dl.ChunkStatus[chunkIndex] = true
	
	// 更新已下载大小
	dl.DownloadedSize += chunkSize
	if dl.DownloadedSize > dl.TotalSize {
		dl.DownloadedSize = dl.TotalSize
	}
	
	// 更新最后更新时间
	dl.LastUpdate = time.Now()
	
	// 检查是否下载完成
	if dl.DownloadedSize >= dl.TotalSize {
		dl.Status = "completed"
		
		// 从下载映射中删除
		delete(nr.resumeDownloads, resourceID)
		
		log.Info("下载已完成", "资源ID", resourceID)
	}
	
	return nil
}

// GetDownloadInfo 获取下载信息
func (nr *NetworkResilience) GetDownloadInfo(resourceID string) (*ResumeDownloadInfo, error) {
	nr.mu.RLock()
	defer nr.mu.RUnlock()
	
	dl, exists := nr.resumeDownloads[resourceID]
	if !exists {
		return nil, fmt.Errorf("下载 %s 不存在", resourceID)
	}
	
	// 返回副本
	infoCopy := *dl
	return &infoCopy, nil
}

// 估计交易大小
func estimateTxSize(tx *types.Transaction) int {
	// 在实际实现中，这里应该准确计算交易大小
	// 这里简化处理，返回固定大小
	return 256
}

// 压缩数据
func compressData(data []byte, level int) []byte {
	// 在实际实现中，这里应该使用真实的压缩算法
	// 这里仅作为示例实现
	return data
}

// 解压数据
func decompressData(data []byte) []byte {
	// 在实际实现中，这里应该使用真实的解压算法
	// 这里仅作为示例实现
	return data
}

// 工具函数 - min
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// 工具函数 - max
func max(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// runLocalP2P 运行本地P2P - 新增
func (nr *NetworkResilience) runLocalP2P() {
	defer nr.wg.Done()
	
	log.Info("本地P2P组网已启动", 
		"连接类型", nr.config.LocalP2PConfig.ConnectionTypes,
		"最大节点", nr.config.LocalP2PConfig.MaxPeers)
	
	// 初始化本地P2P
	if err := nr.initLocalP2P(); err != nil {
		log.Error("初始化本地P2P失败", "错误", err)
		return
	}
	
	// 创建发现定时器
	nr.discoveryTicker = time.NewTicker(nr.config.LocalP2PConfig.DiscoveryInterval)
	defer nr.discoveryTicker.Stop()
	
	// 创建心跳定时器
	nr.heartbeatTicker = time.NewTicker(nr.config.LocalP2PConfig.HeartbeatInterval)
	defer nr.heartbeatTicker.Stop()
	
	// 设置P2P活跃状态
	nr.mu.Lock()
	nr.localP2PActive = true
	nr.mu.Unlock()
	
	// 运行本地P2P循环
	for {
		select {
		case <-nr.ctx.Done():
			// 关闭本地P2P
			nr.shutdownLocalP2P()
			return
			
		case <-nr.discoveryTicker.C:
			// 发现对等节点
			nr.discoverLocalPeers()
			
		case <-nr.heartbeatTicker.C:
			// 发送心跳
			nr.sendHeartbeats()
			
			// 清理过期节点
			nr.cleanupExpiredPeers()
		}
	}
}

// initLocalP2P 初始化本地P2P - 新增
func (nr *NetworkResilience) initLocalP2P() error {
	// 在实际实现中，这里应该初始化不同类型的P2P连接
	// 例如：蓝牙、WiFi直连、局域网等
	
	for _, connType := range nr.config.LocalP2PConfig.ConnectionTypes {
		switch connType {
		case LocalP2PTypeBluetooth:
			if err := nr.initBluetooth(); err != nil {
				log.Warn("初始化蓝牙连接失败", "错误", err)
				// 继续其他连接类型
			}
		case LocalP2PTypeWifiDirect:
			if err := nr.initWifiDirect(); err != nil {
				log.Warn("初始化WiFi直连失败", "错误", err)
				// 继续其他连接类型
			}
		case LocalP2PTypeLAN:
			if err := nr.initLAN(); err != nil {
				log.Warn("初始化局域网连接失败", "错误", err)
				// 继续其他连接类型
			}
		}
	}
	
	return nil
}

// initBluetooth 初始化蓝牙连接 - 新增
func (nr *NetworkResilience) initBluetooth() error {
	// 在实际实现中，这里应该初始化蓝牙连接
	// 这里仅作为示例实现
	log.Info("初始化蓝牙连接")
	return nil
}

// initWifiDirect 初始化WiFi直连 - 新增
func (nr *NetworkResilience) initWifiDirect() error {
	// 在实际实现中，这里应该初始化WiFi直连
	// 这里仅作为示例实现
	log.Info("初始化WiFi直连")
	return nil
}

// initLAN 初始化局域网连接 - 新增
func (nr *NetworkResilience) initLAN() error {
	// 在实际实现中，这里应该初始化局域网连接
	// 这里仅作为示例实现
	log.Info("初始化局域网连接")
	return nil
}

// discoverLocalPeers 发现本地对等节点 - 新增
func (nr *NetworkResilience) discoverLocalPeers() {
	log.Debug("开始发现本地对等节点")
	
	// 在实际实现中，这里应该扫描不同类型的对等节点
	
	// 模拟发现新的对等节点
	for _, connType := range nr.config.LocalP2PConfig.ConnectionTypes {
		newPeers, err := nr.scanForPeers(connType)
		if err != nil {
			log.Warn("扫描对等节点失败", "类型", connType, "错误", err)
			continue
		}
		
		// 处理新发现的对等节点
		for _, peer := range newPeers {
			nr.handleDiscoveredPeer(peer)
		}
	}
}

// scanForPeers 扫描对等节点 - 新增
func (nr *NetworkResilience) scanForPeers(connType string) ([]*LocalPeerInfo, error) {
	// 在实际实现中，这里应该根据连接类型扫描对等节点
	// 这里仅作为示例实现
	
	peers := make([]*LocalPeerInfo, 0)
	
	// 模拟找到一个新的随机节点 (1/5的概率)
	if rand.Intn(5) == 0 {
		peer := &LocalPeerInfo{
			PeerID:         fmt.Sprintf("peer-%s-%d", connType, rand.Intn(1000)),
			DeviceID:       fmt.Sprintf("device-%d", rand.Intn(1000)),
			DeviceName:     fmt.Sprintf("Device-%s-%d", connType, rand.Intn(100)),
			ConnectionType: connType,
			Address:        fmt.Sprintf("addr-%d", rand.Intn(1000)),
			ConnectedAt:    time.Now(),
			LastSeen:       time.Now(),
			Latency:        time.Duration(rand.Intn(100)) * time.Millisecond,
			IsActive:       true,
			Capabilities:   []string{"tx_relay", "data_relay"},
			TxRelayEnabled: true,
			DataRelayEnabled: true,
		}
		peers = append(peers, peer)
	}
	
	return peers, nil
}

// handleDiscoveredPeer 处理发现的对等节点 - 新增
func (nr *NetworkResilience) handleDiscoveredPeer(peer *LocalPeerInfo) {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	// 检查是否已存在
	if existingPeer, exists := nr.localPeers[peer.PeerID]; exists {
		// 更新现有节点信息
		existingPeer.LastSeen = time.Now()
		existingPeer.Latency = peer.Latency
		existingPeer.IsActive = true
		log.Debug("更新现有对等节点", "ID", peer.PeerID, "类型", peer.ConnectionType)
		return
	}
	
	// 检查是否达到最大节点数量
	if len(nr.localPeers) >= nr.config.LocalP2PConfig.MaxPeers {
		log.Debug("达到最大对等节点数量，忽略新节点", "ID", peer.PeerID)
		return
	}
	
	// 检查是否在黑名单中
	for _, blacklisted := range nr.config.LocalP2PConfig.BlacklistedPeers {
		if peer.PeerID == blacklisted || peer.DeviceID == blacklisted {
			log.Debug("忽略黑名单对等节点", "ID", peer.PeerID)
			return
		}
	}
	
	// 如果只允许可信节点且不在可信列表中
	if nr.config.LocalP2PConfig.TrustedPeersOnly {
		trusted := false
		for _, trustedID := range nr.config.LocalP2PConfig.TrustedPeers {
			if peer.PeerID == trustedID || peer.DeviceID == trustedID {
				trusted = true
				break
			}
		}
		
		if !trusted {
			log.Debug("忽略非可信对等节点", "ID", peer.PeerID)
			return
		}
	}
	
	// 添加新节点
	nr.localPeers[peer.PeerID] = peer
	log.Info("发现新对等节点", 
		"ID", peer.PeerID, 
		"名称", peer.DeviceName,
		"类型", peer.ConnectionType,
		"延迟", peer.Latency)
	
	// 如果自动连接启用，尝试连接
	if nr.config.LocalP2PConfig.AutoConnect {
		go nr.connectToPeer(peer)
	}
}

// connectToPeer 连接到对等节点 - 新增
func (nr *NetworkResilience) connectToPeer(peer *LocalPeerInfo) {
	// 在实际实现中，这里应该建立实际的连接
	// 这里仅作为示例实现
	log.Debug("连接到对等节点", "ID", peer.PeerID, "类型", peer.ConnectionType)
	
	// 假设连接成功，更新状态
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	if p, exists := nr.localPeers[peer.PeerID]; exists {
		p.IsActive = true
		p.LastSeen = time.Now()
	}
}

// sendHeartbeats 发送心跳 - 新增
func (nr *NetworkResilience) sendHeartbeats() {
	nr.mu.RLock()
	peers := make([]*LocalPeerInfo, 0, len(nr.localPeers))
	for _, peer := range nr.localPeers {
		if peer.IsActive {
			peers = append(peers, peer)
		}
	}
	nr.mu.RUnlock()
	
	for _, peer := range peers {
		if err := nr.sendHeartbeat(peer); err != nil {
			log.Warn("发送心跳失败", "对等节点", peer.PeerID, "错误", err)
			
			// 标记节点可能不活跃
			nr.mu.Lock()
			if p, exists := nr.localPeers[peer.PeerID]; exists {
				p.IsActive = false
			}
			nr.mu.Unlock()
		}
	}
}

// sendHeartbeat 发送心跳到单个节点 - 新增
func (nr *NetworkResilience) sendHeartbeat(peer *LocalPeerInfo) error {
	// 在实际实现中，这里应该发送实际的心跳
	// 这里仅作为示例实现
	
	// 随机模拟失败 (1/10的概率)
	if rand.Intn(10) == 0 {
		return errors.New("模拟心跳失败")
	}
	
	// 更新节点状态
	nr.mu.Lock()
	if p, exists := nr.localPeers[peer.PeerID]; exists {
		p.LastSeen = time.Now()
		// 模拟延迟变化
		p.Latency = time.Duration(50+rand.Intn(100)) * time.Millisecond
	}
	nr.mu.Unlock()
	
	return nil
}

// cleanupExpiredPeers 清理过期节点 - 新增
func (nr *NetworkResilience) cleanupExpiredPeers() {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	now := time.Now()
	timeout := nr.config.LocalP2PConfig.KeepAliveTimeout
	
	for id, peer := range nr.localPeers {
		// 如果节点最后见到时间超过超时时间，移除节点
		if now.Sub(peer.LastSeen) > timeout {
			log.Info("移除过期对等节点", 
				"ID", id, 
				"名称", peer.DeviceName,
				"最后见到", peer.LastSeen)
			delete(nr.localPeers, id)
		}
	}
}

// shutdownLocalP2P 关闭本地P2P - 新增
func (nr *NetworkResilience) shutdownLocalP2P() {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	// 关闭所有连接
	for _, peer := range nr.localPeers {
		peer.IsActive = false
	}
	
	nr.localP2PActive = false
	log.Info("本地P2P组网已关闭")
}

// RelayTransaction 中继交易 - 新增
func (nr *NetworkResilience) RelayTransaction(tx *types.Transaction) error {
	if !nr.config.LocalP2PEnabled || nr.config.LocalP2PConfig == nil || !nr.config.LocalP2PConfig.TxRelay {
		return errors.New("交易中继未启用")
	}
	
	nr.mu.RLock()
	isActive := nr.localP2PActive
	nr.mu.RUnlock()
	
	if !isActive {
		return errors.New("本地P2P未启动")
	}
	
	txHash := tx.Hash()
	
	// 检查是否已经中继过
	nr.mu.Lock()
	if _, exists := nr.relayTxs[txHash]; exists {
		nr.mu.Unlock()
		return nil // 已经中继过，直接返回
	}
	
	// 添加到中继交易
	nr.relayTxs[txHash] = time.Now()
	nr.mu.Unlock()
	
	// 获取活跃对等节点
	nr.mu.RLock()
	activePeers := make([]*LocalPeerInfo, 0)
	for _, peer := range nr.localPeers {
		if peer.IsActive && peer.TxRelayEnabled {
			activePeers = append(activePeers, peer)
		}
	}
	nr.mu.RUnlock()
	
	// 发送交易到所有活跃节点
	for _, peer := range activePeers {
		go nr.sendTransactionToPeer(tx, peer)
	}
	
	log.Debug("交易已中继到本地网络", 
		"哈希", txHash.Hex(), 
		"节点数", len(activePeers))
	
	return nil
}

// sendTransactionToPeer 发送交易到对等节点 - 新增
func (nr *NetworkResilience) sendTransactionToPeer(tx *types.Transaction, peer *LocalPeerInfo) {
	// 在实际实现中，这里应该发送实际的交易
	// 这里仅作为示例实现
	
	log.Debug("发送交易到对等节点", 
		"交易哈希", tx.Hash().Hex(), 
		"节点", peer.PeerID)
	
	// 模拟发送成功或失败
	if rand.Intn(10) == 0 {
		log.Warn("发送交易到对等节点失败", 
			"交易哈希", tx.Hash().Hex(), 
			"节点", peer.PeerID)
	}
}

// GetLocalPeers 获取本地对等节点 - 新增
func (nr *NetworkResilience) GetLocalPeers() []*LocalPeerInfo {
	nr.mu.RLock()
	defer nr.mu.RUnlock()
	
	peers := make([]*LocalPeerInfo, 0, len(nr.localPeers))
	for _, peer := range nr.localPeers {
		peers = append(peers, peer)
	}
	
	return peers
}

// GetLocalP2PStats 获取本地P2P统计 - 新增
func (nr *NetworkResilience) GetLocalP2PStats() map[string]interface{} {
	nr.mu.RLock()
	defer nr.mu.RUnlock()
	
	stats := make(map[string]interface{})
	
	// 基本信息
	stats["enabled"] = nr.config.LocalP2PEnabled
	stats["active"] = nr.localP2PActive
	stats["peer_count"] = len(nr.localPeers)
	
	// 活跃对等节点数量
	activePeers := 0
	for _, peer := range nr.localPeers {
		if peer.IsActive {
			activePeers++
		}
	}
	stats["active_peers"] = activePeers
	
	// 连接类型统计
	connectionTypes := make(map[string]int)
	for _, peer := range nr.localPeers {
		connectionTypes[peer.ConnectionType] = connectionTypes[peer.ConnectionType] + 1
	}
	stats["connection_types"] = connectionTypes
	
	// 中继统计
	stats["relayed_tx_count"] = len(nr.relayTxs)
	stats["relayed_data_count"] = len(nr.relayData)
	
	return stats
}

// SetChainAdapter 设置链适配器
func (nr *NetworkResilience) SetChainAdapter(adapter ChainAdapter) {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	nr.chainAdapter = adapter
	log.Info("网络弹性模块设置链适配器", "chainType", adapter.GetChainType().String())
}

// NetworkAwareSendTransaction 网络感知的交易发送
// 根据当前网络状态智能处理交易提交
func (nr *NetworkResilience) NetworkAwareSendTransaction(to string, amount *big.Int, data []byte, priority int) (string, error) {
	if nr.chainAdapter == nil {
		return "", errors.New("链适配器未设置")
	}

	nr.mu.RLock()
	currentState := nr.currentState
	nr.mu.RUnlock()
	
	// 创建交易对象（由于我们没有直接访问types.Transaction的创建，所以这里简化处理）
	txHashStr := ""
	var err error
	
	// 根据网络状态选择不同的处理策略
	switch currentState {
	case NetworkStateNormal, NetworkStateStrong:
		// 强网或正常网络，直接发送
		log.Info("网络状态良好，直接发送交易", "to", to, "priority", priority)
		txHashStr, err = nr.chainAdapter.SendTransaction(to, amount, data)
		
	case NetworkStateWeak:
		// 弱网环境，根据优先级决定是直接发送还是本地中继
		if priority >= TxPriorityHigh {
			// 高优先级交易，尝试直接发送
			log.Info("弱网环境下发送高优先级交易", "to", to, "priority", priority)
			txHashStr, err = nr.chainAdapter.SendTransaction(to, amount, data)
		} else if nr.config.LocalP2PEnabled && nr.localP2PActive {
			// 低优先级交易，如果本地P2P可用，尝试通过P2P网络中继
			log.Info("弱网环境下通过本地P2P中继低优先级交易", "to", to, "priority", priority)
			
			// 先尝试通过本地P2P发送
			// 注意：这里需要实际实现通过P2P中继交易的逻辑
			// 简化处理，创建一个待处理交易
			dummyTx := &types.Transaction{}
			txHash := dummyTx.Hash()
			
			pendingTx := &PendingTransaction{
				TxHash:        txHash,
				Tx:            dummyTx,
				SubmitTime:    time.Now(),
				Priority:      priority,
				Attempts:      0,
				Status:        "pending",
				TransferPolicy: TransferPolicyDeferred,
			}
			
			nr.mu.Lock()
			nr.pendingTxs[txHash] = pendingTx
			nr.mu.Unlock()
			
			// 使用交易哈希作为临时返回值
			txHashStr = txHash.Hex()
		} else {
			// 无本地P2P，仍然尝试发送，但设置更长的超时
			log.Info("弱网环境下发送低优先级交易，延长超时", "to", to, "priority", priority)
			
			// 这里可以设置更长的超时，但简化处理
			txHashStr, err = nr.chainAdapter.SendTransaction(to, amount, data)
		}
		
	case NetworkStateOffline:
		// 离线状态，存储交易稍后发送
		log.Info("网络离线，将交易存储待后续处理", "to", to, "priority", priority)
		
		// 创建待处理交易
		dummyTx := &types.Transaction{}
		txHash := dummyTx.Hash()
		
		pendingTx := &PendingTransaction{
			TxHash:        txHash,
			Tx:            dummyTx,
			SubmitTime:    time.Now(),
			Priority:      priority,
			Attempts:      0,
			Status:        "pending",
			TransferPolicy: TransferPolicyDeferred,
		}
		
		nr.mu.Lock()
		nr.pendingTxs[txHash] = pendingTx
		nr.mu.Unlock()
		
		// 使用交易哈希作为临时返回值
		txHashStr = txHash.Hex()
		
	default:
		// 未知状态，暂时默认直接发送
		log.Info("未知网络状态，尝试直接发送交易", "state", currentState, "to", to)
		txHashStr, err = nr.chainAdapter.SendTransaction(to, amount, data)
	}
	
	if err != nil {
		log.Error("交易发送失败", "error", err, "state", currentState)
		return "", err
	}
	
	return txHashStr, nil
}

// GetAdapterNetworkStats 获取适配器网络状态统计
func (nr *NetworkResilience) GetAdapterNetworkStats() map[string]interface{} {
	if nr.chainAdapter == nil {
		return map[string]interface{}{
			"error": "链适配器未设置",
		}
	}
	
	stats := make(map[string]interface{})
	
	// 获取基本链信息
	stats["chainType"] = nr.chainAdapter.GetChainType().String()
	stats["chainID"] = nr.chainAdapter.GetChainID()
	stats["isConnected"] = nr.chainAdapter.IsConnected()
	
	// 获取网络统计信息
	nr.mu.RLock()
	stats["networkState"] = nr.currentState
	stats["pendingTxCount"] = len(nr.pendingTxs)
	stats["localP2PActive"] = nr.localP2PActive
	nr.mu.RUnlock()
	
	// 如果已连接，获取更多连接信息
	if nr.chainAdapter.IsConnected() {
		connectionInfo := nr.chainAdapter.GetConnectionInfo()
		for k, v := range connectionInfo {
			stats["connection_"+k] = v
		}
	}
	
	return stats
}

// startBackgroundTasks 启动后台任务
func (nr *NetworkResilience) startBackgroundTasks() {
	// 启动定期处理待处理交易的任务
	nr.wg.Add(1)
	go func() {
		defer nr.wg.Done()
		
		ticker := time.NewTicker(30 * time.Second) // 每30秒处理一次
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				nr.ProcessPendingTransactions()
			case <-nr.ctx.Done():
				return
			}
		}
	}()
	
	// 启动网络状态监控的任务
	nr.wg.Add(1)
	go func() {
		defer nr.wg.Done()
		
		ticker := time.NewTicker(nr.config.NetworkCheckInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				nr.checkNetworkState()
			case <-nr.ctx.Done():
				return
			}
		}
	}()
	
	// 如果启用了本地P2P，启动P2P维护任务
	if nr.config.LocalP2PEnabled {
		nr.wg.Add(1)
		go func() {
			defer nr.wg.Done()
			
			ticker := time.NewTicker(5 * time.Minute) // 每5分钟维护一次P2P网络
			defer ticker.Stop()
			
			for {
				select {
				case <-ticker.C:
					nr.maintainP2PNetwork()
				case <-nr.ctx.Done():
					return
				}
			}
		}()
	}
}

// ProcessPendingTransactions 处理待处理交易
func (nr *NetworkResilience) ProcessPendingTransactions() {
	// 如果链适配器未设置，则无法处理
	if nr.chainAdapter == nil {
		log.Warn("处理待处理交易失败：链适配器未设置")
		return
	}
	
	// 确认当前网络状态
	nr.mu.RLock()
	currentState := nr.currentState
	isP2PActive := nr.localP2PActive
	nr.mu.RUnlock()
	
	// 如果网络离线，则不处理
	if currentState == NetworkStateOffline {
		log.Debug("网络离线，暂不处理待处理交易")
		return
	}
	
	// 获取待处理交易列表
	var pendingList []*PendingTransaction
	nr.mu.RLock()
	for _, tx := range nr.pendingTxs {
		pendingList = append(pendingList, tx)
	}
	nr.mu.RUnlock()
	
	if len(pendingList) == 0 {
		return
	}
	
	log.Info("开始处理待处理交易", "数量", len(pendingList), "网络状态", currentState)
	
	// 按优先级排序
	sort.Slice(pendingList, func(i, j int) bool {
		return pendingList[i].Priority > pendingList[j].Priority
	})
	
	// 处理交易
	for _, pendingTx := range pendingList {
		// 如果已经成功，跳过
		if pendingTx.Status == "success" {
			continue
		}
		
		// 检查交易是否过期
		if time.Since(pendingTx.SubmitTime) > nr.config.MaxTxLifetime {
			nr.mu.Lock()
			pendingTx.Status = "expired"
			if nr.txCallback != nil {
				nr.txCallback(pendingTx.TxHash, "expired", errors.New("交易已过期"))
			}
			delete(nr.pendingTxs, pendingTx.TxHash)
			nr.mu.Unlock()
			continue
		}
		
		// 根据网络状态和优先级决定是否发送
		shouldSend := false
		
		switch currentState {
		case NetworkStateNormal, NetworkStateStrong:
			// 正常或强网络状态，处理所有交易
			shouldSend = true
		case NetworkStateWeak:
			// 弱网络状态，只处理高优先级交易
			if pendingTx.Priority >= TxPriorityMedium {
				shouldSend = true
			} else if isP2PActive && nr.config.LocalP2PEnabled {
				// 低优先级交易，如果本地P2P活跃，则通过P2P中继
				nr.relayTransactionViaP2P(pendingTx)
				continue
			}
		}
		
		if !shouldSend {
			continue
		}
		
		// 发送交易
		log.Info("发送待处理交易", "交易哈希", pendingTx.TxHash.Hex(), "优先级", pendingTx.Priority)
		
		// 我们这里假设pendingTx.Tx中有足够的信息来重建交易
		// 实际实现中可能需要从pendingTx中提取交易的详细信息
		// 简化实现：使用chainAdapter直接发送交易
		txHash, err := nr.chainAdapter.SendRawTransaction(pendingTx.Tx.Hash().Hex())
		
		nr.mu.Lock()
		pendingTx.Attempts++
		
		if err != nil {
			pendingTx.LastError = err.Error()
			log.Warn("发送待处理交易失败", "交易哈希", pendingTx.TxHash.Hex(), "尝试次数", pendingTx.Attempts, "错误", err)
			
			// 如果达到最大尝试次数，标记为失败
			if pendingTx.Attempts >= nr.config.MaxTxAttempts {
				pendingTx.Status = "failed"
				if nr.txCallback != nil {
					nr.txCallback(pendingTx.TxHash, "failed", err)
				}
				delete(nr.pendingTxs, pendingTx.TxHash)
			}
		} else {
			log.Info("待处理交易发送成功", "交易哈希", pendingTx.TxHash.Hex(), "链上哈希", txHash)
			pendingTx.Status = "success"
			pendingTx.ChainTxHash = common.HexToHash(txHash)
			
			if nr.txCallback != nil {
				nr.txCallback(pendingTx.TxHash, "success", nil)
			}
			
			// 成功后从待处理列表中移除
			delete(nr.pendingTxs, pendingTx.TxHash)
		}
		nr.mu.Unlock()
	}
}

// relayTransactionViaP2P 通过P2P中继交易
func (nr *NetworkResilience) relayTransactionViaP2P(tx *PendingTransaction) {
	// 此处应实现通过本地P2P网络中继交易的逻辑
	// 简化实现，只记录日志
	log.Info("通过本地P2P中继交易", "交易哈希", tx.TxHash.Hex())
	
	nr.mu.Lock()
	nr.relayTxs[tx.TxHash] = time.Now()
	nr.mu.Unlock()
	
	// 实际实现应该包括:
	// 1. 序列化交易
	// 2. 广播到本地P2P网络
	// 3. 跟踪中继状态
}

// checkNetworkState 检查网络状态
func (nr *NetworkResilience) checkNetworkState() {
	// 实现网络状态检查逻辑
	// 这里可以根据需要添加更多的检查逻辑
	log.Info("检查网络状态")
}

// maintainP2PNetwork 维护P2P网络
func (nr *NetworkResilience) maintainP2PNetwork() {
	// 实现P2P网络维护逻辑
	// 这里可以根据需要添加更多的维护逻辑
	log.Info("维护本地P2P网络")
}

// NetworkAdaptiveness 网络适应性分析结果
type NetworkAdaptiveness struct {
	CurrentNetworkType    string    // 当前网络类型（以太坊主网、测试网等）
	ConnectionStability   float64   // 连接稳定性评分（0-1）
	LatencyScore          float64   // 延迟评分（0-1，越高越好）
	BandwidthScore        float64   // 带宽评分（0-1，越高越好）
	ErrorRate             float64   // 错误率
	TxCountLast24h        int       // 过去24小时交易数量
	AvgConfirmationTime   float64   // 平均确认时间（秒）
	RecommendedGasPrice   *big.Int  // 推荐的gas价格
	RecommendedGasLimit   uint64    // 推荐的gas限制
	OptimalBatchSize      int       // 最优批处理大小
	BatchingRecommended   bool      // 是否推荐批处理
	LastUpdated           time.Time // 最后更新时间
	NetworkTrend          string    // 网络趋势（改善、稳定、恶化）
}

// chainIDInfo 链ID信息
type chainIDInfo struct {
	ChainID       *big.Int   // 链ID
	NetworkName   string     // 网络名称
	LastDetected  time.Time  // 最后检测时间
	IsTestnet     bool       // 是否为测试网
}

// DetectChainID 检测当前连接的区块链网络的链ID
func (nr *NetworkResilience) DetectChainID() (*chainIDInfo, error) {
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	// 检查链适配器是否已设置
	if nr.chainAdapter == nil {
		return nil, errors.New("链适配器未初始化")
	}
	
	// 获取链ID
	chainID, err := nr.chainAdapter.GetChainID()
	if err != nil {
		log.Error("无法获取链ID", "错误", err)
		return nil, err
	}
	
	// 获取网络名称
	networkName := nr.getNetworkNameByID(chainID)
	isTestnet := nr.isTestnet(chainID)
	
	// 创建并保存chainIDInfo
	info := &chainIDInfo{
		ChainID:      chainID,
		NetworkName:  networkName,
		LastDetected: time.Now(),
		IsTestnet:    isTestnet,
	}
	
	nr.chainInfo = info
	
	log.Info("检测到网络", "chainID", chainID, "网络名称", networkName, "是否测试网", isTestnet)
	return info, nil
}

// getNetworkNameByID 根据链ID获取网络名称
func (nr *NetworkResilience) getNetworkNameByID(chainID *big.Int) string {
	// 根据常见的链ID映射网络名称
	switch chainID.Int64() {
	case 1:
		return "以太坊主网"
	case 5:
		return "Goerli测试网"
	case 11155111:
		return "Sepolia测试网"
	case 56:
		return "币安智能链"
	case 137:
		return "Polygon"
	case 42161:
		return "Arbitrum One"
	case 10:
		return "Optimism"
	case 100:
		return "Gnosis Chain"
	default:
		return fmt.Sprintf("未知网络(%s)", chainID.String())
	}
}

// isTestnet 判断是否为测试网
func (nr *NetworkResilience) isTestnet(chainID *big.Int) bool {
	// 主要测试网的链ID列表
	testnetIDs := map[int64]bool{
		3:        true, // Ropsten
		4:        true, // Rinkeby
		5:        true, // Goerli
		42:       true, // Kovan
		11155111: true, // Sepolia
		97:       true, // BSC Testnet
		80001:    true, // Mumbai (Polygon Testnet)
		421613:   true, // Arbitrum Goerli
		420:      true, // Optimism Goerli
		1337:     true, // 本地开发网络
		31337:    true, // Hardhat 本地网络
	}
	
	return testnetIDs[chainID.Int64()]
}

// AnalyzeNetworkAdaptiveness 分析网络适应性并提供优化建议
func (nr *NetworkResilience) AnalyzeNetworkAdaptiveness() (*NetworkAdaptiveness, error) {
	nr.mu.RLock()
	defer nr.mu.RUnlock()
	
	if nr.stats == nil {
		return nil, errors.New("网络统计数据不可用")
	}
	
	if nr.chainInfo == nil {
		// 尝试检测链ID
		chainInfo, err := nr.DetectChainID()
		if err != nil {
			log.Warn("无法检测链ID", "错误", err)
			// 继续分析，但无法提供特定于链的建议
		} else {
			nr.chainInfo = chainInfo
		}
	}
	
	// 分析连接稳定性
	connectionStability := 0.0
	if nr.stats.TotalRequests > 0 {
		successRate := float64(nr.stats.SuccessfulRequests) / float64(nr.stats.TotalRequests)
		connectionStability = math.Min(successRate*1.2, 1.0) // 给一个加权，但不超过1
	}
	
	// 分析延迟
	var avgLatency float64
	var latencyScore float64
	if len(nr.latencyHistory) > 0 {
		sum := int64(0)
		for _, latency := range nr.latencyHistory {
			sum += latency
		}
		avgLatency = float64(sum) / float64(len(nr.latencyHistory))
		
		// 延迟得分计算 (假设500ms以下为最佳，2000ms以上为最差)
		if avgLatency <= 500 {
			latencyScore = 1.0
		} else if avgLatency >= 2000 {
			latencyScore = 0.0
		} else {
			latencyScore = 1.0 - (avgLatency-500)/1500
		}
	}
	
	// 分析带宽 (基于吞吐量)
	bandwidthScore := 0.0
	if nr.stats.TotalDataSent > 0 && nr.stats.TotalElapsedTime > 0 {
		throughput := float64(nr.stats.TotalDataSent) / float64(nr.stats.TotalElapsedTime/time.Second)
		// 假设10MB/s以上为最佳，100KB/s以下为最差
		if throughput >= 10*1024*1024 {
			bandwidthScore = 1.0
		} else if throughput <= 100*1024 {
			bandwidthScore = 0.0
		} else {
			bandwidthScore = (throughput - 100*1024) / (10*1024*1024 - 100*1024)
		}
	}
	
	// 分析错误率
	errorRate := 0.0
	if nr.stats.TotalRequests > 0 {
		errorRate = float64(nr.stats.FailedRequests) / float64(nr.stats.TotalRequests)
	}
	
	// 推荐gas价格和限制
	var recommendedGasPrice *big.Int
	var recommendedGasLimit uint64
	
	if nr.chainAdapter != nil {
		gasPrice, err := nr.chainAdapter.SuggestGasPrice(context.Background())
		if err == nil {
			// 根据网络拥堵情况微调gas价格
			if errorRate > 0.3 || latencyScore < 0.3 {
				// 网络拥堵，提高gas价格
				adjustment := big.NewInt(0).Div(gasPrice, big.NewInt(5)) // 增加20%
				recommendedGasPrice = big.NewInt(0).Add(gasPrice, adjustment)
			} else {
				recommendedGasPrice = gasPrice
			}
		}
		
		// 根据最近交易设置推荐gas限制
		if nr.txStats != nil && nr.txStats.AvgGasUsed > 0 {
			// 添加10%的缓冲
			recommendedGasLimit = uint64(float64(nr.txStats.AvgGasUsed) * 1.1)
		} else {
			// 默认值
			recommendedGasLimit = 21000 // 基本ETH转账
		}
	}
	
	// 确定最优批处理大小
	optimalBatchSize := 1
	batchingRecommended := false
	
	if connectionStability > 0.8 && latencyScore > 0.7 {
		// 网络状况良好，可以使用更大的批处理
		optimalBatchSize = 10
		batchingRecommended = true
	} else if connectionStability > 0.6 && latencyScore > 0.5 {
		// 网络状况一般，使用中等批处理
		optimalBatchSize = 5
		batchingRecommended = true
	} else if connectionStability > 0.4 {
		// 网络状况较差，使用小批处理
		optimalBatchSize = 3
		batchingRecommended = true
	} else {
		// 网络状况很差，不推荐批处理
		optimalBatchSize = 1
		batchingRecommended = false
	}
	
	// 确定网络趋势
	networkTrend := "稳定"
	if nr.stats.LastErrorTime.After(time.Now().Add(-5*time.Minute)) && nr.stats.ErrorCount > 3 {
		networkTrend = "恶化"
	} else if nr.stats.SuccessCount > 10 && nr.stats.ErrorCount == 0 {
		networkTrend = "改善"
	}
	
	// 构建分析结果
	analysis := &NetworkAdaptiveness{
		CurrentNetworkType:   nr.chainInfo.NetworkName,
		ConnectionStability:  connectionStability,
		LatencyScore:         latencyScore,
		BandwidthScore:       bandwidthScore,
		ErrorRate:            errorRate,
		RecommendedGasPrice:  recommendedGasPrice,
		RecommendedGasLimit:  recommendedGasLimit,
		OptimalBatchSize:     optimalBatchSize,
		BatchingRecommended:  batchingRecommended,
		LastUpdated:          time.Now(),
		NetworkTrend:         networkTrend,
	}
	
	return analysis, nil
}

// ConfigureForNetwork 根据网络适应性分析结果配置网络参数
func (nr *NetworkResilience) ConfigureForNetwork(analysis *NetworkAdaptiveness) error {
	if analysis == nil {
		return errors.New("分析结果为空")
	}
	
	nr.mu.Lock()
	defer nr.mu.Unlock()
	
	// 1. 调整超时设置
	if analysis.LatencyScore < 0.3 {
		// 网络延迟高，增加超时时间
		nr.currentTimeout = 30 * time.Second
		log.Info("调整超时设置", "新超时", "30秒", "原因", "网络延迟高")
	} else if analysis.LatencyScore < 0.6 {
		// 网络延迟中等
		nr.currentTimeout = 15 * time.Second
		log.Info("调整超时设置", "新超时", "15秒", "原因", "网络延迟中等")
	} else {
		// 网络延迟低
		nr.currentTimeout = 10 * time.Second
		log.Info("调整超时设置", "新超时", "10秒", "原因", "网络延迟低")
	}
	
	// 2. 调整批处理配置
	if nr.config != nil {
		if analysis.BatchingRecommended {
			nr.config.BatchingEnabled = true
			nr.config.BatchSize = analysis.OptimalBatchSize
			log.Info("启用批处理", "批大小", analysis.OptimalBatchSize)
		} else {
			nr.config.BatchingEnabled = false
			log.Info("禁用批处理", "原因", "网络状况不稳定")
		}
	}
	
	// 3. 根据网络状况调整数据压缩级别
	if nr.config != nil {
		if analysis.BandwidthScore < 0.4 {
			// 带宽低，使用高压缩
			nr.config.CompressionLevel = 9 // 最高压缩级别
			log.Info("设置高压缩级别", "级别", 9, "原因", "带宽受限")
		} else if analysis.BandwidthScore < 0.7 {
			// 带宽中等，使用中等压缩
			nr.config.CompressionLevel = 5
			log.Info("设置中等压缩级别", "级别", 5)
		} else {
			// 带宽高，使用低压缩或不压缩
			nr.config.CompressionLevel = 1
			log.Info("设置低压缩级别", "级别", 1, "原因", "带宽充足")
		}
	}
	
	// 4. 根据连接稳定性调整重连间隔
	if analysis.ConnectionStability < 0.5 {
		// 连接不稳定，减少重连间隔
		if nr.config != nil {
			nr.config.ReconnectInterval = 3 * time.Second
		}
		log.Info("减少重连间隔", "新间隔", "3秒", "原因", "连接不稳定")
	} else {
		// 连接稳定，使用正常重连间隔
		if nr.config != nil {
			nr.config.ReconnectInterval = 10 * time.Second
		}
	}
	
	// 5. 网络趋势为"恶化"时，主动切换到备用节点
	if analysis.NetworkTrend == "恶化" && len(nr.backupNodes) > 0 && nr.currentNode != "" {
		// 找到当前节点在列表中的位置
		currentIndex := -1
		for i, node := range nr.backupNodes {
			if node == nr.currentNode {
				currentIndex = i
				break
			}
		}
		
		// 切换到下一个备用节点
		if currentIndex != -1 && currentIndex+1 < len(nr.backupNodes) {
			nextNode := nr.backupNodes[currentIndex+1]
			nr.currentNode = nextNode
			log.Info("切换到备用节点", "新节点", nextNode, "原因", "网络状况恶化")
		} else if currentIndex != -1 {
			// 轮换回第一个节点
			nr.currentNode = nr.backupNodes[0]
			log.Info("切换回主节点", "节点", nr.backupNodes[0], "原因", "已尝试所有备用节点")
		}
	}
	
	// 6. 根据错误率调整重试策略
	if analysis.ErrorRate > 0.3 {
		// 高错误率，增加最大重试次数
		if nr.config != nil {
			nr.config.MaxRetries = 5
			nr.config.RetryBackoff = 1.5 // 指数退避因子
		}
		log.Info("增加重试设置", "最大重试", 5, "原因", "高错误率")
	} else if analysis.ErrorRate > 0.1 {
		// 中等错误率
		if nr.config != nil {
			nr.config.MaxRetries = 3
			nr.config.RetryBackoff = 1.3
		}
	} else {
		// 低错误率
		if nr.config != nil {
			nr.config.MaxRetries = 2
			nr.config.RetryBackoff = 1.0 // 无退避
		}
	}
	
	// 7. 记录已应用的配置
	log.Info("已应用网络适应性配置",
		"网络", analysis.CurrentNetworkType,
		"连接稳定性", analysis.ConnectionStability,
		"延迟得分", analysis.LatencyScore,
		"带宽得分", analysis.BandwidthScore,
		"错误率", analysis.ErrorRate,
		"批处理", analysis.BatchingRecommended)
	
	return nil
}

// isValidMessageType 验证消息类型是否有效
func (nr *NetworkResilience) isValidMessageType(msgType uint8) bool {
	// 使用预定义的消息类型映射进行验证，提高可维护性和性能
	return validMessageTypes[msgType]
}

// handleP2PMessage 处理P2P消息
// 参数:
// - msg: 消息字节数组
// 返回:
// - error: 处理错误
func (nr *NetworkResilience) handleP2PMessage(msg []byte) error {
	if len(msg) == 0 {
		return errors.New("消息为空")
	}

	// 获取消息类型（假设第一个字节是消息类型）
	msgType := msg[0]
	
	// 验证消息类型
	if !nr.isValidMessageType(msgType) {
		log.Warn("无效的消息类型", "类型", msgType)
		return fmt.Errorf("无效的消息类型: %d", msgType)
	}
	
	// 根据消息类型处理
	switch msgType {
	case MessageTypeBlockRequest:
		return nr.handleBlockRequest(msg[1:])
	case MessageTypeBlockResponse:
		return nr.handleBlockResponse(msg[1:])
	case MessageTypeTxRequest:
		return nr.handleTxRequest(msg[1:])
	case MessageTypeTxResponse:
		return nr.handleTxResponse(msg[1:])
	case MessageTypeSync:
		return nr.handleSyncMessage(msg[1:])
	case MessageTypeControl:
		return nr.handleControlMessage(msg[1:])
	case MessageTypeDiscovery:
		return nr.handleDiscoveryMessage(msg[1:])
	case MessageTypeHeartbeat:
		return nr.handleHeartbeatMessage(msg[1:])
	case MessageTypeStateRequest:
		return nr.handleStateRequest(msg[1:])
	case MessageTypeStateResponse:
		return nr.handleStateResponse(msg[1:])
	default:
		// 这种情况理论上不会发生，因为我们已经验证了消息类型
		return fmt.Errorf("未处理的消息类型: %d", msgType)
	}
}

// 以下是各种消息类型的处理函数，根据实际需求实现

// handleBlockRequest 处理区块请求消息
func (nr *NetworkResilience) handleBlockRequest(msg []byte) error {
	// 实现区块请求消息处理逻辑
	return nil
}

// handleBlockResponse 处理区块响应消息
func (nr *NetworkResilience) handleBlockResponse(msg []byte) error {
	// 实现区块响应消息处理逻辑
	return nil
}

// handleTxRequest 处理交易请求消息
func (nr *NetworkResilience) handleTxRequest(msg []byte) error {
	// 实现交易请求消息处理逻辑
	return nil
}

// handleTxResponse 处理交易响应消息
func (nr *NetworkResilience) handleTxResponse(msg []byte) error {
	// 实现交易响应消息处理逻辑
	return nil
}

// handleSyncMessage 处理同步消息
func (nr *NetworkResilience) handleSyncMessage(msg []byte) error {
	// 实现同步消息处理逻辑
	return nil
}

// handleControlMessage 处理控制消息
func (nr *NetworkResilience) handleControlMessage(msg []byte) error {
	// 实现控制消息处理逻辑
	return nil
}

// handleDiscoveryMessage 处理发现消息
func (nr *NetworkResilience) handleDiscoveryMessage(msg []byte) error {
	// 实现发现消息处理逻辑
	return nil
}

// handleHeartbeatMessage 处理心跳消息
func (nr *NetworkResilience) handleHeartbeatMessage(msg []byte) error {
	// 实现心跳消息处理逻辑
	return nil
}

// handleStateRequest 处理状态请求消息
func (nr *NetworkResilience) handleStateRequest(msg []byte) error {
	// 实现状态请求消息处理逻辑
	return nil
}

// handleStateResponse 处理状态响应消息
func (nr *NetworkResilience) handleStateResponse(msg []byte) error {
	// 实现状态响应消息处理逻辑
	return nil
}

// retrySync 替换立即重试的同步函数
func (nr *NetworkResilience) retrySync() {
	if !nr.syncRetryContext.IsRetryAllowed() {
		log.Warn("同步重试次数已达上限，放弃重试",
			"尝试次数", nr.syncRetryContext.attempt,
			"最大尝试次数", nr.syncRetryContext.maxAttempts)
		return
	}
	
	// 计算下次重试延迟
	delay := nr.syncRetryContext.CalculateNextRetryDelay()
	
	log.Info("计划重试同步",
		"尝试次数", nr.syncRetryContext.attempt,
		"延迟", delay,
		"下次重试时间", nr.syncRetryContext.nextRetryTime)
	
	// 使用定时器安排重试，而不是立即重试
	time.AfterFunc(delay, func() {
		// 检查是否已关闭
		select {
		case <-nr.ctx.Done():
			return
		default:
			// 实际执行同步
			nr.performSync()
		}
	})
}

// 实际执行同步的方法
func (nr *NetworkResilience) performSync() {
	// 检查网络状态
	nr.mu.RLock()
	currentState := nr.currentState
	nr.mu.RUnlock()
	
	if currentState == NetworkStateOffline {
		log.Warn("网络离线，无法执行同步")
		// 网络离线时，设置重试
		nr.retrySync()
		return
	}
	
	log.Info("开始执行同步", "网络状态", currentState)
	
	// 在这里实现实际的同步逻辑
	// 如果同步成功，重置重试上下文
	nr.syncRetryContext = NewRetryContext(
		10, // 最大尝试次数
		2 * time.Second, // 初始延迟
		5 * time.Minute, // 最大延迟
		RetryStrategyExponential, // 使用指数退避策略
	)
	
	// 如果同步失败，调用重试
	// 这里模拟一个随机的同步失败
	if rand.Intn(5) == 0 {
		log.Warn("同步失败，将重试")
		nr.retrySync()
	}
}

// 通用的任务重试方法
func (nr *NetworkResilience) retryTask(taskID string, task func()) {
	nr.mu.Lock()
	
	// 获取或创建重试上下文
	retryContext, exists := nr.retryTasks[taskID]
	if !exists {
		retryContext = NewRetryContext(
			5, // 最大尝试次数
			2 * time.Second, // 初始延迟
			1 * time.Minute, // 最大延迟
			RetryStrategyExponential, // 使用指数退避策略
		)
		nr.retryTasks[taskID] = retryContext
	}
	
	nr.mu.Unlock()
	
	if !retryContext.IsRetryAllowed() {
		log.Warn("任务重试次数已达上限，放弃重试", "任务ID", taskID,
			"尝试次数", retryContext.attempt,
			"最大尝试次数", retryContext.maxAttempts)
		return
	}
	
	// 计算下次重试延迟
	delay := retryContext.CalculateNextRetryDelay()
	
	log.Info("计划重试任务", "任务ID", taskID,
		"尝试次数", retryContext.attempt,
		"延迟", delay,
		"下次重试时间", retryContext.nextRetryTime)
	
	// 使用定时器安排重试
	time.AfterFunc(delay, func() {
		// 检查是否已关闭
		select {
		case <-nr.ctx.Done():
			return
		default:
			// 执行任务
			task()
		}
	})
}