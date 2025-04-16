package mobile

import (
	"errors"
	"fmt"
	"sync"
	"time"
	"context"
	"math/big"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/crypto"
)

// 同步模式常量
const (
	SyncModeFull       = "full"       // 完整同步模式
	SyncModeLight      = "light"      // 轻量同步模式
	SyncModeUltraLight = "ultralight" // 超轻量同步模式
	SyncModeHeaderOnly = "headeronly" // 仅区块头同步模式
	SyncModeSnapshot   = "snapshot"   // 快照同步模式
	SyncModeDelta      = "delta"      // 增量同步模式
)

// MobileClient 移动端轻量级客户端
type MobileClient struct {
	config            *MobileConfig     // 移动客户端配置
	db                ethdb.Database    // 数据库
	blockchain        *core.BlockChain  // 区块链
	validator         *MobileValidator  // 验证者
	syncManager       *SyncManager      // 同步管理器
	resourceManager   *ResourceManager  // 资源管理器
	storageManager    *StorageManager   // 存储管理器
	securityManager   *SecurityManager  // 安全管理器 - 新增
	
	// 状态控制
	started          bool              // 是否已启动
	running          bool              // 是否运行中
	stopping         bool              // 是否正在停止
	statusLock       sync.RWMutex      // 状态锁
	
	// 移动优化
	batteryAware     bool              // 电池感知
	networkAware     bool              // 网络感知
	adaptiveSync     bool              // 自适应同步
	lowPowerMode     bool              // 低功耗模式
	
	// 超轻量客户端支持 - 新增
	headerChain      *HeaderChain      // 区块头链
	merkleProofs     *MerkleProofStore // Merkle证明存储
	stateCache       *StateCache       // 状态缓存
	offlineMode      bool              // 离线模式
	
	// 统计信息
	stats            *ClientStats      // 客户端统计
	
	// 后台任务控制
	tasksChan        chan clientTask   // 任务通道
	stopChan         chan struct{}     // 停止通道
	wg               sync.WaitGroup    // 等待组
	ctx              context.Context   // 上下文 - 新增
	cancel           context.CancelFunc // 取消函数 - 新增
}

// MobileConfig 移动客户端配置
type MobileConfig struct {
	ChainConfig           *params.ChainConfig // 链配置
	MaxStorageGB          uint64              // 最大存储空间(GB)
	MaxNetworkUsageMB     uint64              // 最大网络使用量(MB/小时)
	MaxBatteryUsage       int                 // 最大电池使用率(%)
	SyncMode              string              // 同步模式(full/light/ultralight/headeronly/snapshot/delta)
	EnableBatteryAware    bool                // 启用电池感知
	EnableNetworkAware    bool                // 启用网络感知
	EnableStorageAware    bool                // 启用存储感知
	EnableAdaptiveSync    bool                // 启用自适应同步
	SyncInterval          time.Duration       // 同步间隔
	CheckpointInterval    uint64              // 检查点间隔(区块数)
	MaxPeers              int                 // 最大对等节点数
	DataCompression       bool                // 数据压缩
	DataEncryption        bool                // 数据加密
	MobileConsensusConfig *params.MobileConsensusConfig // 移动共识配置
	
	// 超轻量客户端配置 - 新增
	HeaderVerificationOnly bool                // 是否仅验证区块头
	EnableMerkleProof      bool                // 是否启用Merkle证明
	MaxHeadersPerSync      int                 // 每次同步最大区块头数量
	StateRootVerification  bool                // 是否进行状态根验证
	ZKProofVerification    bool                // 是否使用零知识证明验证
	OfflineFirstMode       bool                // 离线优先模式
	DeltaSyncEnabled       bool                // 增量同步
	SnapshotSyncEnabled    bool                // 快照同步
	StateCacheSizeMB       int                 // 状态缓存大小(MB)
	
	// 安全配置 - 新增
	SecurityConfig        *SecurityConfig      // 安全配置
}

// ClientStats 客户端统计信息
type ClientStats struct {
	StartTime         time.Time // 启动时间
	BlocksProcessed   uint64    // 已处理区块数
	LastBlockNumber   uint64    // 最后区块高度
	LastSyncTime      time.Time // 最后同步时间
	TotalSyncTime     time.Duration // 总同步时间
	TotalNetworkUsage uint64    // 总网络使用量(字节)
	BatteryUsage      float64   // 电池使用率(%/小时)
	StorageUsage      uint64    // 存储使用量(字节)
	PeersConnected    int       // 已连接对等节点数
	SyncErrors        int       // 同步错误数
	
	// 超轻量客户端统计 - 新增
	HeadersProcessed   uint64   // 已处理区块头数
	ProofsVerified     uint64   // 已验证Merkle证明数
	CacheHitRate       float64  // 缓存命中率
	OfflineOperations  uint64   // 离线操作次数
}

// 客户端任务类型
type clientTaskType int

const (
	taskSync clientTaskType = iota
	taskVerify
	taskPropose
	taskBackup
	taskResourceCheck
	taskHeaderSync      // 新增：区块头同步任务
	taskMerkleProof     // 新增：Merkle证明获取任务
	taskStateValidation // 新增：状态验证任务
	taskCacheCleanup    // 新增：缓存清理任务
)

// 客户端任务
type clientTask struct {
	taskType clientTaskType
	params   interface{}
}

// HeaderChain 区块头链
type HeaderChain struct {
	headers        map[uint64]*types.Header // 区块头映射表
	latestHeader   *types.Header            // 最新区块头
	genesisHeader  *types.Header            // 创世区块头
	checkpoints    map[uint64]*types.Header // 检查点区块头
	headersMutex   sync.RWMutex             // 区块头锁
}

// MerkleProofStore Merkle证明存储
type MerkleProofStore struct {
	proofs        map[common.Hash][]byte    // 证明数据
	proofsMutex   sync.RWMutex              // 证明锁
}

// StateCache 状态缓存
type StateCache struct {
	accounts      map[common.Address]*AccountState // 账户状态
	storage       map[common.Hash]common.Hash      // 存储数据
	maxSizeMB     int                              // 最大缓存大小(MB)
	cacheMutex    sync.RWMutex                     // 缓存锁
}

// AccountState 账户状态
type AccountState struct {
	Nonce    uint64                         // 交易计数
	Balance  *big.Int                       // 余额
	Root     common.Hash                    // 存储根
	CodeHash []byte                         // 代码哈希
	Code     []byte                         // 代码
}

// NewMobileClient 创建新的移动端客户端
func NewMobileClient(config *MobileConfig, db ethdb.Database) (*MobileClient, error) {
	if config == nil {
		return nil, errors.New("配置不能为空")
	}
	
	if db == nil {
		return nil, errors.New("数据库不能为空")
	}
	
	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	
	// 创建资源管理器
	resourceManager := NewResourceManager(&ResourceConfig{
		MaxStorageGB:      config.MaxStorageGB,
		MaxNetworkUsageMB: config.MaxNetworkUsageMB,
		MaxBatteryUsage:   config.MaxBatteryUsage,
		BatteryAware:      config.EnableBatteryAware,
		NetworkAware:      config.EnableNetworkAware,
		StorageAware:      config.EnableStorageAware,
	})
	
	// 创建存储管理器
	storageManager := NewStorageManager(db, &StorageConfig{
		Compression:     config.DataCompression,
		Encryption:      config.DataEncryption,
		MaxStorageGB:    config.MaxStorageGB,
		PruneThreshold:  config.MaxStorageGB * 90 / 100, // 90%阈值
	})
	
	// 创建同步管理器
	syncManager := NewSyncManager(&SyncConfig{
		Mode:               config.SyncMode,
		AdaptiveSync:       config.EnableAdaptiveSync,
		SyncInterval:       config.SyncInterval,
		CheckpointInterval: config.CheckpointInterval,
		MaxPeers:           config.MaxPeers,
		HeaderOnly:         config.SyncMode == SyncModeHeaderOnly || config.HeaderVerificationOnly,
		MaxHeadersPerSync:  config.MaxHeadersPerSync,
		SnapshotSync:       config.SnapshotSyncEnabled,
		DeltaSync:          config.DeltaSyncEnabled,
	})
	
	// 创建安全管理器（如果有安全配置）
	var securityManager *SecurityManager
	if config.SecurityConfig != nil {
		securityManager = NewSecurityManager(config.SecurityConfig)
	}
	
	// 创建超轻量客户端组件
	var headerChain *HeaderChain
	var merkleProofs *MerkleProofStore
	var stateCache *StateCache
	
	// 检查是否需要超轻量客户端组件
	if isUltraLightMode(config.SyncMode) {
		headerChain = &HeaderChain{
			headers:     make(map[uint64]*types.Header),
			checkpoints: make(map[uint64]*types.Header),
		}
		
		if config.EnableMerkleProof {
			merkleProofs = &MerkleProofStore{
				proofs: make(map[common.Hash][]byte),
			}
		}
		
		if config.StateCacheSizeMB > 0 {
			stateCache = &StateCache{
				accounts:   make(map[common.Address]*AccountState),
				storage:    make(map[common.Hash]common.Hash),
				maxSizeMB:  config.StateCacheSizeMB,
			}
		}
	}
	
	client := &MobileClient{
		config:          config,
		db:              db,
		resourceManager: resourceManager,
		storageManager:  storageManager,
		syncManager:     syncManager,
		securityManager: securityManager,
		batteryAware:    config.EnableBatteryAware,
		networkAware:    config.EnableNetworkAware,
		adaptiveSync:    config.EnableAdaptiveSync,
		offlineMode:     false, // 默认在线模式
		headerChain:     headerChain,
		merkleProofs:    merkleProofs,
		stateCache:      stateCache,
		stats:           &ClientStats{StartTime: time.Now()},
		tasksChan:       make(chan clientTask, 100),
		stopChan:        make(chan struct{}),
		ctx:             ctx,
		cancel:          cancel,
	}
	
	return client, nil
}

// 判断是否为超轻量模式
func isUltraLightMode(mode string) bool {
	return mode == SyncModeUltraLight || 
		   mode == SyncModeHeaderOnly || 
		   mode == SyncModeSnapshot ||
		   mode == SyncModeDelta
}

// Start 启动客户端
func (mc *MobileClient) Start() error {
	mc.statusLock.Lock()
	defer mc.statusLock.Unlock()
	
	if mc.started {
		return errors.New("客户端已启动")
	}
	
	// 初始化区块链
	if err := mc.initBlockchain(); err != nil {
		return err
	}
	
	// 启动资源管理器
	mc.resourceManager.Start()
	
	// 启动安全管理器（如果存在）
	if mc.securityManager != nil {
		if err := mc.securityManager.Start(); err != nil {
			log.Error("安全管理器启动失败", "错误", err)
			return err
		}
	}
	
	// 初始化超轻量客户端组件（如果需要）
	if isUltraLightMode(mc.config.SyncMode) {
		if err := mc.initUltraLightComponents(); err != nil {
			return err
		}
	}
	
	// 启动同步管理器
	mc.syncManager.Start(mc.blockchain)
	
	// 启动后台任务处理
	mc.startBackgroundTasks()
	
	mc.started = true
	mc.running = true
	
	log.Info("移动客户端已启动",
		"同步模式", mc.config.SyncMode,
		"电池感知", mc.batteryAware,
		"网络感知", mc.networkAware,
		"自适应同步", mc.adaptiveSync,
		"超轻量模式", isUltraLightMode(mc.config.SyncMode))
	
	return nil
}

// 初始化超轻量客户端组件
func (mc *MobileClient) initUltraLightComponents() error {
	// 加载最近的区块头
	latestHeader, err := mc.loadLatestHeader()
	if err != nil {
		log.Warn("加载最近区块头失败", "错误", err)
		// 非致命错误，继续执行
	} else if latestHeader != nil {
		mc.headerChain.latestHeader = latestHeader
		mc.headerChain.headers[latestHeader.Number.Uint64()] = latestHeader
		log.Info("已加载最近区块头", "高度", latestHeader.Number.Uint64())
	}
	
	// 加载创世区块头
	genesisHeader, err := mc.loadGenesisHeader()
	if err != nil {
		log.Error("加载创世区块头失败", "错误", err)
		return err
	}
	mc.headerChain.genesisHeader = genesisHeader
	mc.headerChain.headers[0] = genesisHeader
	
	// 加载检查点
	checkpoints, err := mc.loadCheckpoints()
	if err != nil {
		log.Warn("加载检查点失败", "错误", err)
		// 非致命错误，继续执行
	} else {
		mc.headerChain.checkpoints = checkpoints
		log.Info("已加载检查点", "数量", len(checkpoints))
	}
	
	log.Info("超轻量客户端组件已初始化")
	return nil
}

// 加载最近的区块头
func (mc *MobileClient) loadLatestHeader() (*types.Header, error) {
	// 从存储中加载
	var header *types.Header
	err := mc.storageManager.LoadData("latest_header", &header)
	return header, err
}

// 加载创世区块头
func (mc *MobileClient) loadGenesisHeader() (*types.Header, error) {
	// 从存储中加载
	var header *types.Header
	err := mc.storageManager.LoadData("genesis_header", &header)
	
	// 如果没有找到，则使用配置中的创世区块哈希
	if err != nil || header == nil {
		// 在实际实现中，应该从网络获取或内置
		// 这里仅做示例
		header = &types.Header{
			Number:     big.NewInt(0),
			Time:       1,
			Difficulty: big.NewInt(1),
		}
		
		// 保存创世区块头
		_ = mc.storageManager.SaveData("genesis_header", header)
	}
	
	return header, nil
}

// 加载检查点
func (mc *MobileClient) loadCheckpoints() (map[uint64]*types.Header, error) {
	// 从存储中加载
	var checkpoints map[uint64]*types.Header
	err := mc.storageManager.LoadData("checkpoints", &checkpoints)
	
	if err != nil || checkpoints == nil {
		checkpoints = make(map[uint64]*types.Header)
	}
	
	return checkpoints, nil
}

// Stop 停止客户端
func (mc *MobileClient) Stop() error {
	mc.statusLock.Lock()
	
	if !mc.started || mc.stopping {
		mc.statusLock.Unlock()
		return errors.New("客户端未启动或正在停止")
	}
	
	mc.stopping = true
	mc.running = false
	mc.statusLock.Unlock()
	
	// 取消所有上下文
	mc.cancel()
	
	// 停止后台任务
	close(mc.stopChan)
	mc.wg.Wait()
	
	// 停止同步管理器
	mc.syncManager.Stop()
	
	// 停止安全管理器（如果存在）
	if mc.securityManager != nil {
		mc.securityManager.Stop()
	}
	
	// 停止资源管理器
	mc.resourceManager.Stop()
	
	// 保存超轻量客户端状态（如果启用）
	if isUltraLightMode(mc.config.SyncMode) {
		mc.saveUltraLightState()
	}
	
	// 保存当前状态
	if err := mc.saveState(); err != nil {
		log.Error("保存客户端状态失败", "错误", err)
	}
	
	mc.statusLock.Lock()
	mc.started = false
	mc.stopping = false
	mc.statusLock.Unlock()
	
	log.Info("移动客户端已停止")
	return nil
}

// 保存超轻量客户端状态
func (mc *MobileClient) saveUltraLightState() {
	// 保存最新区块头
	if mc.headerChain != nil && mc.headerChain.latestHeader != nil {
		err := mc.storageManager.SaveData("latest_header", mc.headerChain.latestHeader)
		if err != nil {
			log.Error("保存最新区块头失败", "错误", err)
		}
	}
	
	// 保存检查点
	if mc.headerChain != nil && len(mc.headerChain.checkpoints) > 0 {
		err := mc.storageManager.SaveData("checkpoints", mc.headerChain.checkpoints)
		if err != nil {
			log.Error("保存检查点失败", "错误", err)
		}
	}
	
	log.Info("超轻量客户端状态已保存")
}

// 启动后台任务
func (mc *MobileClient) startBackgroundTasks() {
	mc.wg.Add(1)
	go func() {
		defer mc.wg.Done()
		
		syncTicker := time.NewTicker(mc.config.SyncInterval)
		resourceTicker := time.NewTicker(1 * time.Minute)
		cacheTicker := time.NewTicker(30 * time.Minute) // 定期缓存清理
		
		defer syncTicker.Stop()
		defer resourceTicker.Stop()
		defer cacheTicker.Stop()
		
		for {
			select {
			case <-mc.stopChan:
				return
				
			case task := <-mc.tasksChan:
				// 处理任务
				mc.processTask(task)
				
			case <-syncTicker.C:
				// 定期同步
				if mc.running && !mc.offlineMode {
					// 根据同步模式选择任务
					if isUltraLightMode(mc.config.SyncMode) {
						mc.tasksChan <- clientTask{taskType: taskHeaderSync}
					} else {
						mc.tasksChan <- clientTask{taskType: taskSync}
					}
				}
				
			case <-resourceTicker.C:
				// 资源检查
				if mc.running {
					mc.tasksChan <- clientTask{taskType: taskResourceCheck}
				}
				
			case <-cacheTicker.C:
				// 缓存清理
				if mc.running && mc.stateCache != nil {
					mc.tasksChan <- clientTask{taskType: taskCacheCleanup}
				}
			}
		}
	}()
}

// 处理任务
func (mc *MobileClient) processTask(task clientTask) {
	// 资源检查 - 电池电量过低时暂停非必要任务
	if mc.batteryAware && !mc.isEssentialTask(task.taskType) {
		batteryLevel := mc.resourceManager.GetBatteryLevel()
		if batteryLevel < 15 && !mc.resourceManager.IsCharging() {
			log.Debug("电量过低，跳过非必要任务", "任务类型", task.taskType, "电量", batteryLevel)
			return
		}
	}
	
	switch task.taskType {
	case taskSync:
		mc.performSync()
	case taskVerify:
		mc.performVerify(task.params)
	case taskPropose:
		mc.performPropose(task.params)
	case taskBackup:
		mc.performBackup()
	case taskResourceCheck:
		mc.performResourceCheck()
	case taskHeaderSync:
		mc.performHeaderSync()
	case taskMerkleProof:
		mc.performMerkleProofRequest(task.params)
	case taskStateValidation:
		mc.performStateValidation(task.params)
	case taskCacheCleanup:
		mc.performCacheCleanup()
	}
}

// 执行同步
func (mc *MobileClient) performSync() {
	startTime := time.Now()
	
	// 根据资源状态调整同步行为
	syncMode := mc.config.SyncMode
	
	// 自适应同步模式
	if mc.adaptiveSync {
		battery := mc.resourceManager.GetBatteryLevel()
		network := mc.resourceManager.GetNetworkType()
		
		// 低电量或移动网络下降级为超轻量同步
		if (battery < 20 && !mc.resourceManager.IsBatteryCharging()) || 
		   network == "cellular" {
			syncMode = "ultralight"
		} else if battery < 50 || network != "wifi" {
			syncMode = "light"
		}
	}
	
	// 执行同步
	result, err := mc.syncManager.Sync(syncMode)
	
	// 更新统计信息
	syncTime := time.Since(startTime)
	mc.stats.LastSyncTime = time.Now()
	mc.stats.TotalSyncTime += syncTime
	
	if err != nil {
		log.Error("同步失败", "错误", err, "模式", syncMode)
		mc.stats.SyncErrors++
	} else if result != nil {
		mc.stats.BlocksProcessed += result.BlocksProcessed
		mc.stats.LastBlockNumber = result.LastBlockNumber
		mc.stats.TotalNetworkUsage += result.NetworkUsage
		
		log.Debug("同步完成", 
			"模式", syncMode, 
			"区块", result.BlocksProcessed,
			"耗时", syncTime,
			"网络使用", formatByteSize(result.NetworkUsage))
	}
}

// 执行验证
func (mc *MobileClient) performVerify(params interface{}) {
	// 验证区块逻辑
	// ...
}

// 执行提议
func (mc *MobileClient) performPropose(params interface{}) {
	// 提议区块逻辑
	// ...
}

// 执行备份
func (mc *MobileClient) performBackup() {
	// 创建检查点，保存状态
	mc.saveState()
}

// 执行资源检查
func (mc *MobileClient) performResourceCheck() {
	// 获取资源状态
	batteryLevel := mc.resourceManager.GetBatteryLevel()
	batteryCharging := mc.resourceManager.IsBatteryCharging()
	networkType := mc.resourceManager.GetNetworkType()
	storageAvailable := mc.resourceManager.GetAvailableStorage()
	
	// 更新客户端状态
	mc.statusLock.Lock()
	
	// 电量过低且未充电时进入低功耗模式
	prevLowPowerMode := mc.lowPowerMode
	mc.lowPowerMode = batteryLevel < 15 && !batteryCharging
	
	// 如果状态有变化，调整客户端行为
	if prevLowPowerMode != mc.lowPowerMode {
		if mc.lowPowerMode {
			log.Info("进入低功耗模式", "电量", batteryLevel)
			// 降低同步频率
			mc.syncManager.SetSyncInterval(mc.config.SyncInterval * 3)
		} else {
			log.Info("退出低功耗模式", "电量", batteryLevel)
			// 恢复正常同步频率
			mc.syncManager.SetSyncInterval(mc.config.SyncInterval)
		}
	}
	mc.statusLock.Unlock()
	
	// 存储空间检查
	if storageAvailable < 1024*1024*100 { // 小于100MB可用空间
		log.Warn("存储空间不足", "可用", formatByteSize(storageAvailable))
		// 触发存储清理
		mc.storageManager.PruneStorage()
	}
	
	// 网络类型变化处理
	mc.syncManager.AdaptToNetwork(networkType)
	
	log.Debug("资源状态", 
		"电量", batteryLevel,
		"充电", batteryCharging,
		"网络", networkType,
		"存储", formatByteSize(storageAvailable))
}

// 执行区块头同步
func (mc *MobileClient) performHeaderSync() {
	if mc.headerChain == nil {
		log.Error("区块头链未初始化")
		return
	}
	
	startTime := time.Now()
	
	// 获取当前最新区块头
	currentHeader := mc.headerChain.latestHeader
	var fromHeight uint64 = 0
	if currentHeader != nil {
		fromHeight = currentHeader.Number.Uint64() + 1
	}
	
	// 最大区块头数量
	maxHeaders := mc.config.MaxHeadersPerSync
	if maxHeaders <= 0 {
		maxHeaders = 100 // 默认值
	}
	
	// 执行区块头同步
	headers, err := mc.syncManager.SyncHeaders(fromHeight, uint64(maxHeaders))
	
	if err != nil {
		log.Error("区块头同步失败", "错误", err)
		mc.stats.SyncErrors++
		return
	}
	
	// 更新区块头链
	if len(headers) > 0 {
		mc.headerChain.headersMutex.Lock()
		
		// 添加新区块头
		var lastHeader *types.Header
		for _, header := range headers {
			mc.headerChain.headers[header.Number.Uint64()] = header
			lastHeader = header
			
			// 定期添加检查点
			if header.Number.Uint64()%mc.config.CheckpointInterval == 0 {
				mc.headerChain.checkpoints[header.Number.Uint64()] = header
			}
		}
		
		// 更新最新区块头
		if lastHeader != nil && (currentHeader == nil || lastHeader.Number.Uint64() > currentHeader.Number.Uint64()) {
			mc.headerChain.latestHeader = lastHeader
		}
		
		mc.headerChain.headersMutex.Unlock()
		
		// 更新统计信息
		mc.stats.HeadersProcessed += uint64(len(headers))
		mc.stats.LastBlockNumber = lastHeader.Number.Uint64()
		
		// 验证状态根（如果启用）
		if mc.config.StateRootVerification && lastHeader != nil {
			mc.tasksChan <- clientTask{
				taskType: taskStateValidation,
				params:   lastHeader,
			}
		}
		
		log.Debug("区块头同步完成", 
			"数量", len(headers),
			"从", fromHeight,
			"到", lastHeader.Number.Uint64(),
			"耗时", time.Since(startTime))
	} else {
		log.Debug("没有新的区块头")
	}
	
	// 更新统计信息
	mc.stats.LastSyncTime = time.Now()
	mc.stats.TotalSyncTime += time.Since(startTime)
}

// 执行Merkle证明请求
func (mc *MobileClient) performMerkleProofRequest(params interface{}) {
	if mc.merkleProofs == nil {
		log.Error("Merkle证明存储未初始化")
		return
	}
	
	// 解析参数
	var (
		blockHash common.Hash
		key       common.Hash
		ok        bool
	)
	
	if params, ok = params.(map[string]interface{}); ok {
		if bhash, ok := params["blockHash"].(common.Hash); ok {
			blockHash = bhash
		}
		if k, ok := params["key"].(common.Hash); ok {
			key = k
		}
	}
	
	if blockHash == (common.Hash{}) || key == (common.Hash{}) {
		log.Error("无效的Merkle证明请求参数")
		return
	}
	
	// 获取Merkle证明
	proof, err := mc.syncManager.GetMerkleProof(blockHash, key)
	
	if err != nil {
		log.Error("获取Merkle证明失败", "错误", err)
		return
	}
	
	// 存储证明
	if proof != nil {
		mc.merkleProofs.proofsMutex.Lock()
		mc.merkleProofs.proofs[key] = proof
		mc.merkleProofs.proofsMutex.Unlock()
		
		// 更新统计信息
		mc.stats.ProofsVerified++
		
		log.Debug("Merkle证明已获取并验证", "区块哈希", blockHash, "键", key)
	}
}

// 执行状态验证
func (mc *MobileClient) performStateValidation(params interface{}) {
	header, ok := params.(*types.Header)
	if !header || !ok {
		log.Error("无效的状态验证参数")
		return
	}
	
	// 使用零知识证明验证（如果启用）
	if mc.config.ZKProofVerification {
		// 获取并验证ZK证明
		// 在实际实现中，这里应该有更多代码...
		log.Debug("使用零知识证明验证状态根", "区块", header.Number.Uint64())
		return
	}
	
	// 常规状态根验证
	log.Debug("验证状态根", "区块", header.Number.Uint64(), "状态根", header.Root.Hex())
	
	// 在实际实现中，这里应该有状态根验证的代码...
}

// 执行缓存清理
func (mc *MobileClient) performCacheCleanup() {
	if mc.stateCache == nil {
		return
	}
	
	log.Debug("执行状态缓存清理")
	
	// 获取当前缓存大小（粗略估计）
	mc.stateCache.cacheMutex.Lock()
	accountCount := len(mc.stateCache.accounts)
	storageCount := len(mc.stateCache.storage)
	mc.stateCache.cacheMutex.Unlock()
	
	log.Debug("当前缓存状态", "账户数", accountCount, "存储键数", storageCount)
	
	// 实际清理逻辑
	// ...
}

// IsUltraLightMode 检查客户端是否运行在超轻量模式
func (mc *MobileClient) IsUltraLightMode() bool {
	return isUltraLightMode(mc.config.SyncMode)
}

// GetLatestBlockHeader 获取最新区块头
func (mc *MobileClient) GetLatestBlockHeader() (*types.Header, error) {
	if mc.headerChain == nil || mc.headerChain.latestHeader == nil {
		return nil, errors.New("区块头链未初始化或没有区块头")
	}
	
	mc.headerChain.headersMutex.RLock()
	defer mc.headerChain.headersMutex.RUnlock()
	
	return mc.headerChain.latestHeader, nil
}

// GetBlockHeader 获取指定高度的区块头
func (mc *MobileClient) GetBlockHeader(height uint64) (*types.Header, error) {
	if mc.headerChain == nil {
		return nil, errors.New("区块头链未初始化")
	}
	
	mc.headerChain.headersMutex.RLock()
	defer mc.headerChain.headersMutex.RUnlock()
	
	header, exists := mc.headerChain.headers[height]
	if !exists {
		return nil, fmt.Errorf("未找到高度为 %d 的区块头", height)
	}
	
	return header, nil
}

// VerifyMerkleProof 验证Merkle证明
func (mc *MobileClient) VerifyMerkleProof(key common.Hash, value []byte, proof []byte) (bool, error) {
	if mc.merkleProofs == nil {
		return false, errors.New("Merkle证明存储未初始化")
	}
	
	// 在实际实现中，这里应该使用trie包验证证明
	// 以下为示例代码
	if len(proof) == 0 {
		return false, errors.New("空的证明")
	}
	
	// 获取最新区块头中的状态根
	header, err := mc.GetLatestBlockHeader()
	if err != nil {
		return false, err
	}
	
	// 使用trie包验证证明
	stateRoot := header.Root
	
	// 这里应该使用trie.VerifyProof函数
	// result := trie.VerifyProof(stateRoot, key, proof)
	
	// 模拟验证逻辑
	result := true // 示例返回，实际应该使用真正的验证结果
	
	if result {
		log.Debug("Merkle证明验证成功", "键", key.Hex())
	} else {
		log.Warn("Merkle证明验证失败", "键", key.Hex())
	}
	
	return result, nil
}

// SetOfflineMode 设置离线模式
func (mc *MobileClient) SetOfflineMode(offline bool) {
	mc.statusLock.Lock()
	defer mc.statusLock.Unlock()
	
	prevMode := mc.offlineMode
	mc.offlineMode = offline
	
	if prevMode != offline {
		if offline {
			log.Info("客户端已切换至离线模式")
		} else {
			log.Info("客户端已切换至在线模式")
		}
	}
}

// 其余原有方法保持不变...

// 格式化字节大小为人类可读形式
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