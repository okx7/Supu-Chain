// layer2_manager.go - 实现Layer2和分片交互逻辑

package mobile

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// Layer2类型常量
const (
	Layer2TypeZKRollup      = "zkrollup"       // ZK Rollup
	Layer2TypeOptimistic    = "optimistic"     // Optimistic Rollup
	Layer2TypeValidium      = "validium"       // Validium（链下数据可用性）
	Layer2TypePlasma        = "plasma"         // Plasma
	Layer2TypeStarknet      = "starknet"       // StarkNet
	Layer2TypeArbitrum      = "arbitrum"       // Arbitrum
	Layer2TypePolygonZKEVM  = "polygonzkevm"   // Polygon zkEVM - 新增
	Layer2TypeScroll        = "scroll"         // Scroll - 新增
	Layer2TypeLinea         = "linea"          // Linea - 新增
)

// Layer2Config Layer2配置
type Layer2Config struct {
	Enabled            bool              // 是否启用Layer2
	Type               string            // Layer2类型
	ChainID            *big.Int          // 链ID
	BridgeAddress      common.Address    // 跨链桥地址
	RollupAddress      common.Address    // Rollup合约地址
	EndpointURL        string            // 接口URL
	MaxBatchSize       int               // 最大批次大小
	SequencerAddress   common.Address    // 排序器地址
	FinalityBlocks     uint64            // 最终确认区块数
	SyncInterval       time.Duration     // 同步间隔
	VerificationLevel  int               // 验证级别 (0-3)
	UseStatelessMode   bool              // 使用无状态模式
	DirectSubmission   bool              // 直接提交交易到L2 - 新增
	CompressionEnabled bool              // 启用压缩 - 新增
	BatchedRequests    bool              // 批量请求 - 新增
	OfflineMode        bool              // 离线模式 - 新增
	PrefetchState      bool              // 预取状态 - 新增
	LocalProofVerify   bool              // 本地证明验证 - 新增
}

// Layer2Status Layer2状态
type Layer2Status struct {
	IsConnected      bool          // 是否已连接
	LastSyncTime     time.Time     // 最后同步时间
	CurrentL2Block   uint64        // 当前L2区块
	PendingTxCount   int           // 待处理交易数
	BalanceSynced    bool          // 余额是否已同步
	NetworkLatency   time.Duration // 网络延迟
	BatchesProcessed int           // 已处理批次数
	ProofsVerified   int           // 已验证证明数
	L2GasPrice       *big.Int      // L2 Gas价格
	IsProofGeneration bool         // 是否正在生成证明
}

// Layer2Batch Layer2批次
type Layer2Batch struct {
	BatchIndex   uint64         // 批次索引
	BatchRoot    common.Hash    // 批次根
	Transactions [][]byte       // 交易数据
	StateRoot    common.Hash    // 状态根
	Timestamp    time.Time      // 时间戳
	Proof        []byte         // 批次证明
	Verified     bool           // 是否已验证
	L1Block      uint64         // L1区块
}

// Layer2Receipt Layer2收据
type Layer2Receipt struct {
	TxHash          common.Hash    // 交易哈希
	Status          uint64         // 状态
	CumulativeGasUsed uint64       // 累计Gas使用量
	Logs            []*types.Log   // 日志
	L2BlockNumber   uint64         // L2区块高度
	L2TxIndex       uint            // L2交易索引
	L1Confirmation  bool           // L1确认
	L1ConfirmationBlock uint64     // L1确认区块
	L1ConfirmationTime time.Time   // L1确认时间
}

// L2AccountInfo Layer2账户信息
type L2AccountInfo struct {
	Address        common.Address  // 地址
	Balance        *big.Int        // 余额
	Nonce          uint64          // Nonce
	StorageRoot    common.Hash     // 存储根
	CodeHash       []byte          // 代码哈希
	LastUpdateTime time.Time       // 最后更新时间
	Verified       bool            // 已验证
}

// Layer2Manager Layer2管理器
type Layer2Manager struct {
	config            *Layer2Config  // 配置
	status            *Layer2Status  // 状态
	
	accounts          map[common.Address]*L2AccountInfo // 账户信息
	batches           map[uint64]*Layer2Batch  // 批次
	pendingTxs        map[common.Hash][]byte   // 待处理交易
	receipts          map[common.Hash]*Layer2Receipt // 收据
	
	stateProofs       map[common.Hash][]byte   // 状态证明
	accountProofs     map[common.Address][]byte // 账户证明
	
	bridge            *L2Bridge       // L2桥
	verifier          *L2Verifier     // L2验证器
	proofGenerator    *L2ProofGenerator // 证明生成器 - 新增
	
	statelessClient   *StatelessClient // 无状态客户端
	
	// 控制
	syncTimer         *time.Timer     // 同步定时器
	running           bool            // 是否运行中
	mu                sync.RWMutex    // 互斥锁
	wg                sync.WaitGroup  // 等待组
	ctx               context.Context // 上下文
	cancel            context.CancelFunc // 取消函数
	
	// 优化功能 - 新增
	stateCache        *L2StateCache   // 状态缓存
	requestBatcher    *L2RequestBatcher // 请求批处理器
	asyncProcessor    *L2AsyncProcessor // 异步处理器
	proofCache        *L2ProofCache    // 证明缓存
}

// L2Bridge L2桥
type L2Bridge struct {
	bridgeAddress   common.Address  // 桥地址
	l1Client        interface{}     // L1客户端（实际实现中应该是特定类型）
	l2Client        interface{}     // L2客户端
	depositNonce    uint64          // 存款Nonce
	pendingDeposits map[uint64]bool // 待处理存款
	mu              sync.RWMutex    // 互斥锁
}

// L2Verifier L2验证器
type L2Verifier struct {
	verificationLevel int            // 验证级别
	pendingProofs    map[uint64]bool // 待处理证明
	verifiedBatches  map[uint64]bool // 已验证批次
	mu               sync.RWMutex    // 互斥锁
}

// L2ProofGenerator L2证明生成器 - 新增
type L2ProofGenerator struct {
	enabled           bool           // 是否启用
	proofType         string         // 证明类型
	pendingGeneration map[uint64]bool // 待生成证明
	generatedProofs   map[uint64][]byte // 已生成证明
	mu                sync.RWMutex    // 互斥锁
}

// L2StateCache L2状态缓存 - 新增
type L2StateCache struct {
	accounts        map[common.Address]*L2AccountInfo // 账户缓存
	storage         map[common.Address]map[common.Hash]common.Hash // 存储缓存
	maxSize         int                               // 最大大小
	currentSize     int                               // 当前大小
	accessTimes     map[common.Address]time.Time      // 访问时间
	mu              sync.RWMutex                      // 互斥锁
}

// L2RequestBatcher 请求批处理器 - 新增
type L2RequestBatcher struct {
	enabled           bool                            // 是否启用
	pendingRequests   []interface{}                   // 待处理请求
	batchSize         int                             // 批次大小
	batchTimer        *time.Timer                     // 批次定时器
	mu                sync.RWMutex                    // 互斥锁
}

// L2AsyncProcessor 异步处理器 - 新增
type L2AsyncProcessor struct {
	enabled           bool                            // 是否启用
	queue             chan interface{}                // 队列
	workers           int                             // 工作线程数
	wg                sync.WaitGroup                  // 等待组
}

// L2ProofCache 证明缓存 - 新增
type L2ProofCache struct {
	proofs            map[common.Hash][]byte          // 证明缓存
	maxSize           int                             // 最大大小
	currentSize       int                             // 当前大小
	accessTimes       map[common.Hash]time.Time       // 访问时间
	mu                sync.RWMutex                    // 互斥锁
}

// NewLayer2Manager 创建新的Layer2管理器
func NewLayer2Manager(config *Layer2Config) (*Layer2Manager, error) {
	if config == nil {
		return nil, errors.New("配置不能为空")
	}
	
	// 验证Layer2类型
	switch config.Type {
	case Layer2TypeZKRollup, Layer2TypeOptimistic, Layer2TypeValidium, 
	     Layer2TypePlasma, Layer2TypeStarknet, Layer2TypeArbitrum,
	     Layer2TypePolygonZKEVM, Layer2TypeScroll, Layer2TypeLinea:
		// 支持的Layer2类型
	default:
		return nil, fmt.Errorf("不支持的Layer2类型: %s", config.Type)
	}
	
	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	
	// 创建Layer2管理器
	manager := &Layer2Manager{
		config:          config,
		status:          &Layer2Status{LastSyncTime: time.Now()},
		accounts:        make(map[common.Address]*L2AccountInfo),
		batches:         make(map[uint64]*Layer2Batch),
		pendingTxs:      make(map[common.Hash][]byte),
		receipts:        make(map[common.Hash]*Layer2Receipt),
		stateProofs:     make(map[common.Hash][]byte),
		accountProofs:   make(map[common.Address][]byte),
		ctx:             ctx,
		cancel:          cancel,
	}
	
	// 创建L2桥
	manager.bridge = &L2Bridge{
		bridgeAddress:   config.BridgeAddress,
		pendingDeposits: make(map[uint64]bool),
	}
	
	// 创建L2验证器
	manager.verifier = &L2Verifier{
		verificationLevel: config.VerificationLevel,
		pendingProofs:     make(map[uint64]bool),
		verifiedBatches:   make(map[uint64]bool),
	}
	
	// 创建新组件 - 根据配置决定是否启用
	
	// 创建证明生成器（如果需要本地验证）
	if config.LocalProofVerify {
		manager.proofGenerator = &L2ProofGenerator{
			enabled:           true,
			proofType:         config.Type,
			pendingGeneration: make(map[uint64]bool),
			generatedProofs:   make(map[uint64][]byte),
		}
	}
	
	// 创建状态缓存（始终创建，但大小可能不同）
	cacheSize := 10 // 默认10MB
	if config.PrefetchState {
		cacheSize = 50 // 预取模式使用更大缓存
	}
	
	manager.stateCache = &L2StateCache{
		accounts:    make(map[common.Address]*L2AccountInfo),
		storage:     make(map[common.Address]map[common.Hash]common.Hash),
		maxSize:     cacheSize * 1024 * 1024, // 转换为字节
		accessTimes: make(map[common.Address]time.Time),
	}
	
	// 创建请求批处理器（如果启用）
	if config.BatchedRequests {
		manager.requestBatcher = &L2RequestBatcher{
			enabled:         true,
			pendingRequests: make([]interface{}, 0),
			batchSize:       10, // 默认批次大小
			batchTimer:      time.NewTimer(5 * time.Second), // 默认5秒批处理
		}
	}
	
	// 创建异步处理器
	manager.asyncProcessor = &L2AsyncProcessor{
		enabled: true,
		queue:   make(chan interface{}, 100),
		workers: 2, // 默认2个工作线程
	}
	
	// 创建证明缓存
	manager.proofCache = &L2ProofCache{
		proofs:      make(map[common.Hash][]byte),
		maxSize:     20 * 1024 * 1024, // 默认20MB
		accessTimes: make(map[common.Hash]time.Time),
	}
	
	log.Info("Layer2管理器已创建", 
		"类型", config.Type, 
		"链ID", config.ChainID,
		"直接提交", config.DirectSubmission,
		"预取状态", config.PrefetchState,
		"本地验证", config.LocalProofVerify)
	
	return manager, nil
}

// Start 启动Layer2管理器
func (lm *Layer2Manager) Start() error {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	
	if lm.running {
		return errors.New("Layer2管理器已在运行")
	}
	
	// 启动异步处理器
	if lm.asyncProcessor != nil && lm.asyncProcessor.enabled {
		lm.startAsyncProcessor()
	}
	
	// 初始连接
	if err := lm.connect(); err != nil {
		return fmt.Errorf("连接Layer2失败: %v", err)
	}
	
	// 设置同步定时器
	lm.syncTimer = time.AfterFunc(lm.config.SyncInterval, lm.sync)
	
	lm.running = true
	log.Info("Layer2管理器已启动", "类型", lm.config.Type)
	
	return nil
}

// 启动异步处理器
func (lm *Layer2Manager) startAsyncProcessor() {
	for i := 0; i < lm.asyncProcessor.workers; i++ {
		lm.asyncProcessor.wg.Add(1)
		go func(workerID int) {
			defer lm.asyncProcessor.wg.Done()
			lm.asyncProcessorLoop(workerID)
		}(i)
	}
}

// 异步处理器循环
func (lm *Layer2Manager) asyncProcessorLoop(workerID int) {
	log.Debug("Layer2异步处理器已启动", "工作线程", workerID)
	
	for {
		select {
		case <-lm.ctx.Done():
			log.Debug("Layer2异步处理器已停止", "工作线程", workerID)
			return
			
		case task := <-lm.asyncProcessor.queue:
			// 处理任务
			lm.processAsyncTask(task)
		}
	}
}

// 处理异步任务
func (lm *Layer2Manager) processAsyncTask(task interface{}) {
	// 在实际实现中，根据任务类型处理
	// 这里仅作为示例
	switch t := task.(type) {
	case *L2Batch:
		// 处理批次
		_ = lm.processBatch(t)
	case common.Hash:
		// 处理交易哈希
		_ = lm.syncTransactionReceipt(t)
	default:
		log.Warn("未知的异步任务类型", "类型", fmt.Sprintf("%T", t))
	}
}

// 连接Layer2
func (lm *Layer2Manager) connect() error {
	// 在实际实现中，建立与Layer2节点的连接
	// 这里仅作为示例实现
	log.Debug("连接Layer2", "URL", lm.config.EndpointURL)
	
	// 设置连接状态
	lm.status.IsConnected = true
	lm.status.NetworkLatency = 100 * time.Millisecond // 示例值
	
	return nil
}

// 同步Layer2状态
func (lm *Layer2Manager) sync() {
	defer func() {
		// 重新设置定时器
		lm.mu.Lock()
		if lm.running {
			lm.syncTimer.Reset(lm.config.SyncInterval)
		}
		lm.mu.Unlock()
	}()
	
	// 检查是否在离线模式
	if lm.config.OfflineMode {
		log.Debug("Layer2处于离线模式，跳过同步")
		return
	}
	
	// 同步L2状态
	err := lm.syncL2State()
	if err != nil {
		log.Error("同步Layer2状态失败", "错误", err)
		return
	}
	
	// 同步待处理交易
	err = lm.syncPendingTransactions()
	if err != nil {
		log.Error("同步待处理交易失败", "错误", err)
	}
	
	// 同步批次
	err = lm.syncBatches()
	if err != nil {
		log.Error("同步批次失败", "错误", err)
	}
	
	// 更新同步时间
	lm.status.LastSyncTime = time.Now()
}

// 同步Layer2状态
func (lm *Layer2Manager) syncL2State() error {
	// 在实际实现中，获取最新的L2状态
	// 这里仅作为示例实现
	lm.mu.Lock()
	defer lm.mu.Unlock()
	
	// 更新当前L2区块
	lm.status.CurrentL2Block += 1
	
	// 更新Gas价格
	lm.status.L2GasPrice = big.NewInt(1000000000) // 示例值：1 Gwei
	
	log.Debug("同步Layer2状态完成", "区块", lm.status.CurrentL2Block)
	return nil
}

// 同步待处理交易
func (lm *Layer2Manager) syncPendingTransactions() error {
	// 在实际实现中，获取待处理交易状态
	// 这里仅作为示例实现
	lm.mu.Lock()
	defer lm.mu.Unlock()
	
	// 更新待处理交易数
	lm.status.PendingTxCount = len(lm.pendingTxs)
	
	// 检查交易收据
	for txHash := range lm.pendingTxs {
		// 异步获取交易收据
		if lm.asyncProcessor != nil && lm.asyncProcessor.enabled {
			lm.asyncProcessor.queue <- txHash
		} else {
			// 同步获取
			_ = lm.syncTransactionReceipt(txHash)
		}
	}
	
	return nil
}

// 同步交易收据
func (lm *Layer2Manager) syncTransactionReceipt(txHash common.Hash) error {
	// 在实际实现中，从L2获取交易收据
	// 这里仅作为示例实现
	
	// 创建示例收据
	receipt := &Layer2Receipt{
		TxHash:           txHash,
		Status:           1, // 成功
		CumulativeGasUsed: 50000,
		Logs:             make([]*types.Log, 0),
		L2BlockNumber:    lm.status.CurrentL2Block,
		L2TxIndex:        0,
		L1Confirmation:   false,
	}
	
	lm.mu.Lock()
	lm.receipts[txHash] = receipt
	// 如果交易已确认，从待处理中删除
	if receipt.Status == 1 {
		delete(lm.pendingTxs, txHash)
	}
	lm.mu.Unlock()
	
	return nil
}

// 同步批次
func (lm *Layer2Manager) syncBatches() error {
	// 在实际实现中，从L2获取最新批次
	// 这里仅作为示例实现
	
	// 创建新批次
	batchIndex := uint64(len(lm.batches))
	batch := &Layer2Batch{
		BatchIndex:  batchIndex,
		BatchRoot:   common.HexToHash(fmt.Sprintf("0x%x", batchIndex)),
		Timestamp:   time.Now(),
		Transactions: make([][]byte, 0),
		StateRoot:   common.Hash{},
		Verified:    false,
	}
	
	lm.mu.Lock()
	lm.batches[batchIndex] = batch
	lm.status.BatchesProcessed = len(lm.batches)
	lm.mu.Unlock()
	
	// 异步处理批次
	if lm.asyncProcessor != nil && lm.asyncProcessor.enabled {
		lm.asyncProcessor.queue <- batch
	} else {
		// 同步处理
		_ = lm.processBatch(batch)
	}
	
	return nil
}

// 处理批次
func (lm *Layer2Manager) processBatch(batch *Layer2Batch) error {
	// 在实际实现中，处理批次并验证
	// 这里仅作为示例实现
	
	// 验证批次
	if lm.config.LocalProofVerify && lm.proofGenerator != nil {
		// 使用本地证明生成器
		proof, err := lm.generateProofForBatch(batch)
		if err != nil {
			log.Error("生成批次证明失败", "批次", batch.BatchIndex, "错误", err)
			return err
		}
		
		batch.Proof = proof
		lm.verifyBatchProof(batch)
	}
	
	return nil
}

// 生成批次证明
func (lm *Layer2Manager) generateProofForBatch(batch *Layer2Batch) ([]byte, error) {
	if lm.proofGenerator == nil {
		return nil, errors.New("证明生成器未初始化")
	}
	
	lm.proofGenerator.mu.Lock()
	lm.proofGenerator.pendingGeneration[batch.BatchIndex] = true
	lm.proofGenerator.mu.Unlock()
	
	// 模拟证明生成
	proof := []byte(fmt.Sprintf("证明-%d", batch.BatchIndex))
	
	lm.proofGenerator.mu.Lock()
	delete(lm.proofGenerator.pendingGeneration, batch.BatchIndex)
	lm.proofGenerator.generatedProofs[batch.BatchIndex] = proof
	lm.proofGenerator.mu.Unlock()
	
	return proof, nil
}

// 验证批次证明
func (lm *Layer2Manager) verifyBatchProof(batch *Layer2Batch) bool {
	if batch.Proof == nil || len(batch.Proof) == 0 {
		return false
	}
	
	// 在实际实现中，验证批次证明
	// 这里仅作为示例实现
	lm.verifier.mu.Lock()
	lm.verifier.verifiedBatches[batch.BatchIndex] = true
	lm.verifier.mu.Unlock()
	
	batch.Verified = true
	lm.status.ProofsVerified++
	
	return true
}

// 发送Layer2交易
func (lm *Layer2Manager) SendTransaction(tx *types.Transaction) (common.Hash, error) {
	if !lm.running {
		return common.Hash{}, errors.New("Layer2管理器未运行")
	}
	
	if lm.config.OfflineMode {
		return common.Hash{}, errors.New("Layer2处于离线模式")
	}
	
	// 序列化交易
	txBytes, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("序列化交易失败: %v", err)
	}
	
	txHash := tx.Hash()
	
	// 添加到待处理交易
	lm.mu.Lock()
	lm.pendingTxs[txHash] = txBytes
	lm.status.PendingTxCount = len(lm.pendingTxs)
	lm.mu.Unlock()
	
	// 如果启用了直接提交，则立即提交到L2
	if lm.config.DirectSubmission {
		err = lm.submitTransactionToL2(txHash, txBytes)
		if err != nil {
			log.Error("提交交易到L2失败", "哈希", txHash.Hex(), "错误", err)
			// 不返回错误，因为交易仍在待处理队列中
		}
	}
	
	return txHash, nil
}

// 提交交易到Layer2
func (lm *Layer2Manager) submitTransactionToL2(txHash common.Hash, txBytes []byte) error {
	// 在实际实现中，直接将交易提交到L2
	// 这里仅作为示例实现
	log.Debug("提交交易到L2", "哈希", txHash.Hex())
	
	// 模拟交易提交
	time.Sleep(50 * time.Millisecond)
	
	return nil
}

// 获取Layer2交易收据
func (lm *Layer2Manager) GetTransactionReceipt(txHash common.Hash) (*Layer2Receipt, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	
	receipt, exists := lm.receipts[txHash]
	if !exists {
		return nil, fmt.Errorf("找不到交易收据: %s", txHash.Hex())
	}
	
	return receipt, nil
}

// 获取Layer2账户信息
func (lm *Layer2Manager) GetAccountInfo(address common.Address) (*L2AccountInfo, error) {
	// 首先检查缓存
	lm.stateCache.mu.RLock()
	account, exists := lm.stateCache.accounts[address]
	lm.stateCache.mu.RUnlock()
	
	if exists {
		// 更新访问时间
		lm.stateCache.mu.Lock()
		lm.stateCache.accessTimes[address] = time.Now()
		lm.stateCache.mu.Unlock()
		return account, nil
	}
	
	// 如果处于离线模式，且缓存中没有，则返回错误
	if lm.config.OfflineMode {
		return nil, fmt.Errorf("离线模式下，账户 %s 未在缓存中", address.Hex())
	}
	
	// 从L2获取账户信息
	account, err := lm.fetchAccountInfoFromL2(address)
	if err != nil {
		return nil, err
	}
	
	// 添加到缓存
	lm.stateCache.mu.Lock()
	lm.stateCache.accounts[address] = account
	lm.stateCache.accessTimes[address] = time.Now()
	// 更新缓存大小（简化估计）
	lm.stateCache.currentSize += 100 // 假设每个账户约100字节
	lm.stateCache.mu.Unlock()
	
	// 如果缓存超过大小限制，清理
	if lm.stateCache.currentSize > lm.stateCache.maxSize {
		go lm.cleanStateCache()
	}
	
	return account, nil
}

// 从L2获取账户信息
func (lm *Layer2Manager) fetchAccountInfoFromL2(address common.Address) (*L2AccountInfo, error) {
	// 在实际实现中，从L2获取账户信息
	// 这里仅作为示例实现
	account := &L2AccountInfo{
		Address:        address,
		Balance:        big.NewInt(0),
		Nonce:          0,
		StorageRoot:    common.Hash{},
		CodeHash:       nil,
		LastUpdateTime: time.Now(),
		Verified:       false,
	}
	
	return account, nil
}

// 清理状态缓存
func (lm *Layer2Manager) cleanStateCache() {
	lm.stateCache.mu.Lock()
	defer lm.stateCache.mu.Unlock()
	
	if lm.stateCache.currentSize <= lm.stateCache.maxSize*80/100 {
		// 已经在可接受范围内
		return
	}
	
	// 按最后访问时间排序
	type addrTime struct {
		addr common.Address
		time time.Time
	}
	
	addrTimes := make([]addrTime, 0, len(lm.stateCache.accessTimes))
	for addr, t := range lm.stateCache.accessTimes {
		addrTimes = append(addrTimes, addrTime{addr, t})
	}
	
	// 按时间排序（最早的在前）
	sort.Slice(addrTimes, func(i, j int) bool {
		return addrTimes[i].time.Before(addrTimes[j].time)
	})
	
	// 删除最旧的项目，直到缓存大小适中
	for _, at := range addrTimes {
		if lm.stateCache.currentSize <= lm.stateCache.maxSize*80/100 {
			break
		}
		
		// 删除账户
		delete(lm.stateCache.accounts, at.addr)
		delete(lm.stateCache.accessTimes, at.addr)
		
		// 删除存储
		if storage, ok := lm.stateCache.storage[at.addr]; ok {
			lm.stateCache.currentSize -= len(storage) * 64 // 估计每个存储项64字节
			delete(lm.stateCache.storage, at.addr)
		}
		
		lm.stateCache.currentSize -= 100 // 减去账户大小
	}
	
	log.Debug("清理L2状态缓存完成", 
		"当前大小", lm.stateCache.currentSize,
		"最大大小", lm.stateCache.maxSize,
		"剩余账户", len(lm.stateCache.accounts))
}

// Stop 停止Layer2管理器
func (lm *Layer2Manager) Stop() error {
	lm.mu.Lock()
	
	if !lm.running {
		lm.mu.Unlock()
		return errors.New("Layer2管理器未运行")
	}
	
	// 停止同步定时器
	if lm.syncTimer != nil {
		lm.syncTimer.Stop()
	}
	
	lm.running = false
	lm.mu.Unlock()
	
	// 取消上下文
	lm.cancel()
	
	// 等待异步处理器
	if lm.asyncProcessor != nil && lm.asyncProcessor.enabled {
		lm.asyncProcessor.wg.Wait()
	}
	
	log.Info("Layer2管理器已停止")
	return nil
}

// GetLayer2Status 获取Layer2状态
func (lm *Layer2Manager) GetLayer2Status() *Layer2Status {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.status
}

// 获取批次信息
func (lm *Layer2Manager) GetBatchInfo(batchIndex uint64) (*Layer2Batch, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	
	batch, exists := lm.batches[batchIndex]
	if !exists {
		return nil, fmt.Errorf("找不到批次: %d", batchIndex)
	}
	
	return batch, nil
}

// 预取账户信息（批量）- 新增
func (lm *Layer2Manager) PrefetchAccounts(addresses []common.Address) error {
	if !lm.config.PrefetchState {
		return nil // 预取未启用，忽略
	}
	
	// 筛选未缓存的地址
	lm.stateCache.mu.RLock()
	missingAddrs := make([]common.Address, 0)
	for _, addr := range addresses {
		if _, exists := lm.stateCache.accounts[addr]; !exists {
			missingAddrs = append(missingAddrs, addr)
		}
	}
	lm.stateCache.mu.RUnlock()
	
	if len(missingAddrs) == 0 {
		return nil // 所有地址已在缓存中
	}
	
	// 如果启用了批处理请求
	if lm.config.BatchedRequests && lm.requestBatcher != nil {
		lm.requestBatcher.mu.Lock()
		for _, addr := range missingAddrs {
			lm.requestBatcher.pendingRequests = append(
				lm.requestBatcher.pendingRequests,
				struct{ action string; address common.Address }{"fetchAccount", addr},
			)
		}
		lm.requestBatcher.mu.Unlock()
		return nil
	}
	
	// 否则直接获取
	for _, addr := range missingAddrs {
		_, err := lm.GetAccountInfo(addr)
		if err != nil {
			return err
		}
	}
	
	return nil
}

// SetOfflineMode 设置离线模式 - 新增
func (lm *Layer2Manager) SetOfflineMode(offline bool) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	
	if lm.config.OfflineMode != offline {
		lm.config.OfflineMode = offline
		log.Info("设置Layer2离线模式", "离线", offline)
	}
} 