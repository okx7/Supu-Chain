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
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

// 同步模式常量
const (
	StatelessModeBasic    = 1 // 基础无状态模式（只同步区块头）
	StatelessModeZK       = 2 // 零知识证明无状态模式
	StatelessModeFull     = 3 // 完整无状态模式（包含Merkle证明）
	StatelessModeZKRollup = 4 // ZK Rollup无状态模式 - 新增
)

// ZK证明类型
const (
	ZKProofTypeGroth16    = "groth16"    // Groth16证明系统（更小的证明但需要可信设置）
	ZKProofTypePlonk      = "plonk"      // PLONK证明系统（通用且效率高）
	ZKProofTypeStark      = "stark"      // STARK证明系统（后量子安全）
	ZKProofTypeHalo2      = "halo2"      // Halo2证明系统（递归证明支持）
	ZKProofTypeMarlin     = "marlin"     // Marlin证明系统（高性能）
	ZKProofTypeSuperSonic = "supersonic" // SuperSonic证明系统
)

// StatelessClientConfig 无状态客户端配置
type StatelessClientConfig struct {
	Mode                 int           // 无状态模式 (1-4)
	HeaderSyncInterval   time.Duration // 区块头同步间隔
	StateProofInterval   time.Duration // 状态证明同步间隔
	MaxHeaderBatchSize   int           // 最大区块头批量同步数
	ZKProofEnabled       bool          // 启用ZK证明
	ZKProofType          string        // ZK证明类型 - 新增
	MerkleProofEnabled   bool          // 启用Merkle证明
	StateVerificationOnly bool         // 仅状态验证模式
	ProofCacheTTL        time.Duration // 证明缓存TTL
	DeltaStateEnabled    bool          // 增量状态同步启用
	OfflineProofValidation bool        // 离线证明验证
	OnDemandStateSync    bool          // 按需状态同步
	MaxStateCacheSize    int           // 最大状态缓存大小(MB)
	PrioritizeAccounts   []common.Address // 优先同步的账户
	ZKRollupEnabled      bool          // 启用ZK Rollup - 新增
	ZKRollupContract     common.Address // ZK Rollup合约地址 - 新增
	BatchVerification    bool          // 批量验证 - 新增
	RecursiveProofs      bool          // 递归证明支持 - 新增
}

// StatelessClient 无状态客户端
type StatelessClient struct {
	config           *StatelessClientConfig // 配置
	chainConfig      *params.ChainConfig    // 链配置
	
	// 状态管理
	headers          []*types.Header        // 区块头缓存
	stateProofs      map[common.Hash]*StateProof // 状态证明映射
	blockInfos       map[uint64]*BlockInfo  // 区块信息映射
	
	// ZK证明系统
	zkVerifier       *ZKStateVerifier       // ZK状态验证器
	
	// Merkle证明系统
	merkleVerifier   *MerkleStateVerifier   // Merkle状态验证器
	
	// 本地状态缓存
	stateCache       *StateCache            // 状态缓存
	
	// 同步状态
	latestHeader     *types.Header          // 最新区块头
	syncProgress     *SyncProgress          // 同步进度
	
	// 控制
	isRunning        bool                   // 是否运行中
	mu               sync.RWMutex           // 互斥锁
	ctx              context.Context        // 上下文
	cancel           context.CancelFunc     // 取消函数
	wg               sync.WaitGroup         // 等待组
}

// StateProof 状态证明
type StateProof struct {
	BlockHash     common.Hash    // 区块哈希
	StateRoot     common.Hash    // 状态根
	Proof         []byte         // 证明数据
	AccountProofs map[common.Address][]byte // 账户证明
	StorageProofs map[common.Hash][]byte    // 存储证明
	VerifiedAt    time.Time      // 验证时间
	ProofType     string         // 证明类型 (merkle/zk)
}

// BlockInfo 区块信息
type BlockInfo struct {
	Hash        common.Hash     // 区块哈希
	Number      uint64          // 区块高度
	Time        uint64          // 区块时间
	StateRoot   common.Hash     // 状态根
	TxCount     int             // 交易数量
	HasProof    bool            // 是否有证明
	ProofType   string          // 证明类型
}

// SyncProgress 同步进度
type SyncProgress struct {
	StartingBlock uint64         // 起始区块
	CurrentBlock  uint64         // 当前区块
	HighestBlock  uint64         // 最高区块
	HeadersReceived int          // 接收的区块头数量
	ProofsReceived int           // 接收的证明数量
	ProofsVerified int           // 验证的证明数量
	LastSyncTime  time.Time      // 最后同步时间
}

// StateCache 状态缓存
type StateCache struct {
	accounts    map[common.Address]*types.StateAccount // 账户状态
	storage     map[common.Address]map[common.Hash]common.Hash // 存储状态
	code        map[common.Address][]byte            // 合约代码
	cacheSize   int                                  // 缓存大小(bytes)
	maxSize     int                                  // 最大缓存大小(bytes)
	lastAccess  map[common.Address]time.Time         // 最后访问时间
	mu          sync.RWMutex                         // 互斥锁
}

// ZKStateVerifier ZK状态验证器
type ZKStateVerifier struct {
	verifyingKeys   map[string][]byte    // 验证密钥
	prover          common.Address       // 证明者地址
	lastProofBlock  uint64               // 最后证明区块
	mu              sync.RWMutex         // 互斥锁
}

// MerkleStateVerifier Merkle状态验证器
type MerkleStateVerifier struct {
	trie            *trie.Trie           // Merkle树
	lastStateRoot   common.Hash          // 最后状态根
	mu              sync.RWMutex         // 互斥锁
}

// NewStatelessClient 创建新的无状态客户端
func NewStatelessClient(config *StatelessClientConfig, chainConfig *params.ChainConfig) (*StatelessClient, error) {
	if config == nil {
		return nil, errors.New("配置不能为空")
	}
	
	// 验证配置
	if config.Mode < StatelessModeBasic || config.Mode > StatelessModeZKRollup {
		return nil, fmt.Errorf("无效的无状态模式: %d", config.Mode)
	}
	
	// 验证ZK证明类型
	if config.ZKProofEnabled && config.ZKProofType != "" {
		switch config.ZKProofType {
		case ZKProofTypeGroth16, ZKProofTypePlonk, ZKProofTypeStark, ZKProofTypeHalo2, ZKProofTypeMarlin, ZKProofTypeSuperSonic:
			// 有效的证明类型
		default:
			return nil, fmt.Errorf("不支持的ZK证明类型: %s", config.ZKProofType)
		}
	}
	
	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	
	// 创建客户端
	client := &StatelessClient{
		config:        config,
		chainConfig:   chainConfig,
		headers:       make([]*types.Header, 0, 1000),  // 默认缓存1000个区块头
		stateProofs:   make(map[common.Hash]*StateProof),
		blockInfos:    make(map[uint64]*BlockInfo),
		stateCache:    newStateCache(config.MaxStateCacheSize * 1024 * 1024), // 转换为字节
		syncProgress:  &SyncProgress{LastSyncTime: time.Now()},
		ctx:           ctx,
		cancel:        cancel,
	}
	
	// 初始化ZK验证器（如果启用）
	if config.ZKProofEnabled {
		// 根据证明类型创建相应的验证器
		zkVerifierConfig := &ZKStateVerifierConfig{
			ProofType:            config.ZKProofType,
			UseIncrementalProofs: config.DeltaStateEnabled,
			BatchVerificationSize: 10, // 默认批量验证大小
			OfflineVerification:  config.OfflineProofValidation,
			AdvancedChecks:       true,
			UseTrustedSetup:      config.ZKProofType == ZKProofTypeGroth16 || config.ZKProofType == ZKProofTypePlonk,
		}
		
		zkVerifier, err := NewZKStateVerifier(zkVerifierConfig)
		if err != nil {
			return nil, fmt.Errorf("创建ZK验证器失败: %v", err)
		}
		
		client.zkVerifier = zkVerifier
		log.Info("ZK验证器已初始化", "类型", config.ZKProofType)
	}
	
	// 初始化Merkle验证器
	if config.MerkleProofEnabled {
		client.merkleVerifier = &MerkleStateVerifier{}
	}
	
	// 初始化ZK Rollup支持（如果启用）
	if config.ZKRollupEnabled {
		// 这里添加ZK Rollup初始化代码
		log.Info("ZK Rollup模式已启用", "合约地址", config.ZKRollupContract.Hex())
	}
	
	return client, nil
}

// newStateCache 创建新的状态缓存
func newStateCache(maxSize int) *StateCache {
	return &StateCache{
		accounts:   make(map[common.Address]*types.StateAccount),
		storage:    make(map[common.Address]map[common.Hash]common.Hash),
		code:       make(map[common.Address][]byte),
		lastAccess: make(map[common.Address]time.Time),
		maxSize:    maxSize,
	}
}

// Start 启动无状态客户端
func (sc *StatelessClient) Start() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	if sc.isRunning {
		return errors.New("无状态客户端已启动")
	}
	
	// 开始同步任务
	sc.startSyncTasks()
	
	sc.isRunning = true
	log.Info("无状态客户端已启动", 
		"模式", sc.config.Mode, 
		"ZK证明", sc.config.ZKProofEnabled, 
		"Merkle证明", sc.config.MerkleProofEnabled)
	
	return nil
}

// startSyncTasks 启动同步任务
func (sc *StatelessClient) startSyncTasks() {
	// 启动区块头同步任务
	sc.wg.Add(1)
	go sc.headerSyncLoop()
	
	// 如果不是仅区块头模式，启动状态证明同步任务
	if sc.config.Mode > StatelessModeBasic {
		sc.wg.Add(1)
		go sc.stateProofSyncLoop()
		
		// 启动状态缓存维护任务
		sc.wg.Add(1)
		go sc.stateCacheMaintenanceLoop()
	}
}

// Stop 停止无状态客户端
func (sc *StatelessClient) Stop() error {
	sc.mu.Lock()
	
	if !sc.isRunning {
		sc.mu.Unlock()
		return errors.New("无状态客户端未启动")
	}
	
	sc.mu.Unlock()
	
	// 取消上下文
	sc.cancel()
	
	// 等待所有任务结束
	sc.wg.Wait()
	
	sc.mu.Lock()
	sc.isRunning = false
	sc.mu.Unlock()
	
	log.Info("无状态客户端已停止")
	return nil
}

// headerSyncLoop 区块头同步循环
func (sc *StatelessClient) headerSyncLoop() {
	defer sc.wg.Done()
	
	ticker := time.NewTicker(sc.config.HeaderSyncInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-sc.ctx.Done():
			return
			
		case <-ticker.C:
			if err := sc.syncHeaders(); err != nil {
				log.Error("同步区块头失败", "错误", err)
			}
		}
	}
}

// stateProofSyncLoop 状态证明同步循环
func (sc *StatelessClient) stateProofSyncLoop() {
	defer sc.wg.Done()
	
	ticker := time.NewTicker(sc.config.StateProofInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-sc.ctx.Done():
			return
			
		case <-ticker.C:
			if err := sc.syncStateProofs(); err != nil {
				log.Error("同步状态证明失败", "错误", err)
			}
		}
	}
}

// stateCacheMaintenanceLoop 状态缓存维护循环
func (sc *StatelessClient) stateCacheMaintenanceLoop() {
	defer sc.wg.Done()
	
	// 每10分钟清理一次缓存
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-sc.ctx.Done():
			return
			
		case <-ticker.C:
			sc.cleanStateCache()
		}
	}
}

// syncHeaders 同步区块头
func (sc *StatelessClient) syncHeaders() error {
	// 在实际实现中，这里应该从网络获取区块头
	// 这里仅作为示例实现
	
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	// 获取当前同步的区块高度
	currentBlock := sc.syncProgress.CurrentBlock
	
	// 模拟从网络获取新区块头
	// 在实际实现中，应该使用p2p或rpc调用
	newHeaders := sc.fetchNewHeaders(currentBlock, sc.config.MaxHeaderBatchSize)
	
	if len(newHeaders) == 0 {
		return nil
	}
	
	// 验证和处理新区块头
	for _, header := range newHeaders {
		// 验证区块头
		if err := sc.validateHeader(header); err != nil {
			log.Warn("验证区块头失败", "高度", header.Number, "错误", err)
			continue
		}
		
		// 添加到缓存
		sc.headers = append(sc.headers, header)
		
		// 更新区块信息
		sc.blockInfos[header.Number.Uint64()] = &BlockInfo{
			Hash:      header.Hash(),
			Number:    header.Number.Uint64(),
			Time:      header.Time,
			StateRoot: header.Root,
			HasProof:  false,
		}
		
		// 更新同步进度
		sc.syncProgress.CurrentBlock = header.Number.Uint64()
		sc.syncProgress.HeadersReceived++
	}
	
	// 更新最新区块头
	sc.latestHeader = newHeaders[len(newHeaders)-1]
	sc.syncProgress.LastSyncTime = time.Now()
	
	// 控制缓存大小
	if len(sc.headers) > 1000 {
		// 只保留最新的1000个区块头
		sc.headers = sc.headers[len(sc.headers)-1000:]
	}
	
	log.Debug("同步区块头完成", 
		"当前高度", sc.syncProgress.CurrentBlock, 
		"同步数量", len(newHeaders))
	
	return nil
}

// syncStateProofs 同步状态证明
func (sc *StatelessClient) syncStateProofs() error {
	// 在实际实现中，这里应该从网络获取状态证明
	// 这里仅作为示例实现
	
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	// 获取当前同步状态
	currentBlock := sc.syncProgress.CurrentBlock
	
	// 确定需要同步状态证明的区块
	// 这里简化处理，每100个区块同步一次状态证明
	if currentBlock%100 != 0 {
		return nil
	}
	
	// 获取该区块的信息
	blockInfo, exists := sc.blockInfos[currentBlock]
	if !exists {
		return fmt.Errorf("找不到区块信息: %d", currentBlock)
	}
	
	// 如果已经有证明，跳过
	if blockInfo.HasProof {
		return nil
	}
	
	// 模拟从网络获取状态证明
	proof, err := sc.fetchStateProof(blockInfo.Hash)
	if err != nil {
		return fmt.Errorf("获取状态证明失败: %v", err)
	}
	
	// 验证证明
	if err := sc.verifyStateProof(proof); err != nil {
		return fmt.Errorf("验证状态证明失败: %v", err)
	}
	
	// 存储证明
	sc.stateProofs[blockInfo.Hash] = proof
	
	// 更新区块信息
	blockInfo.HasProof = true
	blockInfo.ProofType = proof.ProofType
	
	// 更新同步进度
	sc.syncProgress.ProofsReceived++
	sc.syncProgress.ProofsVerified++
	
	log.Debug("同步状态证明完成", "区块", currentBlock, "类型", proof.ProofType)
	
	return nil
}

// validateHeader 验证区块头
func (sc *StatelessClient) validateHeader(header *types.Header) error {
	// 在实际实现中，应该进行完整的区块头验证
	// 包括PoW/PoS验证、时间戳验证、难度验证等
	// 这里仅作为示例实现
	
	if header == nil {
		return errors.New("区块头为空")
	}
	
	// 检查区块高度
	if sc.latestHeader != nil && header.Number.Uint64() <= sc.latestHeader.Number.Uint64() {
		return fmt.Errorf("区块高度不合法: 当前=%d, 新区块=%d", 
			sc.latestHeader.Number.Uint64(), header.Number.Uint64())
	}
	
	return nil
}

// fetchNewHeaders 获取新区块头
func (sc *StatelessClient) fetchNewHeaders(from uint64, limit int) []*types.Header {
	// 在实际实现中，这里应该从网络获取新区块头
	// 这里仅作为示例，创建一些虚拟的区块头
	headers := make([]*types.Header, 0)
	
	// 模拟新区块头
	for i := 0; i < limit; i++ {
		blockNum := from + uint64(i) + 1
		
		header := &types.Header{
			Number:     big.NewInt(int64(blockNum)),
			Time:       uint64(time.Now().Unix()),
			Difficulty: big.NewInt(1),
			Root:       common.HexToHash(fmt.Sprintf("0x%x", blockNum)),
		}
		
		headers = append(headers, header)
	}
	
	return headers
}

// fetchStateProof 获取状态证明
func (sc *StatelessClient) fetchStateProof(blockHash common.Hash) (*StateProof, error) {
	// 在实际实现中，这里应该从网络获取状态证明
	// 这里仅作为示例，创建一个虚拟的状态证明
	
	proofType := "merkle"
	if sc.config.ZKProofEnabled {
		proofType = "zk"
	}
	
	proof := &StateProof{
		BlockHash:     blockHash,
		StateRoot:     common.HexToHash(fmt.Sprintf("0x%x", blockHash)),
		Proof:         []byte("模拟证明数据"),
		AccountProofs: make(map[common.Address][]byte),
		StorageProofs: make(map[common.Hash][]byte),
		VerifiedAt:    time.Now(),
		ProofType:     proofType,
	}
	
	return proof, nil
}

// verifyStateProof 验证状态证明
func (sc *StatelessClient) verifyStateProof(proof *StateProof) error {
	// 参数验证 - 添加安全检查
	if proof == nil {
		return errors.New("证明对象为空") // 检查输入不为空
	}
	
	// 区块哈希验证
	if proof.BlockHash == (common.Hash{}) {
		return errors.New("区块哈希无效") // 检查区块哈希有效性
	}
	
	// 状态根验证
	if proof.StateRoot == (common.Hash{}) {
		return errors.New("状态根无效") // 检查状态根有效性
	}
	
	// 证明数据验证
	if len(proof.Proof) == 0 {
		return errors.New("证明数据为空") // 检查证明数据
	}
	
	// 时间戳验证 - 防止重放攻击
	if time.Since(proof.VerifiedAt) > sc.config.MaxProofAge {
		return errors.New("证明已过期") // 检查证明是否过期
	}
	
	// 检查是否是重放的证明
	proofID := proof.BlockHash.String() + proof.StateRoot.String()
	sc.mu.Lock()
	if timestamp, exists := sc.verifiedProofs[proofID]; exists {
		if proof.VerifiedAt.Before(timestamp) {
			sc.mu.Unlock()
			return errors.New("检测到重放的证明") // 重放保护
		}
	}
	// 记录验证时间戳
	sc.verifiedProofs[proofID] = proof.VerifiedAt
	sc.mu.Unlock()
	
	// 在实际实现中，这里应该根据证明类型进行验证
	// 这里仅作为示例实现
	
	switch proof.ProofType {
	case "merkle":
		if sc.merkleVerifier == nil {
			return errors.New("Merkle验证器未初始化")
		}
		return sc.verifyMerkleProof(proof)
		
	case "zk":
		if sc.zkVerifier == nil {
			return errors.New("ZK验证器未初始化")
		}
		
		// 创建ZK状态证明
		zkProof := &ZKStateProof{
			ProofData:     proof.Proof,
			BlockHash:     proof.BlockHash,
			StateRoot:     proof.StateRoot,
			ProofType:     sc.config.ZKProofType,
			Timestamp:     time.Now(),
			PublicInputs:  [][]byte{proof.BlockHash.Bytes(), proof.StateRoot.Bytes()}, // 添加公共输入
		}
		
		// 安全检查: 验证证明数据的完整性
		if len(zkProof.ProofData) < sc.config.MinProofSize {
			return errors.New("ZK证明数据过小，可能不完整")
		}
		
		// 将账户证明转换为ZK格式
		for addr, proofData := range proof.AccountProofs {
			// 安全检查: 验证地址有效性
			if addr == (common.Address{}) {
				log.Warn("跳过无效地址的账户证明")
				continue
			}
			
			// 安全检查: 验证证明数据有效性
			if len(proofData) == 0 {
				log.Warn("跳过空证明数据", "地址", addr.Hex())
				continue
			}
			
			accountProof := AccountProof{
				Address:   addr,
				Proof:     proofData,
			}
			zkProof.AccountProofs = append(zkProof.AccountProofs, accountProof)
		}
		
		// 将存储证明转换为ZK格式
		for key, proofData := range proof.StorageProofs {
			parts := key.Bytes()
			// 安全检查: 验证键有效性
			if len(parts) < 20 {
				log.Warn("跳过无效键的存储证明", "键", key.Hex())
				continue
			}
			
			addr := common.BytesToAddress(parts[:20])
			storageKey := common.BytesToHash(parts[20:])
			
			// 安全检查: 验证证明数据有效性
			if len(proofData) == 0 {
				log.Warn("跳过空证明数据", "地址", addr.Hex(), "键", storageKey.Hex())
				continue
			}
			
			storageProof := StorageProof{
				Address:    addr,
				StorageKey: storageKey,
				Proof:      proofData,
			}
			zkProof.StorageProofs = append(zkProof.StorageProofs, storageProof)
		}
		
		// 检查要验证的证明是否为空
		if len(zkProof.AccountProofs) == 0 && len(zkProof.StorageProofs) == 0 {
			return errors.New("没有有效的账户或存储证明可验证")
		}
		
		// 添加日志，便于审计和调试
		log.Debug("验证ZK状态证明", 
			"区块哈希", zkProof.BlockHash.Hex()[:10]+"...", 
			"账户数量", len(zkProof.AccountProofs),
			"存储数量", len(zkProof.StorageProofs))
		
		return sc.zkVerifier.VerifyStateProof(zkProof)
		
	case "zkrollup":
		// ZK Rollup证明验证
		if !sc.config.ZKRollupEnabled {
			return errors.New("ZK Rollup未启用")
		}
		return sc.verifyZKRollupProof(proof)
		
	default:
		return fmt.Errorf("不支持的证明类型: %s", proof.ProofType)
	}
}

// verifyMerkleProof 验证Merkle证明
func (sc *StatelessClient) verifyMerkleProof(proof *StateProof) error {
	// 在实际实现中，这里应该验证Merkle证明
	// 这里仅作为示例实现
	return nil
}

// verifyZKRollupProof 验证ZK Rollup证明
func (sc *StatelessClient) verifyZKRollupProof(proof *StateProof) error {
	// 实际实现中，这里应该验证ZK Rollup证明
	// 目前仅作为示例实现
	log.Debug("验证ZK Rollup证明", "区块哈希", proof.BlockHash.Hex())
	return nil
}

// cleanStateCache 清理状态缓存
func (sc *StatelessClient) cleanStateCache() {
	sc.stateCache.mu.Lock()
	defer sc.stateCache.mu.Unlock()
	
	if sc.stateCache.cacheSize <= sc.stateCache.maxSize {
		return
	}
	
	log.Debug("开始清理状态缓存", 
		"当前大小", sc.stateCache.cacheSize/1024/1024, "MB", 
		"最大大小", sc.stateCache.maxSize/1024/1024, "MB")
	
	// 按最后访问时间排序
	type accountAccessTime struct {
		address   common.Address
		lastAccess time.Time
	}
	
	accounts := make([]accountAccessTime, 0, len(sc.stateCache.lastAccess))
	for addr, t := range sc.stateCache.lastAccess {
		accounts = append(accounts, accountAccessTime{addr, t})
	}
	
	// 按最后访问时间排序（最老的在前面）
	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].lastAccess.Before(accounts[j].lastAccess)
	})
	
	// 删除最老的缓存，直到大小符合要求
	for _, acc := range accounts {
		if sc.stateCache.cacheSize <= sc.stateCache.maxSize*80/100 { // 清理到80%
			break
		}
		
		addr := acc.address
		
		// 计算这个账户占用的缓存大小
		accountSize := 0
		
		// 账户状态大小
		if acct, ok := sc.stateCache.accounts[addr]; ok {
			accountSize += 64 // 估计账户状态大小
			delete(sc.stateCache.accounts, addr)
		}
		
		// 存储大小
		if storage, ok := sc.stateCache.storage[addr]; ok {
			accountSize += len(storage) * 64 // 估计每个存储项大小
			delete(sc.stateCache.storage, addr)
		}
		
		// 代码大小
		if code, ok := sc.stateCache.code[addr]; ok {
			accountSize += len(code)
			delete(sc.stateCache.code, addr)
		}
		
		// 更新缓存大小
		sc.stateCache.cacheSize -= accountSize
		
		// 删除最后访问时间记录
		delete(sc.stateCache.lastAccess, addr)
		
		log.Debug("从缓存中移除账户", "地址", addr.Hex(), "大小", accountSize)
	}
	
	log.Debug("状态缓存清理完成", "当前大小", sc.stateCache.cacheSize/1024/1024, "MB")
}

// GetAccountState 获取账户状态
func (sc *StatelessClient) GetAccountState(addr common.Address) (*types.StateAccount, error) {
	if !sc.isRunning {
		return nil, errors.New("无状态客户端未启动")
	}
	
	// 首先从缓存中查找
	sc.stateCache.mu.RLock()
	account, exists := sc.stateCache.accounts[addr]
	sc.stateCache.mu.RUnlock()
	
	if exists {
		// 更新最后访问时间
		sc.stateCache.mu.Lock()
		sc.stateCache.lastAccess[addr] = time.Now()
		sc.stateCache.mu.Unlock()
		
		return account, nil
	}
	
	// 如果缓存中没有，则从状态证明中获取
	sc.mu.RLock()
	latestHeader := sc.latestHeader
	sc.mu.RUnlock()
	
	if latestHeader == nil {
		return nil, errors.New("没有可用的区块头")
	}
	
	// 获取最新的状态证明
	sc.mu.RLock()
	blockHash := latestHeader.Hash()
	proof, hasProof := sc.stateProofs[blockHash]
	sc.mu.RUnlock()
	
	if !hasProof {
		// 如果没有最新区块的证明，查找最近的区块证明
		proof = sc.findNearestStateProof(latestHeader.Number.Uint64())
		if proof == nil {
			// 如果处于按需同步模式，则请求状态证明
			if sc.config.OnDemandStateSync {
				var err error
				proof, err = sc.requestAccountProof(addr, blockHash)
				if err != nil {
					return nil, fmt.Errorf("请求账户证明失败: %v", err)
				}
			} else {
				return nil, errors.New("没有可用的状态证明")
			}
		}
	}
	
	// 从证明中提取账户状态
	account, err := sc.extractAccountFromProof(addr, proof)
	if err != nil {
		return nil, fmt.Errorf("从证明中提取账户失败: %v", err)
	}
	
	// 添加到缓存
	sc.stateCache.mu.Lock()
	sc.stateCache.accounts[addr] = account
	sc.stateCache.lastAccess[addr] = time.Now()
	// 更新缓存大小（简化估计）
	sc.stateCache.cacheSize += 64
	sc.stateCache.mu.Unlock()
	
	return account, nil
}

// requestAccountProof 请求账户证明
func (sc *StatelessClient) requestAccountProof(addr common.Address, blockHash common.Hash) (*StateProof, error) {
	// 在实际实现中，这里应该从网络请求特定账户的证明
	// 这里仅作为示例实现
	proof := &StateProof{
		BlockHash:     blockHash,
		StateRoot:     common.Hash{},
		AccountProofs: make(map[common.Address][]byte),
		ProofType:     "merkle",
	}
	
	// 模拟账户证明数据
	proof.AccountProofs[addr] = []byte("模拟账户证明数据")
	
	return proof, nil
}

// extractAccountFromProof 从证明中提取账户
func (sc *StatelessClient) extractAccountFromProof(addr common.Address, proof *StateProof) (*types.StateAccount, error) {
	// 在实际实现中，这里应该解析证明并提取账户状态
	// 这里仅作为示例实现
	
	// 检查是否有该账户的证明
	accountProof, exists := proof.AccountProofs[addr]
	if !exists {
		return nil, fmt.Errorf("证明中没有账户 %s 的数据", addr.Hex())
	}
	
	// 解析证明并返回账户状态（模拟）
	account := &types.StateAccount{
		Nonce:    0,
		Balance:  big.NewInt(100),
		Root:     common.Hash{},
		CodeHash: nil,
	}
	
	return account, nil
}

// findNearestStateProof 查找最近的状态证明
func (sc *StatelessClient) findNearestStateProof(blockNumber uint64) *StateProof {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	
	// 从当前区块向前查找，找到最近的有状态证明的区块
	for num := blockNumber; num > 0; num-- {
		blockInfo, exists := sc.blockInfos[num]
		if !exists || !blockInfo.HasProof {
			continue
		}
		
		proof, exists := sc.stateProofs[blockInfo.Hash]
		if exists {
			return proof
		}
	}
	
	return nil
}

// GetStorageAt 获取存储数据
func (sc *StatelessClient) GetStorageAt(addr common.Address, key common.Hash) (common.Hash, error) {
	if !sc.isRunning {
		return common.Hash{}, errors.New("无状态客户端未启动")
	}
	
	// 首先从缓存中查找
	sc.stateCache.mu.RLock()
	storage, exists := sc.stateCache.storage[addr]
	var value common.Hash
	var found bool
	if exists {
		value, found = storage[key]
	}
	sc.stateCache.mu.RUnlock()
	
	if found {
		// 更新最后访问时间
		sc.stateCache.mu.Lock()
		sc.stateCache.lastAccess[addr] = time.Now()
		sc.stateCache.mu.Unlock()
		
		return value, nil
	}
	
	// 如果缓存中没有，则从状态证明中获取
	sc.mu.RLock()
	latestHeader := sc.latestHeader
	sc.mu.RUnlock()
	
	if latestHeader == nil {
		return common.Hash{}, errors.New("没有可用的区块头")
	}
	
	// 请求存储证明
	proof, err := sc.requestStorageProof(addr, key, latestHeader.Hash())
	if err != nil {
		return common.Hash{}, fmt.Errorf("请求存储证明失败: %v", err)
	}
	
	// 从证明中提取存储值
	value, err = sc.extractStorageFromProof(addr, key, proof)
	if err != nil {
		return common.Hash{}, fmt.Errorf("从证明中提取存储失败: %v", err)
	}
	
	// 添加到缓存
	sc.stateCache.mu.Lock()
	if sc.stateCache.storage[addr] == nil {
		sc.stateCache.storage[addr] = make(map[common.Hash]common.Hash)
	}
	sc.stateCache.storage[addr][key] = value
	sc.stateCache.lastAccess[addr] = time.Now()
	// 更新缓存大小（简化估计）
	sc.stateCache.cacheSize += 64
	sc.stateCache.mu.Unlock()
	
	return value, nil
}

// requestStorageProof 请求存储证明
func (sc *StatelessClient) requestStorageProof(addr common.Address, key common.Hash, blockHash common.Hash) (*StateProof, error) {
	// 在实际实现中，这里应该从网络请求特定存储的证明
	// 这里仅作为示例实现
	storageKey := addr.Hex() + "-" + key.Hex()
	proofKey := common.HexToHash(storageKey)
	
	proof := &StateProof{
		BlockHash:     blockHash,
		StateRoot:     common.Hash{},
		StorageProofs: make(map[common.Hash][]byte),
		ProofType:     "merkle",
	}
	
	// 模拟存储证明数据
	proof.StorageProofs[proofKey] = []byte("模拟存储证明数据")
	
	return proof, nil
}

// extractStorageFromProof 从证明中提取存储
func (sc *StatelessClient) extractStorageFromProof(addr common.Address, key common.Hash, proof *StateProof) (common.Hash, error) {
	// 在实际实现中，这里应该解析证明并提取存储值
	// 这里仅作为示例实现
	
	// 构造存储键
	storageKey := addr.Hex() + "-" + key.Hex()
	proofKey := common.HexToHash(storageKey)
	
	// 检查是否有该存储的证明
	storageProof, exists := proof.StorageProofs[proofKey]
	if !exists {
		return common.Hash{}, fmt.Errorf("证明中没有存储 %s 的数据", key.Hex())
	}
	
	// 解析证明并返回存储值（模拟）
	value := common.HexToHash("0x123456")
	
	return value, nil
}

// GetSyncProgress 获取同步进度
func (sc *StatelessClient) GetSyncProgress() *SyncProgress {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	
	// 返回副本
	progress := *sc.syncProgress
	return &progress
}

// GetLatestHeader 获取最新区块头
func (sc *StatelessClient) GetLatestHeader() *types.Header {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	
	return sc.latestHeader
}

// GetHeaderByNumber 通过区块高度获取区块头
func (sc *StatelessClient) GetHeaderByNumber(number uint64) *types.Header {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	
	for _, header := range sc.headers {
		if header.Number.Uint64() == number {
			return header
		}
	}
	
	return nil
}

// GetHeaderByHash 通过区块哈希获取区块头
func (sc *StatelessClient) GetHeaderByHash(hash common.Hash) *types.Header {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	
	for _, header := range sc.headers {
		if header.Hash() == hash {
			return header
		}
	}
	
	return nil
}

// IsSyncing 是否正在同步
func (sc *StatelessClient) IsSyncing() bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	
	// 如果最后同步时间在30秒内，认为正在同步
	return time.Since(sc.syncProgress.LastSyncTime) < 30*time.Second
}

// GetCacheStats 获取缓存统计
func (sc *StatelessClient) GetCacheStats() map[string]interface{} {
	sc.stateCache.mu.RLock()
	defer sc.stateCache.mu.RUnlock()
	
	return map[string]interface{}{
		"accountCount": len(sc.stateCache.accounts),
		"storageCount": func() int {
			count := 0
			for _, storage := range sc.stateCache.storage {
				count += len(storage)
			}
			return count
		}(),
		"codeCount":   len(sc.stateCache.code),
		"cacheSize":   sc.stateCache.cacheSize,
		"maxSize":     sc.stateCache.maxSize,
		"usagePercent": float64(sc.stateCache.cacheSize) / float64(sc.stateCache.maxSize) * 100,
	}
}

// GetProofStats 获取证明统计
func (sc *StatelessClient) GetProofStats() map[string]interface{} {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	
	zkProofs := 0
	merkleProofs := 0
	
	for _, proof := range sc.stateProofs {
		if proof.ProofType == "zk" {
			zkProofs++
		} else if proof.ProofType == "merkle" {
			merkleProofs++
		}
	}
	
	return map[string]interface{}{
		"totalProofs":   len(sc.stateProofs),
		"zkProofs":      zkProofs,
		"merkleProofs":  merkleProofs,
		"proofRatio":    float64(len(sc.stateProofs)) / float64(len(sc.blockInfos)) * 100,
	}
}

// SetPriorityAccounts 设置优先账户
func (sc *StatelessClient) SetPriorityAccounts(accounts []common.Address) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	sc.config.PrioritizeAccounts = accounts
	log.Info("设置优先账户", "数量", len(accounts))
}

// GetBlockInfo 获取区块信息
func (sc *StatelessClient) GetBlockInfo(number uint64) *BlockInfo {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	
	return sc.blockInfos[number]
}

// UpdateMaxCacheSize 更新最大缓存大小
func (sc *StatelessClient) UpdateMaxCacheSize(sizeMB int) {
	sc.stateCache.mu.Lock()
	defer sc.stateCache.mu.Unlock()
	
	oldSize := sc.stateCache.maxSize / 1024 / 1024
	sc.stateCache.maxSize = sizeMB * 1024 * 1024
	
	log.Info("更新最大缓存大小", "从", oldSize, "MB", "到", sizeMB, "MB")
} 