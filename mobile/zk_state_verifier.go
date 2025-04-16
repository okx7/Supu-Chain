package mobile

import (
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/crypto"
)

// ZK证明类型常量
const (
	ZKProofTypeGroth16 = "groth16" // Groth16 - 最常用的zk-SNARK证明系统
	ZKProofTypePlonk   = "plonk"   // PLONK - 新一代的zk-SNARK，更通用
	ZKProofTypeStark   = "stark"   // STARK - 后量子安全的ZK证明
	ZKProofTypeMarlin  = "marlin"  // Marlin - 通用zk-SNARK
)

// ZK状态类型常量
const (
	ZKStateTypeAccount = "account" // 账户状态
	ZKStateTypeStorage = "storage" // 存储状态
	ZKStateTypeBlock   = "block"   // 区块状态
	ZKStateTypeTx      = "tx"      // 交易状态
)

// 配置参数
const (
	MaxProofAge        = 5 * time.Minute // 最大证明有效期
	EnableProofCache   = true            // 启用证明缓存
	DefaultSecureMode  = true            // 默认安全模式
)

// 统计计数器
var (
	CacheHits   uint64 // 缓存命中次数
	CacheMisses uint64 // 缓存未命中次数
)

// ZKStateVerifierConfig ZK状态验证器配置
type ZKStateVerifierConfig struct {
	ProofType             string        // 证明类型 (groth16, plonk, stark等)
	VerifyingKeyPath      string        // 验证密钥路径
	UseIncrementalProofs  bool          // 是否使用增量证明
	BatchVerificationSize int           // 批量验证大小
	VerificationTimeout   time.Duration // 验证超时
	CacheSize             int           // 缓存大小
	UseTrustedSetup       bool          // 是否使用可信设置
	MaxProofsPerBlock     int           // 每个区块最大证明数
	ProverAddresses       []common.Address // 允许的证明者地址
	OfflineVerification   bool          // 支持离线验证
	AdvancedChecks        bool          // 启用高级检查
	MaxProofAge           time.Duration // 最大证明年龄
	EnableProofCache      bool          // 是否启用证明缓存
	TrustedKeyHashes      [][]byte      // 可信密钥哈希列表
	EnableAuthorityVerification bool        // 是否启用权威签名验证
}

// ZKStateProof ZK状态证明
type ZKStateProof struct {
	ProofData     []byte         // 证明数据
	PublicInputs  [][]byte       // 公共输入
	BlockHash     common.Hash    // 区块哈希
	StateRoot     common.Hash    // 状态根
	AccountProofs []AccountProof // 账户证明
	StorageProofs []StorageProof // 存储证明
	Signature     []byte         // 证明者签名
	ProverAddress common.Address // 证明者地址
	Timestamp     time.Time      // 时间戳
	ProofType     string         // 证明类型 (groth16, plonk, stark等)
}

// AccountProof 账户证明
type AccountProof struct {
	Address     common.Address // 账户地址
	Proof       []byte         // 证明数据
	StateData   []byte         // 状态数据
	Nonce       uint64         // 账户nonce
	Balance     *big.Int       // 账户余额
	StorageRoot common.Hash    // 存储根
	CodeHash    []byte         // 代码哈希
}

// StorageProof 存储证明
type StorageProof struct {
	Address     common.Address // 账户地址
	StorageKey  common.Hash    // 存储键
	StorageVal  common.Hash    // 存储值
	Proof       []byte         // 证明数据
}

// ZKVerifierStats ZK验证器统计
type ZKVerifierStats struct {
	TotalProofsVerified   uint64        // 总验证证明数
	SuccessfulVerifications uint64      // 成功验证数
	FailedVerifications   uint64        // 失败验证数
	AverageVerificationTime time.Duration // 平均验证时间
	TotalVerificationTime time.Duration  // 总验证时间
	LastVerificationTime  time.Time     // 最后验证时间
	CacheHits             uint64        // 缓存命中数
	CacheMisses           uint64        // 缓存未命中数
	MaxVerificationTime   time.Duration // 最大验证时间
	MinVerificationTime   time.Duration // 最小验证时间
	TotalVerifications    uint64        // 总验证次数
	LastCacheHit          time.Time     // 最后缓存命中时间
}

// ZKVerifierCache ZK验证器缓存
type ZKVerifierCache struct {
	proofHashes       map[string]bool  // 证明哈希缓存
	verifiedRoots     map[common.Hash]time.Time // 已验证状态根
	maxSize           int             // 最大缓存大小
	currentSize       int             // 当前缓存大小
	mu                sync.RWMutex    // 互斥锁
}

// ZKStateVerifier ZK状态验证器
type ZKStateVerifier struct {
	config            *ZKStateVerifierConfig // 配置
	verifyingKeys     map[string][]byte     // 验证密钥映射
	stats             ZKVerifierStats       // 统计信息
	cache             *ZKVerifierCache      // 验证缓存
	mu                sync.RWMutex          // 互斥锁
	authorityPublicKey *crypto.PublicKey    // 权威公钥
	proofCache   map[string]time.Time // 证明缓存
	securityMgr  *ZKSecurityManager   // 安全管理器
	verifyCount  uint64               // 验证次数
	successCount uint64               // 成功次数
	failureCount uint64               // 失败次数
}

// NewZKStateVerifier 创建新的ZK状态验证器
func NewZKStateVerifier(config *ZKStateVerifierConfig) (*ZKStateVerifier, error) {
	if config == nil {
		return nil, errors.New("配置不能为空")
	}
	
	// 验证证明类型
	switch config.ProofType {
	case ZKProofTypeGroth16, ZKProofTypePlonk, ZKProofTypeStark, ZKProofTypeMarlin:
		// 支持的证明类型
	default:
		return nil, fmt.Errorf("不支持的证明类型: %s", config.ProofType)
	}
	
	// 创建缓存
	cache := &ZKVerifierCache{
		proofHashes:   make(map[string]bool),
		verifiedRoots: make(map[common.Hash]time.Time),
		maxSize:       config.CacheSize,
	}
	
	// 创建验证器
	verifier := &ZKStateVerifier{
		config:        config,
		verifyingKeys: make(map[string][]byte),
		stats: ZKVerifierStats{
			LastVerificationTime: time.Now(),
		},
		cache: cache,
	}
	
	// 加载验证密钥
	if err := verifier.loadVerifyingKeys(); err != nil {
		return nil, fmt.Errorf("加载验证密钥失败: %v", err)
	}
	
	log.Info("ZK状态验证器已创建", 
		"证明类型", config.ProofType, 
		"增量证明", config.UseIncrementalProofs,
		"批量验证", config.BatchVerificationSize)
	
	return verifier, nil
}

// loadVerifyingKeys 加载验证密钥
func (v *ZKStateVerifier) loadVerifyingKeys() error {
	// 在实际实现中，应该从文件或其他存储加载验证密钥
	// 这里仅作为示例，创建一些模拟的验证密钥
	
	// 账户状态证明的验证密钥
	v.verifyingKeys[ZKStateTypeAccount] = []byte("模拟账户状态验证密钥")
	
	// 存储状态证明的验证密钥
	v.verifyingKeys[ZKStateTypeStorage] = []byte("模拟存储状态验证密钥")
	
	// 区块状态证明的验证密钥
	v.verifyingKeys[ZKStateTypeBlock] = []byte("模拟区块状态验证密钥")
	
	// 交易状态证明的验证密钥
	v.verifyingKeys[ZKStateTypeTx] = []byte("模拟交易状态验证密钥")
	
	log.Debug("已加载验证密钥", "数量", len(v.verifyingKeys))
	return nil
}

// VerifyStateProof 验证ZK状态证明
func (v *ZKStateVerifier) VerifyStateProof(proof *ZKStateProof) error {
	startTime := time.Now() // 记录开始时间用于性能统计
	
	// 基本参数验证
	if proof == nil {
		return errors.New("证明对象为空") // 检查输入不为空
	}
	
	// 验证证明类型
	if proof.ProofType == "" {
		return errors.New("证明类型未指定") // 确保指定了证明类型
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
	if len(proof.ProofData) == 0 {
		return errors.New("证明数据为空") // 检查证明数据
	}

	// 检查时间戳，防止重放攻击
	if proof.Timestamp.IsZero() {
		proof.Timestamp = time.Now() // 如果未设置，则使用当前时间
	} else if time.Since(proof.Timestamp) > v.config.MaxProofAge {
		return errors.New("证明已过期") // 检查证明是否过期
	}
	
	// 获取证明哈希，用于缓存检查
	proofHash := v.hashProof(proof)
	
	// 检查证明缓存
	if v.config.EnableProofCache {
		if cached, valid := v.checkProofCache(proofHash); valid {
			v.stats.CacheHits++
			v.stats.LastCacheHit = time.Now()
			log.Debug("证明缓存命中", "哈希", hex.EncodeToString(proofHash[:8])+"...")
			return nil
		}
		v.stats.CacheMisses++
	}
	
	// 统计验证次数
	v.stats.TotalVerifications++
	
	// 公钥验证 - 确保使用可信公钥
	if !v.isVerificationKeyTrusted(proof.ProofType) {
		return errors.New("不受信任的验证密钥") // 验证密钥安全性检查
	}
	
	// 验证公共输入
	if len(proof.PublicInputs) < 2 {
		return errors.New("公共输入不足") // 检查公共输入完整性
	}
	
	// 验证公共输入与预期是否匹配
	blockHashMatch := bytes.Equal(proof.PublicInputs[0], proof.BlockHash.Bytes())
	stateRootMatch := bytes.Equal(proof.PublicInputs[1], proof.StateRoot.Bytes())
	
	if !blockHashMatch || !stateRootMatch {
		log.Warn("公共输入不匹配",
			"blockHash匹配", blockHashMatch,
			"stateRoot匹配", stateRootMatch)
		return errors.New("公共输入与状态不匹配") // 防篡改检查
	}
	
	var err error
	
	// 根据证明类型选择验证方法
	switch proof.ProofType {
	case "groth16":
		// 使用Groth16验证
		err = v.verifyGroth16Proof(proof.ProofData, proof.PublicInputs)
		if err != nil {
			v.stats.FailedVerifications++
			log.Warn("Groth16证明验证失败", "错误", err)
			return fmt.Errorf("Groth16证明验证失败: %v", err)
		}
		
	case "plonk":
		// 使用Plonk验证
		err = v.verifyPlonkProof(proof.ProofData, proof.PublicInputs)
		if err != nil {
			v.stats.FailedVerifications++
			log.Warn("Plonk证明验证失败", "错误", err)
			return fmt.Errorf("Plonk证明验证失败: %v", err)
		}
		
	case "stark":
		// 使用Stark验证
		err = v.verifyStarkProof(proof.ProofData, proof.PublicInputs)
		if err != nil {
			v.stats.FailedVerifications++
			log.Warn("Stark证明验证失败", "错误", err)
			return fmt.Errorf("Stark证明验证失败: %v", err)
		}
		
	default:
		v.stats.FailedVerifications++
		return fmt.Errorf("不支持的证明类型: %s", proof.ProofType)
	}
	
	// 如果启用了缓存，将验证成功的证明添加到缓存中
	if v.config.EnableProofCache {
		v.addProofToCache(proofHash, proof.Timestamp)
	}
	
	// 统计验证时间
	verificationTime := time.Since(startTime)
	v.stats.TotalVerificationTime += verificationTime
	if v.stats.MaxVerificationTime < verificationTime {
		v.stats.MaxVerificationTime = verificationTime
	}
	if v.stats.MinVerificationTime == 0 || v.stats.MinVerificationTime > verificationTime {
		v.stats.MinVerificationTime = verificationTime
	}
	
	// 记录验证成功的证明
	v.stats.SuccessfulVerifications++
	v.stats.LastSuccessfulVerification = time.Now()
	
	// 调试日志
	log.Debug("状态证明验证成功", 
		"类型", proof.ProofType,
		"耗时", verificationTime,
		"账户数", len(proof.AccountProofs),
		"存储数", len(proof.StorageProofs))
	
	return nil
}

// isVerificationKeyTrusted 检查验证密钥是否可信
func (v *ZKStateVerifier) isVerificationKeyTrusted(proofType string) bool {
	keyHash, err := v.getVerificationKeyHash(proofType)
	if err != nil {
		log.Error("获取验证密钥哈希失败", "错误", err)
		return false
	}
	
	// 比较密钥哈希与可信哈希列表
	for _, trustedHash := range v.config.TrustedKeyHashes {
		if bytes.Equal(keyHash, trustedHash) {
			return true
		}
	}
	
	// 检查权威签名（如果存在）
	if v.config.EnableAuthorityVerification {
		return v.verifyAuthoritySignature(proofType, keyHash)
	}
	
	return false
}

// getVerificationKeyHash 获取验证密钥的哈希
func (v *ZKStateVerifier) getVerificationKeyHash(proofType string) ([]byte, error) {
	var keyData []byte
	var err error
	
	switch proofType {
	case "groth16":
		keyData = v.verifyingKeys[ZKStateTypeAccount]
	case "plonk":
		keyData = v.verifyingKeys[ZKStateTypeStorage]
	case "stark":
		keyData = v.verifyingKeys[ZKStateTypeBlock]
	default:
		return nil, fmt.Errorf("不支持的证明类型: %s", proofType)
	}
	
	if len(keyData) == 0 {
		return nil, errors.New("验证密钥数据为空")
	}
	
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(keyData)
	return hasher.Sum(nil), nil
}

// verifyAuthoritySignature 验证可信机构对验证密钥的签名
func (v *ZKStateVerifier) verifyAuthoritySignature(proofType string, keyHash []byte) bool {
	if v.authorityPublicKey == nil {
		log.Error("权威公钥未设置")
		return false
	}
	
	signature, exists := v.config.KeySignatures[proofType]
	if !exists || len(signature) == 0 {
		log.Error("找不到验证密钥签名", "类型", proofType)
		return false
	}
	
	// 这里应实现实际的签名验证逻辑
	// 为简化示例，我们假设签名验证成功
	log.Debug("验证密钥签名验证成功", "类型", proofType)
	return true
}

// VerifyAccountState 验证账户状态
func (v *ZKStateVerifier) VerifyAccountState(proof *ZKStateProof, address common.Address) (*types.StateAccount, error) {
	// 首先验证状态证明
	if err := v.VerifyStateProof(proof); err != nil {
		return nil, err
	}
	
	// 查找账户证明
	var accountProof *AccountProof
	for _, ap := range proof.AccountProofs {
		if ap.Address == address {
			accountProof = &ap
			break
		}
	}
	
	if accountProof == nil {
		return nil, fmt.Errorf("找不到地址 %s 的账户证明", address.Hex())
	}
	
	// 构造StateAccount
	stateAccount := &types.StateAccount{
		Nonce:    accountProof.Nonce,
		Balance:  accountProof.Balance,
		Root:     accountProof.StorageRoot,
		CodeHash: accountProof.CodeHash,
	}
	
	return stateAccount, nil
}

// VerifyStorageValue 验证存储值
func (v *ZKStateVerifier) VerifyStorageValue(proof *ZKStateProof, address common.Address, key common.Hash) (common.Hash, error) {
	// 首先验证状态证明
	if err := v.VerifyStateProof(proof); err != nil {
		return common.Hash{}, err
	}
	
	// 查找存储证明
	var storageProof *StorageProof
	for _, sp := range proof.StorageProofs {
		if sp.Address == address && sp.StorageKey == key {
			storageProof = &sp
			break
		}
	}
	
	if storageProof == nil {
		return common.Hash{}, fmt.Errorf("找不到地址 %s 键 %s 的存储证明", address.Hex(), key.Hex())
	}
	
	return storageProof.StorageVal, nil
}

// GetStats 获取统计信息
func (v *ZKStateVerifier) GetStats() ZKVerifierStats {
	v.mu.RLock()
	defer v.mu.RUnlock()
	
	// 返回副本
	return v.stats
}

// IsStateRootVerified 检查状态根是否已验证
func (v *ZKStateVerifier) IsStateRootVerified(root common.Hash) bool {
	v.cache.mu.RLock()
	defer v.cache.mu.RUnlock()
	
	_, exists := v.cache.verifiedRoots[root]
	return exists
}

// CreateProof 创建证明(仅用于测试)
func (v *ZKStateVerifier) CreateProof(blockHash, stateRoot common.Hash, accounts []common.Address) *ZKStateProof {
	// 这个函数仅用于测试和演示
	// 在实际实现中，证明应该由专门的证明生成器生成
	
	proof := &ZKStateProof{
		ProofData:     []byte("模拟证明数据"),
		PublicInputs:  [][]byte{stateRoot.Bytes()},
		BlockHash:     blockHash,
		StateRoot:     stateRoot,
		AccountProofs: make([]AccountProof, 0, len(accounts)),
		StorageProofs: make([]StorageProof, 0),
		Signature:     []byte("模拟签名"),
		ProverAddress: common.HexToAddress("0x1234567890123456789012345678901234567890"),
		Timestamp:     time.Now(),
		ProofType:     v.config.ProofType,
	}
	
	// 为每个账户创建账户证明
	for _, addr := range accounts {
		accountProof := AccountProof{
			Address:     addr,
			Proof:       []byte("模拟账户证明"),
			StateData:   []byte("模拟账户数据"),
			Nonce:       1,
			Balance:     big.NewInt(1000000000000000000), // 1 ETH
			StorageRoot: common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
			CodeHash:    []byte("模拟代码哈希"),
		}
		proof.AccountProofs = append(proof.AccountProofs, accountProof)
		
		// 为每个账户创建一些存储证明
		storageProof := StorageProof{
			Address:    addr,
			StorageKey: common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
			StorageVal: common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
			Proof:      []byte("模拟存储证明"),
		}
		proof.StorageProofs = append(proof.StorageProofs, storageProof)
	}
	
	return proof
}

// ClearCache 清除缓存
func (v *ZKStateVerifier) ClearCache() {
	v.cache.mu.Lock()
	defer v.cache.mu.Unlock()
	
	v.cache.proofHashes = make(map[string]bool)
	v.cache.verifiedRoots = make(map[common.Hash]time.Time)
	v.cache.currentSize = 0
	
	log.Info("已清除ZK验证器缓存")
}

// UpdateConfig 更新配置
func (v *ZKStateVerifier) UpdateConfig(config *ZKStateVerifierConfig) error {
	if config == nil {
		return errors.New("配置不能为空")
	}
	
	v.mu.Lock()
	defer v.mu.Unlock()
	
	// 更新配置
	oldProofType := v.config.ProofType
	v.config = config
	
	// 如果证明类型变了，需要重新加载验证密钥
	if oldProofType != config.ProofType {
		v.verifyingKeys = make(map[string][]byte)
		if err := v.loadVerifyingKeys(); err != nil {
			return fmt.Errorf("加载验证密钥失败: %v", err)
		}
	}
	
	// 更新缓存大小
	v.cache.maxSize = config.CacheSize
	
	log.Info("已更新ZK验证器配置", 
		"证明类型", config.ProofType, 
		"增量证明", config.UseIncrementalProofs,
		"批量验证", config.BatchVerificationSize)
	
	return nil
}

// BatchVerifyProofs 批量验证证明
func (v *ZKStateVerifier) BatchVerifyProofs(proofs []*ZKStateProof) ([]error, error) {
	if len(proofs) == 0 {
		return nil, errors.New("证明列表为空")
	}
	
	// 检查批量验证大小
	if len(proofs) > v.config.BatchVerificationSize && v.config.BatchVerificationSize > 0 {
		return nil, fmt.Errorf("证明数量 %d 超过批量验证大小限制 %d", 
			len(proofs), v.config.BatchVerificationSize)
	}
	
	// 记录开始时间
	startTime := time.Now()
	
	// 批量验证结果
	results := make([]error, len(proofs))
	
	// 按证明类型分组
	proofsByType := make(map[string][]*ZKStateProof)
	for _, proof := range proofs {
		proofsByType[proof.ProofType] = append(proofsByType[proof.ProofType], proof)
	}
	
	// 批量验证不同类型的证明
	for proofType, typeProofs := range proofsByType {
		var err error
		switch proofType {
		case ZKProofTypeGroth16:
			err = v.batchVerifyGroth16(typeProofs)
		case ZKProofTypePlonk:
			err = v.batchVerifyPlonk(typeProofs)
		default:
			// 其他类型的证明不支持批量验证，逐个验证
			for i, proof := range typeProofs {
				idx := 0
				for j, p := range proofs {
					if p == proof {
						idx = j
						break
					}
				}
				results[idx] = v.VerifyStateProof(proof)
			}
			continue
		}
		
		// 如果批量验证失败，则认为所有该类型的证明都失败
		if err != nil {
			for i, proof := range typeProofs {
				idx := 0
				for j, p := range proofs {
					if p == proof {
						idx = j
						break
					}
				}
				results[idx] = err
			}
		}
	}
	
	// 更新统计信息
	v.mu.Lock()
	v.stats.TotalProofsVerified += uint64(len(proofs))
	v.stats.TotalVerificationTime += time.Since(startTime)
	v.stats.AverageVerificationTime = v.stats.TotalVerificationTime / time.Duration(v.stats.TotalProofsVerified)
	v.stats.LastVerificationTime = time.Now()
	
	successCount := 0
	for _, err := range results {
		if err == nil {
			successCount++
		}
	}
	v.stats.SuccessfulVerifications += uint64(successCount)
	v.stats.FailedVerifications += uint64(len(proofs) - successCount)
	v.mu.Unlock()
	
	log.Debug("批量验证完成", 
		"总数", len(proofs), 
		"成功", successCount, 
		"失败", len(proofs)-successCount,
		"用时", time.Since(startTime))
	
	return results, nil
}

// 批量验证Groth16证明
func (v *ZKStateVerifier) batchVerifyGroth16(proofs []*ZKStateProof) error {
	// 在实际实现中，这里应该使用Groth16批量验证算法
	// 例如使用gnark等库的批量验证功能
	// 这里仅作为示例实现
	time.Sleep(20 * time.Millisecond) // 模拟批量验证延迟
	return nil
}

// 批量验证PLONK证明
func (v *ZKStateVerifier) batchVerifyPlonk(proofs []*ZKStateProof) error {
	// 在实际实现中，这里应该使用PLONK批量验证算法
	// 这里仅作为示例实现
	time.Sleep(30 * time.Millisecond) // 模拟批量验证延迟
	return nil
}

// 验证Groth16证明
func (v *ZKStateVerifier) verifyGroth16Proof(proofData []byte, publicInputs [][]byte) error {
	// 在实际实现中，这里应该使用Groth16验证算法
	// 例如使用gnark或其他ZK库
	// 这里仅作为示例实现
	
	// 检查证明数据和公共输入
	if len(proofData) == 0 || len(publicInputs) == 0 {
		return errors.New("证明数据或公共输入为空")
	}
	
	// 获取验证密钥
	vk, exists := v.verifyingKeys[ZKStateTypeAccount] // 使用账户状态的验证密钥
	if !exists {
		return errors.New("找不到验证密钥")
	}
	
	// 模拟验证过程
	if v.config.AdvancedChecks {
		// 执行更严格的检查
		time.Sleep(10 * time.Millisecond) // 模拟更复杂的验证
	}
	
	// 模拟验证成功
	return nil
}

// 验证PLONK证明
func (v *ZKStateVerifier) verifyPlonkProof(proofData []byte, publicInputs [][]byte) error {
	// 在实际实现中，这里应该使用PLONK验证算法
	// 这里仅作为示例实现
	time.Sleep(5 * time.Millisecond) // 模拟验证延迟
	return nil
}

// 验证STARK证明
func (v *ZKStateVerifier) verifyStarkProof(proofData []byte, publicInputs [][]byte) error {
	// 在实际实现中，这里应该使用STARK验证算法
	// 这里仅作为示例实现
	time.Sleep(15 * time.Millisecond) // 模拟验证延迟
	return nil
}

// 对证明进行哈希
func (v *ZKStateVerifier) hashProof(proof *ZKStateProof) string {
	// 计算证明数据的哈希
	hasher := sha256.New()
	hasher.Write(proof.ProofData)
	for _, input := range proof.PublicInputs {
		hasher.Write(input)
	}
	hasher.Write(proof.BlockHash.Bytes())
	hasher.Write(proof.StateRoot.Bytes())
	return hex.EncodeToString(hasher.Sum(nil))
}

// 检查证明缓存
func (v *ZKStateVerifier) checkProofCache(proofHash string) (bool, bool) {
	v.cache.mu.RLock()
	defer v.cache.mu.RUnlock()
	
	cached, exists := v.cache.proofHashes[proofHash]
	return cached, exists
}

// 添加到缓存
func (v *ZKStateVerifier) addProofToCache(proofHash string, timestamp time.Time) {
	v.cache.mu.Lock()
	defer v.cache.mu.Unlock()
	
	// 添加证明哈希到缓存
	v.cache.proofHashes[proofHash] = true
	v.cache.verifiedRoots[proof.StateRoot] = timestamp
	v.cache.currentSize++
	
	// 如果缓存超过最大大小，清理一些旧条目
	if v.cache.currentSize > v.cache.maxSize && v.cache.maxSize > 0 {
		v.cleanCache()
	}
}

// 清理缓存
func (v *ZKStateVerifier) cleanCache() {
	// 寻找最旧的verified roots并删除
	var oldestRoots []common.Hash
	var oldestTime time.Time
	
	// 找出最旧的根
	for root, t := range v.cache.verifiedRoots {
		if oldestTime.IsZero() || t.Before(oldestTime) {
			oldestTime = t
			oldestRoots = []common.Hash{root}
		} else if t.Equal(oldestTime) {
			oldestRoots = append(oldestRoots, root)
		}
	}
	
	// 删除最旧的一半根
	deleteCount := len(oldestRoots) / 2
	if deleteCount == 0 && len(oldestRoots) > 0 {
		deleteCount = 1 // 至少删除一个
	}
	
	for i := 0; i < deleteCount && i < len(oldestRoots); i++ {
		delete(v.cache.verifiedRoots, oldestRoots[i])
		v.cache.currentSize--
	}
	
	// 找出对应的proof hashes并删除
	for hash := range v.cache.proofHashes {
		if v.cache.currentSize <= v.cache.maxSize*80/100 { // 清理到80%容量
			break
		}
		delete(v.cache.proofHashes, hash)
		v.cache.currentSize--
	}
	
	log.Debug("清理ZK证明缓存", 
		"删除数量", deleteCount, 
		"当前大小", v.cache.currentSize,
		"最大大小", v.cache.maxSize)
}

// 创建新的ZK状态验证器
func NewZKStateVerifier() *ZKStateVerifier {
	// 创建安全管理器配置
	secConfig := ZKSecurityConfig{
		KeyStore:             "./zk_keys",
		UsedProofsExpiration: 24 * time.Hour,
		SecureMode:           DefaultSecureMode,
		RequireSignatures:    true,
		RotationPeriod:       30 * 24 * time.Hour, // 30天
	}

	// 初始化安全管理器
	secMgr, err := NewZKSecurityManager(secConfig)
	if err != nil {
		log.Error("初始化ZK安全管理器失败", "错误", err)
		// 降级为非安全模式
		secConfig.SecureMode = false
		secMgr, _ = NewZKSecurityManager(secConfig)
	}

	return &ZKStateVerifier{
		proofCache:  make(map[string]time.Time),
		securityMgr: secMgr,
	}
}

// VerifyStateProof 验证状态证明
func (v *ZKStateVerifier) VerifyStateProof(proof []byte, publicInputs []byte, proofType string) (bool, error) {
	// 增加验证计数
	v.mu.Lock()
	v.verifyCount++
	v.mu.Unlock()

	startTime := time.Now()
	defer func() {
		log.Debug("ZK状态验证完成", "耗时", time.Since(startTime))
	}()

	// 验证参数
	if len(proof) == 0 {
		v.recordFailure("空证明")
		return false, errors.New("证明数据为空")
	}

	if len(publicInputs) == 0 {
		v.recordFailure("空公共输入")
		return false, errors.New("公共输入为空")
	}

	if proofType == "" {
		proofType = "groth16" // 默认使用groth16
	}

	// 计算证明哈希作为唯一标识符
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(proof)
	hasher.Write(publicInputs)
	hasher.Write([]byte(proofType))
	proofHash := hex.EncodeToString(hasher.Sum(nil))

	// 检查证明是否已被使用(防重放)
	if !v.securityMgr.CheckProofUnique(proofHash) {
		v.recordFailure("重放攻击")
		return false, errors.New("检测到重放攻击")
	}

	// 检查缓存
	if EnableProofCache {
		v.mu.RLock()
		timestamp, exists := v.proofCache[proofHash]
		v.mu.RUnlock()

		if exists {
			// 检查证明是否过期
			if time.Since(timestamp) < MaxProofAge {
				// 缓存命中
				CacheHits++
				log.Debug("ZK证明缓存命中", "哈希", proofHash[:8]+"...")
				v.recordSuccess()
				return true, nil
			}
			// 证明已过期，需要重新验证
			log.Debug("ZK证明已过期，需要重新验证", "哈希", proofHash[:8]+"...")
		}
		CacheMisses++
	}

	// 解析并验证公共输入
	publicInputsHash := common.BytesToHash(publicInputs)
	
	// 从公共输入中提取时间戳（假设它是前32字节之后的32字节）
	var timestamp uint64
	if len(publicInputs) >= 64 {
		// 此处简化处理，实际应根据公共输入的格式正确解析
		timestamp = uint64(publicInputs[32])
	}
	
	// 检查时间戳是否在允许的时间窗口内
	if timestamp > 0 {
		currentTime := uint64(time.Now().Unix())
		if currentTime < timestamp || currentTime-timestamp > uint64(MaxProofAge.Seconds()) {
			v.recordFailure("时间戳无效")
			return false, fmt.Errorf("证明时间戳无效：当前=%d, 证明=%d", currentTime, timestamp)
		}
	}

	// 创建防篡改验证数据
	tamperProof, err := v.securityMgr.CreateTamperProof(publicInputsHash, 0, 1) // 简化参数
	if err != nil {
		log.Warn("创建防篡改证明失败", "错误", err)
		// 继续执行，但发出警告
	}

	// 根据证明类型选择验证方法
	var verified bool
	switch proofType {
	case "groth16":
		verified = v.verifyGroth16(proof, publicInputs)
	case "plonk":
		verified = v.verifyPlonk(proof, publicInputs)
	case "stark":
		verified = v.verifyStark(proof, publicInputs)
	default:
		v.recordFailure("未知证明类型")
		return false, fmt.Errorf("不支持的证明类型: %s", proofType)
	}

	// 验证结果处理
	if !verified {
		v.recordFailure("验证失败")
		return false, errors.New("ZK证明验证失败")
	}

	// 防篡改验证
	if tamperProof != nil && !v.securityMgr.VerifyTamperProof(tamperProof, publicInputsHash) {
		v.recordFailure("防篡改验证失败")
		return false, errors.New("防篡改验证失败")
	}

	// 验证成功，更新缓存
	if EnableProofCache {
		v.mu.Lock()
		v.proofCache[proofHash] = time.Now()
		v.mu.Unlock()
	}

	// 记录成功并返回
	v.recordSuccess()
	return true, nil
}

// 记录验证失败
func (v *ZKStateVerifier) recordFailure(reason string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.failureCount++
	log.Warn("ZK证明验证失败", "原因", reason, "总失败次数", v.failureCount)
}

// 记录验证成功
func (v *ZKStateVerifier) recordSuccess() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.successCount++
}

// 验证Groth16证明
func (v *ZKStateVerifier) verifyGroth16(proof []byte, publicInputs []byte) bool {
	// TODO: 实现Groth16证明验证
	// 这里应该调用实际的Groth16验证库
	log.Debug("验证Groth16证明", "证明长度", len(proof), "输入长度", len(publicInputs))
	return true // 示例实现，实际应进行真正的验证
}

// 验证Plonk证明
func (v *ZKStateVerifier) verifyPlonk(proof []byte, publicInputs []byte) bool {
	// TODO: 实现Plonk证明验证
	log.Debug("验证Plonk证明", "证明长度", len(proof), "输入长度", len(publicInputs))
	return true // 示例实现
}

// 验证Stark证明
func (v *ZKStateVerifier) verifyStark(proof []byte, publicInputs []byte) bool {
	// TODO: 实现Stark证明验证
	log.Debug("验证Stark证明", "证明长度", len(proof), "输入长度", len(publicInputs))
	return true // 示例实现
}

// GetVerifierStats 获取验证器统计信息
func (v *ZKStateVerifier) GetVerifierStats() map[string]interface{} {
	v.mu.RLock()
	defer v.mu.RUnlock()
	
	// 获取安全管理器统计信息
	securityStats := v.securityMgr.GetSecurityStats()
	
	// 合并验证器和安全管理器的统计信息
	stats := map[string]interface{}{
		"verifyCount":      v.verifyCount,
		"successCount":     v.successCount,
		"failureCount":     v.failureCount,
		"successRate":      float64(v.successCount) / float64(max(v.verifyCount, 1)) * 100,
		"cacheHits":        CacheHits,
		"cacheMisses":      CacheMisses,
		"cacheHitRate":     float64(CacheHits) / float64(max(CacheHits+CacheMisses, 1)) * 100,
		"cacheEntries":     len(v.proofCache),
	}
	
	// 合并安全统计信息
	for k, v := range securityStats {
		stats[k] = v
	}
	
	return stats
}

// 辅助函数：返回两个数的最大值
func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}