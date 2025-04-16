package types

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	// ErrMobileBlockInvalid 表示区块无效
	ErrMobileBlockInvalid = errors.New("移动区块无效")
	
	// ErrMobileBlockHashMismatch 表示区块哈希不匹配
	ErrMobileBlockHashMismatch = errors.New("移动区块哈希不匹配")
	
	// ErrMobileBlockSignatureInvalid 表示区块签名无效
	ErrMobileBlockSignatureInvalid = errors.New("移动区块签名无效")
	
	// ErrInvalidShardRange 表示无效的分片范围
	ErrInvalidShardRange = errors.New("无效的分片范围")
	
	// ErrInvalidMobileBlock 表示无效的移动区块
	ErrInvalidMobileBlock = errors.New("无效的移动区块")
	
	// ErrMobileHashMismatch 表示移动区块哈希不匹配
	ErrMobileHashMismatch = errors.New("移动区块哈希不匹配")
	
	// ErrInvalidSignature 表示无效的区块签名
	ErrInvalidSignature = errors.New("无效的区块签名")
	
	// ErrShardRangeOverlap 表示分片范围重叠
	ErrShardRangeOverlap = errors.New("分片范围重叠")
	
	// ErrNoShardRange 表示未定义分片范围
	ErrNoShardRange = errors.New("未定义分片范围")
	
	// ErrUnauthorizedValidator 表示未授权的验证者
	ErrUnauthorizedValidator = errors.New("未授权的验证者")
	
	// ErrInvalidResourceUsage 表示无效的资源使用记录
	ErrInvalidResourceUsage = errors.New("无效的资源使用记录")
	
	// ErrMobileBlockSealing 表示移动区块密封失败
	ErrMobileBlockSealing = errors.New("移动区块密封失败")
	
	// ErrTimeValidation 表示区块时间验证失败
	ErrTimeValidation = errors.New("区块时间验证失败")
	
	// 错误定义
	ErrInvalidMobileBlockHeader  = errors.New("无效的移动区块头")             // 无效的移动区块头
	ErrMaxShardRangeReached      = errors.New("已达到最大分片范围数")            // 已达到最大分片范围数
	ErrMissingParentHash         = errors.New("缺少父区块哈希")               // 缺少父区块哈希
	ErrMobileTxNotFound          = errors.New("移动交易未找到")               // 移动交易未找到
	ErrResourceLimitExceeded     = errors.New("资源限制超出")                // 资源限制超出
	ErrInvalidMobileBlockVersion = errors.New("无效的移动区块版本")             // 无效的移动区块版本
)

const (
	// 移动区块常量
	MaxShardRanges      = 32                // 最大分片范围数
	MaxExtraDataSize    = 1024              // 最大额外数据大小（字节）
	MobileBlockVersion  = 1                 // 移动区块版本
	MaxTransactionsSize = 100 * 1024 * 1024 // 最大交易数据大小（字节）
	MaxBatteryImpact    = 100               // 最大电池影响（0-100）
	MaxProcessingTime   = 30 * time.Second  // 最大处理时间
	
	// 移动端优化常量
	DefaultChunkSize         = 64 * 1024        // 默认分块大小（64KB）
	MaxCompressionLevel      = 9                // 最大压缩级别
	LightVerificationSample  = 10               // 轻量级验证的采样率(%)
	MobileBlockCacheCapacity = 10               // 移动区块缓存容量
	MaxResumeDataAge         = 24 * time.Hour   // 最大恢复数据有效期
	NetworkPriorityHigh      = 3                // 高网络优先级
	NetworkPriorityMedium    = 2                // 中网络优先级
	NetworkPriorityLow       = 1                // 低网络优先级
)

// MobileBlockHeader 移动设备优化的区块头结构
type MobileBlockHeader struct {
	ParentHash   common.Hash    // 父区块的哈希
	UncleHash    common.Hash    // 叔块哈希
	Coinbase     common.Address // 矿工/验证者地址
	Root         common.Hash    // 状态根
	TxHash       common.Hash    // 交易merkle树根
	ReceiptHash  common.Hash    // 收据merkle树根
	Bloom        Bloom          // 布隆过滤器
	Difficulty   *big.Int       // 难度
	Number       *big.Int       // 区块高度
	GasLimit     uint64         // 燃料限制
	GasUsed      uint64         // 已使用燃料
	Time         uint64         // 时间戳
	Extra        []byte         // 额外数据
	MixDigest    common.Hash    // 混合摘要
	Nonce        BlockNonce     // 随机数
	BaseFee      *big.Int       // EIP-1559 基础费用
	CreationTime time.Time      // 创建时间
	ExtraData    []byte         // 额外自定义数据
	
	// 移动区块特有字段
	Version        uint32         // 版本号
	ShardHash      common.Hash    // 分片列表哈希
	ResourceHash   common.Hash    // 资源使用哈希
	ValidatorCount uint16         // 验证者数量
	ShardCount     uint16         // 分片数量
	BatteryUsage   uint8          // 电池使用百分比
	DeviceType     uint8          // 设备类型（1:手机, 2:平板, 3:笔记本）
	NetworkType    uint8          // 网络类型（1:WiFi, 2:4G, 3:5G）
}

// MobileShardRange 表示一个交易分片的范围
type MobileShardRange struct {
	ShardID    uint64      // 分片ID
	StartTxIdx uint64      // 开始交易索引
	EndTxIdx   uint64      // 结束交易索引
	Validator  common.Address // 验证该分片的节点
	Validated  bool        // 是否已验证
}

// ResourceUsage 记录资源使用情况
type ResourceUsage struct {
	CpuTimeMs      uint64  // CPU时间(毫秒)
	MemoryUsageKB  uint64  // 内存使用(KB)
	BatteryImpact  float64 // 电池影响(百分比)
	NetworkUsageKB uint64  // 网络使用(KB)
	ProcessingTime uint64  // 处理时间(毫秒)
}

// ProcessingStats 区块处理统计
type ProcessingStats struct {
	VerificationTimeNs   int64     // 验证时间(纳秒)
	TransmissionTimeNs   int64     // 传输时间(纳秒)
	ProcessingTimeNs     int64     // 处理时间(纳秒)
	CompressionRatio     float64   // 压缩比例
	BatteryConsumption   float64   // 电池消耗
	NetworkConsumption   uint64    // 网络消耗(字节)
	LastProcessingTime   time.Time // 最后处理时间
	SuccessfulChunks     uint64    // 成功处理的分块数
	TotalChunks          uint64    // 总分块数
}

// MobileBlock 为移动设备优化的区块结构
type MobileBlock struct {
	header        *MobileBlockHeader   // 区块头
	transactions  []*Transaction       // 交易列表
	validatorAddr common.Address       // 验证者地址
	signature     []byte               // 区块签名
	validationTime time.Time           // 验证时间
	shardID       uint64               // 分片ID
	txRanges      []*MobileShardRange  // 交易分片范围
	resourceUsage *ResourceUsage       // 资源使用记录
	
	// 缓存字段
	hash atomic.Value // 区块哈希缓存
	size atomic.Value // 区块大小缓存
	
	// 互斥锁用于并发访问
	mu sync.RWMutex
	
	// 移动端优化字段
	compressionEnabled bool         // 是否启用压缩
	compressedData     []byte       // 压缩数据
	lightVerifiable    bool         // 是否支持轻量级验证
	resumeData         []byte       // 断点续传数据
	lastProcessedTx    uint64       // 最后处理的交易索引
	processingStats    *ProcessingStats // 处理统计
	
	// 网络优化
	priorityLevel      int          // 传输优先级
	transmitInChunks   bool         // 是否分块传输
	chunkSize          uint64       // 分块大小
	transmitOffset     uint64       // 传输偏移量
}

// NewMobileBlock 创建新的移动区块
func NewMobileBlock(header *MobileBlockHeader, txs []*Transaction, validatorAddr common.Address, shardID uint64) *MobileBlock {
	b := &MobileBlock{
		header:            header,
		transactions:      make([]*Transaction, len(txs)),
		validatorAddr:     validatorAddr,
		validationTime:    time.Now(),
		shardID:           shardID,
		txRanges:          make([]*MobileShardRange, 0),
		resourceUsage:     &ResourceUsage{},
		
		// 初始化移动优化字段
		compressionEnabled: true,
		lightVerifiable:    true,
		processingStats:    &ProcessingStats{LastProcessingTime: time.Now()},
		priorityLevel:      NetworkPriorityMedium,
		transmitInChunks:   true,
		chunkSize:          DefaultChunkSize,
	}
	
	// 复制交易以避免引用外部数据
	copy(b.transactions, txs)
	
	// 检测设备类型并自动调整参数
	deviceInfo := getDeviceInfo()
	batteryLevel := getBatteryLevel()
	networkType := getNetworkType()
	
	// 根据设备性能自动调整
	if isLowEndDevice(deviceInfo) {
		b.compressionEnabled = true
		b.transmitInChunks = true
		b.chunkSize = DefaultChunkSize / 2 // 降低分块大小
		b.priorityLevel = NetworkPriorityLow
	} else if isHighEndDevice(deviceInfo) {
		b.compressionEnabled = getBatteryLevel() < 50 // 只在电量低时压缩
		b.transmitInChunks = networkType != "wifi"    // 非WiFi环境才分块
		b.chunkSize = DefaultChunkSize * 2 // 增加分块大小
	}
	
	// 根据电池状态调整
	if batteryLevel < 20 {
		b.compressionEnabled = true
		b.priorityLevel = NetworkPriorityLow
	}
	
	// 为大区块启用分块
	if len(txs) > 1000 {
		b.transmitInChunks = true
	}
	
	return b
}

// 判断是否为低端设备
func isLowEndDevice(deviceInfo DeviceInfo) bool {
	return deviceInfo.CPUCores < 4 || deviceInfo.RAMTotal < 2*1024*1024*1024
}

// 判断是否为高端设备
func isHighEndDevice(deviceInfo DeviceInfo) bool {
	return deviceInfo.CPUCores >= 6 && deviceInfo.RAMTotal >= 6*1024*1024*1024
}

// CompressBlock 压缩区块数据
func (b *MobileBlock) CompressBlock() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	// 如果已经压缩，则跳过
	if len(b.compressedData) > 0 {
		return nil
	}
	
	// 构建要压缩的数据
	data := struct {
		Header       *MobileBlockHeader
		Transactions []*Transaction
		TxRanges     []*MobileShardRange
	}{
		Header:       b.header,
		Transactions: b.transactions,
		TxRanges:     b.txRanges,
	}
	
	// 序列化数据
	raw, err := rlp.EncodeToBytes(data)
	if err != nil {
		return err
	}
	
	// 压缩数据
	startTime := time.Now()
	compressed, err := compressData(raw)
	if err != nil {
		return err
	}
	
	// 更新统计信息
	compressionTime := time.Since(startTime)
	compressionRatio := float64(len(compressed)) / float64(len(raw))
	
	b.compressedData = compressed
	b.processingStats.CompressionRatio = compressionRatio
	b.processingStats.ProcessingTimeNs += compressionTime.Nanoseconds()
	
	log.Debug("区块已压缩", 
		"原始大小", len(raw), 
		"压缩大小", len(compressed), 
		"压缩比", compressionRatio, 
		"耗时", compressionTime)
	
	return nil
}

// DecompressBlock 解压区块数据
func (b *MobileBlock) DecompressBlock() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	// 如果没有压缩数据，则跳过
	if len(b.compressedData) == 0 {
		return nil
	}
	
	// 解压数据
	startTime := time.Now()
	decompressed, err := decompressData(b.compressedData)
	if err != nil {
		return err
	}
	
	// 解码数据
	var data struct {
		Header       *MobileBlockHeader
		Transactions []*Transaction
		TxRanges     []*MobileShardRange
	}
	
	if err := rlp.DecodeBytes(decompressed, &data); err != nil {
		return err
	}
	
	// 更新区块
	b.header = data.Header
	b.transactions = data.Transactions
	b.txRanges = data.TxRanges
	
	// 更新统计信息
	decompressTime := time.Since(startTime)
	b.processingStats.ProcessingTimeNs += decompressTime.Nanoseconds()
	
	// 清除压缩数据以节省内存
	b.compressedData = nil
	
	log.Debug("区块已解压", "耗时", decompressTime)
	
	return nil
}

// 压缩数据
func compressData(data []byte) ([]byte, error) {
	// 实际实现应使用压缩库
	// 这里仅为示例
	return data, nil
}

// 解压数据
func decompressData(data []byte) ([]byte, error) {
	// 实际实现应使用压缩库
	// 这里仅为示例
	return data, nil
}

// Header 返回区块头
func (b *MobileBlock) Header() *MobileBlockHeader {
	return b.header
}

// Transactions 返回区块中的交易
func (b *MobileBlock) Transactions() []*Transaction {
	return b.transactions
}

// Transaction 返回指定索引的交易
func (b *MobileBlock) Transaction(idx uint64) *Transaction {
	if idx >= uint64(len(b.transactions)) {
		return nil
	}
	return b.transactions[idx]
}

// NumberU64 返回区块高度
func (b *MobileBlock) NumberU64() uint64 {
	return b.header.Number.Uint64()
}

// ShardID 返回分片ID
func (b *MobileBlock) ShardID() uint64 {
	return b.shardID
}

// TxCount 返回交易数量
func (b *MobileBlock) TxCount() int {
	return len(b.transactions)
}

// Hash 返回区块哈希
func (b *MobileBlock) Hash() common.Hash {
	// 使用缓存的哈希
	if hash := b.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	
	// 计算区块哈希
	v := rlpHash(b.header)
	b.hash.Store(v)
	return v
}

// Size 返回区块近似大小
func (b *MobileBlock) Size() common.StorageSize {
	if size := b.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	
	// 估算大小
	s := common.StorageSize(rlp.EmptySize)
	s += common.StorageSize(len(b.transactions) * 200) // 每个交易估算200字节
	s += common.StorageSize(len(b.signature))
	s += common.StorageSize(len(b.txRanges) * 32) // 每个分片范围估算32字节
	
	b.size.Store(s)
	return s
}

// SignBlock 使用指定的私钥签名区块
func (b *MobileBlock) SignBlock(privateKey *ecdsa.PrivateKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	// 获取区块哈希
	hash := b.Hash()
	
	// 使用私钥签名
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return err
	}
	
	// 存储签名和验证者地址
	b.signature = signature
	b.validatorAddr = crypto.PubkeyToAddress(privateKey.PublicKey)
	b.validationTime = time.Now()
	
	return nil
}

// VerifySignature 验证区块签名
func (b *MobileBlock) VerifySignature() (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	// 检查签名是否存在
	if len(b.signature) == 0 {
		return false, ErrInvalidSignature
	}
	
	// 获取区块哈希
	hash := b.Hash()
	
	// 从签名中恢复公钥
	pubkey, err := crypto.SigToPub(hash.Bytes(), b.signature)
	if err != nil {
		return false, err
	}
	
	// 计算地址
	recoveredAddr := crypto.PubkeyToAddress(*pubkey)
	
	// 如果已知验证者地址，进行比较
	if (b.validatorAddr != common.Address{}) && b.validatorAddr != recoveredAddr {
		return false, ErrMobileBlockSignatureInvalid
	}
	
	return true, nil
}

// ValidatorAddress 返回验证者地址
func (b *MobileBlock) ValidatorAddress() common.Address {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.validatorAddr
}

// ValidationTime 返回验证时间
func (b *MobileBlock) ValidationTime() time.Time {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.validationTime
}

// AddShardRange 添加交易分片范围
func (b *MobileBlock) AddShardRange(shardID, start, end uint64, validator common.Address) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	// 验证范围
	if start > end || end >= uint64(len(b.transactions)) {
		return ErrInvalidShardRange
	}
	
	// 检查范围是否有重叠
	for _, r := range b.txRanges {
		if r.ShardID == shardID && 
		   ((start >= r.StartTxIdx && start <= r.EndTxIdx) || 
		    (end >= r.StartTxIdx && end <= r.EndTxIdx)) {
			return fmt.Errorf("分片范围重叠: 现有范围 [%d-%d], 新范围 [%d-%d]", 
				r.StartTxIdx, r.EndTxIdx, start, end)
		}
	}
	
	// 添加新的分片范围
	b.txRanges = append(b.txRanges, &MobileShardRange{
		ShardID:    shardID,
		StartTxIdx: start,
		EndTxIdx:   end,
		Validator:  validator,
		Validated:  false,
	})
	
	return nil
}

// GetShardRanges 获取所有分片范围
func (b *MobileBlock) GetShardRanges() []*MobileShardRange {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	// 返回副本以防止修改
	result := make([]*MobileShardRange, len(b.txRanges))
	for i, r := range b.txRanges {
		result[i] = &MobileShardRange{
			ShardID:    r.ShardID,
			StartTxIdx: r.StartTxIdx,
			EndTxIdx:   r.EndTxIdx,
			Validator:  r.Validator,
			Validated:  r.Validated,
		}
	}
	
	return result
}

// MarkShardValidated 标记分片已验证
func (b *MobileBlock) MarkShardValidated(shardID uint64, validator common.Address) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	// 查找对应的分片
	for _, r := range b.txRanges {
		if r.ShardID == shardID && r.Validator == validator {
			r.Validated = true
			return nil
		}
	}
	
	return fmt.Errorf("未找到分片 %d 的验证者 %s", shardID, validator.Hex())
}

// IsFullyValidated 检查是否所有分片都已验证
func (b *MobileBlock) IsFullyValidated() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	// 如果没有分片，或有分片未验证，返回false
	if len(b.txRanges) == 0 {
		return false
	}
	
	for _, r := range b.txRanges {
		if !r.Validated {
			return false
		}
	}
	
	return true
}

// GetResourceUsage 获取资源使用情况
func (b *MobileBlock) GetResourceUsage() *ResourceUsage {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	if b.resourceUsage == nil {
		return &ResourceUsage{}
	}
	
	// 返回副本以防止修改
	return &ResourceUsage{
		CpuTimeMs:      b.resourceUsage.CpuTimeMs,
		MemoryUsageKB:  b.resourceUsage.MemoryUsageKB,
		BatteryImpact:  b.resourceUsage.BatteryImpact,
		NetworkUsageKB: b.resourceUsage.NetworkUsageKB,
		ProcessingTime: b.resourceUsage.ProcessingTime,
	}
}

// RecordResourceUsage 记录资源使用情况
func (b *MobileBlock) RecordResourceUsage(cpu, memory uint64, battery float64, network, processingTime uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	if b.resourceUsage == nil {
		b.resourceUsage = &ResourceUsage{}
	}
	
	b.resourceUsage.CpuTimeMs = cpu
	b.resourceUsage.MemoryUsageKB = memory
	b.resourceUsage.BatteryImpact = battery
	b.resourceUsage.NetworkUsageKB = network
	b.resourceUsage.ProcessingTime = processingTime
}

// EncodeMobileBlock 将移动区块编码为RLP字节
func EncodeMobileBlock(block *MobileBlock) ([]byte, error) {
	return rlp.EncodeToBytes(block)
}

// DecodeMobileBlock 从RLP字节解码移动区块
func DecodeMobileBlock(data []byte) (*MobileBlock, error) {
	block := &MobileBlock{}
	if err := rlp.DecodeBytes(data, block); err != nil {
		return nil, err
	}
	return block, nil
}

// NewMobileBlockWithHeader 创建只包含区块头的移动区块
func NewMobileBlockWithHeader(header *MobileBlockHeader) *MobileBlock {
	return &MobileBlock{
		header:       header,
		transactions: []*Transaction{},
		txRanges:     []*MobileShardRange{},
		resourceUsage: &ResourceUsage{},
	}
}

// ValidateTransactions 验证区块中的交易
func (b *MobileBlock) ValidateTransactions(validateFn func(*Transaction) error) error {
	for i, tx := range b.transactions {
		if err := validateFn(tx); err != nil {
			return fmt.Errorf("交易 %d 验证失败: %v", i, err)
		}
	}
	return nil
}

// String 返回区块的可读表示
func (b *MobileBlock) String() string {
	return fmt.Sprintf("MobileBlock(#%v, Shard %v, TxCount: %v, Hash: %v)",
		b.NumberU64(), b.ShardID(), b.TxCount(), b.Hash().Hex())
}

// EncodeRLP 实现rlp.Encoder接口
func (b *MobileBlock) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, struct {
		Header           *MobileBlockHeader
		Transactions     []*Transaction
		ValidatorAddress common.Address
		Signature        []byte
		ShardID          uint64
		TxRanges         []*MobileShardRange
		ResourceUsage    *ResourceUsage
	}{
		Header:           b.header,
		Transactions:     b.transactions,
		ValidatorAddress: b.validatorAddr,
		Signature:        b.signature,
		ShardID:          b.shardID,
		TxRanges:         b.txRanges,
		ResourceUsage:    b.resourceUsage,
	})
}

// DecodeRLP 实现rlp.Decoder接口
func (b *MobileBlock) DecodeRLP(s *rlp.Stream) error {
	var dec struct {
		Header           *MobileBlockHeader
		Transactions     []*Transaction
		ValidatorAddress common.Address
		Signature        []byte
		ShardID          uint64
		TxRanges         []*MobileShardRange
		ResourceUsage    *ResourceUsage
	}
	
	if err := s.Decode(&dec); err != nil {
		return err
	}
	
	b.header = dec.Header
	b.transactions = dec.Transactions
	b.validatorAddr = dec.ValidatorAddress
	b.signature = dec.Signature
	b.shardID = dec.ShardID
	b.txRanges = dec.TxRanges
	b.resourceUsage = dec.ResourceUsage
	b.validationTime = time.Now() // 设置解码时间
	
	return nil
}

// GetValidatorAddress 获取验证者地址
func (b *MobileBlock) GetValidatorAddress() common.Address {
	return b.validatorAddr
}

// GetSignature 获取区块签名
func (b *MobileBlock) GetSignature() []byte {
	sig := make([]byte, len(b.signature))
	copy(sig, b.signature)
	return sig
}

// GetSignatureHex 获取区块签名的十六进制表示
func (b *MobileBlock) GetSignatureHex() string {
	return hexutil.Encode(b.signature)
}

// ShardTransactions 获取当前分片的交易
func (b *MobileBlock) ShardTransactions() []*Transaction {
	// 查找当前分片的交易范围
	for _, r := range b.txRanges {
		if r.ShardID == b.shardID {
			if r.StartTxIdx <= r.EndTxIdx && r.EndTxIdx < uint64(len(b.transactions)) {
				txs := make([]*Transaction, r.EndTxIdx-r.StartTxIdx+1)
				for i := r.StartTxIdx; i <= r.EndTxIdx; i++ {
					txs[i-r.StartTxIdx] = b.transactions[i]
				}
				return txs
			}
		}
	}
	
	// 如果没有找到当前分片的范围，返回空列表
	return []*Transaction{}
}

// MobileBlockHeaderHash 计算区块头哈希
func (h *MobileBlockHeader) Hash() common.Hash {
	return rlpHash(h)
}

// 用于支持计算区块大小的辅助类型
type writeCounter uint64

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}

// VerifyBlock 验证区块
func (b *MobileBlock) VerifyBlock(fullVerification bool) (bool, error) {
	startTime := time.Now()
	startBattery := getBatteryLevel()
	
	// 如果电池电量低且不是必须全面验证，使用轻量级验证
	if !fullVerification && b.lightVerifiable && getBatteryLevel() < 20 {
		isValid, err := b.LightVerify()
		
		// 记录验证统计
		b.recordVerificationStats(time.Since(startTime), startBattery)
		
		return isValid, err
	}
	
	// 执行完整验证
	isValid, err := b.FullVerify()
	
	// 记录验证统计
	b.recordVerificationStats(time.Since(startTime), startBattery)
	
	return isValid, err
}

// LightVerify 执行轻量级验证
func (b *MobileBlock) LightVerify() (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	// 1. 验证区块头
	// 轻量级验证仅验证区块头和区块哈希
	headerHash := rlpHash(b.header)
	if headerHash != b.Hash() {
		return false, ErrMobileHashMismatch
	}
	
	// 2. 验证区块签名
	if len(b.signature) > 0 {
		// 从签名中恢复公钥
		pubkey, err := crypto.SigToPub(headerHash.Bytes(), b.signature)
		if err != nil {
			return false, err
		}
		
		// 计算地址
		recoveredAddr := crypto.PubkeyToAddress(*pubkey)
		
		// 验证地址
		if (b.validatorAddr != common.Address{}) && recoveredAddr != b.validatorAddr {
			return false, ErrInvalidSignature
		}
	}
	
	// 3. 抽样验证交易
	// 在轻量级验证中，只验证一部分交易
	if len(b.transactions) > 0 {
		// 计算抽样间隔
		sampleInterval := 100 / LightVerificationSample
		if sampleInterval < 1 {
			sampleInterval = 1
		}
		
		// 抽样验证
		for i := 0; i < len(b.transactions); i += sampleInterval {
			tx := b.transactions[i]
			
			// 验证交易签名
			_, err := types.Sender(types.NewEIP155Signer(big.NewInt(1)), tx)
			if err != nil {
				return false, err
			}
		}
	}
	
	log.Debug("完成轻量级区块验证", "区块", b.header.Number)
	return true, nil
}

// FullVerify 执行完整验证
func (b *MobileBlock) FullVerify() (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	// 1. 验证区块头
	headerHash := rlpHash(b.header)
	if headerHash != b.Hash() {
		return false, ErrMobileHashMismatch
	}
	
	// 2. 验证区块签名
	if len(b.signature) > 0 {
		// 从签名中恢复公钥
		pubkey, err := crypto.SigToPub(headerHash.Bytes(), b.signature)
		if err != nil {
			return false, err
		}
		
		// 计算地址
		recoveredAddr := crypto.PubkeyToAddress(*pubkey)
		
		// 验证地址
		if (b.validatorAddr != common.Address{}) && recoveredAddr != b.validatorAddr {
			return false, ErrInvalidSignature
		}
	}
	
	// 3. 验证所有交易
	for i, tx := range b.transactions {
		// 验证交易签名
		_, err := types.Sender(types.NewEIP155Signer(big.NewInt(1)), tx)
		if err != nil {
			return false, fmt.Errorf("交易 %d 验证失败: %v", i, err)
		}
	}
	
	// 4. 验证分片范围
	if len(b.txRanges) > 0 {
		// 检查分片覆盖所有交易
		covered := make([]bool, len(b.transactions))
		for _, r := range b.txRanges {
			// 验证分片范围有效
			if r.StartTxIdx > r.EndTxIdx || r.EndTxIdx >= uint64(len(b.transactions)) {
				return false, ErrInvalidShardRange
			}
			
			// 标记覆盖的交易
			for i := r.StartTxIdx; i <= r.EndTxIdx; i++ {
				if covered[i] {
					return false, ErrShardRangeOverlap
				}
				covered[i] = true
			}
		}
		
		// 检查所有交易都被覆盖
		for i, c := range covered {
			if !c {
				return false, fmt.Errorf("交易 %d 未被任何分片覆盖", i)
			}
		}
	}
	
	log.Debug("完成完整区块验证", "区块", b.header.Number)
	return true, nil
}

// 记录验证统计
func (b *MobileBlock) recordVerificationStats(duration time.Duration, startBattery int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	// 更新处理统计
	stats := b.processingStats
	stats.VerificationTimeNs = duration.Nanoseconds()
	stats.ProcessingTimeNs += duration.Nanoseconds()
	
	// 估算电池消耗
	batteryDrain := float64(startBattery - getBatteryLevel())
	if batteryDrain < 0 {
		batteryDrain = 0
	}
	stats.BatteryConsumption += batteryDrain
	
	// 更新最后处理时间
	stats.LastProcessingTime = time.Now()
}

// 获取区块性能统计
func (b *MobileBlock) GetPerformanceStats() *ProcessingStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	if b.processingStats == nil {
		return &ProcessingStats{}
	}
	
	// 返回副本以防止修改
	return &ProcessingStats{
		VerificationTimeNs:   b.processingStats.VerificationTimeNs,
		TransmissionTimeNs:   b.processingStats.TransmissionTimeNs,
		ProcessingTimeNs:     b.processingStats.ProcessingTimeNs,
		CompressionRatio:     b.processingStats.CompressionRatio,
		BatteryConsumption:   b.processingStats.BatteryConsumption,
		NetworkConsumption:   b.processingStats.NetworkConsumption,
		LastProcessingTime:   b.processingStats.LastProcessingTime,
		SuccessfulChunks:     b.processingStats.SuccessfulChunks,
		TotalChunks:          b.processingStats.TotalChunks,
	}
} 