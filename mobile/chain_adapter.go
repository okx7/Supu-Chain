// package mobile 包含移动端相关功能
package mobile

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
)

// ChainType 区块链类型
type ChainType int

const (
	ChainTypeNone ChainType = iota // 未设置
	ChainTypeEthereum              // 以太坊
	ChainTypeSupur                 // Supur链
	ChainTypePolygon               // Polygon
	ChainTypeArbitrum              // Arbitrum
	ChainTypeOptimism              // Optimism
	ChainTypeBSC                   // BSC (币安智能链)
	ChainTypeAvalanche             // Avalanche
	ChainTypeZkSync                // zkSync Era
)

// String 将链类型转为字符串
func (ct ChainType) String() string {
	switch ct {
	case ChainTypeEthereum:
		return "Ethereum"
	case ChainTypePolygon:
		return "Polygon"
	case ChainTypeArbitrum:
		return "Arbitrum"
	case ChainTypeOptimism:
		return "Optimism"
	case ChainTypeBSC:
		return "BSC"
	case ChainTypeAvalanche:
		return "Avalanche"
	case ChainTypeSupur:
		return "Supur"
	case ChainTypeZkSync:
		return "zkSync Era"
	default:
		return "Unknown"
	}
}

// NetworkType 网络类型
type NetworkType int

const (
	NetworkTypeNone   NetworkType = iota // 无网络
	NetworkTypeWeak                     // 弱网络
	NetworkTypeMobile                    // 移动网络
	NetworkTypeWifi                      // WiFi网络
)

// ChainAdapter 区块链适配器接口
type ChainAdapter interface {
	// 连接状态
	Connect() error
	Disconnect() error
	IsConnected() bool
	
	// 获取区块信息
	GetLatestBlockNumber() (uint64, error)
	GetBlockByNumber(number uint64) (*types.Block, error)
	GetHeaderByNumber(number uint64) (*types.Header, error)
	GetHeaderByHash(hash common.Hash) (*types.Header, error)
	
	// 交易相关
	GetTransaction(hash common.Hash) (*types.Transaction, bool, error)
	GetTransactionReceipt(hash common.Hash) (*types.Receipt, error)
	SendTransaction(tx *types.Transaction) error
	
	// 其他查询
	GetBalance(address common.Address, blockNumber *big.Int) (*big.Int, error)
	GetCode(address common.Address, blockNumber *big.Int) ([]byte, error)
	GetStorageAt(address common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error)
}

// MobileChainAdapter 移动设备区块链适配器实现
type MobileChainAdapter struct {
	// 客户端连接
	client           *ethclient.Client
	
	// 连接信息
	rpcURL           string
	connected        bool
	connectTime      time.Time
	
	// 资源管理
	resourceManager  *ResourceManager
	
	// 网络状态跟踪
	networkType      NetworkType
	latencyHistory   []time.Duration
	
	// 缓存
	blockCache       map[uint64]*types.Block
	headerCache      map[common.Hash]*types.Header
	txCache          map[common.Hash]*types.Transaction
	receiptCache     map[common.Hash]*types.Receipt
	
	// 统计信息
	requestCount     int64
	cacheHits        int64
	
	// 上下文
	ctx              context.Context
	cancel           context.CancelFunc
}

// NewMobileChainAdapter 创建新的移动设备区块链适配器
func NewMobileChainAdapter(rpcURL string, resourceManager *ResourceManager) *MobileChainAdapter {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &MobileChainAdapter{
		rpcURL:          rpcURL,
		resourceManager: resourceManager,
		networkType:     NetworkTypeNone,
		blockCache:      make(map[uint64]*types.Block),
		headerCache:     make(map[common.Hash]*types.Header),
		txCache:         make(map[common.Hash]*types.Transaction),
		receiptCache:    make(map[common.Hash]*types.Receipt),
		latencyHistory:  make([]time.Duration, 0, 10),
		ctx:             ctx,
		cancel:          cancel,
	}
}

// Connect 连接到区块链节点
func (mca *MobileChainAdapter) Connect() error {
	if mca.connected && mca.client != nil {
		return nil
	}
	
	// 记录开始时间，用于计算延迟
	startTime := time.Now()
	
	// 创建客户端连接
	client, err := ethclient.Dial(mca.rpcURL)
	if err != nil {
		log.Error("连接区块链节点失败", "URL", mca.rpcURL, "错误", err)
		return err
	}
	
	// 计算连接延迟
	latency := time.Since(startTime)
	mca.updateLatency(latency)
	
	mca.client = client
	mca.connected = true
	mca.connectTime = time.Now()
	
	log.Info("已连接到区块链节点", "URL", mca.rpcURL, "延迟", latency)
	
	// 启动网络状态监控
	go mca.monitorNetwork()
	
	return nil
}

// Disconnect 断开与区块链节点的连接
func (mca *MobileChainAdapter) Disconnect() error {
	if mca.client != nil {
		mca.client.Close()
		mca.client = nil
	}
	
	mca.connected = false
	mca.cancel()
	
	log.Info("已断开与区块链节点的连接", "URL", mca.rpcURL)
	return nil
}

// IsConnected 检查是否已连接到区块链节点
func (mca *MobileChainAdapter) IsConnected() bool {
	return mca.connected && mca.client != nil
}

// GetLatestBlockNumber 获取最新区块号
func (mca *MobileChainAdapter) GetLatestBlockNumber() (uint64, error) {
	if !mca.IsConnected() {
		return 0, ErrNotConnected
	}
	
	// 记录开始时间，用于计算延迟
	startTime := time.Now()
	mca.requestCount++
	
	// 获取最新区块号
	header, err := mca.client.HeaderByNumber(mca.ctx, nil)
	if err != nil {
		log.Error("获取最新区块号失败", "错误", err)
		return 0, err
	}
	
	// 计算请求延迟
	latency := time.Since(startTime)
	mca.updateLatency(latency)
	
	return header.Number.Uint64(), nil
}

// GetHeaderByNumber 根据区块号获取区块头
func (mca *MobileChainAdapter) GetHeaderByNumber(number uint64) (*types.Header, error) {
	if !mca.IsConnected() {
		return nil, ErrNotConnected
	}
	
	// 记录开始时间，用于计算延迟
	startTime := time.Now()
	mca.requestCount++
	
	// 转换为big.Int
	blockNum := new(big.Int).SetUint64(number)
	
	// 获取区块头
	header, err := mca.client.HeaderByNumber(mca.ctx, blockNum)
	if err != nil {
		log.Error("获取区块头失败", "区块号", number, "错误", err)
		return nil, err
	}
	
	// 计算请求延迟
	latency := time.Since(startTime)
	mca.updateLatency(latency)
	
	// 缓存区块头
	mca.headerCache[header.Hash()] = header
	
	return header, nil
}

// GetHeaderByHash 根据哈希获取区块头
func (mca *MobileChainAdapter) GetHeaderByHash(hash common.Hash) (*types.Header, error) {
	if !mca.IsConnected() {
		return nil, ErrNotConnected
	}
	
	// 检查缓存
	if header, ok := mca.headerCache[hash]; ok {
		mca.cacheHits++
		return header, nil
	}
	
	// 记录开始时间，用于计算延迟
	startTime := time.Now()
	mca.requestCount++
	
	// 获取区块头
	header, err := mca.client.HeaderByHash(mca.ctx, hash)
	if err != nil {
		log.Error("获取区块头失败", "哈希", hash.Hex(), "错误", err)
		return nil, err
	}
	
	// 计算请求延迟
	latency := time.Since(startTime)
	mca.updateLatency(latency)
	
	// 缓存区块头
	mca.headerCache[hash] = header
	
	return header, nil
}

// GetBlockByNumber 根据区块号获取完整区块
func (mca *MobileChainAdapter) GetBlockByNumber(number uint64) (*types.Block, error) {
	if !mca.IsConnected() {
		return nil, ErrNotConnected
	}
	
	// 检查缓存
	if block, ok := mca.blockCache[number]; ok {
		mca.cacheHits++
		return block, nil
	}
	
	// 检查资源限制
	if mca.resourceManager != nil && mca.resourceManager.IsLowBattery() {
		// 在低电量模式下，可能只获取区块头而不是整个区块
		log.Debug("低电量模式，只获取区块头")
		// 这里可以实现一个轻量版的获取逻辑
	}
	
	// 记录开始时间，用于计算延迟
	startTime := time.Now()
	mca.requestCount++
	
	// 转换为big.Int
	blockNum := new(big.Int).SetUint64(number)
	
	// 获取完整区块（包含交易）
	block, err := mca.client.BlockByNumber(mca.ctx, blockNum)
	if err != nil {
		log.Error("获取区块失败", "区块号", number, "错误", err)
		return nil, err
	}
	
	// 计算请求延迟
	latency := time.Since(startTime)
	mca.updateLatency(latency)
	
	// 缓存区块
	mca.blockCache[number] = block
	
	// 缓存区块头
	mca.headerCache[block.Hash()] = block.Header()
	
	// 缓存交易
	for _, tx := range block.Transactions() {
		mca.txCache[tx.Hash()] = tx
	}
	
	return block, nil
}

// GetTransaction 获取交易信息
func (mca *MobileChainAdapter) GetTransaction(hash common.Hash) (*types.Transaction, bool, error) {
	if !mca.IsConnected() {
		return nil, false, ErrNotConnected
	}
	
	// 检查缓存
	if tx, ok := mca.txCache[hash]; ok {
		mca.cacheHits++
		return tx, true, nil
	}
	
	// 记录开始时间，用于计算延迟
	startTime := time.Now()
	mca.requestCount++
	
	// 获取交易
	tx, isPending, err := mca.client.TransactionByHash(mca.ctx, hash)
	if err != nil {
		log.Error("获取交易失败", "哈希", hash.Hex(), "错误", err)
		return nil, false, err
	}
	
	// 计算请求延迟
	latency := time.Since(startTime)
	mca.updateLatency(latency)
	
	// 只有在交易不是挂起状态时才缓存
	if !isPending {
		mca.txCache[hash] = tx
	}
	
	return tx, isPending, nil
}

// GetTransactionReceipt 获取交易收据
func (mca *MobileChainAdapter) GetTransactionReceipt(hash common.Hash) (*types.Receipt, error) {
	if !mca.IsConnected() {
		return nil, ErrNotConnected
	}
	
	// 检查缓存
	if receipt, ok := mca.receiptCache[hash]; ok {
		mca.cacheHits++
		return receipt, nil
	}
	
	// 记录开始时间，用于计算延迟
	startTime := time.Now()
	mca.requestCount++
	
	// 获取交易收据
	receipt, err := mca.client.TransactionReceipt(mca.ctx, hash)
	if err != nil {
		log.Error("获取交易收据失败", "哈希", hash.Hex(), "错误", err)
		return nil, err
	}
	
	// 计算请求延迟
	latency := time.Since(startTime)
	mca.updateLatency(latency)
	
	// 缓存收据
	mca.receiptCache[hash] = receipt
	
	return receipt, nil
}

// SendTransaction 发送交易
func (mca *MobileChainAdapter) SendTransaction(tx *types.Transaction) error {
	if !mca.IsConnected() {
		return ErrNotConnected
	}
	
	// 检查电池和网络状态
	if mca.resourceManager != nil && mca.resourceManager.IsCriticalBattery() {
		return ErrLowBattery
	}
	
	// 记录开始时间，用于计算延迟
	startTime := time.Now()
	mca.requestCount++
	
	// 发送交易
	err := mca.client.SendTransaction(mca.ctx, tx)
	if err != nil {
		log.Error("发送交易失败", "哈希", tx.Hash().Hex(), "错误", err)
		return err
	}
	
	// 计算请求延迟
	latency := time.Since(startTime)
	mca.updateLatency(latency)
	
	log.Info("交易发送成功", "哈希", tx.Hash().Hex())
	
	// 缓存交易
	mca.txCache[tx.Hash()] = tx
	
	return nil
}

// GetBalance 获取账户余额
func (mca *MobileChainAdapter) GetBalance(address common.Address, blockNumber *big.Int) (*big.Int, error) {
	if !mca.IsConnected() {
		return nil, ErrNotConnected
	}
	
	// 记录开始时间，用于计算延迟
	startTime := time.Now()
	mca.requestCount++
	
	// 获取余额
	balance, err := mca.client.BalanceAt(mca.ctx, address, blockNumber)
	if err != nil {
		log.Error("获取余额失败", "地址", address.Hex(), "错误", err)
		return nil, err
	}
	
	// 计算请求延迟
	latency := time.Since(startTime)
	mca.updateLatency(latency)
	
	return balance, nil
}

// GetCode 获取合约代码
func (mca *MobileChainAdapter) GetCode(address common.Address, blockNumber *big.Int) ([]byte, error) {
	if !mca.IsConnected() {
		return nil, ErrNotConnected
	}
	
	// 记录开始时间，用于计算延迟
	startTime := time.Now()
	mca.requestCount++
	
	// 获取代码
	code, err := mca.client.CodeAt(mca.ctx, address, blockNumber)
	if err != nil {
		log.Error("获取合约代码失败", "地址", address.Hex(), "错误", err)
		return nil, err
	}
	
	// 计算请求延迟
	latency := time.Since(startTime)
	mca.updateLatency(latency)
	
	return code, nil
}

// GetStorageAt 获取存储值
func (mca *MobileChainAdapter) GetStorageAt(address common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error) {
	if !mca.IsConnected() {
		return nil, ErrNotConnected
	}
	
	// 记录开始时间，用于计算延迟
	startTime := time.Now()
	mca.requestCount++
	
	// 获取存储值
	value, err := mca.client.StorageAt(mca.ctx, address, key, blockNumber)
	if err != nil {
		log.Error("获取存储值失败", "地址", address.Hex(), "键", key.Hex(), "错误", err)
		return nil, err
	}
	
	// 计算请求延迟
	latency := time.Since(startTime)
	mca.updateLatency(latency)
	
	return value, nil
}

// 更新延迟统计
func (mca *MobileChainAdapter) updateLatency(latency time.Duration) {
	// 保持历史记录不超过10个
	if len(mca.latencyHistory) >= 10 {
		// 移除最早的记录
		mca.latencyHistory = mca.latencyHistory[1:]
	}
	
	// 添加新的延迟记录
	mca.latencyHistory = append(mca.latencyHistory, latency)
	
	// 根据延迟更新网络类型
	mca.updateNetworkType()
}

// 更新网络类型
func (mca *MobileChainAdapter) updateNetworkType() {
	if len(mca.latencyHistory) == 0 {
		mca.networkType = NetworkTypeNone
		return
	}
	
	// 计算平均延迟
	var totalLatency time.Duration
	for _, latency := range mca.latencyHistory {
		totalLatency += latency
	}
	avgLatency := totalLatency / time.Duration(len(mca.latencyHistory))
	
	// 根据平均延迟确定网络类型
	switch {
	case avgLatency > 500*time.Millisecond:
		mca.networkType = NetworkTypeWeak
	case avgLatency > 200*time.Millisecond:
		mca.networkType = NetworkTypeMobile
	default:
		mca.networkType = NetworkTypeWifi
	}
	
	// 如果资源管理器可用，更新网络类型
	if mca.resourceManager != nil {
		mca.resourceManager.UpdateNetworkLatency(avgLatency)
	}
}

// 网络状态监控
func (mca *MobileChainAdapter) monitorNetwork() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-mca.ctx.Done():
			return
		case <-ticker.C:
			// 只在已连接状态下进行监控
			if !mca.IsConnected() {
				continue
			}
			
			// 执行一个轻量级检查以测量延迟
			startTime := time.Now()
			_, err := mca.client.HeaderByNumber(mca.ctx, nil)
			
			if err != nil {
				log.Warn("网络监控检测到错误", "错误", err)
				// 检查是否需要重新连接
				mca.handleNetworkError(err)
			} else {
				// 更新延迟
				latency := time.Since(startTime)
				mca.updateLatency(latency)
				
				log.Debug("网络监控", "延迟", latency, "类型", mca.networkType)
			}
		}
	}
}

// 处理网络错误
func (mca *MobileChainAdapter) handleNetworkError(err error) {
	// 根据错误类型进行处理
	// 可能需要断开连接并重新连接
	
	// 临时断开连接
	mca.connected = false
	
	// 检查是否需要重新连接
	if mca.resourceManager == nil || !mca.resourceManager.IsLowBattery() {
		// 尝试重新连接
		err := mca.Connect()
		if err != nil {
			log.Error("重新连接失败", "错误", err)
		}
	}
}

// 错误定义
var (
	ErrNotConnected   = NewMobileError("未连接到区块链节点")
	ErrLowBattery     = NewMobileError("设备电量过低，操作受限")
)

// MobileError 移动设备特定错误
type MobileError struct {
	message string
}

// NewMobileError 创建新的移动设备错误
func NewMobileError(message string) *MobileError {
	return &MobileError{message: message}
}

// Error 实现error接口
func (e *MobileError) Error() string {
	return e.message
}

// Layer2Config Layer2链特定配置
type Layer2Config struct {
	L1RpcURL              string        // L1 RPC URL，用于Layer2与Layer1交互
	L2StandardBridgeAddress string      // L2标准桥地址
}

// ZkSyncConfig zkSync链特定配置
type ZkSyncConfig struct {
	BridgeAddress   string        // zkSync桥接合约地址
	WithdrawAddress string        // zkSync提款合约地址
}

// AdapterConfig 适配器配置
type AdapterConfig struct {
	// 基础配置
	RpcURL                string        // RPC URL
	ChainID               int64         // 链ID
	PrivateKey            string        // 私钥
	GasLimit              uint64        // Gas限制
	GasPrice              int64         // Gas价格
	ConnectionTimeout     time.Duration // 连接超时
	RequestTimeout        time.Duration // 请求超时
	
	// 通用跨链配置
	BridgeContract        string        // 通用桥接合约地址
	MaxRetries            int           // 最大重试次数
	
	// 链特定配置
	Layer2Config          *Layer2Config   // Layer2 特定配置
	ZkSyncConfig          *ZkSyncConfig   // zkSync 特定配置
}

// ChainAdapterFactory 链适配器工厂
type ChainAdapterFactory struct {
	adapters map[ChainType]ChainAdapter
}

// NewChainAdapterFactory 创建一个新的链适配器工厂实例
func NewChainAdapterFactory() *ChainAdapterFactory {
	return &ChainAdapterFactory{
		adapters: make(map[ChainType]ChainAdapter),
	}
}

// GetAdapter 获取指定类型的链适配器，如果不存在则创建
func (factory *ChainAdapterFactory) GetAdapter(chainType ChainType, config *AdapterConfig) (ChainAdapter, error) {
	// 检查适配器是否已存在
	if adapter, exists := factory.adapters[chainType]; exists {
		return adapter, nil
	}

	// 创建新的适配器
	var adapter ChainAdapter
	var err error

	switch chainType {
	case ChainTypeEthereum:
		adapter, err = NewEthereumAdapter(config)
	case ChainTypeSupur:
		adapter, err = NewSupurAdapter(config)
	case ChainTypePolygon:
		adapter, err = NewPolygonAdapter(config)
	case ChainTypeArbitrum:
		adapter, err = NewArbitrumAdapter(config)
	case ChainTypeOptimism:
		adapter, err = NewOptimismAdapter(config)
	case ChainTypeBSC:
		adapter, err = NewBSCAdapter(config)
	case ChainTypeAvalanche:
		adapter, err = NewAvalancheAdapter(config)
	case ChainTypeZkSync:
		adapter, err = NewZkSyncAdapter(config)
	default:
		return nil, fmt.Errorf("不支持的链类型: %d", chainType)
	}

	if err != nil {
		return nil, err
	}

	// 存储适配器实例
	factory.adapters[chainType] = adapter
	return adapter, nil
} 