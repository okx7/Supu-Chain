package mobile

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ArbitrumAdapter Arbitrum链适配器实现
type ArbitrumAdapter struct {
	client        *ethclient.Client // 以太坊客户端
	chainID       *big.Int          // 链ID
	config        *AdapterConfig    // 适配器配置
	isConnected   bool              // 连接状态
	lastConnError error             // 最后一次连接错误
}

// NewArbitrumAdapter 创建新的Arbitrum适配器
func NewArbitrumAdapter(config *AdapterConfig) (*ArbitrumAdapter, error) {
	adapter := &ArbitrumAdapter{
		config:      config,
		isConnected: false,
	}

	// 初始化连接
	err := adapter.Connect()
	if err != nil {
		return nil, fmt.Errorf("无法连接到Arbitrum网络: %v", err)
	}

	return adapter, nil
}

// ChainType 获取链类型
func (adapter *ArbitrumAdapter) ChainType() ChainType {
	return ChainTypeArbitrum
}

// IsConnected 检查连接状态
func (adapter *ArbitrumAdapter) IsConnected() bool {
	return adapter.isConnected
}

// Connect 连接到区块链网络
func (adapter *ArbitrumAdapter) Connect() error {
	// 尝试连接到RPC节点
	client, err := ethclient.Dial(adapter.config.NodeURL)
	if err != nil {
		adapter.isConnected = false
		adapter.lastConnError = err
		return err
	}

	// 获取链ID
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	chainID, err := client.ChainID(ctx)
	if err != nil {
		adapter.isConnected = false
		adapter.lastConnError = err
		client.Close()
		return err
	}

	adapter.client = client
	adapter.chainID = chainID
	adapter.isConnected = true
	adapter.lastConnError = nil
	return nil
}

// Disconnect 断开连接
func (adapter *ArbitrumAdapter) Disconnect() error {
	if adapter.client != nil {
		adapter.client.Close()
		adapter.client = nil
	}
	adapter.isConnected = false
	return nil
}

// GetBalance 获取账户余额
func (adapter *ArbitrumAdapter) GetBalance(address string) (string, error) {
	if !adapter.isConnected {
		return "", fmt.Errorf("未连接到Arbitrum网络")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	account := common.HexToAddress(address)
	balance, err := adapter.client.BalanceAt(ctx, account, nil)
	if err != nil {
		return "", err
	}

	return balance.String(), nil
}

// SignData 使用私钥签名数据
func (adapter *ArbitrumAdapter) SignData(privateKey string, data []byte) ([]byte, error) {
	// 使用以太坊签名方法
	return SignEthereumData(privateKey, data)
}

// SendTransaction 发送交易
func (adapter *ArbitrumAdapter) SendTransaction(privateKey string, toAddress string, amount string, gasLimit uint64, gasPrice string) (string, error) {
	if !adapter.isConnected {
		return "", fmt.Errorf("未连接到Arbitrum网络")
	}

	// 解析参数
	to := common.HexToAddress(toAddress)
	amountBig, ok := new(big.Int).SetString(amount, 10)
	if !ok {
		return "", fmt.Errorf("无效的金额格式")
	}

	gasPriceBig, ok := new(big.Int).SetString(gasPrice, 10)
	if !ok {
		return "", fmt.Errorf("无效的gas价格格式")
	}

	// 创建交易
	tx, err := CreateAndSignEthereumTransaction(adapter.client, adapter.chainID, privateKey, to, amountBig, gasLimit, gasPriceBig, nil)
	if err != nil {
		return "", err
	}

	// 发送交易
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = adapter.client.SendTransaction(ctx, tx)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

// GetTransactionStatus 获取交易状态
func (adapter *ArbitrumAdapter) GetTransactionStatus(txHash string) (string, error) {
	if !adapter.isConnected {
		return "", fmt.Errorf("未连接到Arbitrum网络")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash := common.HexToHash(txHash)
	tx, isPending, err := adapter.client.TransactionByHash(ctx, hash)
	if err != nil {
		return "", err
	}

	if isPending {
		return "pending", nil
	}

	receipt, err := adapter.client.TransactionReceipt(ctx, hash)
	if err != nil {
		return "", err
	}

	if receipt.Status == types.ReceiptStatusSuccessful {
		return "success", nil
	}
	
	return "failed", nil
} 