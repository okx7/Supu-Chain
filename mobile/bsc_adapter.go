package mobile

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum"
)

// BSCAdapter BSC链(币安智能链)适配器实现
type BSCAdapter struct {
	client        *ethclient.Client // 以太坊客户端
	chainID       *big.Int          // 链ID
	config        *AdapterConfig    // 适配器配置
	isConnected   bool              // 连接状态
	lastConnError error             // 最后一次连接错误
	address       string            // 当前地址
}

// NewBSCAdapter 创建新的BSC适配器
func NewBSCAdapter(config *AdapterConfig) (*BSCAdapter, error) {
	adapter := &BSCAdapter{
		config:      config,
		isConnected: false,
	}

	// 初始化连接
	err := adapter.Connect()
	if err != nil {
		return nil, fmt.Errorf("无法连接到BSC网络: %v", err)
	}

	// 如果配置中提供了私钥，从私钥派生地址
	if config.PrivateKey != "" {
		address, err := GetAddressFromPrivateKey(config.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("从私钥派生地址失败: %v", err)
		}
		adapter.address = address
	}

	return adapter, nil
}

// GetChainType 获取链类型
func (adapter *BSCAdapter) GetChainType() ChainType {
	return ChainTypeBSC
}

// GetChainID 获取链ID
func (adapter *BSCAdapter) GetChainID() int64 {
	if adapter.chainID == nil {
		return 0
	}
	return adapter.chainID.Int64()
}

// IsConnected 检查连接状态
func (adapter *BSCAdapter) IsConnected() bool {
	return adapter.isConnected
}

// GetConnectionInfo 获取连接信息
func (adapter *BSCAdapter) GetConnectionInfo() map[string]interface{} {
	info := make(map[string]interface{})
	info["rpcUrl"] = adapter.config.RpcURL
	info["chainId"] = adapter.GetChainID()
	info["isConnected"] = adapter.isConnected
	if adapter.lastConnError != nil {
		info["lastError"] = adapter.lastConnError.Error()
	}
	return info
}

// GetAddress 获取当前地址
func (adapter *BSCAdapter) GetAddress() string {
	return adapter.address
}

// Connect 连接到区块链网络
func (adapter *BSCAdapter) Connect() error {
	// 尝试连接到RPC节点
	client, err := ethclient.Dial(adapter.config.RpcURL)
	if err != nil {
		adapter.isConnected = false
		adapter.lastConnError = err
		return err
	}

	// 获取链ID
	chainID, err := client.ChainID(context.Background())
	if err != nil {
		adapter.isConnected = false
		adapter.lastConnError = err
		return err
	}
	adapter.chainID = chainID
	adapter.client = client
	adapter.isConnected = true
	return nil
}

// GetBalance 获取账户余额
func (adapter *BSCAdapter) GetBalance(address string) (*big.Int, error) {
	account := common.HexToAddress(address)
	balance, err := adapter.client.BalanceAt(context.Background(), account, nil)
	if err != nil {
		return nil, err
	}
	return balance, nil
}

// SendTransaction 发送交易
func (adapter *BSCAdapter) SendTransaction(from, to string, amount *big.Int, privateKey string) (string, error) {
	fromAddress := common.HexToAddress(from)
	toAddress := common.HexToAddress(to)
	nonce, err := adapter.client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return "", err
	}

	gasLimit := uint64(21000) // 假设使用一个固定的gas limit
	gasPrice, err := adapter.client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	tx := types.NewTransaction(nonce, toAddress, amount, gasLimit, gasPrice, nil)

	chainID := big.NewInt(int64(adapter.GetChainID()))

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), common.HexToAddress(privateKey))
	if err != nil {
		return "", err
	}

	err = adapter.client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return "", err
	}

	return signedTx.Hash().Hex(), nil
}

// GetTransactionReceipt 获取交易回执
func (adapter *BSCAdapter) GetTransactionReceipt(txHash string) (*types.Receipt, error) {
	hash, err := common.HexToHash(txHash)
	if err != nil {
		return nil, err
	}
	return adapter.client.TransactionReceipt(context.Background(), hash)
}

// GetBlockNumber 获取最新区块高度
func (adapter *BSCAdapter) GetBlockNumber() (int64, error) {
	blockNumber, err := adapter.client.BlockNumber(context.Background())
	if err != nil {
		return 0, err
	}
	return blockNumber, nil
}

// GetBlockByNumber 获取指定区块
func (adapter *BSCAdapter) GetBlockByNumber(blockNumber int64) (*types.Block, error) {
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return nil, err
	}
	return block, nil
}

// GetBlockTransactionCountByNumber 获取指定区块的交易数量
func (adapter *BSCAdapter) GetBlockTransactionCountByNumber(blockNumber int64) (int, error) {
	count, err := adapter.client.BlockTransactionCountByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

// GetTransactionByHash 获取交易
func (adapter *BSCAdapter) GetTransactionByHash(txHash string) (*types.Transaction, error) {
	hash, err := common.HexToHash(txHash)
	if err != nil {
		return nil, err
	}
	tx, _, err := adapter.client.TransactionByHash(context.Background(), hash)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// GetTransactionCount 获取账户的交易数量
func (adapter *BSCAdapter) GetTransactionCount(address string) (int, error) {
	account := common.HexToAddress(address)
	count, err := adapter.client.TransactionCount(context.Background(), account)
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

// GetTransactionInBlock 获取区块中的交易
func (adapter *BSCAdapter) GetTransactionInBlock(blockNumber int64, index int) (*types.Transaction, error) {
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(block.Transactions()) {
		return nil, fmt.Errorf("index out of range")
	}
	return block.Transactions()[index], nil
}

// GetTransactionReceiptsInBlock 获取区块中的所有交易回执
func (adapter *BSCAdapter) GetTransactionReceiptsInBlock(blockNumber int64) ([]*types.Receipt, error) {
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return nil, err
	}
	receipts := make([]*types.Receipt, len(block.Transactions()))
	for i, tx := range block.Transactions() {
		receipt, err := adapter.client.TransactionReceipt(context.Background(), tx.Hash())
		if err != nil {
			return nil, err
		}
		receipts[i] = receipt
	}
	return receipts, nil
}

// GetTransactionInBlockByIndex 获取区块中的交易
func (adapter *BSCAdapter) GetTransactionInBlockByIndex(blockNumber int64, index int) (*types.Transaction, error) {
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(block.Transactions()) {
		return nil, fmt.Errorf("index out of range")
	}
	return block.Transactions()[index], nil
}

// GetTransactionReceiptInBlockByIndex 获取区块中的交易回执
func (adapter *BSCAdapter) GetTransactionReceiptInBlockByIndex(blockNumber int64, index int) (*types.Receipt, error) {
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(block.Transactions()) {
		return nil, fmt.Errorf("index out of range")
	}
	receipt, err := adapter.client.TransactionReceipt(context.Background(), block.Transactions()[index].Hash())
	if err != nil {
		return nil, err
	}
	return receipt, nil
}

// GetTransactionCountInBlock 获取区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlock(blockNumber int64) (int, error) {
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	return len(block.Transactions()), nil
}

// GetTransactionCountInBlockByIndex 获取区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByIndex(blockNumber int64, index int) (int, error) {
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	if index < 0 || index >= len(block.Transactions()) {
		return 0, fmt.Errorf("index out of range")
	}
	return 1, nil
}

// GetTransactionCountInBlockByAddress 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddress(blockNumber int64, address string) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for _, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			count++
		}
	}
	return count, nil
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.To() == account || tx.From() == account {
			if i == index {
				return 1, nil
			}
			count++
		}
	}
	return 0, fmt.Errorf("index out of range")
}

// GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量
func (adapter *BSCAdapter) GetTransactionCountInBlockByAddressInIndex 获取账户在区块中的交易数量(blockNumber int64, address string, index int) (int, error) {
	account := common.HexToAddress(address)
	block, err := adapter.client.BlockByNumber(context.Background(), big.NewInt(blockNumber))
	if err != nil {
		return 0, err
	}
	count := 0
	for i,