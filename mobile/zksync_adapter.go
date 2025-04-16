// package mobile 包含移动端相关功能
package mobile

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/accounts/abi"
)

// zkSync桥接合约ABI片段
const zkSyncBridgeABI = `[
	{
		"inputs": [
			{"internalType": "address", "name": "_l1Token", "type": "address"},
			{"internalType": "uint256", "name": "_amount", "type": "uint256"},
			{"internalType": "address", "name": "_to", "type": "address"},
			{"internalType": "uint256", "name": "_gasLimit", "type": "uint256"}
		],
		"name": "deposit",
		"outputs": [],
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"inputs": [
			{"internalType": "address", "name": "_to", "type": "address"},
			{"internalType": "uint256", "name": "_gasLimit", "type": "uint256"}
		],
		"name": "depositETH",
		"outputs": [],
		"stateMutability": "payable", 
		"type": "function"
	}
]`

// ZkSyncAdapter zkSync链适配器实现
type ZkSyncAdapter struct {
	client          *ethclient.Client // zkSync客户端
	l1Client        *ethclient.Client // 以太坊L1客户端
	chainID         *big.Int          // 链ID
	l1ChainID       *big.Int          // L1链ID
	config          *AdapterConfig    // 适配器配置
	isConnected     bool              // 连接状态
	l1IsConnected   bool              // L1连接状态
	lastConnError   error             // 最后一次连接错误
	address         string            // 当前地址
}

// NewZkSyncAdapter 创建新的zkSync适配器
func NewZkSyncAdapter(config *AdapterConfig) (*ZkSyncAdapter, error) {
	adapter := &ZkSyncAdapter{
		config:        config,
		isConnected:   false,
		l1IsConnected: false,
	}

	// 初始化连接
	err := adapter.Connect()
	if err != nil {
		return nil, fmt.Errorf("无法连接到zkSync网络: %v", err)
	}

	// 如果配置中提供了私钥，从私钥派生地址
	if config.PrivateKey != "" {
		address, err := GetAddressFromPrivateKey(config.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("从私钥派生地址失败: %v", err)
		}
		adapter.address = address
	}

	// 连接到L1网络(如果提供了L1 RPC URL)
	if config.L1RpcURL != "" {
		err := adapter.ConnectToL1()
		if err != nil {
			// 即使L1连接失败，我们仍然返回适配器，但记录错误
			adapter.lastConnError = err
		}
	}

	return adapter, nil
}

// GetChainType 获取链类型
func (adapter *ZkSyncAdapter) GetChainType() ChainType {
	return ChainTypeZkSync
}

// GetChainID 获取链ID
func (adapter *ZkSyncAdapter) GetChainID() int64 {
	if adapter.chainID == nil {
		return 0
	}
	return adapter.chainID.Int64()
}

// IsConnected 检查连接状态
func (adapter *ZkSyncAdapter) IsConnected() bool {
	return adapter.isConnected
}

// GetConnectionInfo 获取连接信息
func (adapter *ZkSyncAdapter) GetConnectionInfo() map[string]interface{} {
	info := make(map[string]interface{})
	info["rpcUrl"] = adapter.config.RpcURL
	info["l1RpcUrl"] = adapter.config.L1RpcURL
	info["chainId"] = adapter.GetChainID()
	info["isConnected"] = adapter.isConnected
	info["l1IsConnected"] = adapter.l1IsConnected
	if adapter.lastConnError != nil {
		info["lastError"] = adapter.lastConnError.Error()
	}
	return info
}

// GetAddress 获取当前地址
func (adapter *ZkSyncAdapter) GetAddress() string {
	return adapter.address
}

// Connect 连接到zkSync网络
func (adapter *ZkSyncAdapter) Connect() error {
	// 尝试连接到RPC节点
	client, err := ethclient.Dial(adapter.config.RpcURL)
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
	return nil
}

// ConnectToL1 连接到以太坊L1网络
func (adapter *ZkSyncAdapter) ConnectToL1() error {
	if adapter.config.L1RpcURL == "" {
		return errors.New("未设置L1 RPC URL")
	}

	// 尝试连接到L1 RPC节点
	l1Client, err := ethclient.Dial(adapter.config.L1RpcURL)
	if err != nil {
		adapter.l1IsConnected = false
		return err
	}

	// 获取L1链ID
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	l1ChainID, err := l1Client.ChainID(ctx)
	if err != nil {
		adapter.l1IsConnected = false
		l1Client.Close()
		return err
	}

	adapter.l1Client = l1Client
	adapter.l1ChainID = l1ChainID
	adapter.l1IsConnected = true
	return nil
}

// Disconnect 断开连接
func (adapter *ZkSyncAdapter) Disconnect() error {
	if adapter.client != nil {
		adapter.client.Close()
		adapter.client = nil
	}
	
	if adapter.l1Client != nil {
		adapter.l1Client.Close()
		adapter.l1Client = nil
	}
	
	adapter.isConnected = false
	adapter.l1IsConnected = false
	return nil
}

// GetBalance 获取账户余额
func (adapter *ZkSyncAdapter) GetBalance() (*big.Int, error) {
	if !adapter.isConnected {
		return nil, fmt.Errorf("未连接到zkSync网络")
	}

	if adapter.address == "" {
		return nil, fmt.Errorf("未设置地址")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	account := common.HexToAddress(adapter.address)
	balance, err := adapter.client.BalanceAt(ctx, account, nil)
	if err != nil {
		return nil, err
	}

	return balance, nil
}

// SignData 使用私钥签名数据
func (adapter *ZkSyncAdapter) SignData(data []byte) ([]byte, error) {
	if adapter.config.PrivateKey == "" {
		return nil, fmt.Errorf("未设置私钥")
	}
	
	// 使用以太坊签名方法
	return SignEthereumData(adapter.config.PrivateKey, data)
}

// SendTransaction 发送交易
func (adapter *ZkSyncAdapter) SendTransaction(to string, amount *big.Int, data []byte) (string, error) {
	if !adapter.isConnected {
		return "", fmt.Errorf("未连接到zkSync网络")
	}

	if adapter.config.PrivateKey == "" {
		return "", fmt.Errorf("未设置私钥")
	}

	// 解析参数
	toAddress := common.HexToAddress(to)
	gasLimit := adapter.config.GasLimit
	if gasLimit == 0 {
		// 如果未设置，使用默认值或估算Gas
		gasLimit = 21000
		if len(data) > 0 {
			estimated, err := adapter.EstimateGas(to, data)
			if err != nil {
				return "", err
			}
			gasLimit = estimated
		}
	}

	// 获取Gas价格
	var gasPriceBig *big.Int
	if adapter.config.GasPrice > 0 {
		gasPriceBig = big.NewInt(adapter.config.GasPrice)
	} else {
		// 获取当前Gas价格
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		gp, err := adapter.client.SuggestGasPrice(ctx)
		if err != nil {
			return "", err
		}
		gasPriceBig = gp
	}

	// 创建交易
	tx, err := CreateAndSignEthereumTransaction(adapter.client, adapter.chainID, adapter.config.PrivateKey, toAddress, amount, gasLimit, gasPriceBig, data)
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
func (adapter *ZkSyncAdapter) GetTransactionStatus(txHash string) (string, error) {
	if !adapter.isConnected {
		return "", fmt.Errorf("未连接到zkSync网络")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hash := common.HexToHash(txHash)
	_, isPending, err := adapter.client.TransactionByHash(ctx, hash)
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

	if receipt.Status == 1 {
		return "success", nil
	}
	
	return "failed", nil
}

// EstimateGas 估算Gas费用
func (adapter *ZkSyncAdapter) EstimateGas(to string, data []byte) (uint64, error) {
	if !adapter.isConnected {
		return 0, fmt.Errorf("未连接到zkSync网络")
	}

	toAddress := common.HexToAddress(to)
	fromAddress := common.HexToAddress(adapter.address)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msg := ethereum.CallMsg{
		From:     fromAddress,
		To:       &toAddress,
		Data:     data,
		GasPrice: big.NewInt(0),
	}

	gas, err := adapter.client.EstimateGas(ctx, msg)
	if err != nil {
		return 0, err
	}

	// 增加一点缓冲，确保交易成功
	return uint64(float64(gas) * 1.2), nil
}

// DepositETHToZkSync 从L1存款ETH到zkSync
func (adapter *ZkSyncAdapter) DepositETHToZkSync(amount *big.Int) (string, error) {
	if !adapter.l1IsConnected {
		return "", fmt.Errorf("未连接到以太坊L1网络")
	}

	if adapter.config.ZkSyncBridgeAddress == "" {
		return "", fmt.Errorf("未设置zkSync桥接合约地址")
	}

	// 解析zkSync桥接ABI
	parsedABI, err := abi.JSON(strings.NewReader(zkSyncBridgeABI))
	if err != nil {
		return "", fmt.Errorf("解析zkSync桥接ABI失败: %v", err)
	}

	// 准备存款调用数据
	gasLimit := uint64(200000) // 默认gas限制，可以调整
	callData, err := parsedABI.Pack(
		"depositETH",
		common.HexToAddress(adapter.address), // 接收者地址(自己)
		big.NewInt(int64(gasLimit)),         // L2 gas限制
	)
	if err != nil {
		return "", fmt.Errorf("编码存款调用失败: %v", err)
	}

	// 使用L1客户端发送交易
	// 创建交易
	gasPriceBig, err := adapter.l1Client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	// 创建并签名L1交易
	tx, err := CreateAndSignEthereumTransaction(
		adapter.l1Client,
		adapter.l1ChainID,
		adapter.config.PrivateKey,
		common.HexToAddress(adapter.config.ZkSyncBridgeAddress),
		amount,
		300000, // L1 gas限制
		gasPriceBig,
		callData,
	)
	if err != nil {
		return "", err
	}

	// 发送交易
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = adapter.l1Client.SendTransaction(ctx, tx)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

// DepositERC20ToZkSync 从L1存款ERC20代币到zkSync
func (adapter *ZkSyncAdapter) DepositERC20ToZkSync(tokenAddress string, amount *big.Int) (string, error) {
	if !adapter.l1IsConnected {
		return "", fmt.Errorf("未连接到以太坊L1网络")
	}

	if adapter.config.ZkSyncBridgeAddress == "" {
		return "", fmt.Errorf("未设置zkSync桥接合约地址")
	}

	// 首先授权桥接合约使用代币
	approveCallData, err := EncodeApproveERC20(adapter.config.ZkSyncBridgeAddress, amount)
	if err != nil {
		return "", fmt.Errorf("编码授权调用失败: %v", err)
	}
	
	// 发送授权交易
	approveTx, err := CreateAndSignEthereumTransaction(
		adapter.l1Client,
		adapter.l1ChainID,
		adapter.config.PrivateKey,
		common.HexToAddress(tokenAddress),
		big.NewInt(0),
		100000, // gas限制
		nil,    // 使用建议的gas价格
		approveCallData,
	)
	if err != nil {
		return "", fmt.Errorf("创建授权交易失败: %v", err)
	}
	
	// 发送授权交易
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = adapter.l1Client.SendTransaction(ctx, approveTx)
	cancel()
	if err != nil {
		return "", fmt.Errorf("发送授权交易失败: %v", err)
	}
	
	// 等待授权交易确认
	// 简化处理，实际应用中应该有更复杂的确认机制
	time.Sleep(30 * time.Second)
	
	// 解析zkSync桥接ABI
	parsedABI, err := abi.JSON(strings.NewReader(zkSyncBridgeABI))
	if err != nil {
		return "", fmt.Errorf("解析zkSync桥接ABI失败: %v", err)
	}

	// 准备存款调用数据
	gasLimit := uint64(200000) // 默认gas限制，可以调整
	callData, err := parsedABI.Pack(
		"deposit",
		common.HexToAddress(tokenAddress),    // L1代币地址
		amount,                              // 金额
		common.HexToAddress(adapter.address), // 接收者地址(自己)
		big.NewInt(int64(gasLimit)),         // L2 gas限制
	)
	if err != nil {
		return "", fmt.Errorf("编码存款调用失败: %v", err)
	}

	// 使用L1客户端发送交易
	// 创建交易
	gasPriceBig, err := adapter.l1Client.SuggestGasPrice(context.Background())
	if err != nil {
		return "", err
	}

	// 创建并签名L1交易
	tx, err := CreateAndSignEthereumTransaction(
		adapter.l1Client,
		adapter.l1ChainID,
		adapter.config.PrivateKey,
		common.HexToAddress(adapter.config.ZkSyncBridgeAddress),
		big.NewInt(0), // 不发送ETH
		300000,        // L1 gas限制
		gasPriceBig,
		callData,
	)
	if err != nil {
		return "", err
	}

	// 发送交易
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = adapter.l1Client.SendTransaction(ctx, tx)
	if err != nil {
		return "", err
	}

	return tx.Hash().Hex(), nil
}

// WithdrawFromZkSync 从zkSync提款到L1
func (adapter *ZkSyncAdapter) WithdrawFromZkSync(amount *big.Int) (string, error) {
	if !adapter.isConnected {
		return "", fmt.Errorf("未连接到zkSync网络")
	}

	// zkSync的提款逻辑
	// 这需要调用zkSync合约的withdraw方法
	
	// 简化实现，实际需要根据zkSync的最新协议调整
	withdrawData := []byte{} // 这应该是实际的合约调用数据
	
	return adapter.SendTransaction(adapter.config.ZkSyncWithdrawAddress, amount, withdrawData)
}

// BridgeAsset 将资产从zkSync桥接到其他链
func (adapter *ZkSyncAdapter) BridgeAsset(targetChain ChainType, to string, amount *big.Int) (string, error) {
	if !adapter.isConnected {
		return "", fmt.Errorf("未连接到zkSync网络")
	}

	// 如果目标链是以太坊主网，使用直接提款
	if targetChain == ChainTypeEthereum {
		return adapter.WithdrawFromZkSync(amount)
	}

	// 其他情况使用通用桥接逻辑
	if adapter.config.BridgeContract == "" {
		return "", fmt.Errorf("未设置桥接合约地址")
	}

	// 编码桥接调用
	bridgeCallData, err := EncodeBridgeETH(targetChain, to)
	if err != nil {
		return "", fmt.Errorf("编码桥接调用失败: %v", err)
	}

	// 发送交易
	return adapter.SendTransaction(adapter.config.BridgeContract, amount, bridgeCallData)
}

// ClaimAsset 认领资产
func (adapter *ZkSyncAdapter) ClaimAsset(sourceChain ChainType, proofData []byte) (string, error) {
	if !adapter.isConnected {
		return "", fmt.Errorf("未连接到zkSync网络")
	}

	// zkSync通常不需要手动认领
	if sourceChain == ChainTypeEthereum {
		return "", fmt.Errorf("从以太坊到zkSync不需要手动认领")
	}

	// 处理从其他链到zkSync的认领
	if adapter.config.BridgeContract == "" {
		return "", fmt.Errorf("未设置桥接合约地址")
	}

	// 编码认领调用
	claimCallData, err := EncodeClaimTokens(sourceChain, proofData)
	if err != nil {
		return "", fmt.Errorf("编码认领调用失败: %v", err)
	}

	// 发送交易
	return adapter.SendTransaction(adapter.config.BridgeContract, big.NewInt(0), claimCallData)
}

// QueryEvents 查询事件
func (adapter *ZkSyncAdapter) QueryEvents(contractAddr string, eventSig string, fromBlock, toBlock int64) ([]map[string]interface{}, error) {
	// 简化实现，实际应查询链上事件
	return []map[string]interface{}{}, nil
}

// CallContract 调用合约
func (adapter *ZkSyncAdapter) CallContract(contractAddr string, data []byte) ([]byte, error) {
	if !adapter.isConnected {
		return nil, fmt.Errorf("未连接到zkSync网络")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	toAddress := common.HexToAddress(contractAddr)
	msg := ethereum.CallMsg{
		To:   &toAddress,
		Data: data,
	}

	return adapter.client.CallContract(ctx, msg, nil)
} 