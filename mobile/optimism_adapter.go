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
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"strings"
)

// OptimismAdapter Optimism链适配器实现
type OptimismAdapter struct {
	client        *ethclient.Client // 以太坊客户端
	chainID       *big.Int          // 链ID
	config        *AdapterConfig    // 适配器配置
	isConnected   bool              // 连接状态
	lastConnError error             // 最后一次连接错误
	address       string            // 当前地址
	l1Client      *ethclient.Client // L1以太坊客户端，用于跨层通信
	l1ChainID     *big.Int          // L1链ID
}

// L2标准网关ABI片段
const OptimismL2StandardGatewayABI = `[
	{
		"inputs": [
			{"internalType": "address", "name": "l1Token", "type": "address"},
			{"internalType": "address", "name": "to", "type": "address"},
			{"internalType": "uint256", "name": "amount", "type": "uint256"},
			{"internalType": "uint32", "name": "minGasLimit", "type": "uint32"},
			{"internalType": "bytes", "name": "extraData", "type": "bytes"}
		],
		"name": "withdrawERC20",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{"internalType": "address", "name": "to", "type": "address"},
			{"internalType": "uint32", "name": "minGasLimit", "type": "uint32"},
			{"internalType": "bytes", "name": "extraData", "type": "bytes"}
		],
		"name": "withdrawETH",
		"outputs": [],
		"stateMutability": "payable",
		"type": "function"
	}
]`

// OptimismWithdrawalStatus 表示Optimism提款状态
type OptimismWithdrawalStatus int

const (
	WithdrawalStatusUnknown OptimismWithdrawalStatus = iota // 未知状态
	WithdrawalStatusPending                                 // 等待提款处理中
	WithdrawalStatusCompleted                               // 提款已完成
	WithdrawalStatusFailed                                  // 提款失败
)

// NewOptimismAdapter 创建新的Optimism适配器
func NewOptimismAdapter(config *AdapterConfig) (*OptimismAdapter, error) {
	adapter := &OptimismAdapter{
		config:      config,
		isConnected: false,
	}

	// 初始化连接
	err := adapter.Connect()
	if err != nil {
		return nil, fmt.Errorf("无法连接到Optimism网络: %v", err)
	}

	// 如果配置中提供了私钥，从私钥派生地址
	if config.PrivateKey != "" {
		address, err := GetAddressFromPrivateKey(config.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("从私钥派生地址失败: %v", err)
		}
		adapter.address = address
	}

	// 连接到L1网络(如果配置中提供了L1 RPC URL)
	if config.L1RpcURL != "" {
		l1Client, err := ethclient.Dial(config.L1RpcURL)
		if err != nil {
			return adapter, nil // 即使L1连接失败也返回适配器，但记录错误
		}

		// 获取L1链ID
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		l1ChainID, err := l1Client.ChainID(ctx)
		if err != nil {
			l1Client.Close()
		} else {
			adapter.l1Client = l1Client
			adapter.l1ChainID = l1ChainID
		}
	}

	return adapter, nil
}

// GetChainType 获取链类型
func (adapter *OptimismAdapter) GetChainType() ChainType {
	return ChainTypeOptimism
}

// GetChainID 获取链ID
func (adapter *OptimismAdapter) GetChainID() int64 {
	if adapter.chainID == nil {
		return 0
	}
	return adapter.chainID.Int64()
}

// IsConnected 检查连接状态
func (adapter *OptimismAdapter) IsConnected() bool {
	return adapter.isConnected
}

// GetConnectionInfo 获取连接信息
func (adapter *OptimismAdapter) GetConnectionInfo() map[string]interface{} {
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
func (adapter *OptimismAdapter) GetAddress() string {
	return adapter.address
}

// Connect 连接到区块链网络
func (adapter *OptimismAdapter) Connect() error {
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
	adapter.lastConnError = nil
	return nil
}

// Disconnect 断开连接
func (adapter *OptimismAdapter) Disconnect() error {
	if adapter.client != nil {
		adapter.client.Close()
		adapter.client = nil
	}
	adapter.isConnected = false
	return nil
}

// GetBalance 获取账户余额
func (adapter *OptimismAdapter) GetBalance() (*big.Int, error) {
	if !adapter.isConnected {
		return nil, fmt.Errorf("未连接到Optimism网络")
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
func (adapter *OptimismAdapter) SignData(data []byte) ([]byte, error) {
	if adapter.config.PrivateKey == "" {
		return nil, fmt.Errorf("未设置私钥")
	}
	// 使用以太坊签名方法
	return SignEthereumData(adapter.config.PrivateKey, data)
}

// SendTransaction 发送交易
func (adapter *OptimismAdapter) SendTransaction(to string, amount *big.Int, data []byte) (string, error) {
	if !adapter.isConnected {
		return "", fmt.Errorf("未连接到Optimism网络")
	}

	if adapter.config.PrivateKey == "" {
		return "", fmt.Errorf("未设置私钥")
	}

	// 解析参数
	toAddress := common.HexToAddress(to)
	gasLimit := adapter.config.GasLimit
	if gasLimit == 0 {
		// 如果未设置，使用默认值
		gasLimit = 21000
		// 如果有数据，则估算Gas
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
func (adapter *OptimismAdapter) GetTransactionStatus(txHash string) (string, error) {
	if !adapter.isConnected {
		return "", fmt.Errorf("未连接到Optimism网络")
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

// EstimateGas 估算Gas费用
func (adapter *OptimismAdapter) EstimateGas(to string, data []byte) (uint64, error) {
	if !adapter.isConnected {
		return 0, fmt.Errorf("未连接到Optimism网络")
	}

	toAddress := common.HexToAddress(to)
	from := common.HexToAddress(adapter.address)

	msg := ethereum.CallMsg{
		From:     from,
		To:       &toAddress,
		Data:     data,
		GasPrice: big.NewInt(adapter.config.GasPrice),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	gas, err := adapter.client.EstimateGas(ctx, msg)
	if err != nil {
		return 0, err
	}

	// 为保险起见，增加一点余量
	return gas + (gas / 10), nil
}

// BridgeAsset 通过Optimism桥接资产
func (adapter *OptimismAdapter) BridgeAsset(targetChain ChainType, to string, amount *big.Int) (string, error) {
	if !adapter.isConnected {
		return "", fmt.Errorf("未连接到Optimism网络")
	}

	// 检查targetChain，如果是以太坊主网，使用Optimism的提款机制
	if targetChain == ChainTypeEthereum {
		return adapter.WithdrawToL1(to, amount)
	}

	// 如果不是提款到L1，则使用通用桥接方法
	toAddr := common.HexToAddress(to)
	
	// 编码桥接调用数据
	bridgeCallData, err := EncodeBridgeETH(targetChain, to)
	if err != nil {
		return "", fmt.Errorf("编码桥接调用失败: %v", err)
	}
	
	// 发送交易到桥接合约
	return adapter.SendTransaction(adapter.config.BridgeContract, amount, bridgeCallData)
}

// WithdrawToL1 从Optimism(L2)提款到以太坊(L1)
func (adapter *OptimismAdapter) WithdrawToL1(to string, amount *big.Int) (string, error) {
	if adapter.config.L2StandardBridgeAddress == "" {
		return "", fmt.Errorf("未配置L2标准桥地址")
	}

	// 解析L2标准网关ABI
	parsedABI, err := abi.JSON(strings.NewReader(OptimismL2StandardGatewayABI))
	if err != nil {
		return "", fmt.Errorf("解析L2标准网关ABI失败: %v", err)
	}

	// 准备提款调用数据
	// 使用最小gas限制(可以根据需要调整)
	minGasLimit := uint32(200000)
	emptyExtraData := []byte{}
	
	// 编码withdrawETH调用
	callData, err := parsedABI.Pack(
		"withdrawETH", 
		common.HexToAddress(to), 
		minGasLimit, 
		emptyExtraData,
	)
	if err != nil {
		return "", fmt.Errorf("编码提款调用失败: %v", err)
	}

	// 发送交易
	return adapter.SendTransaction(adapter.config.L2StandardBridgeAddress, amount, callData)
}

// WithdrawERC20ToL1 从Optimism(L2)提款ERC20代币到以太坊(L1)
func (adapter *OptimismAdapter) WithdrawERC20ToL1(tokenAddress, to string, amount *big.Int) (string, error) {
	if adapter.config.L2StandardBridgeAddress == "" {
		return "", fmt.Errorf("未配置L2标准桥地址")
	}

	// 解析L2标准网关ABI
	parsedABI, err := abi.JSON(strings.NewReader(OptimismL2StandardGatewayABI))
	if err != nil {
		return "", fmt.Errorf("解析L2标准网关ABI失败: %v", err)
	}

	// 首先授权桥接合约使用代币
	approveCallData, err := EncodeApproveERC20(adapter.config.L2StandardBridgeAddress, amount)
	if err != nil {
		return "", fmt.Errorf("编码授权调用失败: %v", err)
	}
	
	// 发送授权交易
	approveTxHash, err := adapter.SendTransaction(tokenAddress, big.NewInt(0), approveCallData)
	if err != nil {
		return "", fmt.Errorf("授权交易失败: %v", err)
	}
	
	// 等待授权交易确认
	for i := 0; i < adapter.config.MaxRetries; i++ {
		status, err := adapter.GetTransactionStatus(approveTxHash)
		if err != nil {
			return "", fmt.Errorf("获取授权交易状态失败: %v", err)
		}
		
		if status == "success" {
			break
		} else if status == "failed" {
			return "", errors.New("授权交易失败")
		}
		
		time.Sleep(2 * time.Second)
	}
	
	// 准备提款调用数据
	minGasLimit := uint32(200000) // 可以根据需要调整
	emptyExtraData := []byte{}
	
	// 编码withdrawERC20调用
	callData, err := parsedABI.Pack(
		"withdrawERC20", 
		common.HexToAddress(tokenAddress), // L1代币地址(在L2上相同)
		common.HexToAddress(to),
		amount,
		minGasLimit,
		emptyExtraData,
	)
	if err != nil {
		return "", fmt.Errorf("编码提款调用失败: %v", err)
	}

	// 发送交易
	return adapter.SendTransaction(adapter.config.L2StandardBridgeAddress, big.NewInt(0), callData)
}

// GetWithdrawalStatus 获取从L2到L1的提款状态
func (adapter *OptimismAdapter) GetWithdrawalStatus(l2TxHash string) (OptimismWithdrawalStatus, error) {
	if !adapter.isConnected {
		return WithdrawalStatusUnknown, fmt.Errorf("未连接到Optimism网络")
	}
	
	if adapter.l1Client == nil {
		return WithdrawalStatusUnknown, fmt.Errorf("未连接到L1网络，无法验证提款状态")
	}
	
	// 从L2交易获取提款事件并检查L1状态
	// 这里是简化的逻辑，实际实现需要更复杂的跨链验证
	// 包括查询L2的交易收据，获取提款事件，然后查询L1上的状态
	
	// 此处返回一个模拟状态
	return WithdrawalStatusPending, nil
}

// ClaimAsset 认领资产，Optimism通常不需要手动认领
func (adapter *OptimismAdapter) ClaimAsset(sourceChain ChainType, proofData []byte) (string, error) {
	if !adapter.isConnected {
		return "", fmt.Errorf("未连接到Optimism网络")
	}
	
	// Optimism通常不需要手动认领，提款会自动完成
	// 但此处保留方法以兼容通用接口
	
	if sourceChain == ChainTypeEthereum {
		return "", fmt.Errorf("从L1到L2不需要手动认领资产")
	}
	
	// 处理从其他链到Optimism的认领逻辑
	if adapter.config.BridgeContract == "" {
		return "", fmt.Errorf("未配置桥接合约地址")
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
func (adapter *OptimismAdapter) QueryEvents(contractAddr string, eventSig string, fromBlock, toBlock int64) ([]map[string]interface{}, error) {
	if !adapter.isConnected {
		return nil, fmt.Errorf("未连接到Optimism网络")
	}

	// 实现事件查询逻辑
	// 这里需要具体实现，可能需要使用过滤器和日志查询
	// 由于实现相对复杂，此处简化处理
	return nil, fmt.Errorf("功能尚未实现")
}

// CallContract 调用合约
func (adapter *OptimismAdapter) CallContract(contractAddr string, data []byte) ([]byte, error) {
	if !adapter.isConnected {
		return nil, fmt.Errorf("未连接到Optimism网络")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	to := common.HexToAddress(contractAddr)
	from := common.HexToAddress(adapter.address)

	msg := ethereum.CallMsg{
		From: from,
		To:   &to,
		Data: data,
	}

	return adapter.client.CallContract(ctx, msg, nil)
} 