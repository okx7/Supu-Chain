// package mobile 包含移动端相关功能
package mobile

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
	
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// EthereumAdapter 以太坊区块链适配器
type EthereumAdapter struct {
	config      *AdapterConfig   // 配置
	client      *ethclient.Client // 客户端
	privateKey  *ecdsa.PrivateKey // 私钥
	address     common.Address   // 地址
	chainID     *big.Int         // 链ID
	isConnected bool             // 是否已连接
	lastError   error            // 最后错误
	bridgeABI   abi.ABI          // 桥接合约ABI
}

// NewEthereumAdapter 创建新的以太坊适配器
func NewEthereumAdapter(config *AdapterConfig) (*EthereumAdapter, error) {
	// 检查配置
	if config == nil {
		return nil, errors.New("配置不能为空")
	}
	
	if config.RpcURL == "" {
		return nil, errors.New("RPC URL不能为空")
	}
	
	// 创建以太坊客户端
	ctx, cancel := context.WithTimeout(context.Background(), config.ConnectionTimeout)
	defer cancel()
	
	client, err := ethclient.DialContext(ctx, config.RpcURL)
	if err != nil {
		return nil, fmt.Errorf("连接以太坊节点失败: %v", err)
	}
	
	// 解析私钥
	var privateKey *ecdsa.PrivateKey
	if config.PrivateKey != "" {
		privateKeyBytes, err := hex.DecodeString(strings.TrimPrefix(config.PrivateKey, "0x"))
		if err != nil {
			return nil, fmt.Errorf("私钥格式错误: %v", err)
		}
		
		privateKey, err = crypto.ToECDSA(privateKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("私钥解析失败: %v", err)
		}
	}
	
	// 获取公钥和地址
	var address common.Address
	if privateKey != nil {
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("无法获取公钥")
		}
		
		address = crypto.PubkeyToAddress(*publicKeyECDSA)
	}
	
	// 获取网络链ID
	networkID, err := client.NetworkID(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取网络ID失败: %v", err)
	}
	
	// 创建适配器
	adapter := &EthereumAdapter{
		config:      config,
		client:      client,
		privateKey:  privateKey,
		address:     address,
		chainID:     networkID,
		isConnected: true,
	}
	
	// 解析桥接合约ABI
	if config.BridgeContract != "" {
		// 这里应该使用实际的ABI解析
		// bridgeABI, err := abi.JSON(strings.NewReader(BridgeABI))
		// if err != nil {
		//     adapter.lastError = fmt.Errorf("解析桥接合约ABI失败: %v", err)
		// } else {
		//     adapter.bridgeABI = bridgeABI
		// }
	}
	
	return adapter, nil
}

// GetChainType 获取链类型
func (e *EthereumAdapter) GetChainType() ChainType {
	return ChainTypeEthereum
}

// GetBalance 获取账户余额
func (e *EthereumAdapter) GetBalance(address string) (*big.Int, error) {
	if !e.isConnected {
		return nil, errors.New("适配器未连接")
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), e.config.RequestTimeout)
	defer cancel()
	
	// 验证地址
	if !common.IsHexAddress(address) {
		return nil, errors.New("无效的以太坊地址")
	}
	
	// 查询余额
	balance, err := e.client.BalanceAt(ctx, common.HexToAddress(address), nil)
	if err != nil {
		e.lastError = err
		return nil, fmt.Errorf("获取余额失败: %v", err)
	}
	
	return balance, nil
}

// GetTokenBalance 获取代币余额
func (e *EthereumAdapter) GetTokenBalance(address string, tokenContract string) (*big.Int, error) {
	if !e.isConnected {
		return nil, errors.New("适配器未连接")
	}
	
	// 验证地址
	if !common.IsHexAddress(address) || !common.IsHexAddress(tokenContract) {
		return nil, errors.New("无效的地址")
	}
	
	// ERC20 balanceOf 函数ABI
	erc20ABI, err := abi.JSON(strings.NewReader(`[{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"}]`))
	if err != nil {
		return nil, fmt.Errorf("解析ERC20 ABI失败: %v", err)
	}
	
	// 编码调用数据
	callData, err := erc20ABI.Pack("balanceOf", common.HexToAddress(address))
	if err != nil {
		return nil, fmt.Errorf("编码调用数据失败: %v", err)
	}
	
	// 创建调用消息
	msg := ethereum.CallMsg{
		To:   &common.HexToAddress(tokenContract),
		Data: callData,
	}
	
	// 执行调用
	ctx, cancel := context.WithTimeout(context.Background(), e.config.RequestTimeout)
	defer cancel()
	
	result, err := e.client.CallContract(ctx, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("调用合约失败: %v", err)
	}
	
	// 解析结果
	var balance *big.Int
	err = erc20ABI.UnpackIntoInterface(&balance, "balanceOf", result)
	if err != nil {
		return nil, fmt.Errorf("解析结果失败: %v", err)
	}
	
	return balance, nil
}

// SendTransaction 发送交易
func (e *EthereumAdapter) SendTransaction(to string, amount *big.Int, data []byte) (string, error) {
	if !e.isConnected {
		return "", errors.New("适配器未连接")
	}
	
	if e.privateKey == nil {
		return "", errors.New("未设置私钥")
	}
	
	// 验证接收地址
	if !common.IsHexAddress(to) {
		return "", errors.New("无效的以太坊地址")
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), e.config.RequestTimeout)
	defer cancel()
	
	// 获取nonce
	nonce, err := e.client.PendingNonceAt(ctx, e.address)
	if err != nil {
		return "", fmt.Errorf("获取nonce失败: %v", err)
	}
	
	// 获取当前gas价格
	gasPrice, err := e.client.SuggestGasPrice(ctx)
	if err != nil {
		return "", fmt.Errorf("获取gas价格失败: %v", err)
	}
	
	// 创建交易
	toAddress := common.HexToAddress(to)
	tx := types.NewTransaction(nonce, toAddress, amount, e.config.GasLimit, gasPrice, data)
	
	// 签名交易
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(e.chainID), e.privateKey)
	if err != nil {
		return "", fmt.Errorf("签名交易失败: %v", err)
	}
	
	// 发送交易
	err = e.client.SendTransaction(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("发送交易失败: %v", err)
	}
	
	// 返回交易哈希
	return signedTx.Hash().Hex(), nil
}

// BridgeAssets 跨链资产桥接
func (e *EthereumAdapter) BridgeAssets(targetChain ChainType, targetAddress string, tokenContract string, amount *big.Int) (string, error) {
	if !e.isConnected {
		return "", errors.New("适配器未连接")
	}
	
	if e.config.BridgeContract == "" {
		return "", errors.New("桥接合约地址未设置")
	}
	
	// 验证地址
	if !common.IsHexAddress(targetAddress) || !common.IsHexAddress(tokenContract) {
		return "", errors.New("无效的地址")
	}
	
	// 简化版桥接逻辑 - 实际应用中需实现完整的跨链桥接流程
	// 1. 批准桥接合约使用代币
	approvalTx, err := e.approveToken(tokenContract, e.config.BridgeContract, amount)
	if err != nil {
		return "", fmt.Errorf("批准代币使用失败: %v", err)
	}
	
	// 等待批准交易确认
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err = e.waitForTransaction(ctx, approvalTx)
	if err != nil {
		return "", fmt.Errorf("批准交易确认失败: %v", err)
	}
	
	// 2. 调用桥接合约
	// bridgeData, err := e.bridgeABI.Pack("bridgeTokens", uint8(targetChain), targetAddress, tokenContract, amount)
	// if err != nil {
	//     return "", fmt.Errorf("编码桥接调用失败: %v", err)
	// }
	
	// 模拟桥接调用数据
	bridgeData := []byte{} // 真实实现需要使用正确的ABI编码
	
	// 发送桥接交易
	bridgeTxHash, err := e.SendTransaction(e.config.BridgeContract, big.NewInt(0), bridgeData)
	if err != nil {
		return "", fmt.Errorf("发送桥接交易失败: %v", err)
	}
	
	return bridgeTxHash, nil
}

// GetTransactionStatus 获取交易状态
func (e *EthereumAdapter) GetTransactionStatus(txHash string) (TransactionStatus, error) {
	if !e.isConnected {
		return TransactionStatusUnknown, errors.New("适配器未连接")
	}
	
	// 验证交易哈希
	if !strings.HasPrefix(txHash, "0x") || len(txHash) != 66 {
		return TransactionStatusUnknown, errors.New("无效的交易哈希")
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), e.config.RequestTimeout)
	defer cancel()
	
	// 查询交易收据
	receipt, err := e.client.TransactionReceipt(ctx, common.HexToHash(txHash))
	if err != nil {
		// 如果交易未找到，可能是pending状态
		if err == ethereum.NotFound {
			// 检查交易池
			_, isPending, err := e.client.TransactionByHash(ctx, common.HexToHash(txHash))
			if err != nil {
				return TransactionStatusUnknown, fmt.Errorf("获取交易信息失败: %v", err)
			}
			
			if isPending {
				return TransactionStatusPending, nil
			}
			
			return TransactionStatusUnknown, nil
		}
		
		return TransactionStatusUnknown, fmt.Errorf("获取交易收据失败: %v", err)
	}
	
	// 根据收据状态返回
	if receipt.Status == 1 {
		return TransactionStatusSuccess, nil
	}
	
	return TransactionStatusFailed, nil
}

// Connect 连接到区块链网络
func (e *EthereumAdapter) Connect() error {
	if e.isConnected {
		return nil
	}
	
	// 创建以太坊客户端
	ctx, cancel := context.WithTimeout(context.Background(), e.config.ConnectionTimeout)
	defer cancel()
	
	client, err := ethclient.DialContext(ctx, e.config.RpcURL)
	if err != nil {
		e.lastError = err
		return fmt.Errorf("连接以太坊节点失败: %v", err)
	}
	
	// 获取网络链ID
	networkID, err := client.NetworkID(ctx)
	if err != nil {
		e.lastError = err
		return fmt.Errorf("获取网络ID失败: %v", err)
	}
	
	e.client = client
	e.chainID = networkID
	e.isConnected = true
	
	return nil
}

// Disconnect 断开与区块链网络的连接
func (e *EthereumAdapter) Disconnect() error {
	if e.client != nil {
		e.client.Close()
		e.isConnected = false
	}
	
	return nil
}

// IsConnected 检查是否已连接
func (e *EthereumAdapter) IsConnected() bool {
	return e.isConnected
}

// GetLastError 获取最后一次错误
func (e *EthereumAdapter) GetLastError() error {
	return e.lastError
}

// 内部辅助方法

// approveToken 批准代币合约允许桥接合约使用代币
func (e *EthereumAdapter) approveToken(tokenContract, spender string, amount *big.Int) (string, error) {
	// ERC20 approve 函数ABI
	erc20ABI, err := abi.JSON(strings.NewReader(`[{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]`))
	if err != nil {
		return "", fmt.Errorf("解析ERC20 ABI失败: %v", err)
	}
	
	// 编码调用数据
	callData, err := erc20ABI.Pack("approve", common.HexToAddress(spender), amount)
	if err != nil {
		return "", fmt.Errorf("编码调用数据失败: %v", err)
	}
	
	// 发送交易
	return e.SendTransaction(tokenContract, big.NewInt(0), callData)
}

// waitForTransaction 等待交易确认
func (e *EthereumAdapter) waitForTransaction(ctx context.Context, txHash string) (*types.Receipt, error) {
	hash := common.HexToHash(txHash)
	for {
		receipt, err := e.client.TransactionReceipt(ctx, hash)
		if err == nil {
			return receipt, nil
		}
		
		if err != ethereum.NotFound {
			return nil, err
		}
		
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
			// 继续等待
		}
	}
} 