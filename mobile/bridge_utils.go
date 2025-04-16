// package mobile 包含移动端相关功能
package mobile

import (
	"fmt"
	"math/big"
	"strings"
	
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// 标准桥接合约ABI
const StandardBridgeABI = `[
	{
		"inputs": [
			{"internalType": "uint8", "name": "targetChain", "type": "uint8"},
			{"internalType": "address", "name": "recipient", "type": "address"},
			{"internalType": "address", "name": "token", "type": "address"},
			{"internalType": "uint256", "name": "amount", "type": "uint256"}
		],
		"name": "bridgeERC20",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{"internalType": "uint8", "name": "targetChain", "type": "uint8"},
			{"internalType": "address", "name": "recipient", "type": "address"}
		],
		"name": "bridgeETH",
		"outputs": [],
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"inputs": [
			{"internalType": "uint8", "name": "sourceChain", "type": "uint8"},
			{"internalType": "bytes", "name": "proofData", "type": "bytes"}
		],
		"name": "claimTokens",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]`

// 标准的ERC20代币ABI
const StandardERC20ABI = `[
	{
		"inputs": [
			{"internalType": "address", "name": "spender", "type": "address"},
			{"internalType": "uint256", "name": "amount", "type": "uint256"}
		],
		"name": "approve",
		"outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [{"internalType": "address", "name": "account", "type": "address"}],
		"name": "balanceOf",
		"outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
		"stateMutability": "view",
		"type": "function"
	}
]`

// BridgeConfig 桥接配置
type BridgeConfig struct {
	BridgeContract string            // 桥接合约地址
	SupportedChains map[ChainType]bool // 支持的链类型
	GasLimit        uint64           // Gas限制
	GasMultiplier   float64          // Gas乘数（保险起见）
}

// NewBridgeConfig 创建新的桥接配置
func NewBridgeConfig(bridgeContract string) *BridgeConfig {
	return &BridgeConfig{
		BridgeContract:  bridgeContract,
		SupportedChains: make(map[ChainType]bool),
		GasLimit:        300000, // 默认值
		GasMultiplier:   1.1,    // 默认增加10%
	}
}

// AddSupportedChain 添加支持的链
func (bc *BridgeConfig) AddSupportedChain(chainType ChainType) *BridgeConfig {
	bc.SupportedChains[chainType] = true
	return bc
}

// EncodeBridgeERC20 编码ERC20代币桥接调用
func EncodeBridgeERC20(targetChain ChainType, recipient, token string, amount *big.Int) ([]byte, error) {
	// 验证参数
	if !common.IsHexAddress(recipient) {
		return nil, fmt.Errorf("无效的接收地址: %s", recipient)
	}
	
	if !common.IsHexAddress(token) {
		return nil, fmt.Errorf("无效的代币地址: %s", token)
	}
	
	// 解析ABI
	bridgeABI, err := abi.JSON(strings.NewReader(StandardBridgeABI))
	if err != nil {
		return nil, fmt.Errorf("解析桥接ABI失败: %v", err)
	}
	
	// 编码调用数据
	return bridgeABI.Pack(
		"bridgeERC20", 
		uint8(targetChain), 
		common.HexToAddress(recipient), 
		common.HexToAddress(token), 
		amount,
	)
}

// EncodeBridgeETH 编码原生币桥接调用
func EncodeBridgeETH(targetChain ChainType, recipient string) ([]byte, error) {
	// 验证参数
	if !common.IsHexAddress(recipient) {
		return nil, fmt.Errorf("无效的接收地址: %s", recipient)
	}
	
	// 解析ABI
	bridgeABI, err := abi.JSON(strings.NewReader(StandardBridgeABI))
	if err != nil {
		return nil, fmt.Errorf("解析桥接ABI失败: %v", err)
	}
	
	// 编码调用数据
	return bridgeABI.Pack(
		"bridgeETH", 
		uint8(targetChain), 
		common.HexToAddress(recipient),
	)
}

// EncodeClaimTokens 编码认领代币调用
func EncodeClaimTokens(sourceChain ChainType, proofData []byte) ([]byte, error) {
	// 解析ABI
	bridgeABI, err := abi.JSON(strings.NewReader(StandardBridgeABI))
	if err != nil {
		return nil, fmt.Errorf("解析桥接ABI失败: %v", err)
	}
	
	// 编码调用数据
	return bridgeABI.Pack(
		"claimTokens", 
		uint8(sourceChain), 
		proofData,
	)
}

// EncodeApproveERC20 编码ERC20授权调用
func EncodeApproveERC20(spender string, amount *big.Int) ([]byte, error) {
	// 验证参数
	if !common.IsHexAddress(spender) {
		return nil, fmt.Errorf("无效的授权地址: %s", spender)
	}
	
	// 解析ABI
	erc20ABI, err := abi.JSON(strings.NewReader(StandardERC20ABI))
	if err != nil {
		return nil, fmt.Errorf("解析ERC20 ABI失败: %v", err)
	}
	
	// 编码调用数据
	return erc20ABI.Pack(
		"approve", 
		common.HexToAddress(spender), 
		amount,
	)
}

// IsChainSupported 检查链是否受支持
func (bc *BridgeConfig) IsChainSupported(chainType ChainType) bool {
	supported, exists := bc.SupportedChains[chainType]
	return exists && supported
}

// 标准化桥接事件签名
const (
	TokensBridgedEventSig    = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822" // keccak256("TokensBridged(uint8,address,address,uint256)")
	TokensClaimedEventSig    = "0x7a2fc403d0e22679c9ebb1d9923920dc4fe9f8dfa22605bd45713d2e6c1d7917" // keccak256("TokensClaimed(uint8,address,address,uint256)")
	BridgeInitiatedEventSig  = "0x0a0607688c86ec1775abcdbab7b33a3a35a6c9cde677c9be880150c231cc6b0b" // keccak256("BridgeInitiated(uint8,address,uint256)")
	BridgeCompletedEventSig  = "0x4855b7086792e7e8a35d2fb80c80303f44d0288a575adeb95b4b75c2964da8d0" // keccak256("BridgeCompleted(uint8,address,uint256)")
)

// GenerateProofData 生成证明数据（示例）
// 注意：实际应用中，这应该是一个复杂的函数，根据特定的桥接协议生成有效的证明数据
func GenerateProofData(sourceChain ChainType, transactionHash string, recipient string, amount *big.Int) ([]byte, error) {
	// 这里只是一个占位符
	// 实际实现应该使用加密学方法生成有效的证明
	
	// 将所有参数编码成一个简单的字节序列
	packedData, err := abi.Arguments{}.Pack(
		uint8(sourceChain),
		common.HexToHash(transactionHash),
		common.HexToAddress(recipient),
		amount,
	)
	
	if err != nil {
		return nil, fmt.Errorf("生成证明数据失败: %v", err)
	}
	
	return packedData, nil
} 