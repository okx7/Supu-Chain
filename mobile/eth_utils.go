// eth_utils.go 包含以太坊相关的工具函数
package mobile

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// SignEthereumData 使用私钥签名数据
func SignEthereumData(privateKeyHex string, data []byte) ([]byte, error) {
	// 解析私钥
	privateKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("私钥格式错误: %v", err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("私钥解析失败: %v", err)
	}

	// 计算数据哈希
	dataHash := crypto.Keccak256Hash(data)

	// 使用私钥签名哈希
	signature, err := crypto.Sign(dataHash.Bytes(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("签名失败: %v", err)
	}

	return signature, nil
}

// GetAddressFromPrivateKey 从私钥获取以太坊地址
func GetAddressFromPrivateKey(privateKeyHex string) (string, error) {
	// 解析私钥
	privateKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("私钥格式错误: %v", err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return "", fmt.Errorf("私钥解析失败: %v", err)
	}

	// 获取公钥
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("无法获取公钥")
	}

	// 获取地址
	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	return address.Hex(), nil
}

// CreateAndSignEthereumTransaction 创建并签名以太坊交易
func CreateAndSignEthereumTransaction(client *ethclient.Client, chainID *big.Int, privateKeyHex string, 
	to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) (*types.Transaction, error) {
	
	// 解析私钥
	privateKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("私钥格式错误: %v", err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("私钥解析失败: %v", err)
	}

	// 获取公钥和地址
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("无法获取公钥")
	}

	from := crypto.PubkeyToAddress(*publicKeyECDSA)

	// 获取发送方的nonce
	ctx, cancel := context.WithTimeout(context.Background(), ethereum.DefaultContextTimeout)
	defer cancel()

	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return nil, fmt.Errorf("获取nonce失败: %v", err)
	}

	// 创建交易对象
	var tx *types.Transaction
	if to == (common.Address{}) {
		// 部署合约交易
		tx = types.NewContractCreation(nonce, amount, gasLimit, gasPrice, data)
	} else {
		// 普通交易或合约调用
		tx = types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data)
	}

	// 签名交易
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return nil, fmt.Errorf("签名交易失败: %v", err)
	}

	return signedTx, nil
}

// EncodeBridgeCall 编码桥接合约调用
func EncodeBridgeCall(targetChain ChainType, to string, amount *big.Int) ([]byte, error) {
	// 模拟桥接合约ABI
	bridgeABI, err := abi.JSON(strings.NewReader(`[{"inputs":[{"internalType":"uint8","name":"targetChain","type":"uint8"},{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"bridge","outputs":[],"stateMutability":"payable","type":"function"}]`))
	if err != nil {
		return nil, fmt.Errorf("解析桥接ABI失败: %v", err)
	}

	// 验证地址
	if !common.IsHexAddress(to) {
		return nil, errors.New("无效的接收地址")
	}

	// 编码调用数据
	return bridgeABI.Pack("bridge", uint8(targetChain), common.HexToAddress(to), amount)
}

// EncodeClaimCall 编码资产认领调用
func EncodeClaimCall(sourceChain ChainType, proofData []byte) ([]byte, error) {
	// 模拟认领合约ABI
	claimABI, err := abi.JSON(strings.NewReader(`[{"inputs":[{"internalType":"uint8","name":"sourceChain","type":"uint8"},{"internalType":"bytes","name":"proofData","type":"bytes"}],"name":"claim","outputs":[],"stateMutability":"nonpayable","type":"function"}]`))
	if err != nil {
		return nil, fmt.Errorf("解析认领ABI失败: %v", err)
	}

	// 编码调用数据
	return claimABI.Pack("claim", uint8(sourceChain), proofData)
} 