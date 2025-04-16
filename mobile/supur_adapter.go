// package mobile 包含移动端相关功能
package mobile

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// SupurAdapter Supur链适配器
type SupurAdapter struct {
	config        *AdapterConfig    // 配置信息
	client        *http.Client      // HTTP客户端
	privateKey    *ecdsa.PrivateKey // 私钥
	address       string            // 账户地址
	chainID       int64             // 链ID
	isConnected   bool              // 连接状态
	lastError     error             // 最后一次错误
}

// NewSupurAdapter 创建新的Supur链适配器
func NewSupurAdapter(config *AdapterConfig) (ChainAdapter, error) {
	// 检查配置
	if config == nil {
		return nil, errors.New("配置不能为空")
	}
	
	// 验证必需参数
	if config.RpcURL == "" {
		return nil, errors.New("RPC URL不能为空")
	}
	
	adapter := &SupurAdapter{
		config: config,
		client: &http.Client{
			Timeout: config.ConnectionTimeout,
		},
		chainID: config.ChainID,
	}
	
	// 设置私钥
	if config.PrivateKey != "" {
		// 解析私钥
		privateKeyBytes, err := hexutil.Decode(config.PrivateKey)
		if err != nil {
			// 如果不是十六进制格式，尝试直接解析
			if !strings.HasPrefix(config.PrivateKey, "0x") {
				privateKeyBytes, err = hex.DecodeString(config.PrivateKey)
				if err != nil {
					return nil, fmt.Errorf("私钥格式无效: %v", err)
				}
			} else {
				return nil, fmt.Errorf("私钥格式无效: %v", err)
			}
		}
		
		// 将字节转换为私钥
		privateKey, err := crypto.ToECDSA(privateKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("私钥转换失败: %v", err)
		}
		
		// 从私钥生成公钥
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("无法获取公钥")
		}
		
		// 从公钥生成地址
		address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
		
		adapter.privateKey = privateKey
		adapter.address = address
	} else {
		// 如果没有提供私钥，生成新的密钥对
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("生成私钥失败: %v", err)
		}
		
		// 从私钥生成公钥
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("无法获取公钥")
		}
		
		// 从公钥生成地址
		address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
		
		adapter.privateKey = privateKey
		adapter.address = address
	}
	
	// 连接到网络
	err := adapter.Connect()
	if err != nil {
		return nil, err
	}
	
	return adapter, nil
}

// GetChainType 获取链类型
func (s *SupurAdapter) GetChainType() ChainType {
	return ChainTypeSupur
}

// GetChainID 获取链ID
func (s *SupurAdapter) GetChainID() int64 {
	return s.chainID
}

// IsConnected 检查是否已连接
func (s *SupurAdapter) IsConnected() bool {
	return s.isConnected
}

// GetConnectionInfo 获取连接信息
func (s *SupurAdapter) GetConnectionInfo() map[string]interface{} {
	return map[string]interface{}{
		"rpcUrl":      s.config.RpcURL,
		"chainId":     s.chainID,
		"isConnected": s.isConnected,
	}
}

// GetAddress 获取当前地址
func (s *SupurAdapter) GetAddress() string {
	return s.address
}

// GetBalance 获取余额
func (s *SupurAdapter) GetBalance() (*big.Int, error) {
	if !s.isConnected {
		return nil, errors.New("适配器未连接")
	}
	
	// 构建RPC请求
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "supur_getBalance",
		"params":  []interface{}{s.address, "latest"},
		"id":      1,
	}
	
	return s.callRPC(payload)
}

// SignData 签名数据
func (s *SupurAdapter) SignData(data []byte) ([]byte, error) {
	if s.privateKey == nil {
		return nil, errors.New("未设置私钥")
	}
	
	// 计算数据哈希
	dataHash := crypto.Keccak256Hash(data)
	
	// 签名哈希
	signature, err := crypto.Sign(dataHash.Bytes(), s.privateKey)
	if err != nil {
		s.lastError = err
		return nil, fmt.Errorf("签名失败: %v", err)
	}
	
	return signature, nil
}

// SendTransaction 发送交易
func (s *SupurAdapter) SendTransaction(to string, amount *big.Int, data []byte) (string, error) {
	if !s.isConnected {
		return "", errors.New("适配器未连接")
	}
	
	if s.privateKey == nil {
		return "", errors.New("未设置私钥")
	}
	
	// 验证接收地址
	if !common.IsHexAddress(to) {
		return "", errors.New("无效的地址")
	}
	
	// 1. 获取当前nonce
	noncePayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "supur_getTransactionCount",
		"params":  []interface{}{s.address, "pending"},
		"id":      1,
	}
	
	nonceResult, err := s.callRPC(noncePayload)
	if err != nil {
		return "", fmt.Errorf("获取nonce失败: %v", err)
	}
	
	nonce := nonceResult.Int64()
	
	// 2. 构建交易对象
	transaction := map[string]interface{}{
		"from":     s.address,
		"to":       to,
		"gas":      fmt.Sprintf("0x%x", s.config.GasLimit),
		"gasPrice": fmt.Sprintf("0x%x", s.config.GasPrice),
		"value":    fmt.Sprintf("0x%x", amount),
		"data":     hexutil.Encode(data),
		"nonce":    fmt.Sprintf("0x%x", nonce),
		"chainId":  fmt.Sprintf("0x%x", s.chainID),
	}
	
	// 3. 计算交易哈希并签名
	txBytes, err := json.Marshal(transaction)
	if err != nil {
		return "", fmt.Errorf("序列化交易失败: %v", err)
	}
	
	txHash := crypto.Keccak256Hash(txBytes)
	signature, err := crypto.Sign(txHash.Bytes(), s.privateKey)
	if err != nil {
		return "", fmt.Errorf("签名交易失败: %v", err)
	}
	
	// 4. 将签名添加到交易
	transaction["signature"] = hexutil.Encode(signature)
	
	// 5. 发送交易
	sendTxPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "supur_sendRawTransaction",
		"params":  []interface{}{transaction},
		"id":      2,
	}
	
	txHashResult, err := s.callRPC(sendTxPayload)
	if err != nil {
		return "", fmt.Errorf("发送交易失败: %v", err)
	}
	
	// 返回交易哈希
	return txHashResult.String(), nil
}

// GetTransactionStatus 获取交易状态
func (s *SupurAdapter) GetTransactionStatus(txHash string) (string, error) {
	if !s.isConnected {
		return "", errors.New("适配器未连接")
	}
	
	// 验证交易哈希
	if !strings.HasPrefix(txHash, "0x") || len(txHash) != 66 {
		return "", errors.New("无效的交易哈希")
	}
	
	// 查询交易收据
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "supur_getTransactionReceipt",
		"params":  []interface{}{txHash},
		"id":      1,
	}
	
	response, err := s.makeJSONRPCRequest(payload)
	if err != nil {
		return "", fmt.Errorf("获取交易收据失败: %v", err)
	}
	
	// 检查结果
	if response["result"] == nil {
		// 交易可能仍在处理中
		return "pending", nil
	}
	
	receipt, ok := response["result"].(map[string]interface{})
	if !ok {
		return "", errors.New("解析交易收据失败")
	}
	
	// 检查状态
	status, ok := receipt["status"].(string)
	if !ok {
		return "", errors.New("解析交易状态失败")
	}
	
	if status == "0x1" {
		return "success", nil
	} else if status == "0x0" {
		return "failed", nil
	}
	
	return "unknown", nil
}

// EstimateGas 估算Gas费用
func (s *SupurAdapter) EstimateGas(to string, data []byte) (uint64, error) {
	if !s.isConnected {
		return 0, errors.New("适配器未连接")
	}
	
	// 验证接收地址
	if !common.IsHexAddress(to) {
		return 0, errors.New("无效的地址")
	}
	
	// 构建RPC请求
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "supur_estimateGas",
		"params": []interface{}{
			map[string]interface{}{
				"from": s.address,
				"to":   to,
				"data": hexutil.Encode(data),
			},
		},
		"id": 1,
	}
	
	result, err := s.callRPC(payload)
	if err != nil {
		return 0, fmt.Errorf("估算Gas失败: %v", err)
	}
	
	return result.Uint64(), nil
}

// BridgeAsset 资产桥接
func (s *SupurAdapter) BridgeAsset(targetChain ChainType, to string, amount *big.Int) (string, error) {
	if !s.isConnected {
		return "", errors.New("适配器未连接")
	}
	
	if s.config.BridgeContract == "" {
		return "", errors.New("桥接合约地址未设置")
	}
	
	// 验证地址
	if !common.IsHexAddress(to) {
		return "", errors.New("无效的目标地址")
	}
	
	// 实际应用中，这里应该调用桥接合约执行跨链交易
	// 为简化实现，这里直接构造合约调用数据
	
	// 调用桥接合约
	bridgeData := []byte("bridge") // 实际应用中需编码正确的调用参数
	
	// 发送交易到桥接合约
	txHash, err := s.SendTransaction(s.config.BridgeContract, amount, bridgeData)
	if err != nil {
		return "", fmt.Errorf("发送桥接交易失败: %v", err)
	}
	
	return txHash, nil
}

// ClaimAsset 资产认领
func (s *SupurAdapter) ClaimAsset(sourceChain ChainType, proofData []byte) (string, error) {
	if !s.isConnected {
		return "", errors.New("适配器未连接")
	}
	
	if s.config.BridgeContract == "" {
		return "", errors.New("桥接合约地址未设置")
	}
	
	// 实际应用中，这里应该调用桥接合约验证证明并认领资产
	// 为简化实现，这里直接构造合约调用数据
	
	// 调用桥接合约认领方法
	claimData := []byte("claim") // 实际应用中需编码正确的调用参数
	
	// 发送交易到桥接合约
	txHash, err := s.SendTransaction(s.config.BridgeContract, big.NewInt(0), claimData)
	if err != nil {
		return "", fmt.Errorf("发送认领交易失败: %v", err)
	}
	
	return txHash, nil
}

// QueryEvents 查询事件
func (s *SupurAdapter) QueryEvents(contractAddr string, eventSig string, fromBlock, toBlock int64) ([]map[string]interface{}, error) {
	if !s.isConnected {
		return nil, errors.New("适配器未连接")
	}
	
	// 验证合约地址
	if !common.IsHexAddress(contractAddr) {
		return nil, errors.New("无效的合约地址")
	}
	
	// 构建RPC请求
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "supur_getLogs",
		"params": []interface{}{
			map[string]interface{}{
				"address":   contractAddr,
				"topics":    []string{crypto.Keccak256Hash([]byte(eventSig)).Hex()},
				"fromBlock": fmt.Sprintf("0x%x", fromBlock),
				"toBlock":   fmt.Sprintf("0x%x", toBlock),
			},
		},
		"id": 1,
	}
	
	response, err := s.makeJSONRPCRequest(payload)
	if err != nil {
		return nil, fmt.Errorf("查询事件失败: %v", err)
	}
	
	// 检查结果
	results, ok := response["result"].([]interface{})
	if !ok {
		return nil, errors.New("解析结果失败")
	}
	
	// 转换结果
	events := make([]map[string]interface{}, 0, len(results))
	for _, item := range results {
		event, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		events = append(events, event)
	}
	
	return events, nil
}

// CallContract 调用合约
func (s *SupurAdapter) CallContract(contractAddr string, data []byte) ([]byte, error) {
	if !s.isConnected {
		return nil, errors.New("适配器未连接")
	}
	
	// 验证合约地址
	if !common.IsHexAddress(contractAddr) {
		return nil, errors.New("无效的合约地址")
	}
	
	// 构建RPC请求
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "supur_call",
		"params": []interface{}{
			map[string]interface{}{
				"from": s.address,
				"to":   contractAddr,
				"data": hexutil.Encode(data),
			},
			"latest",
		},
		"id": 1,
	}
	
	response, err := s.makeJSONRPCRequest(payload)
	if err != nil {
		return nil, fmt.Errorf("调用合约失败: %v", err)
	}
	
	// 检查结果
	result, ok := response["result"].(string)
	if !ok {
		return nil, errors.New("解析结果失败")
	}
	
	// 解码结果
	return hexutil.Decode(result)
}

// Connect 连接到区块链网络
func (s *SupurAdapter) Connect() error {
	if s.isConnected {
		return nil
	}
	
	// 测试连接
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "supur_chainId",
		"params":  []interface{}{},
		"id":      1,
	}
	
	result, err := s.callRPC(payload)
	if err != nil {
		s.lastError = err
		return fmt.Errorf("连接失败: %v", err)
	}
	
	// 更新链ID
	chainID := result.Int64()
	if s.config.ChainID > 0 && s.config.ChainID != chainID {
		return fmt.Errorf("链ID不匹配，配置:%d，实际:%d", s.config.ChainID, chainID)
	}
	
	s.chainID = chainID
	s.isConnected = true
	
	return nil
}

// Disconnect 断开连接
func (s *SupurAdapter) Disconnect() error {
	s.isConnected = false
	return nil
}

// GetLastError 获取最后一次错误
func (s *SupurAdapter) GetLastError() error {
	return s.lastError
}

// 内部辅助方法

// callRPC 执行RPC调用并返回big.Int结果
func (s *SupurAdapter) callRPC(payload map[string]interface{}) (*big.Int, error) {
	response, err := s.makeJSONRPCRequest(payload)
	if err != nil {
		return nil, err
	}
	
	// 检查结果
	result, ok := response["result"].(string)
	if !ok {
		return nil, errors.New("解析结果失败")
	}
	
	// 解析十六进制字符串
	value, err := hexutil.DecodeBig(result)
	if err != nil {
		return nil, fmt.Errorf("解码结果失败: %v", err)
	}
	
	return value, nil
}

// makeJSONRPCRequest 发送JSON-RPC请求
func (s *SupurAdapter) makeJSONRPCRequest(payload map[string]interface{}) (map[string]interface{}, error) {
	// 序列化请求
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %v", err)
	}
	
	// 创建HTTP请求
	req, err := http.NewRequest("POST", s.config.RpcURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	// 设置超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), s.config.RequestTimeout)
	defer cancel()
	
	req = req.WithContext(ctx)
	
	// 发送请求
	resp, err := s.client.Do(req)
	if err != nil {
		s.lastError = err
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	
	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}
	
	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("请求失败，状态码: %d，响应: %s", resp.StatusCode, string(body))
	}
	
	// 解析响应
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}
	
	// 检查错误
	if errObj, exists := response["error"]; exists && errObj != nil {
		errMap, ok := errObj.(map[string]interface{})
		if ok {
			errMsg := fmt.Sprintf("RPC错误: %v", errMap["message"])
			return nil, errors.New(errMsg)
		}
		return nil, fmt.Errorf("RPC错误: %v", errObj)
	}
	
	return response, nil
} 