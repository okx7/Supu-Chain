// package mobile 包含移动端相关功能
package mobile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// BridgeTransactionVerifier 桥接交易验证器
type BridgeTransactionVerifier struct {
	factory        *ChainAdapterFactory // 链适配器工厂
	securityConfig *BridgeSecurityConfig // 安全配置
}

// BridgeSecurityConfig 桥接安全配置
type BridgeSecurityConfig struct {
	MinConfirmations        map[ChainType]int64 // 最小确认数
	MaxTransactionAge       time.Duration       // 最大交易年龄
	AllowedDestinations     map[ChainType]bool  // 允许的目标链
	MaxTransactionAmount    map[ChainType]*big.Int // 最大交易金额
	TrustedContractAddresses map[ChainType][]string // 受信任的合约地址
	EnablePriceImpactCheck  bool                // 启用价格影响检查
	MaxPriceImpactPercent   int                 // 最大价格影响百分比
}

// NewBridgeSecurityConfig 创建新的桥接安全配置
func NewBridgeSecurityConfig() *BridgeSecurityConfig {
	return &BridgeSecurityConfig{
		MinConfirmations:        make(map[ChainType]int64),
		AllowedDestinations:     make(map[ChainType]bool),
		MaxTransactionAmount:    make(map[ChainType]*big.Int),
		TrustedContractAddresses: make(map[ChainType][]string),
		MaxTransactionAge:       24 * time.Hour,
		EnablePriceImpactCheck:  true,
		MaxPriceImpactPercent:   5, // 默认最大价格影响为5%
	}
}

// NewBridgeTransactionVerifier 创建新的桥接交易验证器
func NewBridgeTransactionVerifier(factory *ChainAdapterFactory, config *BridgeSecurityConfig) *BridgeTransactionVerifier {
	return &BridgeTransactionVerifier{
		factory:        factory,
		securityConfig: config,
	}
}

// VerifyBridgeTransaction 验证桥接交易
func (v *BridgeTransactionVerifier) VerifyBridgeTransaction(sourceChain, destChain ChainType, txHash, recipient string, amount *big.Int) (bool, string, error) {
	// 验证参数
	if txHash == "" {
		return false, "交易哈希为空", errors.New("交易哈希为空")
	}
	
	if recipient == "" || !common.IsHexAddress(recipient) {
		return false, "接收地址无效", errors.New("接收地址无效")
	}
	
	if amount == nil || amount.Cmp(big.NewInt(0)) <= 0 {
		return false, "金额无效", errors.New("金额无效")
	}
	
	// 检查目标链是否允许
	if !v.securityConfig.AllowedDestinations[destChain] {
		return false, fmt.Sprintf("不允许桥接到目标链: %s", destChain.String()), errors.New("目标链不允许")
	}
	
	// 检查交易金额是否超过最大限制
	if maxAmount, exists := v.securityConfig.MaxTransactionAmount[sourceChain]; exists && maxAmount != nil {
		if amount.Cmp(maxAmount) > 0 {
			return false, fmt.Sprintf("交易金额超过最大限制: %s", amount.String()), errors.New("交易金额超过限制")
		}
	}
	
	// 获取源链适配器
	sourceAdapter, err := v.factory.GetAdapter(sourceChain, nil)
	if err != nil {
		return false, fmt.Sprintf("获取源链适配器失败: %v", err), err
	}
	
	// 验证交易确认数
	confirmed, err := v.verifyTransactionConfirmations(sourceAdapter, txHash, sourceChain)
	if err != nil {
		return false, fmt.Sprintf("验证交易确认数失败: %v", err), err
	}
	
	if !confirmed {
		return false, "交易未达到最小确认数", errors.New("交易未确认")
	}
	
	// 验证交易内容（接收者、金额等）
	validContent, err := v.verifyTransactionContent(sourceAdapter, txHash, recipient, amount)
	if err != nil {
		return false, fmt.Sprintf("验证交易内容失败: %v", err), err
	}
	
	if !validContent {
		return false, "交易内容验证失败", errors.New("交易内容无效")
	}
	
	// 检查价格影响（可选）
	if v.securityConfig.EnablePriceImpactCheck {
		priceImpact, err := v.checkPriceImpact(sourceChain, destChain, amount)
		if err != nil {
			// 价格影响检查失败不阻止交易，但记录警告
			fmt.Printf("价格影响检查失败: %v\n", err)
		} else if priceImpact > v.securityConfig.MaxPriceImpactPercent {
			return false, fmt.Sprintf("价格影响过大: %d%%", priceImpact), errors.New("价格影响过大")
		}
	}
	
	// 所有检查通过
	return true, "验证通过", nil
}

// verifyTransactionConfirmations 验证交易确认数
func (v *BridgeTransactionVerifier) verifyTransactionConfirmations(adapter ChainAdapter, txHash string, chainType ChainType) (bool, error) {
	// 获取交易状态
	status, err := adapter.GetTransactionStatus(txHash)
	if err != nil {
		return false, err
	}
	
	// 如果交易尚未成功，直接返回false
	if status != "success" {
		return false, nil
	}
	
	// 如果链类型没有设置最小确认数，默认为1
	minConfirmations, exists := v.securityConfig.MinConfirmations[chainType]
	if !exists {
		minConfirmations = 1
	}
	
	// 这里应该实现获取交易确认数的逻辑
	// 由于不同链的接口不同，这里只是一个示例，实际应用中需要根据具体链实现
	confirmations := int64(10) // 假设当前有10个确认
	
	return confirmations >= minConfirmations, nil
}

// verifyTransactionContent 验证交易内容
func (v *BridgeTransactionVerifier) verifyTransactionContent(adapter ChainAdapter, txHash, expectedRecipient string, expectedAmount *big.Int) (bool, error) {
	// 这里应该实现验证交易内容的逻辑
	// 包括检查交易接收者是否匹配预期、金额是否匹配预期等
	// 由于不同链的接口不同，这里只是一个示例
	
	// 假设实现了一些逻辑，验证交易内容
	return true, nil
}

// checkPriceImpact 检查价格影响
func (v *BridgeTransactionVerifier) checkPriceImpact(sourceChain, destChain ChainType, amount *big.Int) (int, error) {
	// 实际应用中，应该通过调用价格预言机或DEX获取实时汇率
	// 计算跨链交易的价格影响
	// 这里只是一个示例
	return 2, nil // 假设价格影响为2%
}

// GenerateTransactionProof 生成交易证明
func (v *BridgeTransactionVerifier) GenerateTransactionProof(sourceChain ChainType, txHash, recipient string, amount *big.Int) ([]byte, error) {
	// 获取源链适配器
	sourceAdapter, err := v.factory.GetAdapter(sourceChain, nil)
	if err != nil {
		return nil, fmt.Errorf("获取源链适配器失败: %v", err)
	}
	
	// 检查交易是否已确认
	status, err := sourceAdapter.GetTransactionStatus(txHash)
	if err != nil {
		return nil, fmt.Errorf("获取交易状态失败: %v", err)
	}
	
	if status != "success" {
		return nil, errors.New("交易尚未成功确认")
	}
	
	// 构建证明数据
	// 在实际应用中，应该包含交易详细信息、链特定的验证数据等
	// 这里只是一个简化的示例
	
	// 组合关键数据
	message := fmt.Sprintf("%s:%s:%s:%s", sourceChain.String(), txHash, recipient, amount.String())
	
	// 计算哈希
	hash := sha256.Sum256([]byte(message))
	
	// 使用私钥签名（实际可能需要链特定的签名逻辑）
	// 这里假设已经有了一个用于证明的私钥
	privateKeyHex := "0000000000000000000000000000000000000000000000000000000000000001" // 示例私钥，实际应用中应安全存储
	
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %v", err)
	}
	
	signature, err := crypto.Sign(hash[:], privateKey)
	if err != nil {
		return nil, fmt.Errorf("签名失败: %v", err)
	}
	
	// 构建完整证明数据
	proofData := append(hash[:], signature...)
	
	return proofData, nil
}

// VerifyTransactionProof 验证交易证明
func (v *BridgeTransactionVerifier) VerifyTransactionProof(sourceChain ChainType, proofData []byte) (bool, *BridgeProofResult, error) {
	if len(proofData) < 32+65 { // 至少应包含32字节哈希和65字节签名
		return false, nil, errors.New("证明数据长度不足")
	}
	
	// 分离哈希和签名
	hash := proofData[:32]
	signature := proofData[32:97] // 假设ECDSA签名为65字节
	
	// 从签名恢复公钥
	pubKey, err := crypto.Ecrecover(hash, signature)
	if err != nil {
		return false, nil, fmt.Errorf("从签名恢复公钥失败: %v", err)
	}
	
	// 验证公钥是否是受信任的验证者
	// 这里应该有一个逻辑来检查公钥是否被授权
	
	// 解析证明数据中的交易信息
	// 这里是示例逻辑，实际应用中应从proofData中提取
	result := &BridgeProofResult{
		SourceChain: sourceChain,
		TxHash:      "0xExample",
		Recipient:   "0xRecipient",
		Amount:      big.NewInt(1000000000000000000),
		Timestamp:   time.Now(),
	}
	
	return true, result, nil
}

// BridgeProofResult 桥接证明结果
type BridgeProofResult struct {
	SourceChain ChainType  // 源链
	TxHash      string     // 交易哈希
	Recipient   string     // 接收者
	Amount      *big.Int   // 金额
	Timestamp   time.Time  // 时间戳
}

// GetBridgeSecurityStatus 获取桥接安全状态
func (v *BridgeTransactionVerifier) GetBridgeSecurityStatus() map[string]interface{} {
	status := make(map[string]interface{})
	
	// 汇总安全配置
	minConfigs := make(map[string]int64)
	for chainType, value := range v.securityConfig.MinConfirmations {
		minConfigs[chainType.String()] = value
	}
	status["minConfirmations"] = minConfigs
	
	allowedDests := make([]string, 0)
	for chainType, allowed := range v.securityConfig.AllowedDestinations {
		if allowed {
			allowedDests = append(allowedDests, chainType.String())
		}
	}
	status["allowedDestinations"] = allowedDests
	
	maxAmounts := make(map[string]string)
	for chainType, value := range v.securityConfig.MaxTransactionAmount {
		if value != nil {
			maxAmounts[chainType.String()] = value.String()
		}
	}
	status["maxTransactionAmounts"] = maxAmounts
	
	status["maxTransactionAge"] = v.securityConfig.MaxTransactionAge.String()
	status["enablePriceImpactCheck"] = v.securityConfig.EnablePriceImpactCheck
	status["maxPriceImpactPercent"] = v.securityConfig.MaxPriceImpactPercent
	
	return status
}

// IsContractTrusted 检查合约是否受信任
func (v *BridgeTransactionVerifier) IsContractTrusted(chainType ChainType, contractAddress string) bool {
	if !common.IsHexAddress(contractAddress) {
		return false
	}
	
	normalizedAddr := strings.ToLower(common.HexToAddress(contractAddress).Hex())
	
	trustedAddresses, exists := v.securityConfig.TrustedContractAddresses[chainType]
	if !exists {
		return false
	}
	
	for _, trusted := range trustedAddresses {
		if strings.ToLower(trusted) == normalizedAddr {
			return true
		}
	}
	
	return false
}

// AddTrustedContract 添加受信任的合约
func (v *BridgeTransactionVerifier) AddTrustedContract(chainType ChainType, contractAddress string) error {
	if !common.IsHexAddress(contractAddress) {
		return errors.New("无效的合约地址")
	}
	
	normalizedAddr := strings.ToLower(common.HexToAddress(contractAddress).Hex())
	
	trustedAddresses, exists := v.securityConfig.TrustedContractAddresses[chainType]
	if !exists {
		v.securityConfig.TrustedContractAddresses[chainType] = []string{normalizedAddr}
		return nil
	}
	
	// 检查是否已存在
	for _, trusted := range trustedAddresses {
		if strings.ToLower(trusted) == normalizedAddr {
			return nil // 已经存在，不需要添加
		}
	}
	
	// 添加到受信任列表
	v.securityConfig.TrustedContractAddresses[chainType] = append(trustedAddresses, normalizedAddr)
	return nil
}

// SetMinConfirmations 设置最小确认数
func (v *BridgeTransactionVerifier) SetMinConfirmations(chainType ChainType, confirmations int64) {
	v.securityConfig.MinConfirmations[chainType] = confirmations
}

// SetMaxTransactionAmount 设置最大交易金额
func (v *BridgeTransactionVerifier) SetMaxTransactionAmount(chainType ChainType, amount *big.Int) {
	v.securityConfig.MaxTransactionAmount[chainType] = amount
}

// SetAllowedDestination 设置允许的目标链
func (v *BridgeTransactionVerifier) SetAllowedDestination(chainType ChainType, allowed bool) {
	v.securityConfig.AllowedDestinations[chainType] = allowed
}

// SetPriceImpactCheck 设置价格影响检查
func (v *BridgeTransactionVerifier) SetPriceImpactCheck(enable bool, maxPercentage int) {
	v.securityConfig.EnablePriceImpactCheck = enable
	if maxPercentage > 0 {
		v.securityConfig.MaxPriceImpactPercent = maxPercentage
	}
} 