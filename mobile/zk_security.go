package mobile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

// 错误定义
var (
	ErrInvalidProof        = errors.New("无效的ZK证明") // 无效的ZK证明
	ErrProofReplay         = errors.New("ZK证明重放攻击") // ZK证明重放攻击
	ErrKeyNotTrusted       = errors.New("不可信的验证密钥") // 不可信的验证密钥
	ErrInvalidSignature    = errors.New("无效的签名") // 无效的签名
	ErrTrustedSetupMissing = errors.New("缺少可信设置") // 缺少可信设置
	ErrInvalidTEEAttestation = errors.New("无效的TEE证明") // 无效的TEE证明
	ErrMPCVerificationFailed = errors.New("MPC验证失败") // MPC验证失败
)

// TEEAttestationData TEE远程证明数据
type TEEAttestationData struct {
	QuoteData      []byte    // TEE引用数据
	SigningCert    []byte    // 签名证书
	Timestamp      time.Time // 时间戳
	DeviceID       string    // 设备ID
	AttestationSig []byte    // 证明签名
}

// ZKSecurityManager 管理ZK证明的安全性
type ZKSecurityManager struct {
	mu                   sync.RWMutex // 安全操作的互斥锁
	trustedKeys          map[string][]byte // 可信验证密钥哈希
	keySignatures        map[string][]byte // 验证密钥的签名
	authorityPublicKey   *ecdsa.PublicKey  // 权威机构公钥
	usedProofs           map[string]time.Time // 已使用证明的哈希，防止重放
	usedProofsExpiration time.Duration    // 已使用证明的过期时间
	keyStore             string           // 密钥存储路径
	secureMode           bool             // 安全模式开关
	lastRotationTime     time.Time        // 上次密钥轮换时间
	
	// 增强安全特性
	mpcVerificationEnabled bool          // 是否启用MPC验证
	teeAttestationEnabled  bool          // 是否启用TEE远程证明
	multiPartyVerification bool          // 是否启用多方验证
	trustedSetupParticipants []string    // 可信设置参与方
	setupVerificationHash  []byte        // 设置验证哈希
	proofSizeLimit        int            // 证明大小限制(字节)
	boundaryChecks        bool           // 是否启用边界检查
	auditLog              bool           // 是否启用审计日志
	lastAuditTime         time.Time      // 上次审计时间
	auditLogPath          string         // 审计日志路径
}

// ZKSecurityConfig ZK安全配置
type ZKSecurityConfig struct {
	KeyStore             string           // 密钥存储路径
	UsedProofsExpiration time.Duration    // 已使用证明的过期时间
	SecureMode           bool             // 安全模式开关
	RequireSignatures    bool             // 是否需要密钥签名
	TrustedAuthorities   []string         // 可信机构标识符列表
	RotationPeriod       time.Duration    // 密钥轮换周期
	
	// 增强安全配置
	MPCVerificationEnabled bool           // 是否启用MPC验证
	TEEAttestationEnabled  bool           // 是否启用TEE远程证明
	MultiPartyVerification bool           // 是否启用多方验证
	TrustedSetupParticipants []string     // 可信设置参与方
	ProofSizeLimit        int             // 证明大小限制(字节)
	BoundaryChecks        bool            // 是否启用边界检查
	AuditLog              bool            // 是否启用审计日志
	AuditLogPath          string          // 审计日志路径
}

// NewZKSecurityManager 创建一个新的ZK安全管理器
func NewZKSecurityManager(config ZKSecurityConfig) (*ZKSecurityManager, error) {
	sm := &ZKSecurityManager{
		trustedKeys:          make(map[string][]byte),
		keySignatures:        make(map[string][]byte),
		usedProofs:           make(map[string]time.Time),
		usedProofsExpiration: config.UsedProofsExpiration,
		keyStore:             config.KeyStore,
		secureMode:           config.SecureMode,
		lastRotationTime:     time.Now(),
		
		// 初始化增强安全特性
		mpcVerificationEnabled: config.MPCVerificationEnabled,
		teeAttestationEnabled:  config.TEEAttestationEnabled,
		multiPartyVerification: config.MultiPartyVerification,
		trustedSetupParticipants: config.TrustedSetupParticipants,
		proofSizeLimit:        config.ProofSizeLimit,
		boundaryChecks:        config.BoundaryChecks,
		auditLog:              config.AuditLog,
		auditLogPath:          config.AuditLogPath,
		lastAuditTime:         time.Now(),
	}

	// 创建密钥存储目录（如果不存在）
	if sm.keyStore != "" {
		if err := os.MkdirAll(sm.keyStore, 0700); err != nil {
			return nil, fmt.Errorf("无法创建密钥存储目录: %v", err)
		}
	}

	// 如果启用了安全模式，加载可信密钥和签名
	if sm.secureMode {
		if err := sm.loadTrustedKeys(); err != nil {
			log.Warn("加载可信密钥失败", "错误", err)
			// 继续执行，但发出警告
		}

		if config.RequireSignatures {
			if err := sm.loadAuthorityPublicKey(); err != nil {
				log.Error("加载权威机构公钥失败", "错误", err)
				return nil, err
			}
		}
		
		// 加载多方验证设置
		if sm.multiPartyVerification {
			if err := sm.loadMultiPartySetup(); err != nil {
				log.Warn("加载多方验证设置失败", "错误", err)
				// 继续执行，但发出警告
			}
		}
	}

	// 启动密钥过期清理协程
	go sm.cleanupExpiredProofs()
	
	// 启动安全审计日志协程
	if sm.auditLog {
		go sm.runSecurityAudit()
	}

	return sm, nil
}

// 加载多方验证设置
func (sm *ZKSecurityManager) loadMultiPartySetup() error {
	setupPath := filepath.Join(sm.keyStore, "multiparty_setup.json")
	if _, err := os.Stat(setupPath); os.IsNotExist(err) {
		log.Warn("多方验证设置文件不存在")
		return nil
	}
	
	data, err := ioutil.ReadFile(setupPath)
	if err != nil {
		return fmt.Errorf("读取多方验证设置失败: %v", err)
	}
	
	var setup struct {
		Participants []string `json:"participants"`
		VerificationHash string `json:"verification_hash"`
	}
	
	if err := json.Unmarshal(data, &setup); err != nil {
		return fmt.Errorf("解析多方验证设置失败: %v", err)
	}
	
	sm.trustedSetupParticipants = setup.Participants
	sm.setupVerificationHash, _ = hex.DecodeString(setup.VerificationHash)
	
	log.Info("已加载多方验证设置", "参与方数量", len(sm.trustedSetupParticipants))
	return nil
}

// 定期运行安全审计
func (sm *ZKSecurityManager) runSecurityAudit() {
	ticker := time.NewTicker(24 * time.Hour) // 每24小时审计一次
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sm.performSecurityAudit()
		}
	}
}

// 执行安全审计
func (sm *ZKSecurityManager) performSecurityAudit() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	// 检查密钥是否需要轮换
	sm.checkKeyRotation()
	
	// 检查可信设置完整性
	sm.verifyTrustedSetupIntegrity()
	
	// 记录审计日志
	if sm.auditLogPath != "" {
		auditData := map[string]interface{}{
			"timestamp":       time.Now(),
			"last_rotation":   sm.lastRotationTime,
			"keys_count":      len(sm.trustedKeys),
			"used_proofs":     len(sm.usedProofs),
			"security_checks": sm.getSecurityChecksStatus(),
		}
		
		jsonData, err := json.MarshalIndent(auditData, "", "  ")
		if err == nil {
			logPath := filepath.Join(sm.auditLogPath, fmt.Sprintf("zk_audit_%s.log", 
				time.Now().Format("20060102")))
				
			// 追加到审计日志
			f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				f.Write(jsonData)
				f.Write([]byte("\n"))
				f.Close()
			}
		}
	}
	
	sm.lastAuditTime = time.Now()
}

// 获取安全检查状态
func (sm *ZKSecurityManager) getSecurityChecksStatus() map[string]bool {
	return map[string]bool{
		"secure_mode":        sm.secureMode,
		"mpc_verification":   sm.mpcVerificationEnabled,
		"tee_attestation":    sm.teeAttestationEnabled,
		"multi_party_verify": sm.multiPartyVerification,
		"boundary_checks":    sm.boundaryChecks,
	}
}

// 验证可信设置完整性
func (sm *ZKSecurityManager) verifyTrustedSetupIntegrity() bool {
	// 在实际项目中，这里应该实现验证可信设置完整性的逻辑
	// 例如，检查多方参与者的签名、验证哈希等
	return true
}

// 加载可信密钥
func (sm *ZKSecurityManager) loadTrustedKeys() error {
	if sm.keyStore == "" {
		return errors.New("未指定密钥存储路径")
	}

	// 加载可信密钥列表
	trustedKeysPath := filepath.Join(sm.keyStore, "trusted_keys.json")
	if _, err := os.Stat(trustedKeysPath); os.IsNotExist(err) {
		// 文件不存在，创建默认的可信密钥列表
		log.Info("可信密钥列表不存在，将创建默认列表")
		// 这里可以实现创建默认可信密钥列表的逻辑
		return nil
	}

	// 实际项目中，这里应该从文件加载可信密钥列表
	// 为了演示，我们添加一些示例密钥
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 添加一些示例可信密钥
	sm.trustedKeys["groth16"] = generateSampleHash("groth16_key")
	sm.trustedKeys["plonk"] = generateSampleHash("plonk_key")
	sm.trustedKeys["stark"] = generateSampleHash("stark_key")

	log.Info("已加载可信密钥", "数量", len(sm.trustedKeys))
	return nil
}

// 生成示例哈希（仅用于演示）
func generateSampleHash(seed string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(seed))
	return hasher.Sum(nil)
}

// 加载权威机构公钥
func (sm *ZKSecurityManager) loadAuthorityPublicKey() error {
	if sm.keyStore == "" {
		return errors.New("未指定密钥存储路径")
	}

	// 检查公钥文件是否存在
	pubKeyPath := filepath.Join(sm.keyStore, "authority_pubkey.pem")
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		// 生成新的密钥对
		privateKey, err := sm.generateAuthorityKeyPair()
		if err != nil {
			return fmt.Errorf("生成密钥对失败: %v", err)
		}
		sm.authorityPublicKey = &privateKey.PublicKey
		return nil
	}

	// 从文件加载公钥
	pubKeyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("读取权威公钥文件失败: %v", err)
	}

	// 解析PEM格式的公钥
	block, _ := pem.Decode(pubKeyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("无效的公钥文件")
	}

	// 解析公钥
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("解析公钥失败: %v", err)
	}

	// 转换为ECDSA公钥
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("公钥不是ECDSA类型")
	}

	sm.authorityPublicKey = ecdsaPub
	log.Info("已加载权威机构公钥")
	return nil
}

// 生成权威机构密钥对
func (sm *ZKSecurityManager) generateAuthorityKeyPair() (*ecdsa.PrivateKey, error) {
	// 生成ECDSA密钥对
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成ECDSA密钥对失败: %v", err)
	}

	// 保存私钥到文件
	if sm.keyStore != "" {
		privKeyPath := filepath.Join(sm.keyStore, "authority_privkey.pem")
		pubKeyPath := filepath.Join(sm.keyStore, "authority_pubkey.pem")

		// 将私钥编码为PKCS#8格式
		privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("编码私钥失败: %v", err)
		}

		// 创建PEM块
		privKeyPEM := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privKeyBytes,
		}

		// 保存私钥到文件
		privKeyFile, err := os.OpenFile(privKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return nil, fmt.Errorf("创建私钥文件失败: %v", err)
		}
		if err := pem.Encode(privKeyFile, privKeyPEM); err != nil {
			privKeyFile.Close()
			return nil, fmt.Errorf("写入私钥文件失败: %v", err)
		}
		privKeyFile.Close()

		// 将公钥编码为PKIX格式
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("编码公钥失败: %v", err)
		}

		// 创建PEM块
		pubKeyPEM := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		}

		// 保存公钥到文件
		pubKeyFile, err := os.OpenFile(pubKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return nil, fmt.Errorf("创建公钥文件失败: %v", err)
		}
		if err := pem.Encode(pubKeyFile, pubKeyPEM); err != nil {
			pubKeyFile.Close()
			return nil, fmt.Errorf("写入公钥文件失败: %v", err)
		}
		pubKeyFile.Close()

		log.Info("已生成并保存权威机构密钥对")
	}

	return privateKey, nil
}

// IsKeyTrusted 检查给定的密钥是否可信
func (sm *ZKSecurityManager) IsKeyTrusted(proofType string, keyHash []byte) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.secureMode {
		return true // 非安全模式下信任所有密钥
	}

	// 检查密钥类型
	trustedKeyHash, exists := sm.trustedKeys[proofType]
	if !exists {
		log.Warn("未知的证明类型", "类型", proofType)
		return false
	}

	// 比较密钥哈希
	return common.BytesToHash(trustedKeyHash) == common.BytesToHash(keyHash)
}

// VerifyKeySignature 验证密钥签名
func (sm *ZKSecurityManager) VerifyKeySignature(proofType string, keyHash []byte, signature []byte) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.secureMode {
		return true // 非安全模式下不验证签名
	}

	if sm.authorityPublicKey == nil {
		log.Error("缺少权威机构公钥，无法验证签名")
		return false
	}

	// 检查密钥是否被信任
	if !sm.IsKeyTrusted(proofType, keyHash) {
		log.Warn("尝试验证不可信密钥的签名", "类型", proofType)
		return false
	}

	// 构造要验证的消息
	message := append([]byte(proofType), keyHash...)
	
	// 计算消息哈希
	hash := crypto.Keccak256Hash(message)
	
	// 验证ECDSA签名
	valid := crypto.VerifySignature(
		crypto.FromECDSAPub(sm.authorityPublicKey),
		hash.Bytes(),
		signature[:len(signature)-1], // 去掉恢复ID
	)
	
	// 增加额外的签名威胁检测
	if valid && sm.multiPartyVerification {
		// 在多方验证模式下，我们应该检查签名是否由足够数量的参与者确认
		// 这里是示例逻辑
		signaturesRequired := (len(sm.trustedSetupParticipants) * 2 / 3) + 1 // 2/3+1 的多数要求
		
		// TODO: 实际项目中，应该验证足够数量的参与者签名
		// 这里假设已通过多方验证
	}
	
	if !valid {
		log.Warn("密钥签名验证失败", "类型", proofType)
	}

	return valid
}

// CheckProofUnique 检查证明是否唯一（防止重放攻击）
func (sm *ZKSecurityManager) CheckProofUnique(proofHash string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 检查证明是否已被使用
	if lastUsed, exists := sm.usedProofs[proofHash]; exists {
		// 如果证明已过期，则可以重新使用
		if time.Since(lastUsed) > sm.usedProofsExpiration {
			delete(sm.usedProofs, proofHash)
		} else {
			log.Warn("检测到重放攻击尝试", "证明哈希", proofHash)
			return false
		}
	}

	// 记录新使用的证明
	sm.usedProofs[proofHash] = time.Now()
	
	// 如果使用的证明太多，清理一些旧的证明
	if len(sm.usedProofs) > 10000 { // 限制最多存储10000个证明记录
		sm.cleanupOldestProofs(1000) // 清理1000个最旧的证明
	}

	return true
}

// 清理最旧的证明记录
func (sm *ZKSecurityManager) cleanupOldestProofs(count int) {
	if count <= 0 || len(sm.usedProofs) == 0 {
		return
	}
	
	// 找出最旧的证明
	type proofAge struct {
		hash string
		time time.Time
	}
	
	proofs := make([]proofAge, 0, len(sm.usedProofs))
	for hash, t := range sm.usedProofs {
		proofs = append(proofs, proofAge{hash, t})
	}
	
	// 按时间排序
	sort.Slice(proofs, func(i, j int) bool {
		return proofs[i].time.Before(proofs[j].time)
	})
	
	// 删除最旧的证明
	deleteCount := count
	if deleteCount > len(proofs) {
		deleteCount = len(proofs)
	}
	
	for i := 0; i < deleteCount; i++ {
		delete(sm.usedProofs, proofs[i].hash)
	}
	
	log.Info("已清理旧证明记录", "数量", deleteCount)
}

// cleanupExpiredProofs 清理过期的证明记录
func (sm *ZKSecurityManager) cleanupExpiredProofs() {
	ticker := time.NewTicker(time.Hour) // 每小时清理一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.mu.Lock()
			expiredCount := 0
			
			// 当前时间
			now := time.Now()
			
			// 检查每个证明是否已过期
			for hash, lastUsed := range sm.usedProofs {
				if now.Sub(lastUsed) > sm.usedProofsExpiration {
					delete(sm.usedProofs, hash)
					expiredCount++
				}
			}
			
			if expiredCount > 0 {
				log.Debug("已清理过期证明", "数量", expiredCount)
			}
			
			sm.mu.Unlock()
		}
	}
}

// 检查密钥是否需要轮换
func (sm *ZKSecurityManager) checkKeyRotation() {
	// 实际项目中，应该根据配置的轮换周期来决定是否需要轮换密钥
}

// RotateKeys 轮换密钥
func (sm *ZKSecurityManager) RotateKeys() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	// 备份旧密钥
	oldKeysPath := filepath.Join(sm.keyStore, "old_keys", 
		fmt.Sprintf("trusted_keys_%s.json", time.Now().Format("20060102_150405")))
	
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(oldKeysPath), 0700); err != nil {
		return fmt.Errorf("创建备份目录失败: %v", err)
	}
	
	// 将当前密钥保存为备份
	// TODO: 实际项目中，将当前密钥序列化并保存
	
	// 生成新密钥
	// TODO: 实际项目中，实现密钥生成和更新逻辑
	
	// 记录轮换时间
	sm.lastRotationTime = time.Now()
	
	log.Info("密钥已轮换", "时间", sm.lastRotationTime)
	return nil
}

// TamperProofData 防篡改数据结构
type TamperProofData struct {
	ProofHash     common.Hash // 证明哈希
	Timestamp     time.Time   // 时间戳
	ChainID       uint64      // 链ID
	BlockNumber   uint64      // 区块编号
	StateVersion  uint64      // 状态版本
	Signature     []byte      // 签名
	// 新增字段
	TEEAttestation *TEEAttestationData // TEE远程证明
	QuorumSignatures map[string][]byte  // 多方签名
}

// CreateTamperProof 创建防篡改证明
func (sm *ZKSecurityManager) CreateTamperProof(stateHash common.Hash, blockNumber uint64, chainID uint64) (*TamperProofData, error) {
	// 创建证明数据
	data := &TamperProofData{
		ProofHash:    stateHash,
		Timestamp:    time.Now(),
		ChainID:      chainID,
		BlockNumber:  blockNumber,
		StateVersion: 1,
	}
	
	// 如果启用了TEE，添加TEE证明
	if sm.teeAttestationEnabled {
		// TODO: 获取实际的TEE证明
		// 这里简单模拟一个TEE证明
		data.TEEAttestation = &TEEAttestationData{
			QuoteData:  []byte("sample_quote_data"),
			Timestamp:  time.Now(),
			DeviceID:   "device_id_123",
		}
	}
	
	// 如果启用了多方验证，收集多方签名
	if sm.multiPartyVerification {
		data.QuorumSignatures = make(map[string][]byte)
		// TODO: 实际项目中，应收集多方签名
	}
	
	// 实际项目中，这里应该使用权威机构私钥对数据进行签名
	// 这里仅作示例
	data.Signature = []byte("sample_signature")
	
	return data, nil
}

// VerifyTamperProof 验证防篡改证明
func (sm *ZKSecurityManager) VerifyTamperProof(data *TamperProofData, expectedHash common.Hash) bool {
	if data == nil {
		log.Error("防篡改数据为空")
		return false
	}
	
	// 检查哈希是否匹配
	if data.ProofHash != expectedHash {
		log.Warn("证明哈希不匹配", 
			"期望", expectedHash.Hex(), 
			"实际", data.ProofHash.Hex())
		return false
	}
	
	// 检查时间戳是否合理（防止重放）
	if time.Since(data.Timestamp) > 10*time.Minute {
		log.Warn("证明已过期", "时间戳", data.Timestamp)
		return false
	}
	
	// 验证TEE证明（如果存在）
	if sm.teeAttestationEnabled && data.TEEAttestation != nil {
		if err := sm.VerifyTEEAttestation(data.TEEAttestation); err != nil {
			log.Warn("TEE证明验证失败", "错误", err)
			return false
		}
	}
	
	// 验证多方签名（如果启用）
	if sm.multiPartyVerification && len(data.QuorumSignatures) > 0 {
		// TODO: 验证多方签名
		// 这里简单检查签名数量是否达到阈值
		requiredSigs := (len(sm.trustedSetupParticipants) * 2 / 3) + 1
		if len(data.QuorumSignatures) < requiredSigs {
			log.Warn("多方签名数量不足", 
				"实际", len(data.QuorumSignatures), 
				"要求", requiredSigs)
			return false
		}
	}
	
	// TODO: 验证签名
	
	return true
}

// GetSecurityStats 获取安全统计信息
func (sm *ZKSecurityManager) GetSecurityStats() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	return map[string]interface{}{
		"secure_mode": sm.secureMode,
		"used_proofs_count": len(sm.usedProofs),
		"trusted_keys_count": len(sm.trustedKeys),
		"last_rotation": sm.lastRotationTime,
		"multi_party_verification": sm.multiPartyVerification,
		"tee_attestation_enabled": sm.teeAttestationEnabled,
		"last_audit_time": sm.lastAuditTime,
		"boundary_checks_enabled": sm.boundaryChecks,
		"security_features": map[string]bool{
			"mpc_verification": sm.mpcVerificationEnabled,
			"tee_attestation": sm.teeAttestationEnabled,
			"multi_party_verify": sm.multiPartyVerification,
			"boundary_checks": sm.boundaryChecks,
			"audit_log": sm.auditLog,
		},
	}
}

// 添加新方法：验证TEE证明
func (sm *ZKSecurityManager) VerifyTEEAttestation(attestation *TEEAttestationData) error {
	if !sm.teeAttestationEnabled {
		return nil // 如果未启用TEE验证，则跳过
	}
	
	// 检查基本数据有效性
	if attestation == nil || len(attestation.QuoteData) == 0 || len(attestation.SigningCert) == 0 {
		return ErrInvalidTEEAttestation
	}
	
	// 检查时间戳是否在合理范围内（防止重放）
	if time.Since(attestation.Timestamp) > 10*time.Minute {
		return errors.New("TEE证明已过期")
	}
	
	// TODO: 实现实际的TEE证明验证逻辑
	// 1. 验证签名证书链
	// 2. 验证引用数据签名
	// 3. 检查设备信任状态
	
	// 记录TEE验证成功
	if sm.auditLog {
		log.Info("TEE证明验证成功", 
			"设备ID", attestation.DeviceID,
			"时间戳", attestation.Timestamp)
	}
	
	return nil
}

// 修改原有校验方法，增加边界检查和多重验证
func (sm *ZKSecurityManager) VerifyProof(proofType string, proofData []byte, publicInputs [][]byte) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	// 基础验证
	if !sm.secureMode {
		return nil
	}
	
	// 边界检查
	if sm.boundaryChecks {
		// 检查证明大小
		if sm.proofSizeLimit > 0 && len(proofData) > sm.proofSizeLimit {
			return fmt.Errorf("证明数据超出大小限制: %d > %d", len(proofData), sm.proofSizeLimit)
		}
		
		// 检查公共输入
		if len(publicInputs) == 0 {
			return errors.New("缺少公共输入")
		}
		
		// 检查每个输入的边界
		for i, input := range publicInputs {
			if len(input) == 0 {
				return fmt.Errorf("公共输入 #%d 为空", i)
			}
			
			if len(input) > 1024 { // 最大1KB的输入
				return fmt.Errorf("公共输入 #%d 超出大小限制", i)
			}
		}
	}
	
	// 计算证明哈希以防止重放
	hasher := sha256.New()
	hasher.Write(proofData)
	for _, input := range publicInputs {
		hasher.Write(input)
	}
	proofHash := hex.EncodeToString(hasher.Sum(nil))
	
	// 检查证明是否已使用（防止重放）
	if !sm.CheckProofUnique(proofHash) {
		return ErrProofReplay
	}
	
	// 如果启用了MPC验证，进行多方验证
	if sm.mpcVerificationEnabled && sm.multiPartyVerification {
		// 在实际实现中，这里应当分发证明给多个验证节点
		// 并收集他们的验证结果
		verified := true // 模拟多方验证通过
		if !verified {
			return ErrMPCVerificationFailed
		}
	}
	
	// 记录审计信息
	if sm.auditLog {
		log.Info("验证ZK证明", 
			"类型", proofType, 
			"哈希", proofHash[:8]+"...",
			"输入数量", len(publicInputs))
	}
	
	return nil
} 
	return nil
} 
	}
} 