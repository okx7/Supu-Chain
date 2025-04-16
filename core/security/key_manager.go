// Copyright 2023 The Supur-Chain Authors
// This file is part of the Supur-Chain library.
//
// 密钥管理模块，提供安全的密钥存储、备份和恢复机制

package security

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

// 密钥类型
type KeyType int

const (
	// 密钥类型定义
	KeyTypeSoftware KeyType = iota // 软件密钥（本地存储）
	KeyTypeMPC                     // 多方计算密钥
	KeyTypeTEE                     // 可信执行环境密钥
	KeyTypeHardware                // 硬件密钥（如硬件钱包）
)

// 密钥状态
type KeyStatus int

const (
	// 密钥状态定义
	KeyStatusActive KeyStatus = iota // 活跃状态
	KeyStatusLocked                  // 锁定状态
	KeyStatusDisabled                // 禁用状态
	KeyStatusBackedUp                // 已备份状态
)

// 密钥信息
type KeyInfo struct {
	Address    common.Address // 地址
	Type       KeyType        // 类型
	Status     KeyStatus      // 状态
	CreateTime time.Time      // 创建时间
	LastUsed   time.Time      // 最后使用时间
	Metadata   string         // 元数据（可包含额外信息）
}

// 备份方式
type BackupMethod int

const (
	// 备份方式定义
	BackupLocal BackupMethod = iota // 本地备份
	BackupCloud                     // 云端备份
	BackupPaper                     // 纸质备份（助记词等）
	BackupShard                     // 分片备份
)

// 备份配置
type BackupConfig struct {
	Methods         []BackupMethod // 备份方式
	AutoBackup      bool           // 自动备份
	BackupFrequency time.Duration  // 备份频率
	BackupPath      string         // 备份路径
	EncryptBackup   bool           // 备份是否加密
	BackupPassword  string         // 备份密码
}

// 密钥管理器配置
type KeyManagerConfig struct {
	KeyStorePath       string        // 密钥存储路径
	AutoBackup         bool          // 自动备份
	BackupConfig       BackupConfig  // 备份配置
	KeyRotationEnabled bool          // 是否启用密钥轮换
	KeyRotationPeriod  time.Duration // 密钥轮换周期
	UseHardwareSigning bool          // 使用硬件签名
	MPCThreshold       int           // MPC阈值（n-of-m中的n）
	MPCTotalParties    int           // MPC总方数（n-of-m中的m）
	TEEProvider        string        // TEE提供者（如Intel SGX, ARM TrustZone）
}

// 默认密钥管理器配置
var DefaultKeyManagerConfig = KeyManagerConfig{
	KeyStorePath:       "keystore",
	AutoBackup:         true,
	BackupConfig: BackupConfig{
		Methods:         []BackupMethod{BackupLocal, BackupShard},
		AutoBackup:      true,
		BackupFrequency: time.Hour * 24,
		BackupPath:      "backup",
		EncryptBackup:   true,
	},
	KeyRotationEnabled: false,
	KeyRotationPeriod:  time.Hour * 24 * 30, // 30天
	UseHardwareSigning: false,
	MPCThreshold:       2,
	MPCTotalParties:    3,
	TEEProvider:        "sgx",
}

// 密钥管理器
type KeyManager struct {
	config       KeyManagerConfig   // 配置
	keys         map[common.Address]*keyEntry // 密钥映射
	defaultKey   common.Address     // 默认密钥
	mu           sync.RWMutex       // 读写锁
	backupTicker *time.Ticker       // 备份定时器
	stopCh       chan struct{}      // 停止信号
}

// 内部密钥条目
type keyEntry struct {
	info       KeyInfo             // 密钥信息
	privateKey *ecdsa.PrivateKey   // 私钥（仅软件密钥使用）
	signer     KeySigner           // 签名器
	backups    map[BackupMethod]string // 备份信息
}

// 密钥签名接口
type KeySigner interface {
	Sign(digestHash []byte) ([]byte, error) // 签名方法
	Address() common.Address                 // 获取地址
	Type() KeyType                           // 获取类型
}

// 软件密钥签名器
type SoftwareKeySigner struct {
	privateKey *ecdsa.PrivateKey // 私钥
	address    common.Address    // 地址
}

// 构造软件密钥签名器
func NewSoftwareKeySigner(privateKey *ecdsa.PrivateKey) *SoftwareKeySigner {
	return &SoftwareKeySigner{
		privateKey: privateKey,
		address:    crypto.PubkeyToAddress(privateKey.PublicKey),
	}
}

// 获取密钥类型
func (s *SoftwareKeySigner) Type() KeyType {
	return KeyTypeSoftware
}

// 获取地址
func (s *SoftwareKeySigner) Address() common.Address {
	return s.address
}

// 签名方法
func (s *SoftwareKeySigner) Sign(digestHash []byte) ([]byte, error) {
	return crypto.Sign(digestHash, s.privateKey)
}

// MPC密钥签名器
type MPCKeySigner struct {
	address    common.Address // 地址
	threshold  int            // 阈值
	totalParties int          // 总方数
	partyIDs   []string       // 参与方ID
}

// 构造MPC密钥签名器
func NewMPCKeySigner(address common.Address, threshold, totalParties int, partyIDs []string) *MPCKeySigner {
	return &MPCKeySigner{
		address:    address,
		threshold:  threshold,
		totalParties: totalParties,
		partyIDs:   partyIDs,
	}
}

// 获取密钥类型
func (m *MPCKeySigner) Type() KeyType {
	return KeyTypeMPC
}

// 获取地址
func (m *MPCKeySigner) Address() common.Address {
	return m.address
}

// 签名方法（MPC实现）
func (m *MPCKeySigner) Sign(digestHash []byte) ([]byte, error) {
	// 实际项目中，这里应该调用MPC库的签名逻辑
	// 此处为简化示例，仅返回错误
	return nil, errors.New("MPC签名未实现")
}

// 创建新的密钥管理器
func NewKeyManager(config KeyManagerConfig) (*KeyManager, error) {
	// 创建密钥存储目录
	if err := os.MkdirAll(config.KeyStorePath, 0700); err != nil {
		return nil, fmt.Errorf("创建密钥存储目录失败: %v", err)
	}
	
	// 如果启用备份，创建备份目录
	if config.AutoBackup {
		if err := os.MkdirAll(config.BackupConfig.BackupPath, 0700); err != nil {
			return nil, fmt.Errorf("创建备份目录失败: %v", err)
		}
	}
	
	km := &KeyManager{
		config:       config,
		keys:         make(map[common.Address]*keyEntry),
		stopCh:       make(chan struct{}),
	}
	
	// 加载已有密钥
	if err := km.loadKeys(); err != nil {
		log.Warn("加载密钥失败", "error", err)
	}
	
	// 如果启用自动备份，启动备份定时器
	if config.AutoBackup && config.BackupConfig.AutoBackup {
		km.backupTicker = time.NewTicker(config.BackupConfig.BackupFrequency)
		go km.autoBackupLoop()
	}
	
	return km, nil
}

// 停止密钥管理器
func (km *KeyManager) Stop() {
	close(km.stopCh)
	if km.backupTicker != nil {
		km.backupTicker.Stop()
	}
}

// 自动备份循环
func (km *KeyManager) autoBackupLoop() {
	for {
		select {
		case <-km.stopCh:
			return
		case <-km.backupTicker.C:
			if err := km.BackupAllKeys(); err != nil {
				log.Error("自动备份密钥失败", "error", err)
			} else {
				log.Info("自动备份密钥成功")
			}
		}
	}
}

// 加载密钥
func (km *KeyManager) loadKeys() error {
	files, err := ioutil.ReadDir(km.config.KeyStorePath)
	if err != nil {
		return fmt.Errorf("读取密钥目录失败: %v", err)
	}
	
	var loadErrors []error
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}
		
		keypath := filepath.Join(km.config.KeyStorePath, file.Name())
		key, err := km.loadKeyFile(keypath)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Errorf("加载密钥文件 %s 失败: %v", keypath, err))
			continue
		}
		
		km.keys[key.Address()] = &keyEntry{
			info: KeyInfo{
				Address:    key.Address(),
				Type:       key.Type(),
				Status:     KeyStatusActive,
				CreateTime: file.ModTime(),
				LastUsed:   time.Now(),
			},
			signer:  key,
			backups: make(map[BackupMethod]string),
		}
		
		// 如果是第一个密钥，设为默认
		if km.defaultKey == (common.Address{}) {
			km.defaultKey = key.Address()
		}
	}
	
	if len(loadErrors) > 0 {
		log.Warn("加载部分密钥失败", "errors", loadErrors)
	}
	
	return nil
}

// 加载密钥文件（简化示例）
func (km *KeyManager) loadKeyFile(path string) (KeySigner, error) {
	// 实际项目中应实现完整的密钥加载逻辑
	// 此处简化为创建一个随机私钥
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	
	return NewSoftwareKeySigner(privateKey), nil
}

// 创建新密钥
func (km *KeyManager) CreateKey(keyType KeyType) (common.Address, error) {
	km.mu.Lock()
	defer km.mu.Unlock()
	
	var (
		key  KeySigner
		err  error
	)
	
	switch keyType {
	case KeyTypeSoftware:
		// 创建软件密钥
		privateKey, err := crypto.GenerateKey()
		if err != nil {
			return common.Address{}, fmt.Errorf("生成私钥失败: %v", err)
		}
		key = NewSoftwareKeySigner(privateKey)
		
	case KeyTypeMPC:
		// 创建MPC密钥（简化示例）
		privateKey, err := crypto.GenerateKey()
		if err != nil {
			return common.Address{}, fmt.Errorf("生成MPC临时私钥失败: %v", err)
		}
		address := crypto.PubkeyToAddress(privateKey.PublicKey)
		key = NewMPCKeySigner(address, km.config.MPCThreshold, km.config.MPCTotalParties, []string{"party1", "party2", "party3"})
		
	case KeyTypeTEE:
		// TEE密钥实现...
		return common.Address{}, errors.New("TEE密钥创建未实现")
		
	case KeyTypeHardware:
		// 硬件密钥实现...
		return common.Address{}, errors.New("硬件密钥创建未实现")
		
	default:
		return common.Address{}, fmt.Errorf("不支持的密钥类型: %v", keyType)
	}
	
	// 保存密钥信息
	entry := &keyEntry{
		info: KeyInfo{
			Address:    key.Address(),
			Type:       keyType,
			Status:     KeyStatusActive,
			CreateTime: time.Now(),
			LastUsed:   time.Now(),
		},
		signer:  key,
		backups: make(map[BackupMethod]string),
	}
	
	km.keys[key.Address()] = entry
	
	// 如果是首个密钥，设为默认
	if km.defaultKey == (common.Address{}) {
		km.defaultKey = key.Address()
	}
	
	// 保存密钥到文件
	if err := km.saveKey(key); err != nil {
		log.Error("保存密钥失败", "address", key.Address(), "error", err)
	}
	
	// 如果配置了自动备份，立即进行备份
	if km.config.AutoBackup {
		for _, method := range km.config.BackupConfig.Methods {
			if err := km.BackupKey(key.Address(), method); err != nil {
				log.Error("备份密钥失败", "address", key.Address(), "method", method, "error", err)
			}
		}
	}
	
	log.Info("创建密钥成功", "address", key.Address(), "type", keyType)
	return key.Address(), nil
}

// 保存密钥（简化示例）
func (km *KeyManager) saveKey(key KeySigner) error {
	// 实际项目中应实现完整的密钥保存逻辑
	// 此处省略具体实现
	return nil
}

// 使用指定密钥签名数据
func (km *KeyManager) Sign(address common.Address, digestHash []byte) ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	
	entry, ok := km.keys[address]
	if !ok {
		return nil, fmt.Errorf("密钥不存在: %s", address.Hex())
	}
	
	if entry.info.Status != KeyStatusActive {
		return nil, fmt.Errorf("密钥不可用，当前状态: %v", entry.info.Status)
	}
	
	// 更新最后使用时间
	entry.info.LastUsed = time.Now()
	
	// 调用签名器签名
	signature, err := entry.signer.Sign(digestHash)
	if err != nil {
		// 签名失败，尝试恢复
		if recoveredSig, err := km.tryRecoverySign(address, digestHash); err == nil {
			return recoveredSig, nil
		}
		
		return nil, fmt.Errorf("签名失败: %v", err)
	}
	
	return signature, nil
}

// 尝试恢复签名（当主签名方式失败时）
func (km *KeyManager) tryRecoverySign(address common.Address, digestHash []byte) ([]byte, error) {
	log.Warn("尝试恢复签名", "address", address)
	
	entry, ok := km.keys[address]
	if !ok {
		return nil, fmt.Errorf("密钥不存在: %s", address.Hex())
	}
	
	// 如果是MPC密钥，尝试降级阈值后重试
	if entry.signer.Type() == KeyTypeMPC {
		mpcSigner, ok := entry.signer.(*MPCKeySigner)
		if ok && mpcSigner.threshold > 1 {
			log.Warn("降级MPC阈值尝试签名", "address", address, "原阈值", mpcSigner.threshold)
			
			// 实际MPC签名实现...
			// 此处为简化示例
			return nil, errors.New("MPC恢复签名未实现")
		}
	}
	
	// 查找备份，尝试从备份恢复
	for method, backup := range entry.backups {
		log.Info("尝试从备份恢复签名", "address", address, "method", method)
		
		// 实际恢复逻辑...
		// 此处为简化示例
	}
	
	return nil, errors.New("恢复签名失败")
}

// 使用默认密钥签名交易
func (km *KeyManager) SignTx(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	km.mu.RLock()
	defaultAddr := km.defaultKey
	km.mu.RUnlock()
	
	if defaultAddr == (common.Address{}) {
		return nil, errors.New("无默认密钥")
	}
	
	signer := types.NewEIP155Signer(chainID)
	txHash := signer.Hash(tx)
	
	signature, err := km.Sign(defaultAddr, txHash.Bytes())
	if err != nil {
		return nil, fmt.Errorf("签名交易失败: %v", err)
	}
	
	return tx.WithSignature(signer, signature)
}

// 备份指定密钥
func (km *KeyManager) BackupKey(address common.Address, method BackupMethod) error {
	km.mu.Lock()
	defer km.mu.Unlock()
	
	entry, ok := km.keys[address]
	if !ok {
		return fmt.Errorf("密钥不存在: %s", address.Hex())
	}
	
	var backupPath string
	var err error
	
	switch method {
	case BackupLocal:
		// 本地备份
		backupDir := filepath.Join(km.config.BackupConfig.BackupPath, "local")
		if err := os.MkdirAll(backupDir, 0700); err != nil {
			return fmt.Errorf("创建本地备份目录失败: %v", err)
		}
		
		backupFile := filepath.Join(backupDir, fmt.Sprintf("%s_%s.backup", 
			address.Hex(), time.Now().Format("20060102150405")))
		
		// 实际备份逻辑...
		// 此处为简化示例，仅创建空文件
		if err := ioutil.WriteFile(backupFile, []byte{}, 0600); err != nil {
			return fmt.Errorf("写入本地备份文件失败: %v", err)
		}
		
		backupPath = backupFile
		
	case BackupShard:
		// 分片备份
		backupDir := filepath.Join(km.config.BackupConfig.BackupPath, "shard")
		if err := os.MkdirAll(backupDir, 0700); err != nil {
			return fmt.Errorf("创建分片备份目录失败: %v", err)
		}
		
		// 生成3个分片，需要2个分片恢复
		// 实际分片备份逻辑...
		// 此处为简化示例
		for i := 1; i <= 3; i++ {
			shardFile := filepath.Join(backupDir, fmt.Sprintf("%s_shard%d_%s.backup", 
				address.Hex(), i, time.Now().Format("20060102150405")))
			
			if err := ioutil.WriteFile(shardFile, []byte{}, 0600); err != nil {
				return fmt.Errorf("写入分片备份文件失败: %v", err)
			}
		}
		
		backupPath = backupDir
		
	case BackupCloud:
		// 云端备份
		// 实际云端备份逻辑...
		return errors.New("云端备份未实现")
		
	case BackupPaper:
		// 纸质备份
		// 生成助记词或密钥纸质备份内容
		// 实际纸质备份逻辑...
		return errors.New("纸质备份未实现")
		
	default:
		return fmt.Errorf("不支持的备份方式: %v", method)
	}
	
	// 记录备份信息
	entry.backups[method] = backupPath
	entry.info.Status = KeyStatusBackedUp
	
	log.Info("备份密钥成功", "address", address, "method", method, "path", backupPath)
	return nil
}

// 备份所有密钥
func (km *KeyManager) BackupAllKeys() error {
	km.mu.RLock()
	addresses := make([]common.Address, 0, len(km.keys))
	for addr := range km.keys {
		addresses = append(addresses, addr)
	}
	km.mu.RUnlock()
	
	var errs []error
	for _, addr := range addresses {
		for _, method := range km.config.BackupConfig.Methods {
			if err := km.BackupKey(addr, method); err != nil {
				errs = append(errs, fmt.Errorf("备份密钥 %s 失败: %v", addr.Hex(), err))
			}
		}
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("部分密钥备份失败: %v", errs)
	}
	
	return nil
}

// 从备份恢复密钥
func (km *KeyManager) RestoreFromBackup(backupPath string, password string) (common.Address, error) {
	// 实际恢复逻辑...
	// 此处为简化示例
	return common.Address{}, errors.New("从备份恢复密钥未实现")
}

// 禁用密钥
func (km *KeyManager) DisableKey(address common.Address) error {
	km.mu.Lock()
	defer km.mu.Unlock()
	
	entry, ok := km.keys[address]
	if !ok {
		return fmt.Errorf("密钥不存在: %s", address.Hex())
	}
	
	entry.info.Status = KeyStatusDisabled
	log.Info("禁用密钥", "address", address)
	return nil
}

// 启用密钥
func (km *KeyManager) EnableKey(address common.Address) error {
	km.mu.Lock()
	defer km.mu.Unlock()
	
	entry, ok := km.keys[address]
	if !ok {
		return fmt.Errorf("密钥不存在: %s", address.Hex())
	}
	
	entry.info.Status = KeyStatusActive
	log.Info("启用密钥", "address", address)
	return nil
}

// 设置默认密钥
func (km *KeyManager) SetDefaultKey(address common.Address) error {
	km.mu.Lock()
	defer km.mu.Unlock()
	
	if _, ok := km.keys[address]; !ok {
		return fmt.Errorf("密钥不存在: %s", address.Hex())
	}
	
	km.defaultKey = address
	log.Info("设置默认密钥", "address", address)
	return nil
}

// 获取所有密钥信息
func (km *KeyManager) ListKeys() []KeyInfo {
	km.mu.RLock()
	defer km.mu.RUnlock()
	
	keys := make([]KeyInfo, 0, len(km.keys))
	for _, entry := range km.keys {
		keys = append(keys, entry.info)
	}
	
	return keys
}

// 轮换密钥
func (km *KeyManager) RotateKey(address common.Address) (common.Address, error) {
	km.mu.Lock()
	defer km.mu.Unlock()
	
	entry, ok := km.keys[address]
	if !ok {
		return common.Address{}, fmt.Errorf("密钥不存在: %s", address.Hex())
	}
	
	keyType := entry.signer.Type()
	oldStatus := entry.info.Status
	
	// 禁用旧密钥
	entry.info.Status = KeyStatusDisabled
	
	// 创建新密钥
	newAddress, err := km.CreateKey(keyType)
	if err != nil {
		// 恢复旧密钥状态
		entry.info.Status = oldStatus
		return common.Address{}, fmt.Errorf("创建新密钥失败: %v", err)
	}
	
	// 如果旧密钥是默认密钥，将新密钥设为默认
	if km.defaultKey == address {
		km.defaultKey = newAddress
	}
	
	log.Info("轮换密钥成功", "oldAddress", address, "newAddress", newAddress)
	return newAddress, nil
} 