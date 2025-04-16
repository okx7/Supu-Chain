// security_manager.go - 实现分布式密钥管理和安全功能

package mobile

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
	"context"
	"runtime"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/patrickmn/go-cache" // 添加TTL缓存库
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
)

// 安全管理器常量
const (
	// 密钥类型
	KeyTypeStandard   = 0 // 标准密钥
	KeyTypeMPC        = 1 // MPC密钥
	KeyTypeSocial     = 2 // 社交恢复密钥
	KeyTypeHardware   = 3 // 硬件密钥
	KeyTypeBiometric  = 4 // 生物识别密钥
	
	// 恢复方式
	RecoveryTypeNone      = 0 // 无恢复
	RecoveryTypeSocial    = 1 // 社交恢复
	RecoveryTypeBackup    = 2 // 备份恢复
	RecoveryTypeThreshold = 3 // 门限恢复
	
	// 安全级别
	SecurityLevelLow    = 0 // 低安全级别
	SecurityLevelMedium = 1 // 中安全级别
	SecurityLevelHigh   = 2 // 高安全级别
	
	// 密钥分片配置
	DefaultThreshold = 2  // 默认门限值(需要2个分片来恢复)
	DefaultShards    = 3  // 默认分片数量(创建3个分片)
)

// SecurityConfig 安全配置
type SecurityConfig struct {
	// 基本设置
	TEEEnabled              bool   // 是否启用可信执行环境
	BiometricAuthRequired   bool   // 是否要求生物识别认证
	HardwareKeyStoreEnabled bool   // 是否启用硬件密钥存储
	AutoLockTimeout         int    // 自动锁定超时（分钟）
	
	// MPC钱包配置
	MPCWalletEnabled        bool   // 是否启用MPC钱包
	MPCParticipants         int    // MPC参与者数量
	MPCThreshold            int    // MPC门限值
	
	// 社交恢复配置
	SocialRecoveryEnabled   bool   // 是否启用社交恢复
	SocialRecoveryThreshold int    // 社交恢复门限值
	SocialRecoveryContacts  int    // 社交恢复联系人数量
	
	// 高级安全配置
	ThresholdSignatures     bool   // 是否启用门限签名
	SecureBackupEnabled     bool   // 是否启用安全备份
	AntiPhishingProtection  bool   // 是否启用防钓鱼保护
	PrivateTransactions     bool   // 是否启用私密交易
	EndToEndEncryption      bool   // 是否启用端到端加密
	TransactionNotification bool   // 是否启用交易通知
	
	// 本地安全配置
	LocalEncryptionEnabled  bool   // 是否启用本地加密
	LocalEncryptionKey      string // 本地加密密钥（应通过安全方式设置）
	SecureElementEnabled    bool   // 是否启用安全元件
	
	// 新增TEE相关字段
	TEESecureStorage     bool   // 是否启用TEE安全存储
	TEEKeyManagement     bool   // 是否启用TEE密钥管理
}

// SecurityManager 安全管理器
type SecurityManager struct {
	config         *SecurityConfig     // 安全配置
	keyStore       *KeyStore           // 密钥存储
	mpcWallet      *MPCWallet          // MPC钱包
	socialRecovery *SocialRecovery     // 社交恢复
	encryptionManager *EncryptionManager // 加密管理器
	
	// 状态
	isLocked       bool                // 是否锁定
	lastActivity   time.Time           // 最后活动时间
	
	// 控制
	mu             sync.RWMutex        // 互斥锁
	ctx            context.Context     // 上下文
	cancel         context.CancelFunc  // 取消函数
	wg             sync.WaitGroup      // 等待组
	
	// 新增TEE相关字段
	teeInitialized  bool               // TEE是否已初始化
	teeOperations   map[string]bool    // TEE支持的操作
	
	// 新增网络弹性相关字段
	offlineModeEnabled bool            // 离线模式是否启用
	offlineQueue       []interface{}   // 离线队列
	offlineQueueMutex  sync.RWMutex    // 离线队列互斥锁
	reconnectStrategy  string          // 重连策略
	reconnectAttempts  int             // 重连尝试次数
	reconnectDelay     time.Duration   // 重连延迟
	onNetworkDisruption func()         // 网络中断回调
	onNetworkRecovery   func()         // 网络恢复回调
}

// KeyStore 密钥存储
type KeyStore struct {
	keys           map[common.Address]*Key // 密钥映射
	encryptionKey  []byte                  // 加密密钥
	hardware       bool                    // 是否使用硬件
	tee            bool                    // 是否使用TEE
	mu             sync.RWMutex            // 互斥锁
}

// Key 密钥
type Key struct {
	Address     common.Address       // 地址
	PrivateKey  *ecdsa.PrivateKey   // 私钥（如果可用）
	KeyType     int                 // 密钥类型
	RecoveryType int                // 恢复类型
	Metadata    map[string]string   // 元数据
	Shards      []*KeyShard         // 密钥分片
}

// KeyShard 密钥分片
type KeyShard struct {
	Index       int                 // 分片索引
	Data        []byte              // 分片数据
	Holder      string              // 分片持有者
	IsRecovered bool                // 是否已恢复
}

// MPCWallet MPC钱包
type MPCWallet struct {
	addresses     []common.Address   // 地址列表
	participants  []string           // 参与者列表
	threshold     int                // 门限值
	sessions      map[string]*MPCSession // 会话映射
	mu            sync.RWMutex       // 互斥锁
}

// MPCSession MPC会话
type MPCSession struct {
	ID            string             // 会话ID
	Address       common.Address     // 地址
	Participants  []string           // 参与者
	Shares        map[string][]byte  // 分享
	Status        string             // 状态
	StartTime     time.Time          // 开始时间
	CompletedTime time.Time          // 完成时间
}

// SocialRecovery 社交恢复
type SocialRecovery struct {
	guardians     []string                      // 监护人列表
	threshold     int                           // 门限值
	recoveries    map[common.Address]*Recovery  // 恢复映射
	mu            sync.RWMutex                  // 互斥锁
}

// Recovery 恢复
type Recovery struct {
	Address       common.Address     // 地址
	Guardians     []string           // 监护人
	Approvals     map[string]bool    // T批准情况
	Status        string             // 状态
	StartTime     time.Time          // 开始时间
	CompletedTime time.Time          // 完成时间
}

// EncryptionManager 加密管理器
type EncryptionManager struct {
	enabled       bool               // 是否启用
	key           []byte             // 加密密钥
	endToEnd      bool               // 是否端到端加密
	secureStorage *SecureStorage     // 安全存储
	mu            sync.RWMutex       // 互斥锁
}

// SecureStorage 安全存储结构体
type SecureStorage struct {
	encryptionKey []byte             // 加密密钥
	nonceCache    *cache.Cache       // 使用TTL缓存代替sync.Map
	nonceTTL      time.Duration      // nonce生存时间
	mu            sync.RWMutex       // 读写锁
}

// NewSecureStorage 创建新的安全存储
func NewSecureStorage(encryptionKey []byte) *SecureStorage {
	return &SecureStorage{
		encryptionKey: encryptionKey,
		nonceTTL:      24 * time.Hour, // 默认nonce有效期为24小时
		nonceCache:    cache.New(24*time.Hour, 1*time.Hour), // 创建缓存，默认过期时间24小时，每1小时清理一次过期项
	}
}

// encrypt 加密数据
func (s *SecureStorage) encrypt(data []byte) ([]byte, []byte, error) {
	// 生成一个随机nonce(16字节)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("生成nonce失败: %v", err)
	}
	
	// 在实际实现中，这里应使用AES-GCM等安全的加密算法
	// 以下是简化的示例（不要在生产环境使用）
	ciphertext := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		ciphertext[i] = data[i] ^ s.encryptionKey[i%len(s.encryptionKey)] ^ nonce[i%len(nonce)]
	}
	
	return ciphertext, nonce, nil
}

// decrypt 解密数据同时检查nonce有效性
func (s *SecureStorage) decrypt(ciphertext []byte, nonce []byte) ([]byte, error) {
	// 检查nonce是否有效
	if len(nonce) != 16 {
		return nil, errors.New("无效的nonce长度")
	}
	
	// 检查nonce是否已被使用过（防止重放攻击）
	nonceKey := hex.EncodeToString(nonce) // 转换成字符串键
	if _, found := s.nonceCache.Get(nonceKey); found {
		return nil, errors.New("检测到重放攻击")
	}
	
	// 在实际实现中，这里应使用AES-GCM等安全的加密算法
	// 以下是简化的示例（不要在生产环境使用）
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		plaintext[i] = ciphertext[i] ^ s.encryptionKey[i%len(s.encryptionKey)] ^ nonce[i%len(nonce)]
	}
	
	// 将使用过的nonce添加到缓存，防止重放，并设置过期时间
	s.nonceCache.Set(nonceKey, true, s.nonceTTL)
	
	return plaintext, nil
}

// cleanupNonceCache 该方法不再需要，由缓存自动清理
// 可以保留方法但内容改为空，保持向后兼容
func (s *SecureStorage) cleanupNonceCache() {
	// 缓存会自动清理过期项，不需要手动清理
}

// StartCleanupRoutine 启动定期清理nonce的例程
// 方法保留但简化实现，因为缓存会自动清理
func (s *SecureStorage) StartCleanupRoutine(ctx context.Context) {
	// 不再需要定期清理，缓存会自动处理
	// 为了保持兼容性，保留此方法但仅等待上下文结束
	<-ctx.Done()
}

// NewSecurityManager 创建新的安全管理器
func NewSecurityManager(config *SecurityConfig) *SecurityManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	// 创建密钥存储
	keyStore := &KeyStore{
		keys:          make(map[common.Address]*Key),
		hardware:      config.HardwareKeyStoreEnabled,
		tee:           config.TEEEnabled,
	}
	
	// 创建MPC钱包（如果启用）
	var mpcWallet *MPCWallet
	if config.MPCWalletEnabled {
		mpcWallet = &MPCWallet{
			addresses:    make([]common.Address, 0),
			participants: make([]string, 0),
			threshold:    config.MPCThreshold,
			sessions:     make(map[string]*MPCSession),
		}
	}
	
	// 创建社交恢复（如果启用）
	var socialRecovery *SocialRecovery
	if config.SocialRecoveryEnabled {
		socialRecovery = &SocialRecovery{
			guardians:  make([]string, 0),
			threshold:  config.SocialRecoveryThreshold,
			recoveries: make(map[common.Address]*Recovery),
		}
	}
	
	// 创建加密管理器
	encryptionManager := &EncryptionManager{
		enabled:  config.LocalEncryptionEnabled,
		endToEnd: config.EndToEndEncryption,
	}
	
	return &SecurityManager{
		config:            config,
		keyStore:          keyStore,
		mpcWallet:         mpcWallet,
		socialRecovery:    socialRecovery,
		encryptionManager: encryptionManager,
		isLocked:          true,
		lastActivity:      time.Now(),
		ctx:               ctx,
		cancel:            cancel,
	}
}

// Start 启动安全管理器
func (sm *SecurityManager) Start() error {
	if sm.config.TEEEnabled {
		if err := sm.initializeTEE(); err != nil {
			return fmt.Errorf("TEE初始化失败: %v", err)
		}
	}
	
	// 启动自动锁定定时器
	if sm.config.AutoLockTimeout > 0 {
		sm.wg.Add(1)
		go sm.autoLockRoutine()
	}
	
	// 初始化MPC钱包
	if sm.mpcWallet != nil {
		if err := sm.initializeMPCWallet(); err != nil {
			log.Warn("MPC钱包初始化失败", "错误", err)
			// 非致命错误，继续执行
		}
	}
	
	// 初始化社交恢复
	if sm.socialRecovery != nil {
		if err := sm.initializeSocialRecovery(); err != nil {
			log.Warn("社交恢复初始化失败", "错误", err)
			// 非致命错误，继续执行
		}
	}
	
	// 初始化加密管理器
	if sm.config.LocalEncryptionEnabled {
		if err := sm.initializeEncryption(); err != nil {
			return fmt.Errorf("加密初始化失败: %v", err)
		}
	}
	
	log.Info("安全管理器已启动",
		"TEE", sm.config.TEEEnabled,
		"MPC", sm.config.MPCWalletEnabled,
		"社交恢复", sm.config.SocialRecoveryEnabled)
	
	return nil
}

// Stop 停止安全管理器
func (sm *SecurityManager) Stop() {
	sm.cancel()
	sm.wg.Wait()
	log.Info("安全管理器已停止")
}

// 增强 TEEEnabled 相关功能
func (sm *SecurityManager) initializeTEE() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	// 检查TEE可用性
	if !sm.config.TEEEnabled {
		log.Info("TEE支持未启用")
		return nil
	}
	
	log.Info("正在初始化TEE环境")
	
	// 检查设备TEE支持
	isTEEAvailable, err := sm.checkTEEAvailability()
	if err != nil {
		log.Error("TEE可用性检查失败", "error", err)
		return err
	}
	
	if !isTEEAvailable {
		log.Warn("设备不支持TEE，将使用标准安全存储")
		return nil
	}
	
	// 初始化TEE环境
	err = sm.setupTEEEnvironment()
	if err != nil {
		log.Error("TEE环境设置失败", "error", err)
		return err
	}
	
	// 初始化TEE安全存储
	if sm.config.TEESecureStorage {
		err = sm.initializeTEEStorage()
		if err != nil {
			log.Error("TEE安全存储初始化失败", "error", err)
			return err
		}
	}
	
	// 初始化TEE密钥管理
	if sm.config.TEEKeyManagement {
		err = sm.initializeTEEKeyManager()
		if err != nil {
			log.Error("TEE密钥管理初始化失败", "error", err)
			return err
		}
	}
	
	log.Info("TEE环境初始化成功")
	sm.teeInitialized = true
	return nil
}

// 检查设备TEE可用性
func (sm *SecurityManager) checkTEEAvailability() (bool, error) {
	// 在实际应用中，这里应该根据不同平台检查TEE可用性：
	// - Android: Trusty TEE, Samsung Knox, Qualcomm SEE
	// - iOS: Secure Enclave
	
	// 模拟实现
	log.Debug("检查设备TEE可用性")
	
	// 检查操作系统
	switch runtime.GOOS {
	case "android":
		// 检查Android TEE
		return true, nil
	case "ios":
		// 检查iOS Secure Enclave
		return true, nil
	case "darwin", "linux", "windows":
		// 桌面环境可能也有TEE
		log.Debug("在非移动平台上检测TEE是实验性功能")
		return false, nil
	default:
		log.Warn("不支持的平台，无法检测TEE", "platform", runtime.GOOS)
		return false, nil
	}
}

// 设置TEE环境
func (sm *SecurityManager) setupTEEEnvironment() error {
	log.Debug("设置TEE环境")
	
	// 初始化TEE操作映射
	sm.teeOperations = make(map[string]bool)
	
	// 根据平台初始化不同的TEE后端
	switch runtime.GOOS {
	case "android":
		// Android TEE初始化
		sm.teeOperations["key_generation"] = true
		sm.teeOperations["signing"] = true
		sm.teeOperations["encryption"] = true
		sm.teeOperations["secure_storage"] = true
	case "ios":
		// iOS Secure Enclave初始化
		sm.teeOperations["key_generation"] = true
		sm.teeOperations["signing"] = true
		sm.teeOperations["encryption"] = true
		sm.teeOperations["secure_storage"] = true
	default:
		// 不支持的平台使用有限功能
		sm.teeOperations["encryption"] = true
		log.Warn("当前平台仅支持有限的TEE功能")
	}
	
	return nil
}

// 初始化TEE安全存储
func (sm *SecurityManager) initializeTEEStorage() error {
	log.Debug("初始化TEE安全存储")
	
	// 在实际实现中，这将与底层TEE API交互
	// 模拟实现
	if sm.teeOperations["secure_storage"] {
		// 初始化安全存储
		log.Info("TEE安全存储已初始化")
		return nil
	}
	
	return errors.New("当前TEE环境不支持安全存储")
}

// 初始化TEE密钥管理
func (sm *SecurityManager) initializeTEEKeyManager() error {
	log.Debug("初始化TEE密钥管理")
	
	// 在实际实现中，这将与底层TEE API交互
	// 模拟实现
	if sm.teeOperations["key_generation"] && sm.teeOperations["signing"] {
		// 初始化密钥管理
		log.Info("TEE密钥管理已初始化")
		return nil
	}
	
	return errors.New("当前TEE环境不支持完整密钥管理")
}

// 生成TEE保护的密钥
func (sm *SecurityManager) generateTEEProtectedKey() (*Key, error) {
	if !sm.teeInitialized || !sm.teeOperations["key_generation"] {
		return nil, errors.New("TEE密钥生成不可用")
	}
	
	log.Debug("在TEE中生成受保护密钥")
	
	// 在实际实现中，应该使用TEE API生成密钥
	// 但私钥材料永远不会离开TEE环境
	// 以下是简化实现
	
	// 生成密钥对
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	
	// 创建密钥对象
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	key := &Key{
		Address:     address,
		PrivateKey:  privateKey, // 实际实现中这应该是nil或引用
		KeyType:     KeyTypeHardware,
		RecoveryType: RecoveryTypeNone,
		Metadata:    map[string]string{
			"tee_protected": "true",
			"created_at":    time.Now().Format(time.RFC3339),
		},
	}
	
	// 记录TEE保护的密钥创建
	log.Info("已创建TEE保护的密钥", "address", address.Hex())
	
	return key, nil
}

// 使用TEE签名数据
func (sm *SecurityManager) signWithTEE(address common.Address, hash []byte) ([]byte, error) {
	if !sm.teeInitialized || !sm.teeOperations["signing"] {
		return nil, errors.New("TEE签名功能不可用")
	}
	
	log.Debug("使用TEE执行签名操作", "address", address.Hex())
	
	// 检查密钥是否存在
	sm.keyStore.mu.RLock()
	key, exists := sm.keyStore.keys[address]
	sm.keyStore.mu.RUnlock()
	
	if !exists {
		return nil, errors.New("密钥不存在")
	}
	
	// 检查密钥类型是否兼容
	if key.KeyType != KeyTypeHardware {
		return nil, errors.New("非TEE保护的密钥")
	}
	
	// 实际实现中，此处应调用TEE API完成签名
	// 数据从不离开TEE环境
	
	// 简化实现 - 实际应用中不要这样做
	if key.PrivateKey != nil {
		return crypto.Sign(hash, key.PrivateKey)
	}
	
	return nil, errors.New("无法访问私钥")
}

// 配置网络中断保护
func (sm *SecurityManager) configureNetworkResilience() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	log.Info("配置网络中断保护")
	
	// 配置离线模式行为
	sm.offlineModeEnabled = true
	sm.offlineQueue = make([]interface{}, 0)
	
	// 设置重连策略
	sm.reconnectStrategy = "exponential_backoff"
	sm.reconnectAttempts = 0
	sm.reconnectDelay = 5 * time.Second // 初始延迟5秒
	
	log.Info("网络中断保护已启用", 
		"策略", sm.reconnectStrategy, 
		"初始延迟", sm.reconnectDelay)
}

// 处理网络中断
func (sm *SecurityManager) handleNetworkDisruption() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	log.Warn("检测到网络中断，启用离线模式")
	
	// 激活离线模式
	sm.offlineModeEnabled = true
	
	// 通知所有依赖连接的组件
	if sm.onNetworkDisruption != nil {
		go sm.onNetworkDisruption()
	}
}

// 处理网络恢复
func (sm *SecurityManager) handleNetworkRecovery() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	log.Info("网络已恢复")
	
	// 重置重连参数
	sm.reconnectAttempts = 0
	sm.reconnectDelay = 5 * time.Second
	
	// 处理离线队列
	go sm.processOfflineQueue()
	
	// 通知所有依赖连接的组件
	if sm.onNetworkRecovery != nil {
		go sm.onNetworkRecovery()
	}
}

// 将操作加入离线队列
func (sm *SecurityManager) enqueueOfflineOperation(opType string, data interface{}) {
	sm.offlineQueueMutex.Lock()
	defer sm.offlineQueueMutex.Unlock()
	
	// 创建离线操作
	op := map[string]interface{}{
		"type":      opType,
		"data":      data,
		"timestamp": time.Now(),
	}
	
	// 添加到队列
	sm.offlineQueue = append(sm.offlineQueue, op)
	
	log.Debug("操作已加入离线队列", "type", opType, "queue_size", len(sm.offlineQueue))
}

// 处理离线队列
func (sm *SecurityManager) processOfflineQueue() {
	sm.offlineQueueMutex.Lock()
	defer sm.offlineQueueMutex.Unlock()
	
	if len(sm.offlineQueue) == 0 {
		log.Debug("离线队列为空，无需处理")
		return
	}
	
	log.Info("处理离线队列", "operations", len(sm.offlineQueue))
	
	// 遍历并处理队列中的操作
	var remainingOps []interface{}
	
	for _, op := range sm.offlineQueue {
		opMap, ok := op.(map[string]interface{})
		if !ok {
			continue
		}
		
		opType, ok := opMap["type"].(string)
		if !ok {
			continue
		}
		
		// 尝试处理操作
		success := sm.processOfflineOperation(opType, opMap["data"])
		
		if !success {
			// 添加到剩余操作
			remainingOps = append(remainingOps, op)
		}
	}
	
	// 更新队列
	sm.offlineQueue = remainingOps
	
	log.Info("离线队列处理完成", "remaining", len(sm.offlineQueue))
}

// 处理单个离线操作
func (sm *SecurityManager) processOfflineOperation(opType string, data interface{}) bool {
	log.Debug("处理离线操作", "type", opType)
	
	// 根据操作类型处理
	switch opType {
	case "sign_transaction":
		// 处理离线交易签名
		return true
		
	case "create_account":
		// 处理离线账户创建
		return true
		
	case "backup_key":
		// 处理离线密钥备份
		return true
		
	default:
		log.Warn("未知的离线操作类型", "type", opType)
		return false
	}
}

// 设置网络中断回调
func (sm *SecurityManager) SetNetworkDisruptionCallback(callback func()) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onNetworkDisruption = callback
}

// 设置网络恢复回调
func (sm *SecurityManager) SetNetworkRecoveryCallback(callback func()) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onNetworkRecovery = callback
}

// 检查TEE是否可用
func (sm *SecurityManager) IsTEEAvailable() bool {
	return sm.teeInitialized && len(sm.teeOperations) > 0
}

// 检查特定TEE操作是否可用
func (sm *SecurityManager) IsTEEOperationAvailable(operation string) bool {
	if !sm.teeInitialized {
		return false
	}
	
	if available, exists := sm.teeOperations[operation]; exists && available {
		return true
	}
	
	return false
}

// 为账户创建TEE保护的密钥
func (sm *SecurityManager) CreateTEEProtectedAccount() (common.Address, error) {
	if !sm.IsTEEOperationAvailable("key_generation") {
		return common.Address{}, errors.New("TEE密钥生成不可用")
	}
	
	// 检查是否锁定
	if sm.isLocked {
		return common.Address{}, errors.New("安全管理器已锁定")
	}
	
	// 生成TEE保护的密钥
	key, err := sm.generateTEEProtectedKey()
	if err != nil {
		return common.Address{}, err
	}
	
	// 存储密钥信息
	sm.keyStore.mu.Lock()
	sm.keyStore.keys[key.Address] = key
	sm.keyStore.mu.Unlock()
	
	log.Info("已创建TEE保护的账户", "address", key.Address.Hex())
	
	return key.Address, nil
}

// 使用TEE签名交易
func (sm *SecurityManager) SignTransactionWithTEE(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
	if !sm.IsTEEOperationAvailable("signing") {
		return nil, errors.New("TEE签名功能不可用")
	}
	
	// 检查是否锁定
	if sm.isLocked {
		return nil, errors.New("安全管理器已锁定")
	}
	
	// 获取当前链ID
	chainID := big.NewInt(1) // 默认值，实际应从配置或链状态获取
	
	// 创建签名者
	signer := types.NewEIP155Signer(chainID)
	
	// 获取待签名的哈希
	hash := signer.Hash(tx)
	
	// 使用TEE签名
	signature, err := sm.signWithTEE(address, hash.Bytes())
	if err != nil {
		return nil, err
	}
	
	// 应用签名到交易
	signedTx, err := tx.WithSignature(signer, signature)
	if err != nil {
		return nil, err
	}
	
	log.Debug("交易已使用TEE签名", "txhash", signedTx.Hash().Hex())
	
	return signedTx, nil
}

// 初始化TEE（可信执行环境）
func (sm *SecurityManager) initializeTEE() error {
	// 在实际实现中，这里应该初始化TEE环境
	log.Info("TEE环境已初始化")
	return nil
}

// 初始化MPC钱包
func (sm *SecurityManager) initializeMPCWallet() error {
	// 在实际实现中，这里应该初始化MPC钱包环境
	log.Info("MPC钱包已初始化", "门限值", sm.mpcWallet.threshold)
	return nil
}

// 初始化社交恢复
func (sm *SecurityManager) initializeSocialRecovery() error {
	// 在实际实现中，这里应该初始化社交恢复环境
	log.Info("社交恢复已初始化", "门限值", sm.socialRecovery.threshold)
	return nil
}

// 初始化加密管理器
func (sm *SecurityManager) initializeEncryption() error {
	if !sm.config.LocalEncryptionEnabled {
		return nil
	}
	
	// 创建或加载加密密钥
	var key []byte
	if sm.config.LocalEncryptionKey != "" {
		var err error
		key, err = hex.DecodeString(sm.config.LocalEncryptionKey)
		if err != nil {
			return fmt.Errorf("解析加密密钥失败: %v", err)
		}
	} else {
		// 生成新的加密密钥
		key = make([]byte, 32) // 256位密钥
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("生成加密密钥失败: %v", err)
		}
		
		// 在实际应用中，应该安全存储此密钥
		sm.config.LocalEncryptionKey = hex.EncodeToString(key)
	}
	
	// 创建安全存储
	secureStorage := NewSecureStorage(key)
	
	// 启动nonce清理例程
	go secureStorage.StartCleanupRoutine(sm.ctx)
	
	// 初始化加密管理器
	sm.encryptionManager = &EncryptionManager{
		enabled:      true,
		key:          key,
		endToEnd:     sm.config.EndToEndEncryption,
		secureStorage: secureStorage,
	}
	
	return nil
}

// 自动锁定定时器
func (sm *SecurityManager) autoLockRoutine() {
	defer sm.wg.Done()
	
	ticker := time.NewTicker(time.Duration(sm.config.AutoLockTimeout) * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sm.mu.RLock()
			timeSinceActivity := time.Since(sm.lastActivity)
			sm.mu.RUnlock()
			
			if timeSinceActivity >= time.Duration(sm.config.AutoLockTimeout)*time.Minute {
				sm.Lock()
				log.Info("安全管理器已自动锁定", "不活动时间", timeSinceActivity)
			}
			
		case <-sm.ctx.Done():
			return
		}
	}
}

// UpdateActivity 更新最后活动时间
func (sm *SecurityManager) UpdateActivity() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sm.lastActivity = time.Now()
}

// Lock 锁定安全管理器
func (sm *SecurityManager) Lock() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sm.isLocked = true
	log.Info("安全管理器已锁定")
}

// Unlock 解锁安全管理器
func (sm *SecurityManager) Unlock(password string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	// 在实际实现中，这里应该验证密码
	
	sm.isLocked = false
	sm.lastActivity = time.Now()
	log.Info("安全管理器已解锁")
	return nil
}

// IsLocked 检查安全管理器是否已锁定
func (sm *SecurityManager) IsLocked() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	return sm.isLocked
}

// RequiresBiometric 检查是否需要生物识别认证
func (sm *SecurityManager) RequiresBiometric() bool {
	return sm.config.BiometricAuthRequired
}

// 创建钱包账户

// CreateAccount 创建普通账户
func (sm *SecurityManager) CreateAccount(password string) (common.Address, error) {
	if sm.IsLocked() {
		return common.Address{}, errors.New("安全管理器已锁定")
	}
	
	// 创建新的ECDSA密钥对
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return common.Address{}, err
	}
	
	// 计算以太坊地址
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	
	// 创建密钥记录
	key := &Key{
		Address:     address,
		PrivateKey:  privateKey,
		KeyType:     KeyTypeStandard,
		RecoveryType: RecoveryTypeNone,
		Metadata:    make(map[string]string),
	}
	
	// 保存密钥
	sm.keyStore.mu.Lock()
	sm.keyStore.keys[address] = key
	sm.keyStore.mu.Unlock()
	
	// 更新活动时间
	sm.UpdateActivity()
	
	log.Info("创建了新账户", "地址", address.Hex())
	return address, nil
}

// CreateMPCAccount 创建MPC账户
func (sm *SecurityManager) CreateMPCAccount(participants []string) (common.Address, error) {
	if sm.IsLocked() {
		return common.Address{}, errors.New("安全管理器已锁定")
	}
	
	if sm.mpcWallet == nil {
		return common.Address{}, errors.New("MPC钱包未启用")
	}
	
	if len(participants) < 2 {
		return common.Address{}, errors.New("MPC需要至少2个参与者")
	}
	
	// 在实际的实现中，这里应该是MPC密钥生成协议
	// 这里仅作为示例，创建一个常规私钥，并假装它是MPC分布式生成的
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return common.Address{}, err
	}
	
	// 计算以太坊地址
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	
	// 创建MPC会话
	sessionID := fmt.Sprintf("mpc-%s-%d", address.Hex(), time.Now().Unix())
	session := &MPCSession{
		ID:           sessionID,
		Address:      address,
		Participants: participants,
		Shares:       make(map[string][]byte),
		Status:       "completed", // 在实际实现中，这应该是一个状态机
		StartTime:    time.Now(),
		CompletedTime: time.Now(),
	}
	
	// 保存会话
	sm.mpcWallet.mu.Lock()
	sm.mpcWallet.addresses = append(sm.mpcWallet.addresses, address)
	sm.mpcWallet.sessions[sessionID] = session
	sm.mpcWallet.mu.Unlock()
	
	// 创建密钥记录（注意：MPC钱包不存储完整私钥）
	key := &Key{
		Address:     address,
		KeyType:     KeyTypeMPC,
		RecoveryType: RecoveryTypeSocial,
		Metadata:    map[string]string{
			"mpc_session": sessionID,
			"participants": fmt.Sprintf("%d", len(participants)),
			"threshold":   fmt.Sprintf("%d", sm.mpcWallet.threshold),
		},
	}
	
	// 保存密钥引用
	sm.keyStore.mu.Lock()
	sm.keyStore.keys[address] = key
	sm.keyStore.mu.Unlock()
	
	// 更新活动时间
	sm.UpdateActivity()
	
	log.Info("创建了MPC账户", 
		"地址", address.Hex(), 
		"参与者", len(participants),
		"门限值", sm.mpcWallet.threshold)
		
	return address, nil
}

// CreateSocialRecoveryAccount 创建带社交恢复的账户
func (sm *SecurityManager) CreateSocialRecoveryAccount(guardians []string, threshold int) (common.Address, error) {
	if sm.IsLocked() {
		return common.Address{}, errors.New("安全管理器已锁定")
	}
	
	if sm.socialRecovery == nil {
		return common.Address{}, errors.New("社交恢复未启用")
	}
	
	if len(guardians) < threshold {
		return common.Address{}, fmt.Errorf("监护人数量(%d)小于门限值(%d)", len(guardians), threshold)
	}
	
	// 创建新的ECDSA密钥对
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return common.Address{}, err
	}
	
	// 计算以太坊地址
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	
	// 创建密钥分片
	shards, err := sm.createKeyShards(privateKey, len(guardians), threshold)
	if err != nil {
		return common.Address{}, err
	}
	
	// 创建密钥记录
	key := &Key{
		Address:     address,
		PrivateKey:  privateKey, // 在实际实现中，这应该被加密保存
		KeyType:     KeyTypeSocial,
		RecoveryType: RecoveryTypeSocial,
		Metadata:    map[string]string{
			"guardians":  fmt.Sprintf("%d", len(guardians)),
			"threshold":  fmt.Sprintf("%d", threshold),
		},
		Shards:      shards,
	}
	
	// 保存密钥
	sm.keyStore.mu.Lock()
	sm.keyStore.keys[address] = key
	sm.keyStore.mu.Unlock()
	
	// 创建恢复配置
	recovery := &Recovery{
		Address:    address,
		Guardians:  guardians,
		Approvals:  make(map[string]bool),
		Status:     "active",
		StartTime:  time.Now(),
	}
	
	// 保存恢复配置
	sm.socialRecovery.mu.Lock()
	sm.socialRecovery.recoveries[address] = recovery
	sm.socialRecovery.mu.Unlock()
	
	// 更新活动时间
	sm.UpdateActivity()
	
	log.Info("创建了社交恢复账户", 
		"地址", address.Hex(),
		"监护人", len(guardians),
		"门限值", threshold)
		
	return address, nil
}

// 创建密钥分片（简化版本，真实实现应使用SSS或其他密钥分享算法）
func (sm *SecurityManager) createKeyShards(privateKey *ecdsa.PrivateKey, n, t int) ([]*KeyShard, error) {
	// 在实际实现中，这里应该使用Shamir秘密共享(SSS)或其他阈值密码方案
	// 以下是简化的示例实现
	
	// 将私钥转换为字节
	privateKeyBytes := crypto.FromECDSA(privateKey)
	
	// 创建n个分片
	shards := make([]*KeyShard, n)
	for i := 0; i < n; i++ {
		// 在实际实现中，这里应该是实际的分片数据
		// 这里仅作为示例，每个分片都包含完整的私钥（这不是真正的分片！）
		shards[i] = &KeyShard{
			Index:       i + 1,
			Data:        privateKeyBytes, // 在实际实现中，这应该是分片数据
			Holder:      fmt.Sprintf("guardian-%d", i+1),
			IsRecovered: false,
		}
	}
	
	return shards, nil
}

// GetAccounts 获取所有账户
func (sm *SecurityManager) GetAccounts() []common.Address {
	if sm.IsLocked() {
		return nil
	}
	
	sm.keyStore.mu.RLock()
	defer sm.keyStore.mu.RUnlock()
	
	accounts := make([]common.Address, 0, len(sm.keyStore.keys))
	for addr := range sm.keyStore.keys {
		accounts = append(accounts, addr)
	}
	
	return accounts
}

// GetAccountType 获取账户类型
func (sm *SecurityManager) GetAccountType(address common.Address) (int, error) {
	if sm.IsLocked() {
		return -1, errors.New("安全管理器已锁定")
	}
	
	sm.keyStore.mu.RLock()
	defer sm.keyStore.mu.RUnlock()
	
	key, exists := sm.keyStore.keys[address]
	if !exists {
		return -1, fmt.Errorf("账户 %s 不存在", address.Hex())
	}
	
	return key.KeyType, nil
}

// 签名相关方法

// SignHash 对哈希进行签名
func (sm *SecurityManager) SignHash(address common.Address, hash []byte) ([]byte, error) {
	if sm.IsLocked() {
		return nil, errors.New("安全管理器已锁定")
	}
	
	sm.keyStore.mu.RLock()
	key, exists := sm.keyStore.keys[address]
	sm.keyStore.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("账户 %s 不存在", address.Hex())
	}
	
	// 根据密钥类型使用不同的签名方法
	switch key.KeyType {
	case KeyTypeStandard:
		// 标准ECDSA签名
		if key.PrivateKey == nil {
			return nil, errors.New("私钥不可用")
		}
		
		// 使用正确的以太坊签名格式
		return crypto.Sign(hash, key.PrivateKey)
		
	case KeyTypeMPC:
		// MPC签名需要协作
		return sm.signMPC(address, hash)
		
	case KeyTypeHardware:
		// 硬件签名需要硬件交互
		return sm.signHardware(address, hash)
		
	case KeyTypeBiometric:
		// 生物识别签名需要用户验证
		return sm.signBiometric(address, hash)
		
	default:
		return nil, fmt.Errorf("不支持的密钥类型: %d", key.KeyType)
	}
}

// MPC签名（简化示例，实际应该是分布式计算）
func (sm *SecurityManager) signMPC(address common.Address, hash []byte) ([]byte, error) {
	if sm.mpcWallet == nil {
		return nil, errors.New("MPC钱包未启用")
	}
	
	sm.keyStore.mu.RLock()
	key, exists := sm.keyStore.keys[address]
	sm.keyStore.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("账户 %s 不存在", address.Hex())
	}
	
	// 获取MPC会话ID
	sessionID, exists := key.Metadata["mpc_session"]
	if !exists {
		return nil, errors.New("MPC会话信息丢失")
	}
	
	sm.mpcWallet.mu.RLock()
	session, exists := sm.mpcWallet.sessions[sessionID]
	sm.mpcWallet.mu.RUnlock()
	
	if !exists {
		return nil, errors.New("MPC会话不存在")
	}
	
	// 在实际实现中，这里应该启动MPC签名协议
	// 这是简化的示例实现，使用一个常规私钥来模拟结果
	
	// 创建一个临时私钥用于示例
	privateKey, _ := crypto.GenerateKey()
	signature, err := crypto.Sign(hash, privateKey)
	
	if err != nil {
		return nil, err
	}
	
	log.Info("执行MPC签名", 
		"地址", address.Hex(),
		"参与者", len(session.Participants))
		
	return signature, nil
}

// 硬件签名
func (sm *SecurityManager) signHardware(address common.Address, hash []byte) ([]byte, error) {
	// 在实际实现中，这里应该与硬件设备通信
	return nil, errors.New("硬件签名未实现")
}

// 生物识别签名
func (sm *SecurityManager) signBiometric(address common.Address, hash []byte) ([]byte, error) {
	// 在实际实现中，这里应该请求生物识别验证
	return nil, errors.New("生物识别签名未实现")
}

// 社交恢复相关方法

// InitiateRecovery 发起社交恢复
func (sm *SecurityManager) InitiateRecovery(address common.Address) (string, error) {
	if sm.socialRecovery == nil {
		return "", errors.New("社交恢复未启用")
	}
	
	sm.socialRecovery.mu.RLock()
	recovery, exists := sm.socialRecovery.recoveries[address]
	sm.socialRecovery.mu.RUnlock()
	
	if !exists {
		return "", fmt.Errorf("账户 %s 没有社交恢复配置", address.Hex())
	}
	
	// 创建恢复ID
	recoveryID := fmt.Sprintf("recovery-%s-%d", address.Hex(), time.Now().Unix())
	
	// 重置恢复状态
	sm.socialRecovery.mu.Lock()
	recovery.Approvals = make(map[string]bool)
	recovery.Status = "pending"
	recovery.StartTime = time.Now()
	sm.socialRecovery.mu.Unlock()
	
	log.Info("社交恢复已发起", 
		"地址", address.Hex(),
		"恢复ID", recoveryID)
		
	return recoveryID, nil
}

// ApproveRecovery 批准社交恢复
func (sm *SecurityManager) ApproveRecovery(address common.Address, guardian string) error {
	if sm.socialRecovery == nil {
		return errors.New("社交恢复未启用")
	}
	
	sm.socialRecovery.mu.Lock()
	defer sm.socialRecovery.mu.Unlock()
	
	recovery, exists := sm.socialRecovery.recoveries[address]
	if !exists {
		return fmt.Errorf("账户 %s 没有社交恢复配置", address.Hex())
	}
	
	// 检查监护人是否有效
	isValidGuardian := false
	for _, g := range recovery.Guardians {
		if g == guardian {
			isValidGuardian = true
			break
		}
	}
	
	if !isValidGuardian {
		return fmt.Errorf("无效的监护人: %s", guardian)
	}
	
	// 记录批准
	recovery.Approvals[guardian] = true
	
	// 检查是否达到门限
	approvalCount := 0
	for _, approved := range recovery.Approvals {
		if approved {
			approvalCount++
		}
	}
	
	log.Info("监护人批准了恢复", 
		"地址", address.Hex(),
		"监护人", guardian,
		"批准数", approvalCount,
		"门限值", sm.socialRecovery.threshold)
		
	// 如果达到门限，执行恢复
	if approvalCount >= sm.socialRecovery.threshold {
		recovery.Status = "approved"
		recovery.CompletedTime = time.Now()
		
		// 在实际实现中，这里应该重建密钥
		log.Info("社交恢复已完成！", "地址", address.Hex())
	}
	
	return nil
}

// GetRecoveryStatus 获取恢复状态
func (sm *SecurityManager) GetRecoveryStatus(address common.Address) (string, int, int, error) {
	if sm.socialRecovery == nil {
		return "", 0, 0, errors.New("社交恢复未启用")
	}
	
	sm.socialRecovery.mu.RLock()
	defer sm.socialRecovery.mu.RUnlock()
	
	recovery, exists := sm.socialRecovery.recoveries[address]
	if !exists {
		return "", 0, 0, fmt.Errorf("账户 %s 没有社交恢复配置", address.Hex())
	}
	
	// 计算批准数
	approvalCount := 0
	for _, approved := range recovery.Approvals {
		if approved {
			approvalCount++
		}
	}
	
	return recovery.Status, approvalCount, sm.socialRecovery.threshold, nil
}

// 加密相关方法

// EncryptData 加密数据
func (sm *SecurityManager) EncryptData(data []byte) ([]byte, error) {
	if !sm.config.LocalEncryptionEnabled {
		return nil, errors.New("本地加密未启用")
	}
	
	sm.encryptionManager.mu.RLock()
	defer sm.encryptionManager.mu.RUnlock()
	
	if sm.encryptionManager.key == nil {
		return nil, errors.New("加密密钥不可用")
	}
	
	// 使用安全存储进行加密
	ciphertext, nonce, err := sm.encryptionManager.secureStorage.encrypt(data)
	if err != nil {
		return nil, err
	}
	
	// 将nonce附加到密文前面以便解密时使用
	result := append(nonce, ciphertext...)
	
	return result, nil
}

// DecryptData 解密数据
func (sm *SecurityManager) DecryptData(encryptedData []byte) ([]byte, error) {
	if !sm.config.LocalEncryptionEnabled {
		return nil, errors.New("本地加密未启用")
	}
	
	sm.encryptionManager.mu.RLock()
	defer sm.encryptionManager.mu.RUnlock()
	
	if sm.encryptionManager.key == nil {
		return nil, errors.New("加密密钥不可用")
	}
	
	// 确保数据长度足够
	if len(encryptedData) <= 16 {
		return nil, errors.New("加密数据长度不足")
	}
	
	// 前16字节是nonce
	nonce := encryptedData[:16]
	ciphertext := encryptedData[16:]
	
	// 使用安全存储进行解密，包含nonce验证
	return sm.encryptionManager.secureStorage.decrypt(ciphertext, nonce)
}

// IsPrivateTransactionEnabled 检查是否启用私密交易
func (sm *SecurityManager) IsPrivateTransactionEnabled() bool {
	return sm.config.PrivateTransactions
}

// IsEndToEndEncryptionEnabled 检查是否启用端到端加密
func (sm *SecurityManager) IsEndToEndEncryptionEnabled() bool {
	return sm.config.EndToEndEncryption
}

// IsMPCWalletEnabled 检查是否启用MPC钱包
func (sm *SecurityManager) IsMPCWalletEnabled() bool {
	return sm.config.MPCWalletEnabled
}

// IsSocialRecoveryEnabled 检查是否启用社交恢复
func (sm *SecurityManager) IsSocialRecoveryEnabled() bool {
	return sm.config.SocialRecoveryEnabled
}

// IsHardwareKeyStoreEnabled 检查是否启用硬件密钥存储
func (sm *SecurityManager) IsHardwareKeyStoreEnabled() bool {
	return sm.config.HardwareKeyStoreEnabled
}

// IsTEEEnabled 检查是否启用可信执行环境
func (sm *SecurityManager) IsTEEEnabled() bool {
	return sm.config.TEEEnabled
} 