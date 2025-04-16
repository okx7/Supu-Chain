package mobile

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

// MPC密钥分片协议常量
const (
	MPCProtocolSSS     = "shamir"     // Shamir's Secret Sharing
	MPCProtocolDFeldman = "dfeldman"   // Distributed Feldman
	MPCProtocolGG20     = "gg20"       // Gennaro-Goldfeder 2020协议
	MPCProtocolFrost    = "frost"      // FROST: Flexible Round-Optimized Schnorr Threshold签名
)

// MPC恢复协议常量 
const (
	RecoveryModeSocial   = "social"   // 社交恢复
	RecoveryModeBackup   = "backup"   // 备份恢复
	RecoveryModeHardware = "hardware" // 硬件恢复
	RecoveryModeMPC      = "mpc"      // MPC恢复
	RecoveryModeMultiSig = "multisig" // 多签恢复
	RecoveryModeHybrid   = "hybrid"   // 混合恢复 - 新增
)

// 安全级别常量
const (
	SecurityLevelStandard = 1 // 标准安全级别
	SecurityLevelHigh     = 2 // 高安全级别
	SecurityLevelExtreme  = 3 // 极高安全级别
)

// MPCWalletConfig MPC钱包配置
type MPCWalletConfig struct {
	ThresholdSign         int              // 签名阈值
	TotalShares           int              // 总份额
	KeygenTimeout         time.Duration    // 密钥生成超时
	SignTimeout           time.Duration    // 签名超时
	KeyRefreshInterval    time.Duration    // 密钥刷新间隔
	EnableKeyRotation     bool             // 启用密钥轮换
	EnableDistributedSign bool             // 启用分布式签名
	RecoveryModes         []string         // 恢复方式
	TrustedPeers          []common.Address // 可信节点
	ShareEncryption       bool             // 份额加密
	BiometricProtection   bool             // 生物特征保护
	AllowOfflineSign      bool             // 允许离线签名
	DeviceLimit           int              // 设备数量限制
	LocalSharePath        string           // 本地份额路径
	AllowedRecoverers     []common.Address // 允许的恢复者 - 新增
	RecoveryDelay         time.Duration    // 恢复延迟 - 新增
	RecoveryThreshold     int              // 恢复阈值 - 新增
	GuardianEmails        []string         // 监护人邮箱 - 新增
	GuardianPhones        []string         // 监护人手机 - 新增
	SocialRecoveryDelay   time.Duration    // 社交恢复延迟 - 新增
	DeviceSyncEnabled     bool             // 设备同步 - 新增
	SecurityQuestions     []string         // 安全问题 - 新增
	SecurityAnswers       []string         // 安全答案 - 新增
}

// KeyShare 密钥分片
type KeyShare struct {
	ShareID       string         // 分片ID
	ShareData     []byte         // 分片数据
	DeviceID      string         // 设备ID
	CreatedAt     time.Time      // 创建时间
	LastUsed      time.Time      // 最后使用时间
	Verification  []byte         // 验证数据
	MetaData      map[string]string // 元数据
}

// MPCSession MPC会话
type MPCSession struct {
	SessionID    string              // 会话ID
	SessionType  string              // 会话类型 (keygen, signing)
	StartTime    time.Time           // 开始时间
	Timeout      time.Duration       // 超时
	Participants []int               // 参与者
	Data         interface{}         // 会话数据
	Status       string              // 状态
	Result       interface{}         // 结果
}

// Guardian 监护人 - 新增
type Guardian struct {
	Address       common.Address // 地址
	Name          string         // 名称
	Email         string         // 邮箱
	Phone         string         // 手机号
	TrustLevel    int            // 信任级别 (1-5)
	AddedTime     time.Time      // 添加时间
	LastConfirmed time.Time      // 最后确认时间
	Status        string         // 状态 (active, pending, revoked)
	RecoveryKey   []byte         // 恢复密钥
	PublicKey     *ecdsa.PublicKey // 公钥
}

// MPCWallet MPC钱包
type MPCWallet struct {
	config         *MPCWalletConfig    // 配置
	address        common.Address      // 地址
	publicKey      *ecdsa.PublicKey    // 公钥
	localShare     []byte              // 本地份额
	shareIndex     int                 // 份额索引
	session        *MPCSession         // MPC会话
	activeSessions map[string]*MPCSession // 活动会话
	peers          map[string]*MPCPeer // 对等节点
	
	// 社交恢复 - 新增或增强
	socialGuardians       map[common.Address]*Guardian // 社交监护人
	recoveryRequests      map[string]*RecoveryRequest  // 恢复请求
	guardianApprovals     map[string][]common.Address  // 监护人批准
	pendingRecovery       bool                         // 正在恢复
	recoveryStartTime     time.Time                    // 恢复开始时间
	
	// 多设备支持 - 新增
	pairedDevices       map[string]*PairedDevice    // 已配对设备
	deviceCoordinator   *DeviceCoordinator          // 设备协调器
	pendingCoordination map[string]*CoordinationRequest // 待处理协调
	
	// 安全增强 - 新增
	securityPolicies   *SecurityPolicies           // 安全策略
	transactionLimits  *TransactionLimits          // 交易限制
	riskAssessment     *RiskAssessment             // 风险评估
	
	// 控制
	mu               sync.RWMutex         // 互斥锁
	ctx              context.Context      // 上下文
	cancel           context.CancelFunc   // 取消函数
	isInitialized    bool                 // 是否已初始化
	keygenInProgress bool                 // 正在生成密钥
	signInProgress   bool                 // 正在签名
}

// MPCPeer MPC对等节点
type MPCPeer struct {
	Address    common.Address        // 地址
	PublicKey  *ecdsa.PublicKey      // 公钥
	ShareIndex int                   // 份额索引
	Status     string                // 状态
	LastSeen   time.Time             // 最后见到时间
}

// ShareInfo 份额信息
type ShareInfo struct {
	ShareIndex int                   // 份额索引
	Share      []byte                // 份额
	IsEncrypted bool                 // 是否加密
}

// Security error definitions - 新增安全错误定义
var (
	ErrInvalidRecoverySignature  = errors.New("无效的恢复签名") // 无效的恢复签名
	ErrRecoveryRequestExpired    = errors.New("恢复请求已过期") // 恢复请求已过期
	ErrInsufficientApprovals     = errors.New("批准数量不足") // 批准数量不足
	ErrRecoveryAlreadyInProgress = errors.New("恢复已在进行中") // 恢复已在进行中
	ErrRecoveryTimeout           = errors.New("恢复超时") // 恢复超时
	ErrUnauthorizedRecovery      = errors.New("未授权的恢复尝试") // 未授权的恢复尝试
	ErrBiometricRequired         = errors.New("需要生物特征验证") // 需要生物特征验证
	ErrSecurityPolicyViolation   = errors.New("违反安全策略") // 违反安全策略
	ErrExcessiveRecoveryAttempts = errors.New("恢复尝试次数过多") // 恢复尝试次数过多
	ErrRecoveryDelayActive       = errors.New("恢复延迟期仍在进行") // 恢复延迟期仍在进行
)

// RecoveryAttempt 定义恢复尝试记录 - 新增
type RecoveryAttempt struct {
	AttemptTime time.Time      // 尝试时间
	IPAddress   string         // IP地址
	DeviceID    string         // 设备ID
	DeviceInfo  string         // 设备信息
	GeoLocation string         // 地理位置
	Success     bool           // 是否成功
	FailReason  string         // 失败原因
	Method      string         // 尝试方法
}

// SecurityProofData 安全证明数据 - 新增
type SecurityProofData struct {
	Timestamp      time.Time      // 时间戳
	DeviceID       string         // 设备ID
	TEEAttestation []byte         // TEE证明
	Challenge      []byte         // 挑战数据
	Response       []byte         // 响应数据
	Signature      []byte         // 签名
}

// 为RecoveryRequest添加新字段
type RecoveryRequest struct {
	ID               string         // 请求ID
	RequestorAddress common.Address // 请求者地址
	RequestTime      time.Time      // 请求时间
	ExpiryTime       time.Time      // 过期时间
	RecoveryMethod   string         // 恢复方法
	Status           string         // 状态
	ApprovalCount    int            // 批准数量
	RejectionCount   int            // 拒绝数量
	NewPublicKey     *ecdsa.PublicKey // 新公钥
	ProofData        []byte         // 证明数据
	
	// 新增安全字段
	Attempts         []RecoveryAttempt // 尝试记录
	SecurityProof    *SecurityProofData // 安全证明
	NotificationSent bool              // 是否已发送通知
	DelayTimeRemaining time.Duration   // 剩余延迟时间
	GuardianResponses map[common.Address]string // 监护人响应记录
	DelayEndTime      time.Time        // 延迟结束时间
	IPRestrictions    []string         // IP限制
	GeoRestrictions   []string         // 地理位置限制
	RequireBiometric  bool             // 是否要求生物特征验证
	RecoveryCode      string           // 恢复码
}

// PairedDevice 已配对设备 - 新增
type PairedDevice struct {
	DeviceID        string         // 设备ID
	DeviceName      string         // 设备名称
	DeviceType      string         // 设备类型
	PairingTime     time.Time      // 配对时间
	LastActiveTime  time.Time      // 最后活动时间
	Status          string         // 状态
	PublicKey       *ecdsa.PublicKey // 公钥
	ShareIndex      int            // 份额索引
	Permission      int            // 权限级别
	BiometricStatus bool           // 生物特征状态
}

// DeviceCoordinator 设备协调器 - 新增
type DeviceCoordinator struct {
	masterDevice     bool                   // 是否主设备
	connectedDevices map[string]bool        // 已连接设备
	activeRequests   map[string]interface{} // 活动请求
	coordMu          sync.RWMutex           // 协调互斥锁
}

// CoordinationRequest 协调请求 - 新增
type CoordinationRequest struct {
	RequestID     string      // 请求ID
	RequestType   string      // 请求类型 (sign, keygen, etc)
	DeviceID      string      // 发起设备ID
	Status        string      // 状态
	CreatedTime   time.Time   // 创建时间
	ExpiryTime    time.Time   // 过期时间
	Payload       interface{} // 请求数据
	ResponseCount int         // 响应数量
}

// SecurityPolicies 安全策略 - 新增
type SecurityPolicies struct {
	RequireBiometricForHigh   bool          // 大额交易需要生物特征
	RequireMultiDeviceForHigh bool          // 大额交易需要多设备
	TimeBasedRestrictions     bool          // 基于时间的限制
	AllowedTimeStart          int           // 允许时间开始 (24小时制)
	AllowedTimeEnd            int           // 允许时间结束 (24小时制)
	GeoRestrictions           []string      // 地理限制
	WhitelistedAddresses      []common.Address // 白名单地址
	CooldownPeriod            time.Duration // 冷却期
	LastHighValueTx           time.Time     // 最后高价值交易
}

// TransactionLimits 交易限制 - 新增
type TransactionLimits struct {
	DailyLimit        *big.Int       // 日限额
	SingleTxLimit     *big.Int       // 单笔限额
	DailyUsed         *big.Int       // 今日已用
	LastReset         time.Time      // 最后重置时间
	HighValueThreshold *big.Int      // 高价值阈值
	RequireExtra       bool          // 需要额外确认
}

// RiskAssessment 风险评估 - 新增
type RiskAssessment struct {
	riskScoring    map[string]int    // 风险评分
	suspiciousActivities []string    // 可疑活动
	lastAssessment time.Time         // 最后评估时间
	riskLevel      int               // 风险级别 (1-5)
}

// MPCAccount MPC账户
type MPCAccount struct {
	Address      common.Address // 账户地址
	PublicKey    []byte         // 公钥
	Path         string         // 路径
	ShareIDs     []string       // 分片ID
	CreatedAt    time.Time      // 创建时间
	LastActivity time.Time      // 最后活动时间
	Label        string         // 标签
	Status       string         // 状态
	MetaData     map[string]string // 元数据
}

// SignRequest 签名请求
type SignRequest struct {
	RequestID    string         // 请求ID
	AccountAddr  common.Address // 账户地址
	TxHash       common.Hash    // 交易哈希
	RawData      []byte         // 原始数据
	FromDeviceID string         // 发起设备ID
	Deadline     time.Time      // 截止时间
	Status       string         // 状态
	Signatures   map[string][]byte // 分片签名映射
	FinalSig     []byte         // 最终签名
	Error        string         // 错误信息
}

// MPCPeerManager 对等节点管理器
type MPCPeerManager struct {
	peerInfo     map[string]*PeerInfo // 对等节点信息
	config       *MPCWalletConfig     // 配置
	mu           sync.RWMutex         // 互斥锁
	
	// 通信通道
	messageHandlers map[string]func(message []byte, peerId string) error // 消息处理器
}

// PeerInfo 对等节点信息
type PeerInfo struct {
	DeviceID     string        // 设备ID
	PublicKey    []byte        // 公钥
	IsOnline     bool          // 是否在线
	LastSeen     time.Time     // 最后可见时间
	IsTrusted    bool          // 是否信任
	ConnectionInfo map[string]string // 连接信息
}

// NewMPCWallet 创建新的MPC钱包
func NewMPCWallet(config *MPCWalletConfig) (*MPCWallet, error) {
	if config == nil {
		return nil, errors.New("配置不能为空")
	}
	
	// 验证配置
	if config.ThresholdSign <= 0 || config.TotalShares <= 0 || config.ThresholdSign > config.TotalShares {
		return nil, fmt.Errorf("无效的阈值或份额: 阈值=%d, 份额=%d", config.ThresholdSign, config.TotalShares)
	}
	
	// 默认恢复模式
	if len(config.RecoveryModes) == 0 {
		config.RecoveryModes = []string{RecoveryModeSocial, RecoveryModeBackup}
	}
	
	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	
	// 创建MPC钱包
	wallet := &MPCWallet{
		config:             config,
		activeSessions:     make(map[string]*MPCSession),
		peers:              make(map[string]*MPCPeer),
		ctx:                ctx,
		cancel:             cancel,
		isInitialized:      false,
		keygenInProgress:   false,
		signInProgress:     false,
		socialGuardians:    make(map[common.Address]*Guardian),
		recoveryRequests:   make(map[string]*RecoveryRequest),
		guardianApprovals:  make(map[string][]common.Address),
		pairedDevices:      make(map[string]*PairedDevice),
		pendingCoordination: make(map[string]*CoordinationRequest),
	}
	
	// 初始化设备协调器
	wallet.deviceCoordinator = &DeviceCoordinator{
		masterDevice:     true, // 创建者为主设备
		connectedDevices: make(map[string]bool),
		activeRequests:   make(map[string]interface{}),
	}
	
	// 初始化交易限制
	wallet.transactionLimits = &TransactionLimits{
		DailyLimit:        big.NewInt(0),
		SingleTxLimit:     big.NewInt(0),
		DailyUsed:         big.NewInt(0),
		LastReset:         time.Now(),
		HighValueThreshold: big.NewInt(0),
	}
	
	// 初始化安全策略
	wallet.securityPolicies = &SecurityPolicies{
		RequireBiometricForHigh: config.BiometricProtection,
		RequireMultiDeviceForHigh: config.EnableDistributedSign,
		WhitelistedAddresses:    make([]common.Address, 0),
	}
	
	// 初始化风险评估
	wallet.riskAssessment = &RiskAssessment{
		riskScoring: make(map[string]int),
		suspiciousActivities: make([]string, 0),
		lastAssessment: time.Now(),
		riskLevel: 1, // 默认最低风险
	}
	
	log.Info("MPC钱包已创建", 
		"阈值", config.ThresholdSign, 
		"份额", config.TotalShares,
		"恢复", strings.Join(config.RecoveryModes, ","),
		"多设备", config.DeviceSyncEnabled)
	
	return wallet, nil
}

// Initialize 初始化钱包
func (w *MPCWallet) Initialize() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	if w.isInitialized {
		return errors.New("MPC钱包已初始化")
	}
	
	// 检查是否已有本地份额
	if len(w.localShare) > 0 {
		// 尝试从本地份额恢复
		if err := w.restoreFromLocalShare(); err != nil {
			return fmt.Errorf("从本地份额恢复失败: %v", err)
		}
		w.isInitialized = true
		return nil
	}
	
	// 生成新的MPC密钥
	if err := w.generateMPCKey(); err != nil {
		return fmt.Errorf("生成MPC密钥失败: %v", err)
	}
	
	w.isInitialized = true
	log.Info("MPC钱包已初始化", "地址", w.address.Hex())
	return nil
}

// AddGuardian 添加监护人 - 新增
func (w *MPCWallet) AddGuardian(address common.Address, name, email, phone string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	// 检查地址是否已是监护人
	if _, exists := w.socialGuardians[address]; exists {
		return fmt.Errorf("地址 %s 已是监护人", address.Hex())
	}
	
	// 创建新监护人
	guardian := &Guardian{
		Address:       address,
		Name:          name,
		Email:         email,
		Phone:         phone,
		TrustLevel:    3, // 默认中等信任级别
		AddedTime:     time.Now(),
		LastConfirmed: time.Now(),
		Status:        "pending", // 需要确认
	}
	
	// 生成恢复密钥
	recoveryKey := make([]byte, 32)
	if _, err := rand.Read(recoveryKey); err != nil {
		return fmt.Errorf("生成恢复密钥失败: %v", err)
	}
	guardian.RecoveryKey = recoveryKey
	
	// 添加监护人
	w.socialGuardians[address] = guardian
	
	// 发送确认请求（实际实现中应该发送确认邮件/短信）
	log.Info("已添加监护人", 
		"地址", address.Hex(), 
		"名称", name,
		"状态", "pending")
	
	return nil
}

// ConfirmGuardian 确认监护人 - 新增
func (w *MPCWallet) ConfirmGuardian(address common.Address) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	guardian, exists := w.socialGuardians[address]
	if !exists {
		return fmt.Errorf("找不到地址为 %s 的监护人", address.Hex())
	}
	
	if guardian.Status != "pending" {
		return fmt.Errorf("监护人状态不是pending: %s", guardian.Status)
	}
	
	// 更新监护人状态
	guardian.Status = "active"
	guardian.LastConfirmed = time.Now()
	
	log.Info("监护人已确认", "地址", address.Hex(), "名称", guardian.Name)
	return nil
}

// InitiateRecovery 发起恢复 - 新增
func (w *MPCWallet) InitiateRecovery(requestorAddress common.Address, method string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	// 检查是否已有正在进行的恢复流程
	if w.pendingRecovery {
		log.Warn("已有恢复流程正在进行中", "requestor", requestorAddress)
		return "", ErrRecoveryAlreadyInProgress
	}
	
	// 验证请求者是否有权限发起恢复
	isAuthorized := false
	if len(w.config.AllowedRecoverers) > 0 {
		for _, addr := range w.config.AllowedRecoverers {
			if addr == requestorAddress {
				isAuthorized = true
				break
			}
		}
	} else {
		// 如果没有明确指定允许的恢复者，检查是否为已注册的监护人
		if _, exists := w.socialGuardians[requestorAddress]; exists {
			isAuthorized = true
		}
	}
	
	if !isAuthorized {
		log.Warn("未授权的恢复尝试", "请求者", requestorAddress.Hex())
		return "", ErrUnauthorizedRecovery
	}
	
	// 验证恢复方法是否支持
	methodSupported := false
	for _, mode := range w.config.RecoveryModes {
		if mode == method {
			methodSupported = true
			break
		}
	}
	
	if !methodSupported {
		return "", fmt.Errorf("不支持的恢复方法: %s", method)
	}
	
	// 创建新的恢复请求
	requestID := generateRandomID()
	now := time.Now()
	
	// 设置恢复延迟
	delayDuration := w.config.RecoveryDelay
	if method == RecoveryModeSocial {
		delayDuration = w.config.SocialRecoveryDelay
	}
	
	request := &RecoveryRequest{
		ID:                requestID,
		RequestorAddress:  requestorAddress,
		RequestTime:       now,
		ExpiryTime:        now.Add(24 * time.Hour), // 默认24小时过期
		RecoveryMethod:    method,
		Status:            "pending",
		ApprovalCount:     0,
		RejectionCount:    0,
		GuardianResponses: make(map[common.Address]string),
		DelayEndTime:      now.Add(delayDuration),
		Attempts:          make([]RecoveryAttempt, 0),
	}
	
	// 添加当前尝试记录
	attempt := RecoveryAttempt{
		AttemptTime: now,
		DeviceID:    "current_device", // 实际中应当获取真实设备ID
		Method:      method,
	}
	request.Attempts = append(request.Attempts, attempt)
	
	// 初始化恢复请求
	if w.recoveryRequests == nil {
		w.recoveryRequests = make(map[string]*RecoveryRequest)
	}
	w.recoveryRequests[requestID] = request
	
	// 标记恢复进行中
	w.pendingRecovery = true
	w.recoveryStartTime = now
	
	// 通知所有监护人（实际实现应发送实际通知）
	w.notifyGuardiansOfRecovery(request)
	
	log.Info("已初始化恢复流程", 
		"方法", method, 
		"请求ID", requestID, 
		"请求者", requestorAddress.Hex(),
		"延迟结束时间", request.DelayEndTime)
	
	return requestID, nil
}

// 通知监护人有关恢复请求
func (w *MPCWallet) notifyGuardiansOfRecovery(request *RecoveryRequest) {
	if len(w.socialGuardians) == 0 {
		log.Warn("没有监护人可通知")
		return
	}
	
	// 标记为已通知
	request.NotificationSent = true
	
	// 实际实现应通过多种渠道（邮件、短信等）通知监护人
	log.Info("已通知所有监护人关于恢复请求", 
		"请求ID", request.ID, 
		"监护人数量", len(w.socialGuardians))
}

// ApproveRecovery 批准恢复 - 新增
func (w *MPCWallet) ApproveRecovery(requestID string, guardianAddress common.Address, signature []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	// 查找恢复请求
	request, exists := w.recoveryRequests[requestID]
	if !exists {
		return fmt.Errorf("未找到恢复请求: %s", requestID)
	}
	
	// 检查请求是否过期
	if time.Now().After(request.ExpiryTime) {
		request.Status = "expired"
		return ErrRecoveryRequestExpired
	}
	
	// 验证监护人身份
	guardian, isGuardian := w.socialGuardians[guardianAddress]
	if !isGuardian {
		log.Warn("未知的监护人尝试批准恢复", 
			"地址", guardianAddress.Hex(), 
			"请求ID", requestID)
		return ErrUnauthorizedRecovery
	}
	
	// 验证监护人状态
	if guardian.Status != "active" {
		log.Warn("非活动监护人尝试批准恢复", 
			"地址", guardianAddress.Hex(), 
			"状态", guardian.Status)
		return fmt.Errorf("监护人状态异常: %s", guardian.Status)
	}
	
	// 检查是否已经提交了响应
	if response, responded := request.GuardianResponses[guardianAddress]; responded {
		log.Warn("监护人已响应此恢复请求", 
			"地址", guardianAddress.Hex(), 
			"响应", response)
		return fmt.Errorf("已提交响应: %s", response)
	}
	
	// 验证签名
	// 为验证构造消息
	message := append([]byte(requestID), guardianAddress.Bytes()...)
	
	// 获取监护人公钥
	if guardian.PublicKey == nil {
		return errors.New("监护人缺少公钥")
	}
	
	// 验证签名
	messageHash := crypto.Keccak256Hash(message)
	if len(signature) == 0 || !crypto.VerifySignature(
		crypto.FromECDSAPub(guardian.PublicKey),
		messageHash.Bytes(),
		signature[:len(signature)-1]) {
		log.Warn("恢复批准签名验证失败", 
			"监护人", guardianAddress.Hex())
		return ErrInvalidRecoverySignature
	}
	
	// 记录批准
	request.ApprovalCount++
	request.GuardianResponses[guardianAddress] = "approved"
	
	log.Info("监护人已批准恢复请求", 
		"监护人", guardianAddress.Hex(), 
		"请求ID", requestID, 
		"当前批准数", request.ApprovalCount)
	
	// 检查是否已收集足够的批准
	if request.ApprovalCount >= w.config.RecoveryThreshold {
		// 检查是否仍在延迟期
		if time.Now().Before(request.DelayEndTime) {
			// 计算剩余延迟时间
			request.DelayTimeRemaining = time.Until(request.DelayEndTime)
			log.Info("恢复请求已得到足够批准，但仍在延迟期", 
				"请求ID", requestID, 
				"剩余时间", request.DelayTimeRemaining)
			return nil
		}
		
		// 延迟期已过，执行恢复
		log.Info("恢复请求已获得足够批准且延迟期已过，执行恢复", 
			"请求ID", requestID)
		
		request.Status = "approved"
		
		// 异步执行恢复(避免锁定太久)
		go func() {
			if err := w.executeRecovery(request); err != nil {
				log.Error("执行恢复失败", "错误", err)
				w.mu.Lock()
				request.Status = "failed"
				w.pendingRecovery = false
				w.mu.Unlock()
			}
		}()
	}
	
	return nil
}

// executeCoordinatedAction 执行协调操作 - 新增
func (w *MPCWallet) executeCoordinatedAction(request *CoordinationRequest) error {
	switch request.RequestType {
	case "sign":
		// 在实际实现中，这里应该完成多设备签名
		log.Info("执行多设备签名", "请求ID", request.RequestID)
		return nil
	
	case "keygen":
		// 在实际实现中，这里应该完成多设备密钥生成
		log.Info("执行多设备密钥生成", "请求ID", request.RequestID)
		return nil
	
	default:
		return fmt.Errorf("不支持的请求类型: %s", request.RequestType)
	}
}

// CoordinatedSignTransaction 协同签名交易 - 新增
func (w *MPCWallet) CoordinatedSignTransaction(tx *types.Transaction) (common.Hash, error) {
	// 验证交易
	if tx == nil {
		return common.Hash{}, errors.New("交易为空")
	}
	
	// 安全检查
	if err := w.validateTransaction(tx); err != nil {
		return common.Hash{}, err
	}
	
	// 发起协调签名
	requestID, err := w.InitiateCoordinatedAction("sign", tx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("发起协调签名失败: %v", err)
	}
	
	// 在实际实现中，这里应该等待其他设备的响应
	// 为了演示，我们假设等待一段时间后检查结果
	
	// 获取结果
	txHash := tx.Hash()
	log.Info("已发起协同签名", "交易哈希", txHash.Hex(), "请求ID", requestID)
	
	return txHash, nil
}

// validateTransaction 验证交易 - 新增
func (w *MPCWallet) validateTransaction(tx *types.Transaction) error {
	// 获取交易金额
	value := tx.Value()
	
	// 检查单笔限额
	if w.transactionLimits.SingleTxLimit.Sign() > 0 && value.Cmp(w.transactionLimits.SingleTxLimit) > 0 {
		return fmt.Errorf("交易金额 %s 超过单笔限额 %s", 
			value.String(), w.transactionLimits.SingleTxLimit.String())
	}
	
	// 检查日限额
	if w.transactionLimits.DailyLimit.Sign() > 0 {
		// 检查是否需要重置每日使用量
		now := time.Now()
		if now.Sub(w.transactionLimits.LastReset).Hours() >= 24 {
			w.transactionLimits.DailyUsed = big.NewInt(0)
			w.transactionLimits.LastReset = now
		}
		
		// 计算新的使用量
		newUsed := new(big.Int).Add(w.transactionLimits.DailyUsed, value)
		if newUsed.Cmp(w.transactionLimits.DailyLimit) > 0 {
			return fmt.Errorf("交易后总额 %s 将超过日限额 %s", 
				newUsed.String(), w.transactionLimits.DailyLimit.String())
		}
	}
	
	// 检查是否为高价值交易
	isHighValue := false
	if w.transactionLimits.HighValueThreshold.Sign() > 0 && 
	   value.Cmp(w.transactionLimits.HighValueThreshold) >= 0 {
		isHighValue = true
	}
	
	// 高价值交易额外检查
	if isHighValue {
		// 检查是否需要生物特征
		if w.securityPolicies.RequireBiometricForHigh {
			// 在实际实现中，这里应该要求生物特征认证
			log.Info("高价值交易需要生物特征认证")
		}
		
		// 检查是否需要多设备
		if w.securityPolicies.RequireMultiDeviceForHigh && len(w.pairedDevices) < 2 {
			return errors.New("高价值交易需要多设备签名，但配对设备不足")
		}
		
		// 检查冷却期
		if w.securityPolicies.CooldownPeriod > 0 && 
		   time.Since(w.securityPolicies.LastHighValueTx) < w.securityPolicies.CooldownPeriod {
			cooldownRemaining := w.securityPolicies.CooldownPeriod - time.Since(w.securityPolicies.LastHighValueTx)
			return fmt.Errorf("高价值交易冷却期未结束，还需等待 %v", cooldownRemaining)
		}
		
		// 更新最后高价值交易时间
		w.securityPolicies.LastHighValueTx = time.Now()
	}
	
	// 检查时间限制
	if w.securityPolicies.TimeBasedRestrictions {
		hour := time.Now().Hour()
		if hour < w.securityPolicies.AllowedTimeStart || hour >= w.securityPolicies.AllowedTimeEnd {
			return fmt.Errorf("当前时间 %d 超出允许的交易时间范围 %d-%d", 
				hour, w.securityPolicies.AllowedTimeStart, w.securityPolicies.AllowedTimeEnd)
		}
	}
	
	// 更新日使用量（如果所有检查都通过）
	w.transactionLimits.DailyUsed = new(big.Int).Add(w.transactionLimits.DailyUsed, value)
	
	return nil
}

// GetPendingCoordinations 获取待处理协调 - 新增
func (w *MPCWallet) GetPendingCoordinations() []*CoordinationRequest {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	requests := make([]*CoordinationRequest, 0)
	
	for _, request := range w.pendingCoordination {
		if request.Status == "pending" && time.Now().Before(request.ExpiryTime) {
			requests = append(requests, request)
		}
	}
	
	return requests
}

// 拒绝恢复请求 - 新增
func (w *MPCWallet) RejectRecovery(requestID string, guardianAddress common.Address, signature []byte, reason string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	// 查找恢复请求
	request, exists := w.recoveryRequests[requestID]
	if !exists {
		return fmt.Errorf("未找到恢复请求: %s", requestID)
	}
	
	// 检查请求是否过期
	if time.Now().After(request.ExpiryTime) {
		request.Status = "expired"
		return ErrRecoveryRequestExpired
	}
	
	// 验证监护人身份
	guardian, isGuardian := w.socialGuardians[guardianAddress]
	if !isGuardian {
		return ErrUnauthorizedRecovery
	}
	
	// 验证签名
	messageHash := crypto.Keccak256Hash(append([]byte(requestID), guardianAddress.Bytes()...))
	if !crypto.VerifySignature(
		crypto.FromECDSAPub(guardian.PublicKey),
		messageHash.Bytes(),
		signature[:len(signature)-1]) {
		return ErrInvalidRecoverySignature
	}
	
	// 记录拒绝
	request.RejectionCount++
	request.GuardianResponses[guardianAddress] = "rejected: " + reason
	
	// 检查是否已被大多数拒绝
	requiredRejections := (len(w.socialGuardians) / 2) + 1
	if request.RejectionCount >= requiredRejections {
		request.Status = "rejected"
		w.pendingRecovery = false
		
		log.Info("恢复请求已被拒绝", 
			"请求ID", requestID, 
			"拒绝数", request.RejectionCount)
	}
	
	return nil
}

// 执行恢复的增强实现
func (w *MPCWallet) executeRecovery(request *RecoveryRequest) error {
	// 再次检查状态
	if request.Status != "approved" {
		return fmt.Errorf("无法执行未批准的恢复: %s", request.Status)
	}
	
	// 根据不同的恢复方法执行不同的恢复流程
	var err error
	switch request.RecoveryMethod {
	case RecoveryModeSocial:
		err = w.executeSocialRecovery(request)
	case RecoveryModeBackup:
		err = w.executeBackupRecovery(request)
	case RecoveryModeHardware:
		err = w.executeHardwareRecovery(request)
	case RecoveryModeMPC:
		err = w.executeMPCRecovery(request)
	case RecoveryModeMultiSig:
		err = w.executeMultiSigRecovery(request)
	case RecoveryModeHybrid:
		err = w.executeHybridRecovery(request)
	default:
		err = fmt.Errorf("未知的恢复方法: %s", request.RecoveryMethod)
	}
	
	// 添加新的尝试记录
	attempt := RecoveryAttempt{
		AttemptTime: time.Now(),
		DeviceID:    "recovery_device", // 实际中应当获取真实设备ID
		Method:      request.RecoveryMethod,
		Success:     err == nil,
	}
	
	if err != nil {
		attempt.FailReason = err.Error()
	}
	
	w.mu.Lock()
	request.Attempts = append(request.Attempts, attempt)
	
	// 更新恢复状态
	if err == nil {
		request.Status = "completed"
		w.pendingRecovery = false
		log.Info("恢复成功完成", "请求ID", request.ID, "方法", request.RecoveryMethod)
	} else {
		request.Status = "failed"
		w.pendingRecovery = false
		log.Error("恢复执行失败", "错误", err, "请求ID", request.ID)
	}
	w.mu.Unlock()
	
	return err
}

// 社交恢复增强版
func (w *MPCWallet) executeSocialRecovery(request *RecoveryRequest) error {
	log.Info("执行社交恢复", "请求ID", request.ID)
	
	// 验证批准数量是否达到阈值
	if request.ApprovalCount < w.config.RecoveryThreshold {
		return ErrInsufficientApprovals
	}
	
	// 验证延迟期是否已过
	if time.Now().Before(request.DelayEndTime) {
		remainingTime := time.Until(request.DelayEndTime)
		return fmt.Errorf("恢复延迟期未结束，剩余%v", remainingTime)
	}
	
	// 实际在这里应该执行密钥重建
	// 1. 收集批准的监护人提供的密钥分片
	// 2. 验证分片的真实性
	// 3. 重建密钥
	// 4. 更新钱包状态
	
	// 模拟密钥恢复延迟
	time.Sleep(2 * time.Second)
	
	// 生成新的密钥对（实际应使用重建的密钥）
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成新密钥对失败: %v", err)
	}
	
	// 更新钱包状态
	w.mu.Lock()
	w.publicKey = &privateKey.PublicKey
	// 更新其他状态...
	w.mu.Unlock()
	
	// 记录恢复完成
	log.Info("社交恢复完成", "请求ID", request.ID)
	
	return nil
}

// 备份恢复实现
func (w *MPCWallet) executeBackupRecovery(request *RecoveryRequest) error {
	log.Info("执行备份恢复", "请求ID", request.ID)
	
	// 模拟从备份恢复
	time.Sleep(1 * time.Second)
	
	// 实际实现中，这里应该:
	// 1. 验证备份的真实性
	// 2. 解密备份数据
	// 3. 恢复密钥和状态
	
	// 生成新的密钥对（实际应使用恢复的密钥）
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成新密钥对失败: %v", err)
	}
	
	// 更新钱包状态
	w.mu.Lock()
	w.publicKey = &privateKey.PublicKey
	// 更新其他状态...
	w.mu.Unlock()
	
	return nil
}

// 硬件恢复实现
func (w *MPCWallet) executeHardwareRecovery(request *RecoveryRequest) error {
	log.Info("执行硬件恢复", "请求ID", request.ID)
	
	// 实际实现中，这里应该:
	// 1. 与硬件设备通信
	// 2. 验证硬件设备的身份
	// 3. 从硬件设备获取密钥数据
	
	// 模拟硬件恢复过程
	time.Sleep(2 * time.Second)
	
	// 生成新的密钥对（实际应使用硬件设备提供的密钥）
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成新密钥对失败: %v", err)
	}
	
	// 更新钱包状态
	w.mu.Lock()
	w.publicKey = &privateKey.PublicKey
	// 更新其他状态...
	w.mu.Unlock()
	
	return nil
}

// MPC恢复实现
func (w *MPCWallet) executeMPCRecovery(request *RecoveryRequest) error {
	log.Info("执行MPC恢复", "请求ID", request.ID)
	
	// 实际实现中，这里应该:
	// 1. 启动MPC恢复协议
	// 2. 收集其他参与方的密钥分片
	// 3. 重建完整密钥
	
	// 模拟MPC恢复过程
	time.Sleep(3 * time.Second)
	
	// 生成新的密钥对（实际应使用MPC重建的密钥）
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成新密钥对失败: %v", err)
	}
	
	// 更新钱包状态
	w.mu.Lock()
	w.publicKey = &privateKey.PublicKey
	// 更新其他状态...
	w.mu.Unlock()
	
	return nil
}

// 多签恢复实现
func (w *MPCWallet) executeMultiSigRecovery(request *RecoveryRequest) error {
	log.Info("执行多签恢复", "请求ID", request.ID)
	
	// 实际实现中，这里应该:
	// 1. 验证多签恢复交易
	// 2. 收集足够签名
	// 3. 执行恢复操作
	
	// 模拟多签恢复过程
	time.Sleep(1 * time.Second)
	
	// 生成新的密钥对
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成新密钥对失败: %v", err)
	}
	
	// 更新钱包状态
	w.mu.Lock()
	w.publicKey = &privateKey.PublicKey
	// 更新其他状态...
	w.mu.Unlock()
	
	return nil
}

// 混合恢复实现
func (w *MPCWallet) executeHybridRecovery(request *RecoveryRequest) error {
	log.Info("执行混合恢复", "请求ID", request.ID)
	
	// 混合恢复通常结合多种恢复方式
	// 实际实现中，这里应该根据配置选择和组合不同的恢复方法
	
	// 例如：社交恢复 + 硬件确认
	socialErr := w.executeSocialRecovery(request)
	if socialErr != nil {
		return fmt.Errorf("社交恢复步骤失败: %v", socialErr)
	}
	
	hardwareErr := w.executeHardwareRecovery(request)
	if hardwareErr != nil {
		return fmt.Errorf("硬件恢复步骤失败: %v", hardwareErr)
	}
	
	return nil
}

// 获取钱包恢复状态 - 新增
func (w *MPCWallet) GetRecoveryStatus(requestID string) (map[string]interface{}, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	request, exists := w.recoveryRequests[requestID]
	if !exists {
		return nil, fmt.Errorf("未找到恢复请求: %s", requestID)
	}
	
	// 计算剩余延迟时间
	var delayRemaining time.Duration
	if time.Now().Before(request.DelayEndTime) {
		delayRemaining = time.Until(request.DelayEndTime)
	}
	
	// 构建状态信息
	status := map[string]interface{}{
		"id":                requestID,
		"status":            request.Status,
		"method":            request.RecoveryMethod,
		"requestor":         request.RequestorAddress.Hex(),
		"request_time":      request.RequestTime,
		"expiry_time":       request.ExpiryTime,
		"approval_count":    request.ApprovalCount,
		"rejection_count":   request.RejectionCount,
		"threshold":         w.config.RecoveryThreshold,
		"delay_remaining":   delayRemaining.String(),
		"attempts":          len(request.Attempts),
		"guardians_total":   len(w.socialGuardians),
		"guardians_responded": len(request.GuardianResponses),
	}
	
	return status, nil
}

// 取消恢复请求 - 新增
func (w *MPCWallet) CancelRecovery(requestID string, requesterAddress common.Address, signature []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	// 查找恢复请求
	request, exists := w.recoveryRequests[requestID]
	if !exists {
		return fmt.Errorf("未找到恢复请求: %s", requestID)
	}
	
	// 只有请求者或管理员可以取消
	if request.RequestorAddress != requesterAddress && !w.isAdmin(requesterAddress) {
		return ErrUnauthorizedRecovery
	}
	
	// 验证签名
	messageHash := crypto.Keccak256Hash(append([]byte("cancel:"+requestID), requesterAddress.Bytes()...))
	if !crypto.VerifySignature(
		crypto.FromECDSAPub(w.getPublicKeyForAddress(requesterAddress)),
		messageHash.Bytes(),
		signature[:len(signature)-1]) {
		return ErrInvalidRecoverySignature
	}
	
	// 如果请求已经是完成或失败状态，则不能取消
	if request.Status == "completed" || request.Status == "failed" {
		return fmt.Errorf("无法取消状态为 %s 的恢复请求", request.Status)
	}
	
	// 取消恢复
	request.Status = "cancelled"
	w.pendingRecovery = false
	
	log.Info("恢复请求已取消", 
		"请求ID", requestID, 
		"取消者", requesterAddress.Hex())
	
	return nil
}

// 判断地址是否为管理员 - 新增辅助方法
func (w *MPCWallet) isAdmin(address common.Address) bool {
	// 实际实现中应该检查地址是否为管理员
	// 这里简化处理，假设配置中的第一个受信任对等节点为管理员
	if len(w.config.TrustedPeers) > 0 {
		return w.config.TrustedPeers[0] == address
	}
	return false
}

// 获取地址对应的公钥 - 新增辅助方法
func (w *MPCWallet) getPublicKeyForAddress(address common.Address) *ecdsa.PublicKey {
	// 对于请求者，从监护人列表中查找
	if guardian, exists := w.socialGuardians[address]; exists && guardian.PublicKey != nil {
		return guardian.PublicKey
	}
	
	// 如果是钱包地址，返回钱包公钥
	if address == crypto.PubkeyToAddress(*w.publicKey) {
		return w.publicKey
	}
	
	// 在配对设备中查找
	for _, device := range w.pairedDevices {
		if crypto.PubkeyToAddress(*device.PublicKey) == address {
			return device.PublicKey
		}
	}
	
	// 未找到公钥
	return nil
} 