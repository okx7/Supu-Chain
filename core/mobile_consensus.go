package core

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	// 共识错误定义
	ErrMobileValidator           = errors.New("移动验证者错误")                        // 移动验证者错误
	ErrInvalidValidator          = errors.New("无效的验证者")                         // 无效的验证者
	ErrValidatorAlreadyExists    = errors.New("验证者已存在")                         // 验证者已存在
	ErrValidatorNotExists        = errors.New("验证者不存在")                         // 验证者不存在
	ErrInvalidConfirmation       = errors.New("无效的区块确认")                        // 无效的区块确认
	ErrInsufficientConfirmations = errors.New("区块确认数不足")                        // 区块确认数不足
	ErrMobileBatteryTooLow       = errors.New("移动设备电量过低，不能参与验证")                 // 移动设备电量过低
	ErrMobileNetworkUnstable     = errors.New("移动设备网络不稳定，不能参与验证")                // 移动设备网络不稳定
	ErrExceedMobileResourceLimit = errors.New("超出移动设备资源限制")                      // 超出移动设备资源限制
	ErrTooManyValidators         = errors.New("验证者数量超过限制")                       // 验证者数量超过限制
	ErrNoActiveValidators        = errors.New("没有活跃的验证者")                        // 没有活跃的验证者
	ErrValidatorBusy             = errors.New("验证者正忙")                          // 验证者正忙
	ErrValidatorTimeout          = errors.New("验证者超时")                          // 验证者超时
	ErrBlockRejected             = errors.New("区块被拒绝")                          // 区块被拒绝
	ErrMobileConsensusInactive   = errors.New("移动共识机制未激活")                      // 移动共识机制未激活
	ErrDeviceTypeMismatch        = errors.New("设备类型不匹配")                         // 设备类型不匹配
	ErrValidatorUnauthorized     = errors.New("验证器未授权")                 // 验证器未被授权
	ErrLowBatteryPercentage      = errors.New("电池电量过低")                 // 电池电量过低
	ErrLowNetworkSpeed           = errors.New("网络速度过低")                 // 网络速度过低
	ErrDeviceNotQualified        = errors.New("设备不符合要求")                // 设备不符合要求
	ErrInsufficientResource      = errors.New("资源不足")                   // 资源不足
	ErrMaxValidatorsReached      = errors.New("已达到最大验证器数量")             // 已达到最大验证器数量
)

// 资源限制常量
const (
	MinBatteryPercentage  = 20             // 最低电池电量百分比
	MinNetworkSpeed       = 1024 * 1024    // 最低网络速度(字节/秒)
	MinDeviceMemory       = 4 * 1024 * 1024 // 最低设备内存(字节)
	MaxValidatorCount     = 100            // 最大验证器数量
	MinConfirmations      = 5                // 最小确认数
	ValidatorTimeoutSec   = 10               // 验证者超时时间(秒)
	HeartbeatIntervalSec  = 30               // 心跳间隔(秒)
	BlockCacheSize        = 100              // 区块缓存大小
	ConfirmationCacheSize = 1000             // 确认缓存大小
	
	// 共识参数
	ConfirmationThreshold  = 0.67  // 确认阈值(67%)
	BlockInterval          = 5     // 区块间隔(秒)
	MaxConfirmationTimeout = 30    // 最大确认超时时间(秒)
	MaxDeviceDowntime      = 300   // 最大设备离线时间(秒)
	
	// 移动优化参数
	MinBlockIntervalLowBattery = 15    // 低电量时的最小区块间隔(秒)
	MaxCpuUsagePercent = 70            // 最大CPU使用率(百分比)
	MaxMemoryUsagePercent = 80         // 最大内存使用率(百分比)
	LowBatteryThreshold = 20           // 低电量阈值(百分比)
	CriticalBatteryThreshold = 10      // 严重低电量阈值(百分比)
	PoorNetworkThreshold = 100 * 1024  // 较差网络阈值(字节/秒)
	SyncResumeRetryInterval = 30       // 同步恢复重试间隔(秒)
)

// ResourceStats 资源统计信息
type ResourceStats struct {
	CpuUsage         float64   // CPU使用率(百分比)
	MemoryUsage      uint64    // 内存使用量(字节)
	BatteryLevel     int       // 电池电量(百分比)
	BatteryCharging  bool      // 是否正在充电
	NetworkType      string    // 网络类型(wifi/cellular)
	NetworkSpeed     uint64    // 网络速度(字节/秒)
	StorageAvailable uint64    // 可用存储空间(字节)
	LastUpdated      time.Time // 最后更新时间
	
	// 性能监控
	ProcessingTimes []time.Duration // 近期处理时间
	SyncTimes       []time.Duration // 近期同步时间
	BatteryDrain    []float64       // 近期电池消耗
}

// 设备类型
const (
	DeviceTypeSmartphone = "smartphone"  // 智能手机
	DeviceTypeTablet     = "tablet"      // 平板电脑
	DeviceTypeWearable   = "wearable"    // 可穿戴设备
	DeviceTypeIoT        = "iot"         // 物联网设备
)

// DeviceInfo 存储设备信息
type DeviceInfo struct {
	DeviceID      string // 设备ID
	DeviceModel   string // 设备型号
	OSVersion     string // 操作系统版本
	MemoryTotal   uint64 // 总内存(字节)
	StorageTotal  uint64 // 总存储空间(字节)
	ProcessorInfo string // 处理器信息
	NetworkType   string // 网络类型(WiFi/4G/5G等)
}

// MobileValidator 表示一个移动验证者
type MobileValidator struct {
	Address       common.Address // 验证者地址
	DeviceInfo    DeviceInfo     // 设备信息
	DeviceType    string         // 设备类型
	NetworkInfo   string         // 网络信息
	Status        int            // 状态(0:离线,1:在线,2:验证中)
	BatteryLevel  int            // 电池电量(0-100)
	IsActive      bool           // 是否活跃
	LastSeen      time.Time      // 最后一次活跃时间
	BlocksSealed  uint64         // 已密封区块数
	BlocksSigned  uint64         // 已签名区块数
	Stake         *big.Int       // 质押数量
	NetworkSpeed  uint64         // 网络速度(字节/秒)
	LastActive    time.Time      // 最后活动时间
	ConfirmCount  uint64         // 确认次数
	RegisterTime  time.Time      // 注册时间
}

// BlockConfirmation 表示对一个区块的确认信息
type BlockConfirmation struct {
	BlockHash   common.Hash     // 区块哈希
	BlockNumber uint64          // 区块高度
	Validator   common.Address  // 验证者地址
	Timestamp   time.Time       // 确认时间戳
	Signature   []byte          // 确认签名
	DeviceInfo  string          // 设备信息
}

// MobileConsensus 实现基于移动设备的共识机制
type MobileConsensus struct {
	config       *params.ChainConfig  // 链配置
	validatorsMu sync.RWMutex          // 验证者列表互斥锁
	validators   map[common.Address]*MobileValidator  // 验证者映射
	
	confirmationsMu sync.RWMutex // 确认互斥锁
	confirmations   map[common.Hash]map[common.Address]*BlockConfirmation // 区块确认映射
	sealedBlocks    map[common.Hash]bool    // 已封印区块映射
	chain           consensus.ChainReader   // 链读取器
	
	// 互斥锁
	validatorMu     sync.RWMutex  // 验证者互斥锁
	confirmationMu  sync.RWMutex  // 确认互斥锁
	blockMu         sync.RWMutex  // 区块互斥锁
	
	// 指标
	validatorCountGauge  metrics.Gauge  // 验证者数量指标
	batteryLevelGauge    metrics.Gauge  // 平均电池电量指标
	networkSpeedGauge    metrics.Gauge  // 平均网络速度指标
	confirmationGauge    metrics.Gauge  // 确认数量指标
	activeValidatorGauge metrics.Gauge  // 活跃验证器指标
	
	// 是否激活
	active    bool  // 是否激活
	
	// 移动端优化参数
	adaptiveBlockInterval bool         // 是否启用自适应区块间隔
	batteryAware          bool         // 是否启用电池感知
	networkAware          bool         // 是否启用网络感知
	resourceLimitEnabled  bool         // 是否启用资源限制
	incrementalSync       bool         // 是否启用增量同步
	
	// 资源管理
	lastSyncPoint       common.Hash    // 最后同步点
	syncResumeData      []byte         // 同步恢复数据
	resourceStats       *ResourceStats // 资源统计
	lowResourceMode     bool           // 低资源模式
	
	// 新增指标
	batteryDrainGauge     metrics.Gauge // 电池消耗指标
	processingTimeGauge   metrics.Gauge // 处理时间指标
	syncSpeedGauge        metrics.Gauge // 同步速度指标
	resourceUsageGauge    metrics.Gauge // 资源使用指标
}

// MobileConsensusConfig 是移动共识配置
type MobileConsensusConfig struct {
	MinConfirmations     int             // 最小确认数
	MaxValidators        int             // 最大验证者数量
	MinBatteryLevel      int             // 最低电池电量要求
	HeartbeatInterval    time.Duration   // 心跳间隔
	BlockTimeout         time.Duration   // 区块超时时间
	EnableSharding       bool            // 是否启用分片
	ShardCount           int             // 分片数量
	ResourceCheckEnabled bool            // 是否启用资源检查
	ValidatorTimeout     time.Duration   // 验证者超时时间
	BatteryCheckInterval time.Duration   // 电池检查间隔
}

// NewMobileConsensus 创建一个新的移动共识实例
func NewMobileConsensus(config *params.ChainConfig) *MobileConsensus {
	mc := &MobileConsensus{
		config:       config,
		validators:   make(map[common.Address]*MobileValidator),
		confirmations: make(map[common.Hash]map[common.Address]*BlockConfirmation),
		sealedBlocks: make(map[common.Hash]bool),
		active:       true,
		validatorCountGauge:  metrics.NewRegisteredGauge("mobile/validators/count", nil),
		batteryLevelGauge:    metrics.NewRegisteredGauge("mobile/validators/battery", nil),
		networkSpeedGauge:    metrics.NewRegisteredGauge("mobile/validators/network", nil),
		confirmationGauge:    metrics.NewRegisteredGauge("mobile/confirmations/count", nil),
		activeValidatorGauge: metrics.NewRegisteredGauge("mobile/validators/active", nil),
		
		// 初始化移动端优化参数
		adaptiveBlockInterval: true,        // 默认启用自适应区块间隔
		batteryAware:          true,        // 默认启用电池感知
		networkAware:          true,        // 默认启用网络感知
		resourceLimitEnabled:  true,        // 默认启用资源限制
		incrementalSync:       true,        // 默认启用增量同步
		resourceStats:         &ResourceStats{LastUpdated: time.Now()},
		
		// 初始化新增指标
		batteryDrainGauge:     metrics.NewRegisteredGauge("mobile/resource/battery_drain", nil),
		processingTimeGauge:   metrics.NewRegisteredGauge("mobile/resource/processing_time_ms", nil),
		syncSpeedGauge:        metrics.NewRegisteredGauge("mobile/resource/sync_speed_bps", nil),
		resourceUsageGauge:    metrics.NewRegisteredGauge("mobile/resource/usage_percent", nil),
	}
	
	// 定期更新指标
	go mc.updateMetrics()
	
	// 启动资源监控
	go mc.monitorResources()
	
	log.Info("移动共识机制初始化", 
		"最大验证者", config.MaxValidators, 
		"最小确认数", config.MinConfirmations,
		"电池感知", mc.batteryAware,
		"网络感知", mc.networkAware)
	
	return mc
}

// 更新指标函数
func (mc *MobileConsensus) updateMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			mc.validatorMu.RLock()
			
			// 更新验证器数量
			mc.validatorCountGauge.Update(int64(len(mc.validators)))
			
			// 计算平均电池电量和网络速度
			if len(mc.validators) > 0 {
				var totalBattery int64
				var totalNetworkSpeed int64
				var activeCount int64
				
				now := time.Now()
				for _, v := range mc.validators {
					totalBattery += int64(v.BatteryLevel)
					totalNetworkSpeed += int64(v.NetworkSpeed)
					
					// 检查验证器是否活跃(5分钟内有活动)
					if now.Sub(v.LastActive) < 5*time.Minute {
						activeCount++
					}
				}
				
				mc.batteryLevelGauge.Update(totalBattery / int64(len(mc.validators)))
				mc.networkSpeedGauge.Update(totalNetworkSpeed / int64(len(mc.validators)))
				mc.activeValidatorGauge.Update(activeCount)
			}
			
			mc.validatorMu.RUnlock()
			
			// 更新确认数量
			mc.confirmationMu.RLock()
			var totalConfirmations int64
			for _, confs := range mc.confirmations {
				totalConfirmations += int64(len(confs))
			}
			mc.confirmationGauge.Update(totalConfirmations)
			mc.confirmationMu.RUnlock()
		}
	}
}

// 资源监控函数
func (mc *MobileConsensus) monitorResources() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// 更新资源统计
			mc.updateResourceStats()
			
			// 检查资源限制
			if mc.resourceLimitEnabled {
				mc.enforceResourceLimits()
			}
		}
	}
}

// 更新资源统计
func (mc *MobileConsensus) updateResourceStats() {
	stats := mc.resourceStats
	
	// 在真实实现中，这些数据应该从系统API获取
	// 这里仅用模拟数据示例
	stats.BatteryLevel = getBatteryLevel()
	stats.BatteryCharging = isBatteryCharging()
	stats.NetworkType = getNetworkType()
	stats.NetworkSpeed = getNetworkSpeed()
	stats.CpuUsage = getCpuUsage()
	stats.MemoryUsage = getMemoryUsage()
	stats.StorageAvailable = getStorageAvailable()
	stats.LastUpdated = time.Now()
	
	// 更新指标
	mc.batteryDrainGauge.Update(int64(calculateBatteryDrain(stats)))
	mc.resourceUsageGauge.Update(int64(stats.CpuUsage))
}

// 强制资源限制
func (mc *MobileConsensus) enforceResourceLimits() {
	stats := mc.resourceStats
	
	// 低电量模式
	if stats.BatteryLevel < LowBatteryThreshold && !stats.BatteryCharging {
		if !mc.lowResourceMode {
			log.Info("进入低资源模式", "电量", stats.BatteryLevel)
			mc.lowResourceMode = true
		}
	} else if (stats.BatteryLevel > LowBatteryThreshold+10 || stats.BatteryCharging) && mc.lowResourceMode {
		log.Info("退出低资源模式", "电量", stats.BatteryLevel)
		mc.lowResourceMode = false
	}
	
	// 其他资源限制逻辑
	// ...
}

// 模拟获取电池电量
func getBatteryLevel() int {
	// 实际实现应该调用系统API
	return 50 // 假设电量为50%
}

// 模拟检查电池是否充电
func isBatteryCharging() bool {
	// 实际实现应该调用系统API
	return false
}

// 模拟获取网络类型
func getNetworkType() string {
	// 实际实现应该调用系统API
	return "wifi"
}

// 模拟获取网络速度
func getNetworkSpeed() uint64 {
	// 实际实现应该调用系统API
	return 1024 * 1024 * 10 // 10MB/s
}

// 模拟获取CPU使用率
func getCpuUsage() float64 {
	// 实际实现应该调用系统API
	return 30.0 // 30%
}

// 模拟获取内存使用量
func getMemoryUsage() uint64 {
	// 实际实现应该调用系统API
	return 500 * 1024 * 1024 // 500MB
}

// 模拟获取可用存储空间
func getStorageAvailable() uint64 {
	// 实际实现应该调用系统API
	return 5 * 1024 * 1024 * 1024 // 5GB
}

// 计算电池消耗率
func calculateBatteryDrain(stats *ResourceStats) float64 {
	// 简单实现，实际应基于历史数据计算
	if len(stats.BatteryDrain) < 2 {
		return 0.0
	}
	
	sum := 0.0
	for _, drain := range stats.BatteryDrain {
		sum += drain
	}
	
	return sum / float64(len(stats.BatteryDrain))
}

// RegisterValidator 注册一个新的移动验证者
func (mc *MobileConsensus) RegisterValidator(address common.Address, deviceInfo DeviceInfo, batteryLevel int, networkSpeed uint64) error {
	mc.validatorMu.Lock()
	defer mc.validatorMu.Unlock()
	
	// 检查共识机制是否激活
	if !mc.active {
		return ErrMobileConsensusInactive
	}
	
	// 验证设备类型
	validDeviceTypes := map[string]bool{
		DeviceTypeSmartphone: true,
		DeviceTypeTablet:     true,
		DeviceTypeWearable:   true,
		DeviceTypeIoT:        true,
	}
	
	if !validDeviceTypes[deviceInfo.DeviceModel] {
		return ErrDeviceTypeMismatch
	}
	
	// 检查验证者数量
	if len(mc.validators) >= mc.config.MaxValidators {
		return ErrTooManyValidators
	}
	
	// 检查验证者是否已存在
	if _, exists := mc.validators[address]; exists {
		return ErrValidatorAlreadyExists
	}
	
	// 检查电池电量
	if batteryLevel < mc.config.MinBatteryLevel {
		return ErrMobileBatteryTooLow
	}
	
	// 检查网络速度
	if networkSpeed < mc.config.MinNetworkSpeed {
		return ErrLowNetworkSpeed
	}
	
	// 检查设备内存
	if deviceInfo.MemoryTotal < mc.config.MinDeviceMemory {
		return ErrDeviceNotQualified
	}
	
	// 创建新验证者
	validator := &MobileValidator{
		Address:       address,
		DeviceInfo:    deviceInfo,
		DeviceType:    deviceInfo.DeviceModel,
		NetworkInfo:   "",
		Status:        1, // 在线
		BatteryLevel:  batteryLevel,
		IsActive:      true,
		LastSeen:      time.Now(),
		BlocksSealed:  0,
		BlocksSigned:  0,
		Stake:         new(big.Int),
		NetworkSpeed:  networkSpeed,
		LastActive:    time.Now(),
		ConfirmCount:  0,
		RegisterTime:  time.Now(),
	}
	
	// 添加到验证者映射
	mc.validators[address] = validator
	
	// 更新指标
	mc.validatorCountGauge.Update(int64(len(mc.validators)))
	mc.activeValidatorGauge.Inc(1)
	
	log.Info("已注册移动验证者", "地址", address.Hex(), "设备", deviceInfo.DeviceModel)
	
	return nil
}

// UnregisterValidator 注销一个移动验证者
func (mc *MobileConsensus) UnregisterValidator(address common.Address) error {
	mc.validatorMu.Lock()
	defer mc.validatorMu.Unlock()
	
	// 检查共识机制是否激活
	if !mc.active {
		return ErrMobileConsensusInactive
	}
	
	// 检查验证者是否存在
	validator, exists := mc.validators[address]
	if !exists {
		return ErrValidatorNotExists
	}
	
	// 检查验证者是否活跃
	if validator.IsActive {
		mc.activeValidatorGauge.Dec(1)
	}
	
	// 从映射中删除
	delete(mc.validators, address)
	
	// 更新指标
	mc.validatorCountGauge.Update(int64(len(mc.validators)))
	
	log.Info("已注销移动验证者", "地址", address.Hex())
	
	return nil
}

// GetValidator 获取验证者信息
func (mc *MobileConsensus) GetValidator(address common.Address) (*MobileValidator, error) {
	mc.validatorMu.RLock()
	defer mc.validatorMu.RUnlock()
	
	validator, exists := mc.validators[address]
	if !exists {
		return nil, ErrValidatorNotExists
	}
	
	// 返回副本以防止修改
	return &MobileValidator{
		Address:      validator.Address,
		DeviceInfo:   validator.DeviceInfo,
		DeviceType:   validator.DeviceType,
		NetworkInfo:  validator.NetworkInfo,
		Status:       validator.Status,
		BatteryLevel: validator.BatteryLevel,
		IsActive:     validator.IsActive,
		LastSeen:     validator.LastSeen,
		BlocksSealed: validator.BlocksSealed,
		BlocksSigned: validator.BlocksSigned,
		Stake:        new(big.Int).Set(validator.Stake),
		NetworkSpeed: validator.NetworkSpeed,
		LastActive:   validator.LastActive,
		ConfirmCount: validator.ConfirmCount,
		RegisterTime: validator.RegisterTime,
	}, nil
}

// UpdateValidatorStatus 更新验证者状态
func (mc *MobileConsensus) UpdateValidatorStatus(address common.Address, batteryLevel int, networkSpeed uint64, status int) error {
	mc.validatorMu.Lock()
	defer mc.validatorMu.Unlock()
	
	// 检查共识机制是否激活
	if !mc.active {
		return ErrMobileConsensusInactive
	}
	
	// 检查验证者是否存在
	validator, exists := mc.validators[address]
	if !exists {
		return ErrValidatorNotExists
	}
	
	// 检查电池电量变化
	wasActive := validator.IsActive
	batteryTooLow := batteryLevel < mc.config.MinBatteryLevel
	
	// 更新验证者信息
	validator.BatteryLevel = batteryLevel
	validator.NetworkSpeed = networkSpeed
	validator.Status = status
	validator.LastSeen = time.Now()
	
	// 根据电池电量和网络状态更新活跃状态
	if batteryTooLow {
		validator.IsActive = false
		validator.Status = 0 // 设置为离线状态
	} else if status == 0 {
		validator.IsActive = false
		validator.Status = 0 // 设置为离线状态
	} else {
		validator.IsActive = true
		validator.Status = 1 // 设置为在线状态
	}
	
	// 更新活跃验证者指标
	if wasActive && !validator.IsActive {
		mc.activeValidatorGauge.Dec(1)
	} else if !wasActive && validator.IsActive {
		mc.activeValidatorGauge.Inc(1)
	}
	
	// 更新平均电池电量
	totalBattery := 0
	activeCount := 0
	for _, v := range mc.validators {
		if v.IsActive {
			totalBattery += v.BatteryLevel
			activeCount++
		}
	}
	
	if activeCount > 0 {
		mc.batteryLevelGauge.Update(int64(totalBattery / activeCount))
	}
	
	log.Debug("已更新验证者状态", "地址", address.Hex(), "电池", batteryLevel, "活跃", validator.IsActive)
	
	return nil
}

// AddConfirmation 添加区块确认
func (mc *MobileConsensus) AddConfirmation(blockHash common.Hash, blockNumber uint64, validator common.Address, signature []byte) error {
	mc.validatorMu.RLock()
	validatorObj, exists := mc.validators[validator]
	mc.validatorMu.RUnlock()
	
	// 验证验证者是否存在
	if !exists {
		return ErrValidatorNotExists
	}
	
	// 验证验证者是否活跃
	if !validatorObj.IsActive {
		return ErrInvalidValidator
	}
	
	mc.confirmationMu.Lock()
	defer mc.confirmationMu.Unlock()
	
	// 检查确认是否已存在
	for _, conf := range mc.confirmations[blockHash] {
		if conf.Validator == validator {
			return ErrInvalidConfirmation
		}
	}
	
	// 添加新确认
	confirmation := &BlockConfirmation{
		BlockHash:   blockHash,
		BlockNumber: blockNumber,
		Validator:   validator,
		Timestamp:   time.Now(),
		Signature:   signature,
		DeviceInfo:  validatorObj.DeviceInfo.DeviceModel,
	}
	
	mc.confirmations[blockHash][validator] = confirmation
	
	// 更新指标
	mc.confirmationGauge.Inc(1)
	
	// 更新验证者的区块签名计数
	mc.validatorMu.Lock()
	validatorObj.BlocksSigned++
	mc.validatorMu.Unlock()
	
	log.Debug("区块确认已接收", "区块", blockHash.Hex(), "验证者", validator.Hex(), "确认数", len(mc.confirmations[blockHash]))
	
	return nil
}

// GetConfirmations 获取区块的确认信息
func (mc *MobileConsensus) GetConfirmations(blockHash common.Hash) []*BlockConfirmation {
	mc.confirmationMu.RLock()
	defer mc.confirmationMu.RUnlock()
	
	confirmations := mc.confirmations[blockHash]
	result := make([]*BlockConfirmation, 0, len(confirmations))
	for _, c := range confirmations {
		result = append(result, c)
	}
	
	return result
}

// GetConfirmationCount 获取区块的确认数量
func (mc *MobileConsensus) GetConfirmationCount(blockHash common.Hash) int {
	mc.confirmationMu.RLock()
	defer mc.confirmationMu.RUnlock()
	
	return len(mc.confirmations[blockHash])
}

// IsSufficientlyConfirmed 检查区块是否有足够的确认
func (mc *MobileConsensus) IsSufficientlyConfirmed(blockHash common.Hash) bool {
	confirmCount := mc.GetConfirmationCount(blockHash)
	return confirmCount >= mc.config.MinConfirmations
}

// SelectValidatorsForBlock 为区块选择验证者
func (mc *MobileConsensus) SelectValidatorsForBlock(blockNumber uint64, seed int64) []common.Address {
	mc.validatorMu.RLock()
	defer mc.validatorMu.RUnlock()
	
	// 获取活跃验证者
	activeValidators := make([]common.Address, 0)
	for addr, validator := range mc.validators {
		if validator.IsActive {
			activeValidators = append(activeValidators, addr)
		}
	}
	
	// 如果没有足够的活跃验证者，返回所有活跃验证者
	if len(activeValidators) <= mc.config.MinConfirmations {
		return activeValidators
	}
	
	// 简单的伪随机选择验证者
	// 在实际生产环境中，需要使用更好的随机选择算法
	r := big.NewInt(seed)
	r.Add(r, big.NewInt(int64(blockNumber)))
	
	selected := make([]common.Address, mc.config.MinConfirmations)
	for i := 0; i < mc.config.MinConfirmations; i++ {
		r.Add(r, big.NewInt(int64(i)))
		index := new(big.Int).Mod(r, big.NewInt(int64(len(activeValidators)))).Int64()
		selected[i] = activeValidators[index]
	}
	
	return selected
}

// 以下是实现共识接口所需的方法

// Author 返回区块提案者的以太坊地址
func (mc *MobileConsensus) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader 验证区块头
func (mc *MobileConsensus) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	// 检查共识机制是否激活
	if !mc.active {
		return ErrMobileConsensusInactive
	}
	
	// 资源感知验证 - 电池电量低时采用轻量级验证
	if mc.batteryAware && mc.resourceStats.BatteryLevel < LowBatteryThreshold {
		return mc.lightVerifyHeader(chain, header, seal)
	}
	
	// 检查是否有活跃验证者
	mc.validatorMu.RLock()
	activeCount := 0
	for _, validator := range mc.validators {
		if validator.IsActive {
			activeCount++
		}
	}
	mc.validatorMu.RUnlock()
	
	if activeCount < mc.config.MinConfirmations {
		return ErrNoActiveValidators
	}
	
	// 基本区块头验证可以委托给默认验证
	// 但这里需要额外验证移动共识特有的属性
	
	return nil
}

// 轻量级区块头验证 - 为低资源环境优化
func (mc *MobileConsensus) lightVerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	// 只验证最基本的字段，跳过复杂验证
	
	// 验证区块号
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return ErrUnknownBlock
	}
	
	// 验证时间戳
	if header.Time <= parent.Time {
		return ErrTimeValidation
	}
	
	// 记录资源使用
	startTime := time.Now()
	defer func() {
		processingTime := time.Since(startTime)
		mc.processingTimeGauge.Update(int64(processingTime.Milliseconds()))
		
		// 记录处理时间
		stats := mc.resourceStats
		stats.ProcessingTimes = append(stats.ProcessingTimes, processingTime)
		if len(stats.ProcessingTimes) > 10 {
			stats.ProcessingTimes = stats.ProcessingTimes[1:]
		}
	}()
	
	log.Debug("执行轻量级区块头验证", "区块", header.Number)
	return nil
}

// VerifyHeaders 批量验证区块头
func (mc *MobileConsensus) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	results := make(chan error, len(headers))
	abort := make(chan struct{})
	
	go func() {
		for i, header := range headers {
			err := mc.VerifyHeader(chain, header, seals[i])
			
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	
	return abort, results
}

// VerifySeal 验证区块头的密封
func (mc *MobileConsensus) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	// 检查共识机制是否激活
	if !mc.active {
		return ErrMobileConsensusInactive
	}
	
	mc.confirmationMu.RLock()
	confirmations := mc.confirmations[header.Hash()]
	mc.confirmationMu.RUnlock()
	
	// 检查确认数量
	if len(confirmations) < mc.config.MinConfirmations {
		return ErrInsufficientConfirmations
	}
	
	// 验证通过
	return nil
}

// Prepare 准备区块头
func (mc *MobileConsensus) Prepare(chain consensus.ChainReader, header *types.Header) error {
	// 在区块头中设置额外数据
	
	// 资源自适应 - 根据设备状态调整区块生成
	if mc.adaptiveBlockInterval && mc.batteryAware {
		// 低电量情况下增加区块间隔以节省资源
		batteryLevel := mc.resourceStats.BatteryLevel
		if batteryLevel < LowBatteryThreshold && !mc.resourceStats.BatteryCharging {
			// 在额外数据中标记此区块是在低资源模式下生成的
			extraData := append(header.Extra, []byte("LowResourceMode")...)
			if len(extraData) <= MaxExtraDataSize {
				header.Extra = extraData
			}
		}
	}
	
	return nil
}

// Finalize 完成区块的状态处理
func (mc *MobileConsensus) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	// 处理区块最终状态，例如奖励验证者
	
	// 更新活跃验证者的区块密封计数
	mc.validatorMu.Lock()
	for addr, validator := range mc.validators {
		if validator.IsActive {
			if header.Coinbase == addr {
				validator.BlocksSealed++
				log.Info("验证者完成区块密封", "地址", addr.Hex(), "区块", header.Number.Uint64(), "总密封数", validator.BlocksSealed)
			}
		}
	}
	mc.validatorMu.Unlock()
	
	// 将区块标记为已密封
	mc.blockMu.Lock()
	mc.sealedBlocks[header.Hash()] = true
	mc.blockMu.Unlock()
}

// Seal 对区块进行密封
func (mc *MobileConsensus) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	// 移动共识不直接密封区块，而是收集确认
	log.Info("接收到区块密封请求", "区块", block.Number().Uint64(), "交易", len(block.Transactions()))
	return nil
}

// SealHash 返回用于签名的哈希
func (mc *MobileConsensus) SealHash(header *types.Header) common.Hash {
	return header.Hash()
}

// CalcDifficulty 计算区块难度
func (mc *MobileConsensus) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	// 移动共识使用固定难度
	return big.NewInt(1)
}

// APIs 返回由共识引擎提供的RPC API
func (mc *MobileConsensus) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{
		{
			Namespace: "mobile",
			Version:   "1.0",
			Service:   &MobileConsensusAPI{mc: mc},
			Public:    true,
		},
	}
}

// Close 关闭共识引擎
func (mc *MobileConsensus) Close() error {
	mc.active = false
	log.Info("移动共识机制已关闭")
	return nil
}

// MobileConsensusAPI 提供移动共识的RPC API
type MobileConsensusAPI struct {
	mc *MobileConsensus
}

// GetValidators 获取所有验证者信息
func (api *MobileConsensusAPI) GetValidators() map[string]*MobileValidator {
	api.mc.validatorMu.RLock()
	defer api.mc.validatorMu.RUnlock()
	
	result := make(map[string]*MobileValidator)
	for addr, validator := range api.mc.validators {
		result[addr.Hex()] = &MobileValidator{
			Address:      validator.Address,
			DeviceInfo:   validator.DeviceInfo,
			DeviceType:   validator.DeviceType,
			NetworkInfo:  validator.NetworkInfo,
			Status:       validator.Status,
			BatteryLevel: validator.BatteryLevel,
			IsActive:     validator.IsActive,
			LastSeen:     validator.LastSeen,
			BlocksSealed: validator.BlocksSealed,
			BlocksSigned: validator.BlocksSigned,
			Stake:        new(big.Int).Set(validator.Stake),
			NetworkSpeed: validator.NetworkSpeed,
			LastActive:   validator.LastActive,
			ConfirmCount: validator.ConfirmCount,
		}
	}
	
	return result
}

// GetActiveValidators 获取活跃验证者数量
func (api *MobileConsensusAPI) GetActiveValidators() int {
	api.mc.validatorMu.RLock()
	defer api.mc.validatorMu.RUnlock()
	
	count := 0
	for _, validator := range api.mc.validators {
		if validator.IsActive {
			count++
		}
	}
	
	return count
}

// GetConfirmationsForBlock 获取区块的确认信息
func (api *MobileConsensusAPI) GetConfirmationsForBlock(blockHash common.Hash) []*BlockConfirmation {
	return api.mc.GetConfirmations(blockHash)
}

// IsSufficientlyConfirmed 检查区块是否有足够的确认
func (api *MobileConsensusAPI) IsSufficientlyConfirmed(blockHash common.Hash) bool {
	return api.mc.IsSufficientlyConfirmed(blockHash)
}

// GetStatistics 获取移动共识统计信息
func (api *MobileConsensusAPI) GetStatistics() map[string]interface{} {
	api.mc.validatorMu.RLock()
	validatorCount := len(api.mc.validators)
	
	// 计算统计信息
	activeCount := 0
	totalBattery := 0
	totalBlocksSealed := uint64(0)
	totalBlocksSigned := uint64(0)
	
	for _, validator := range api.mc.validators {
		if validator.IsActive {
			activeCount++
			totalBattery += validator.BatteryLevel
		}
		totalBlocksSealed += validator.BlocksSealed
		totalBlocksSigned += validator.BlocksSigned
	}
	api.mc.validatorMu.RUnlock()
	
	avgBattery := 0
	if activeCount > 0 {
		avgBattery = totalBattery / activeCount
	}
	
	api.mc.confirmationMu.RLock()
	confirmationCount := len(api.mc.confirmations)
	api.mc.confirmationMu.RUnlock()
	
	return map[string]interface{}{
		"validatorCount":       validatorCount,
		"activeValidators":     activeCount,
		"confirmationCount":    confirmationCount,
		"averageBatteryLevel":  avgBattery,
		"totalBlocksSealed":    totalBlocksSealed,
		"totalBlocksSigned":    totalBlocksSigned,
		"minConfirmations":     api.mc.config.MinConfirmations,
		"maxValidators":        api.mc.config.MaxValidators,
		"minBatteryLevel":      api.mc.config.MinBatteryLevel,
		"consensusActive":      api.mc.active,
	}
}

// GetConfig 获取移动共识配置
func (api *MobileConsensusAPI) GetConfig() *MobileConsensusConfig {
	return &MobileConsensusConfig{
		MinConfirmations:     api.mc.config.MinConfirmations,
		MaxValidators:        api.mc.config.MaxValidators,
		MinBatteryLevel:      api.mc.config.MinBatteryLevel,
		HeartbeatInterval:    api.mc.config.HeartbeatInterval,
		BlockTimeout:         api.mc.config.BlockTimeout,
		EnableSharding:       api.mc.config.EnableSharding,
		ShardCount:           api.mc.config.ShardCount,
		ResourceCheckEnabled: api.mc.config.ResourceCheckEnabled,
		ValidatorTimeout:     api.mc.config.ValidatorTimeout,
		BatteryCheckInterval: api.mc.config.BatteryCheckInterval,
	}
}

// 支持增量同步
func (mc *MobileConsensus) SupportIncrementalSync(targetBlockHash common.Hash) error {
	// 记录同步起始点
	mc.lastSyncPoint = targetBlockHash
	
	// 准备恢复数据
	resumeData := struct {
		LastSyncHash common.Hash
		Timestamp    time.Time
	}{
		LastSyncHash: targetBlockHash,
		Timestamp:    time.Now(),
	}
	
	// 序列化恢复数据
	var err error
	mc.syncResumeData, err = rlp.EncodeToBytes(resumeData)
	if err != nil {
		return err
	}
	
	log.Info("启用增量同步", "目标区块", targetBlockHash.Hex())
	return nil
}

// 从中断点恢复同步
func (mc *MobileConsensus) ResumeSyncFromCheckpoint() error {
	if len(mc.syncResumeData) == 0 {
		return errors.New("没有可用的恢复数据")
	}
	
	// 解码恢复数据
	var resumeInfo struct {
		LastSyncHash common.Hash
		Timestamp    time.Time
	}
	
	if err := rlp.DecodeBytes(mc.syncResumeData, &resumeInfo); err != nil {
		return err
	}
	
	// 检查恢复数据是否过期
	if time.Since(resumeInfo.Timestamp) > 24*time.Hour {
		return errors.New("恢复数据已过期")
	}
	
	log.Info("从检查点恢复同步", 
		"区块", resumeInfo.LastSyncHash.Hex(),
		"时间", resumeInfo.Timestamp)
	
	// 实际恢复逻辑将在同步过程中实现
	return nil
}

// 创建同步检查点
func (mc *MobileConsensus) CreateSyncCheckpoint(blockHash common.Hash) error {
	// 更新最后同步点
	mc.lastSyncPoint = blockHash
	
	// 创建新的恢复数据
	resumeData := struct {
		LastSyncHash common.Hash
		Timestamp    time.Time
	}{
		LastSyncHash: blockHash,
		Timestamp:    time.Now(),
	}
	
	// 序列化并存储
	var err error
	mc.syncResumeData, err = rlp.EncodeToBytes(resumeData)
	if err != nil {
		return err
	}
	
	log.Debug("创建同步检查点", "区块", blockHash.Hex())
	return nil
} 