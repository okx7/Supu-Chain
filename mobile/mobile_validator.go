// mobile_validator.go - 实现移动设备可信度评分和验证功能

package mobile

import (
	"math"
	"sync"
	"time"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

// ValidatorRank 验证者等级
type ValidatorRank int

// 验证者等级常量
const (
	RankUnknown  ValidatorRank = iota // 未知等级
	RankBronze                       // 青铜等级
	RankSilver                       // 白银等级
	RankGold                         // 黄金等级
	RankPlatinum                     // 铂金等级
	RankDiamond                      // 钻石等级
)

// 评分阈值常量
const (
	ScoreThresholdBronze    = 30.0  // 青铜等级阈值
	ScoreThresholdSilver    = 50.0  // 白银等级阈值
	ScoreThresholdGold      = 70.0  // 黄金等级阈值
	ScoreThresholdPlatinum  = 85.0  // 铂金等级阈值
	ScoreThresholdDiamond   = 95.0  // 钻石等级阈值
)

// 评分权重常量
const (
	WeightSecurity     = 0.35  // 安全评分权重
	WeightNetwork      = 0.25  // 网络评分权重
	WeightPerformance  = 0.25  // 性能评分权重
	WeightConsistency  = 0.15  // 一致性评分权重
)

// MobileValidator 移动验证者结构体
type MobileValidator struct {
	Address        common.Address     // 验证者地址
	LastActive     time.Time          // 最后活跃时间
	JoinTime       time.Time          // 加入时间
	SecurityScore  float64            // 安全评分(0-100)
	NetworkScore   float64            // 网络质量评分(0-100)
	PerformanceScore float64          // 性能评分(0-100)
	ConsistencyScore float64          // 一致性评分(0-100)
	TotalScore     float64            // 总体评分(0-100)
	Rank           ValidatorRank      // 验证者等级
	
	// 安全指标
	TEEEnabled     bool               // 可信执行环境是否启用
	BiometricAuth  bool               // 生物识别认证是否启用
	SecureEnclave  bool               // 安全飞地是否可用
	DeviceIntegrity float64           // 设备完整性(0-100)
	MalwareScore   float64            // 恶意软件检测评分(0-100)
	
	// 网络指标
	ConnectionStability float64       // 连接稳定性(0-100)
	AverageLatency     int            // 平均延迟(ms)
	PacketLossRate     float64        // 丢包率(%)
	UploadBandwidth    int            // 上传带宽(KB/s)
	DownloadBandwidth  int            // 下载带宽(KB/s)
	
	// 性能指标
	CPUBenchmark     float64          // CPU基准测试(0-100)
	MemoryAvailable  int              // 可用内存(MB)
	BatteryHealth    float64          // 电池健康度(0-100)
	AvgBlockTime     float64          // 平均区块处理时间(ms)
	
	// 一致性指标
	UptimePercentage float64          // 在线时间百分比(%)
	ValidBlocks      int              // 有效区块数
	InvalidBlocks    int              // 无效区块数
	MissedBlocks     int              // 漏块数
	TimeDeviation    float64          // 时间偏差(ms)
	
	// 统计数据
	TotalValidations int               // 总验证次数
	SuccessfulValidations int          // 成功验证次数
	FailedValidations int              // 失败验证次数
	LastScoreUpdate  time.Time         // 最后评分更新时间
	
	// 内部控制
	mu              sync.RWMutex       // 互斥锁
}

// NewMobileValidator 创建新的移动验证者
func NewMobileValidator(address common.Address) *MobileValidator {
	now := time.Now()
	return &MobileValidator{
		Address:        address,
		LastActive:     now,
		JoinTime:       now,
		SecurityScore:  50.0, // 初始评分
		NetworkScore:   50.0, // 初始评分
		PerformanceScore: 50.0, // 初始评分
		ConsistencyScore: 50.0, // 初始评分
		TotalScore:     50.0, // 初始评分
		Rank:           RankBronze, // 初始等级
		LastScoreUpdate: now,
	}
}

// UpdateSecurityScore 更新安全评分
func (mv *MobileValidator) UpdateSecurityScore(
	teeEnabled bool, 
	biometricAuth bool, 
	secureEnclave bool, 
	deviceIntegrity float64,
	malwareScore float64,
) {
	mv.mu.Lock()
	defer mv.mu.Unlock()
	
	// 更新安全指标
	mv.TEEEnabled = teeEnabled
	mv.BiometricAuth = biometricAuth
	mv.SecureEnclave = secureEnclave
	mv.DeviceIntegrity = deviceIntegrity
	mv.MalwareScore = malwareScore
	
	// 计算安全评分
	var score float64 = 0
	
	// TEE 加分
	if mv.TEEEnabled {
		score += 25
	}
	
	// 生物识别认证加分
	if mv.BiometricAuth {
		score += 20
	}
	
	// 安全飞地加分
	if mv.SecureEnclave {
		score += 15
	}
	
	// 设备完整性得分
	score += mv.DeviceIntegrity * 0.2
	
	// 恶意软件检测得分
	score += mv.MalwareScore * 0.2
	
	// 限制评分范围
	mv.SecurityScore = math.Max(0, math.Min(100, score))
	
	// 更新总评分
	mv.updateTotalScore()
}

// UpdateNetworkScore 更新网络评分
func (mv *MobileValidator) UpdateNetworkScore(
	connectionStability float64,
	averageLatency int,
	packetLossRate float64,
	uploadBandwidth int,
	downloadBandwidth int,
) {
	mv.mu.Lock()
	defer mv.mu.Unlock()
	
	// 更新网络指标
	mv.ConnectionStability = connectionStability
	mv.AverageLatency = averageLatency
	mv.PacketLossRate = packetLossRate
	mv.UploadBandwidth = uploadBandwidth
	mv.DownloadBandwidth = downloadBandwidth
	
	// 计算网络评分
	var score float64 = 0
	
	// 连接稳定性得分(0-40分)
	score += mv.ConnectionStability * 0.4
	
	// 延迟得分(0-25分)，延迟越低越好
	latencyScore := 0.0
	if mv.AverageLatency <= 50 {
		latencyScore = 25.0 // 极佳延迟
	} else if mv.AverageLatency <= 100 {
		latencyScore = 20.0 // 优秀延迟
	} else if mv.AverageLatency <= 200 {
		latencyScore = 15.0 // 良好延迟
	} else if mv.AverageLatency <= 300 {
		latencyScore = 10.0 // 一般延迟
	} else if mv.AverageLatency <= 500 {
		latencyScore = 5.0 // 较差延迟
	}
	score += latencyScore
	
	// 丢包率得分(0-15分)，丢包率越低越好
	packetLossScore := 15.0 * (1.0 - (mv.PacketLossRate / 100.0))
	score += packetLossScore
	
	// 带宽得分(0-20分)
	bandwidthScore := 0.0
	totalBandwidth := mv.UploadBandwidth + mv.DownloadBandwidth
	if totalBandwidth >= 5000 { // 5MB/s以上
		bandwidthScore = 20.0
	} else if totalBandwidth >= 2000 { // 2MB/s以上
		bandwidthScore = 15.0
	} else if totalBandwidth >= 1000 { // 1MB/s以上
		bandwidthScore = 10.0
	} else if totalBandwidth >= 500 { // 500KB/s以上
		bandwidthScore = 5.0
	}
	score += bandwidthScore
	
	// 限制评分范围
	mv.NetworkScore = math.Max(0, math.Min(100, score))
	
	// 更新总评分
	mv.updateTotalScore()
}

// UpdatePerformanceScore 更新性能评分
func (mv *MobileValidator) UpdatePerformanceScore(
	cpuBenchmark float64,
	memoryAvailable int,
	batteryHealth float64,
	avgBlockTime float64,
) {
	mv.mu.Lock()
	defer mv.mu.Unlock()
	
	// 更新性能指标
	mv.CPUBenchmark = cpuBenchmark
	mv.MemoryAvailable = memoryAvailable
	mv.BatteryHealth = batteryHealth
	mv.AvgBlockTime = avgBlockTime
	
	// 计算性能评分
	var score float64 = 0
	
	// CPU基准测试得分(0-35分)
	score += mv.CPUBenchmark * 0.35
	
	// 内存得分(0-25分)
	memoryScore := 0.0
	if mv.MemoryAvailable >= 2048 { // 2GB以上
		memoryScore = 25.0
	} else if mv.MemoryAvailable >= 1024 { // 1GB以上
		memoryScore = 20.0
	} else if mv.MemoryAvailable >= 512 { // 512MB以上
		memoryScore = 15.0
	} else if mv.MemoryAvailable >= 256 { // 256MB以上
		memoryScore = 10.0
	} else {
		memoryScore = 5.0
	}
	score += memoryScore
	
	// 电池健康度得分(0-20分)
	score += mv.BatteryHealth * 0.2
	
	// 区块处理时间得分(0-20分)，处理时间越短越好
	blockTimeScore := 0.0
	if mv.AvgBlockTime <= 50 { // 50ms以下
		blockTimeScore = 20.0
	} else if mv.AvgBlockTime <= 100 { // 100ms以下
		blockTimeScore = 15.0
	} else if mv.AvgBlockTime <= 200 { // 200ms以下
		blockTimeScore = 10.0
	} else if mv.AvgBlockTime <= 500 { // 500ms以下
		blockTimeScore = 5.0
	}
	score += blockTimeScore
	
	// 限制评分范围
	mv.PerformanceScore = math.Max(0, math.Min(100, score))
	
	// 更新总评分
	mv.updateTotalScore()
}

// UpdateConsistencyScore 更新一致性评分
func (mv *MobileValidator) UpdateConsistencyScore(
	uptimePercentage float64,
	validBlocks int,
	invalidBlocks int,
	missedBlocks int,
	timeDeviation float64,
) {
	mv.mu.Lock()
	defer mv.mu.Unlock()
	
	// 更新一致性指标
	mv.UptimePercentage = uptimePercentage
	mv.ValidBlocks = validBlocks
	mv.InvalidBlocks = invalidBlocks
	mv.MissedBlocks = missedBlocks
	mv.TimeDeviation = timeDeviation
	
	// 计算一致性评分
	var score float64 = 0
	
	// 在线时间得分(0-30分)
	score += mv.UptimePercentage * 0.3
	
	// 有效区块率得分(0-35分)
	totalBlocks := mv.ValidBlocks + mv.InvalidBlocks + mv.MissedBlocks
	if totalBlocks > 0 {
		validRate := float64(mv.ValidBlocks) / float64(totalBlocks)
		score += validRate * 35
	}
	
	// 时间偏差得分(0-35分)，偏差越小越好
	timeDeviationScore := 0.0
	if mv.TimeDeviation <= 10 { // 10ms以下
		timeDeviationScore = 35.0
	} else if mv.TimeDeviation <= 50 { // 50ms以下
		timeDeviationScore = 25.0
	} else if mv.TimeDeviation <= 100 { // 100ms以下
		timeDeviationScore = 15.0
	} else if mv.TimeDeviation <= 200 { // 200ms以下
		timeDeviationScore = 5.0
	}
	score += timeDeviationScore
	
	// 限制评分范围
	mv.ConsistencyScore = math.Max(0, math.Min(100, score))
	
	// 更新总评分
	mv.updateTotalScore()
}

// updateTotalScore 更新总评分
func (mv *MobileValidator) updateTotalScore() {
	// 计算加权总分
	totalScore := mv.SecurityScore * WeightSecurity +
		mv.NetworkScore * WeightNetwork +
		mv.PerformanceScore * WeightPerformance +
		mv.ConsistencyScore * WeightConsistency
	
	// 更新总分
	mv.TotalScore = math.Round(totalScore*100) / 100 // 保留两位小数
	
	// 更新等级
	mv.updateRank()
	
	// 更新最后评分时间
	mv.LastScoreUpdate = time.Now()
	
	log.Debug("更新验证者评分", 
		"地址", mv.Address.Hex(),
		"安全", mv.SecurityScore,
		"网络", mv.NetworkScore,
		"性能", mv.PerformanceScore,
		"一致性", mv.ConsistencyScore,
		"总分", mv.TotalScore,
		"等级", mv.Rank)
}

// updateRank 更新验证者等级
func (mv *MobileValidator) updateRank() {
	// 根据总分确定等级
	switch {
	case mv.TotalScore >= ScoreThresholdDiamond:
		mv.Rank = RankDiamond
	case mv.TotalScore >= ScoreThresholdPlatinum:
		mv.Rank = RankPlatinum
	case mv.TotalScore >= ScoreThresholdGold:
		mv.Rank = RankGold
	case mv.TotalScore >= ScoreThresholdSilver:
		mv.Rank = RankSilver
	case mv.TotalScore >= ScoreThresholdBronze:
		mv.Rank = RankBronze
	default:
		mv.Rank = RankUnknown
	}
}

// GetScoreDetails 获取评分详情
func (mv *MobileValidator) GetScoreDetails() map[string]interface{} {
	mv.mu.RLock()
	defer mv.mu.RUnlock()
	
	return map[string]interface{}{
		"address": mv.Address.Hex(),
		"total_score": mv.TotalScore,
		"rank": mv.Rank,
		"security_score": mv.SecurityScore,
		"network_score": mv.NetworkScore,
		"performance_score": mv.PerformanceScore,
		"consistency_score": mv.ConsistencyScore,
		"join_time": mv.JoinTime,
		"last_active": mv.LastActive,
		"last_update": mv.LastScoreUpdate,
		"security_details": map[string]interface{}{
			"tee_enabled": mv.TEEEnabled,
			"biometric_auth": mv.BiometricAuth,
			"secure_enclave": mv.SecureEnclave,
			"device_integrity": mv.DeviceIntegrity,
			"malware_score": mv.MalwareScore,
		},
		"network_details": map[string]interface{}{
			"connection_stability": mv.ConnectionStability,
			"average_latency": mv.AverageLatency,
			"packet_loss_rate": mv.PacketLossRate,
			"upload_bandwidth": mv.UploadBandwidth,
			"download_bandwidth": mv.DownloadBandwidth,
		},
		"performance_details": map[string]interface{}{
			"cpu_benchmark": mv.CPUBenchmark,
			"memory_available": mv.MemoryAvailable,
			"battery_health": mv.BatteryHealth,
			"avg_block_time": mv.AvgBlockTime,
		},
		"consistency_details": map[string]interface{}{
			"uptime_percentage": mv.UptimePercentage,
			"valid_blocks": mv.ValidBlocks,
			"invalid_blocks": mv.InvalidBlocks,
			"missed_blocks": mv.MissedBlocks,
			"time_deviation": mv.TimeDeviation,
		},
		"validations": map[string]interface{}{
			"total": mv.TotalValidations,
			"successful": mv.SuccessfulValidations,
			"failed": mv.FailedValidations,
			"success_rate": getSuccessRate(mv.SuccessfulValidations, mv.TotalValidations),
		},
	}
}

// RecordValidation 记录验证结果
func (mv *MobileValidator) RecordValidation(success bool) {
	mv.mu.Lock()
	defer mv.mu.Unlock()
	
	// 更新总验证次数
	mv.TotalValidations++
	
	// 更新成功/失败次数
	if success {
		mv.SuccessfulValidations++
	} else {
		mv.FailedValidations++
	}
	
	// 更新最后活跃时间
	mv.LastActive = time.Now()
}

// IsActive 检查验证者是否活跃
func (mv *MobileValidator) IsActive() bool {
	mv.mu.RLock()
	defer mv.mu.RUnlock()
	
	// 检查最后活跃时间是否在24小时内
	return time.Since(mv.LastActive) <= 24*time.Hour
}

// GetSuccessRate 获取成功率
func getSuccessRate(successful, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(successful) / float64(total) * 100
}

// RankToString 将等级转换为字符串
func RankToString(rank ValidatorRank) string {
	switch rank {
	case RankDiamond:
		return "钻石"
	case RankPlatinum:
		return "铂金"
	case RankGold:
		return "黄金"
	case RankSilver:
		return "白银"
	case RankBronze:
		return "青铜"
	default:
		return "未知"
	}
} 