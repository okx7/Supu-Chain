package types

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// MobileValidator 定义了移动端验证者的结构和功能
type MobileValidator struct {
	Address     common.Address // 验证者地址
	PrivateKey  *ecdsa.PrivateKey // 私钥（加密存储）
	Stake       *big.Int       // 质押的代币数量
	Reputation  uint64         // 验证者声誉值
	LastActive  time.Time      // 上次活跃时间
	
	// 资源控制相关
	MaxStorageGB    uint64 // 最大存储空间（GB）
	MaxBandwidthMB  uint64 // 最大带宽使用（MB/小时）
	BatteryAware    bool   // 是否启用电量感知验证

	// 移动端特有的中断恢复机制
	recoveryMutex sync.Mutex
	pendingTasks  []ValidatorTask
	
	// 新增移动设备优化属性
	DeviceInfo         DeviceInfo    // 设备详细信息
	BatteryOptimization bool          // 是否启用电池优化
	NetworkOptimization bool          // 是否启用网络优化
	StorageOptimization bool          // 是否启用存储优化
	ResourceProfile     string        // 资源配置文件(high/medium/low)
	SyncMode            string        // 同步模式(full/light/ultralightl)
	
	// 性能监控
	performanceLogs []PerformanceLog // 性能日志记录
	resourceStats   ResourceStats    // 资源使用统计
	
	// 自适应调整参数
	dynamicBatchSize    int           // 动态批处理大小
	processingThreshold time.Duration // 处理时间阈值
	syncInterval        time.Duration // 同步间隔
	
	// 中断恢复扩展
	lastCheckpointBlock uint64       // 最后检查点区块
	checkpointHash      common.Hash  // 检查点哈希
	resumeData          []byte       // 恢复数据
}

// DeviceInfo 存储详细的设备信息
type DeviceInfo struct {
	Model             string    // 设备型号
	OS                string    // 操作系统
	OSVersion         string    // 操作系统版本
	CPUCores          int       // CPU核心数
	RAMTotal          uint64    // 总内存
	StorageTotal      uint64    // 总存储
	BatteryCapacity   int       // 电池容量(mAh)
	ScreenSize        float64   // 屏幕尺寸(英寸)
	NetworkInterfaces []string  // 网络接口
	SensorInfo        []string  // 传感器信息
}

// ResourceStats 记录资源使用统计
type ResourceStats struct {
	CpuAverage       float64       // CPU平均使用率
	MemoryAverage    uint64        // 内存平均使用
	BatteryDrain     float64       // 电池耗电率(%/小时)
	NetworkUsage     uint64        // 网络使用量(字节)
	StorageGrowth    uint64        // 存储增长(字节/天)
	ProcessingTimes  []time.Duration // 处理时间记录
	EnergyEfficiency float64       // 能源效率评分
}

// PerformanceLog 单次操作的性能日志
type PerformanceLog struct {
	Operation       string        // 操作类型
	BlockNumber     uint64        // 区块号
	StartTime       time.Time     // 开始时间
	Duration        time.Duration // 持续时间
	CpuUsage        float64       // CPU使用率
	MemoryUsage     uint64        // 内存使用量
	BatteryImpact   float64       // 电池影响
	NetworkTransfer uint64        // 网络传输量
}

// ValidatorTask 表示验证者的任务
type ValidatorTask struct {
	BlockHash    common.Hash
	BlockNumber  uint64
	TaskType     string // "verify", "propose", "finalize"
	CreatedAt    time.Time
	Priority     int    // 任务优先级
	ResourceReq  ResourceRequirement // 资源需求
	Dependencies []common.Hash       // 依赖的区块哈希
}

// ResourceRequirement 定义任务的资源需求
type ResourceRequirement struct {
	MinBattery      int           // 最低电池电量要求
	MaxProcessTime  time.Duration // 最大处理时间
	MinNetworkSpeed uint64        // 最低网络速度
	MinMemory       uint64        // 最低内存要求
}

// NewMobileValidator 创建一个新的移动端验证者
func NewMobileValidator(privateKeyHex string) (*MobileValidator, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, errors.New("无效的私钥格式")
	}
	
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("无法获取公钥")
	}
	
	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	
	// 获取设备信息
	deviceInfo := getDeviceInfo()
	
	// 根据设备性能自动选择配置文件
	resourceProfile := determineResourceProfile(deviceInfo)
	
	validator := &MobileValidator{
		Address:            address,
		PrivateKey:         privateKey,
		Stake:              new(big.Int),
		Reputation:         100, // 初始声誉值
		LastActive:         time.Now(),
		MaxStorageGB:       5,   // 默认限制5GB存储
		MaxBandwidthMB:     100, // 默认每小时100MB带宽
		BatteryAware:       true,
		pendingTasks:       make([]ValidatorTask, 0),
		
		// 新增移动优化参数
		DeviceInfo:          deviceInfo,
		BatteryOptimization: true,
		NetworkOptimization: true,
		StorageOptimization: true,
		ResourceProfile:     resourceProfile,
		SyncMode:            determineSyncMode(resourceProfile),
		
		// 初始化性能监控
		performanceLogs:     make([]PerformanceLog, 0, 100),
		resourceStats:       ResourceStats{},
		
		// 初始化自适应参数
		dynamicBatchSize:    determineBatchSize(resourceProfile),
		processingThreshold: determineProcessingThreshold(resourceProfile),
		syncInterval:        determineSyncInterval(resourceProfile),
	}
	
	// 初始化资源统计
	validator.initResourceStats()
	
	// 启动资源监控
	go validator.monitorResources()
	
	return validator, nil
}

// 根据设备信息获取设备配置文件
func determineResourceProfile(deviceInfo DeviceInfo) string {
	// 高性能设备
	if deviceInfo.CPUCores >= 6 && deviceInfo.RAMTotal >= 6*1024*1024*1024 {
		return "high"
	}
	// 中等性能设备
	if deviceInfo.CPUCores >= 4 && deviceInfo.RAMTotal >= 4*1024*1024*1024 {
		return "medium"
	}
	// 低性能设备
	return "low"
}

// 根据资源配置文件确定同步模式
func determineSyncMode(profile string) string {
	switch profile {
	case "high":
		return "full"
	case "medium":
		return "light"
	default:
		return "ultralight"
	}
}

// 确定批处理大小
func determineBatchSize(profile string) int {
	switch profile {
	case "high":
		return 500
	case "medium":
		return 200
	default:
		return 50
	}
}

// 确定处理时间阈值
func determineProcessingThreshold(profile string) time.Duration {
	switch profile {
	case "high":
		return 5 * time.Second
	case "medium":
		return 10 * time.Second
	default:
		return 20 * time.Second
	}
}

// 确定同步间隔
func determineSyncInterval(profile string) time.Duration {
	switch profile {
	case "high":
		return 10 * time.Second
	case "medium":
		return 20 * time.Second
	default:
		return 60 * time.Second
	}
}

// 初始化资源统计
func (mv *MobileValidator) initResourceStats() {
	mv.resourceStats = ResourceStats{
		CpuAverage:      0,
		MemoryAverage:   0,
		BatteryDrain:     0,
		NetworkUsage:    0,
		StorageGrowth:    0,
		ProcessingTimes:  make([]time.Duration, 0, 100),
		EnergyEfficiency: 100, // 初始能效评分
	}
}

// 监控资源使用
func (mv *MobileValidator) monitorResources() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	var lastBatteryLevel int = getBatteryLevel()
	var lastStorageUsed uint64 = getStorageUsed()
	var startTime = time.Now()
	
	for range ticker.C {
		// 获取当前资源状态
		currentBattery := getBatteryLevel()
		currentStorageUsed := getStorageUsed()
		elapsedHours := time.Since(startTime).Hours()
		
		// 计算电池消耗率(%/小时)
		if elapsedHours > 0 {
			batteryDrain := float64(lastBatteryLevel-currentBattery) / elapsedHours
			mv.resourceStats.BatteryDrain = batteryDrain
		}
		
		// 计算存储增长率(字节/天)
		if elapsedHours > 0 {
			storageGrowthPerHour := int64(currentStorageUsed - lastStorageUsed) / int64(elapsedHours)
			mv.resourceStats.StorageGrowth = uint64(storageGrowthPerHour * 24) // 转换为每天
		}
		
		// 更新基准值
		lastBatteryLevel = currentBattery
		lastStorageUsed = currentStorageUsed
		startTime = time.Now()
		
		// 根据资源状态调整参数
		mv.adaptToResourceState()
	}
}

// 根据资源状态自适应调整
func (mv *MobileValidator) adaptToResourceState() {
	batteryLevel := getBatteryLevel()
	networkType := getNetworkType()
	
	// 低电量模式
	if batteryLevel < 20 {
		mv.dynamicBatchSize = mv.dynamicBatchSize / 2
		mv.syncInterval = mv.syncInterval * 2
		mv.SyncMode = "ultralight"
	} else if batteryLevel > 50 {
		// 恢复正常模式
		mv.dynamicBatchSize = determineBatchSize(mv.ResourceProfile)
		mv.syncInterval = determineSyncInterval(mv.ResourceProfile)
		mv.SyncMode = determineSyncMode(mv.ResourceProfile)
	}
	
	// 根据网络类型调整
	if networkType == "cellular" {
		mv.NetworkOptimization = true
		mv.dynamicBatchSize = mv.dynamicBatchSize / 2
	} else if networkType == "wifi" {
		mv.NetworkOptimization = false
		// 恢复正常批处理大小
		mv.dynamicBatchSize = determineBatchSize(mv.ResourceProfile)
	}
}

// 模拟获取电池电量
func getBatteryLevel() int {
	// 实际实现应该调用系统API
	return 50 // 假设电量为50%
}

// 模拟获取已使用存储空间
func getStorageUsed() uint64 {
	// 实际实现应该调用系统API
	return 1024 * 1024 * 1024 // 1GB
}

// 模拟获取网络类型
func getNetworkType() string {
	// 实际实现应该调用系统API
	return "wifi"
}

// 获取设备信息
func getDeviceInfo() DeviceInfo {
	// 实际实现应该调用系统API获取真实信息
	return DeviceInfo{
		Model:           "模拟设备",
		OS:              "Android",
		OSVersion:       "12.0",
		CPUCores:        4,
		RAMTotal:        4 * 1024 * 1024 * 1024, // 4GB
		StorageTotal:    64 * 1024 * 1024 * 1024, // 64GB
		BatteryCapacity: 4000,
		ScreenSize:      6.1,
		NetworkInterfaces: []string{"wifi", "cellular"},
		SensorInfo:      []string{"accelerometer", "gyroscope"},
	}
}

// VerifyBlock 实现轻量级区块验证
func (mv *MobileValidator) VerifyBlock(blockHash common.Hash, blockNumber uint64) (bool, error) {
	// 记录性能数据
	startTime := time.Now()
	startBattery := getBatteryLevel()
	startCpu := getCpuUsage()
	startMemory := getMemoryUsage()
	startNetwork := getNetworkUsage()
	
	// 资源感知验证 - 检查电池电量
	if mv.BatteryAware && getBatteryLevel() < 20 && !isBatteryCharging() {
		// 将任务加入待处理队列并创建检查点
		task := ValidatorTask{
			BlockHash:   blockHash,
			BlockNumber: blockNumber,
			TaskType:    "verify",
			CreatedAt:   time.Now(),
			Priority:    1,
			ResourceReq: ResourceRequirement{
				MinBattery: 20,
				MaxProcessTime: 5 * time.Second,
			},
		}
		
		// 创建恢复数据
		resumePoint := struct {
			BlockHash   common.Hash
			BlockNumber uint64
			TaskType    string
			Timestamp   time.Time
		}{
			BlockHash:   blockHash,
			BlockNumber: blockNumber,
			TaskType:    "verify",
			Timestamp:   time.Now(),
		}
		
		resumeData, err := rlp.EncodeToBytes(resumePoint)
		if err == nil {
			mv.resumeData = resumeData
			mv.lastCheckpointBlock = blockNumber
			mv.checkpointHash = blockHash
		}
		
		mv.addPendingTask(task)
		return false, errors.New("电量不足，任务已加入待处理队列")
	}
	
	// 资源感知验证 - 检查网络状态
	if mv.NetworkOptimization && getNetworkType() == "cellular" && getNetworkQuality() < 50 {
		// 在弱网环境下实施轻量化验证
		isValid, err := mv.lightVerifyBlock(blockHash, blockNumber)
		
		// 记录性能数据
		mv.recordPerformanceLog("light_verify", blockNumber, startTime, startBattery, startCpu, startMemory, startNetwork)
		
		return isValid, err
	}
	
	// 标准验证逻辑
	isValid, err := mv.standardVerifyBlock(blockHash, blockNumber)
	
	// 记录性能数据
	mv.recordPerformanceLog("standard_verify", blockNumber, startTime, startBattery, startCpu, startMemory, startNetwork)
	
	// 更新最后活跃时间
	mv.LastActive = time.Now()
	
	return isValid, err
}

// 轻量级区块验证
func (mv *MobileValidator) lightVerifyBlock(blockHash common.Hash, blockNumber uint64) (bool, error) {
	// 轻量级验证实现 - 只验证区块头和部分交易
	// 在实际实现中，应该是对完整验证的优化版本
	
	// 模拟轻量级验证
	time.Sleep(100 * time.Millisecond)
	
	// 更新验证统计
	return true, nil
}

// 标准区块验证
func (mv *MobileValidator) standardVerifyBlock(blockHash common.Hash, blockNumber uint64) (bool, error) {
	// 完整验证实现
	// 在实际实现中，这里会有完整的验证逻辑
	
	// 模拟完整验证
	time.Sleep(300 * time.Millisecond)
	
	// 更新验证统计
	return true, nil
}

// 记录性能日志
func (mv *MobileValidator) recordPerformanceLog(operation string, blockNumber uint64, 
	startTime time.Time, startBattery int, startCpu float64, startMemory, startNetwork uint64) {
	
	duration := time.Since(startTime)
	batteryDrain := float64(startBattery - getBatteryLevel())
	cpuUsage := (getCpuUsage() + startCpu) / 2
	memoryUsage := getMemoryUsage()
	networkTransfer := getNetworkUsage() - startNetwork
	
	log := PerformanceLog{
		Operation:       operation,
		BlockNumber:     blockNumber,
		StartTime:       startTime,
		Duration:        duration,
		CpuUsage:        cpuUsage,
		MemoryUsage:     memoryUsage,
		BatteryImpact:   batteryDrain,
		NetworkTransfer: networkTransfer,
	}
	
	// 添加到性能日志
	mv.performanceLogs = append(mv.performanceLogs, log)
	if len(mv.performanceLogs) > 100 {
		// 只保留最近100条记录
		mv.performanceLogs = mv.performanceLogs[1:]
	}
	
	// 更新统计数据
	mv.updateResourceStats(log)
}

// 更新资源统计
func (mv *MobileValidator) updateResourceStats(log PerformanceLog) {
	stats := &mv.resourceStats
	
	// 更新处理时间
	stats.ProcessingTimes = append(stats.ProcessingTimes, log.Duration)
	if len(stats.ProcessingTimes) > 50 {
		stats.ProcessingTimes = stats.ProcessingTimes[1:]
	}
	
	// 计算平均值
	var totalCpu float64
	var totalMemory uint64
	var totalTime time.Duration
	
	for _, l := range mv.performanceLogs {
		totalCpu += l.CpuUsage
		totalMemory += l.MemoryUsage
		totalTime += l.Duration
	}
	
	logCount := float64(len(mv.performanceLogs))
	if logCount > 0 {
		stats.CpuAverage = totalCpu / logCount
		stats.MemoryAverage = totalMemory / uint64(logCount)
	}
	
	// 计算能效评分
	// 能效评分基于处理速度、资源消耗和电池影响的综合指标
	avgTime := totalTime.Seconds() / logCount
	stats.EnergyEfficiency = 100 / (1 + (stats.CpuAverage/100 + float64(stats.MemoryAverage)/(1024*1024*1024) + stats.BatteryDrain) * avgTime / 10)
}

// 获取CPU使用率模拟函数
func getCpuUsage() float64 {
	return 20.0 // 模拟20%的CPU使用率
}

// 获取内存使用模拟函数
func getMemoryUsage() uint64 {
	return 300 * 1024 * 1024 // 模拟300MB内存使用
}

// 获取网络使用模拟函数
func getNetworkUsage() uint64 {
	return 1024 * 1024 // 模拟1MB网络使用
}

// 获取网络质量模拟函数
func getNetworkQuality() int {
	return 80 // 模拟80%的网络质量
}

// 电池是否充电模拟函数
func isBatteryCharging() bool {
	return false // 模拟未充电状态
}

// 添加待处理任务
func (mv *MobileValidator) addPendingTask(task ValidatorTask) {
	mv.recoveryMutex.Lock()
	defer mv.recoveryMutex.Unlock()
	
	// 如果已存在相同任务，则更新而不是添加
	for i, existingTask := range mv.pendingTasks {
		if existingTask.BlockHash == task.BlockHash && existingTask.TaskType == task.TaskType {
			// 更新现有任务
			mv.pendingTasks[i] = task
			return
		}
	}
	
	// 按优先级插入任务
	inserted := false
	for i, existingTask := range mv.pendingTasks {
		if task.Priority > existingTask.Priority {
			// 在此位置插入
			mv.pendingTasks = append(mv.pendingTasks[:i], append([]ValidatorTask{task}, mv.pendingTasks[i:]...)...)
			inserted = true
			break
		}
	}
	
	// 如果没有插入，则追加到末尾
	if !inserted {
		mv.pendingTasks = append(mv.pendingTasks, task)
	}
}

// ProcessPendingTasks 处理之前由于资源限制未能完成的任务
func (mv *MobileValidator) ProcessPendingTasks() error {
	// 检查资源状态是否允许处理任务
	if mv.BatteryAware && getBatteryLevel() < 20 && !isBatteryCharging() {
		return errors.New("电量仍然不足，无法处理待处理任务")
	}

	mv.recoveryMutex.Lock()
	
	// 获取任务并清空队列
	tasks := make([]ValidatorTask, len(mv.pendingTasks))
	copy(tasks, mv.pendingTasks)
	mv.pendingTasks = make([]ValidatorTask, 0)
	
	mv.recoveryMutex.Unlock()
	
	if len(tasks) == 0 {
		return nil
	}
	
	// 记录开始处理批次任务
	log.Info("开始处理待处理任务", "数量", len(tasks))
	
	var successCount, failCount int
	
	for _, task := range tasks {
		// 根据任务类型执行相应操作
		startTime := time.Now()
		var err error
		
		switch task.TaskType {
		case "verify":
			_, err = mv.VerifyBlock(task.BlockHash, task.BlockNumber)
		case "propose":
			err = mv.proposeBlock(task.BlockHash, task.BlockNumber)
		case "finalize":
			err = mv.finalizeBlock(task.BlockHash, task.BlockNumber)
		}
		
		// 检查处理结果
		if err == nil {
			successCount++
			log.Debug("成功处理待处理任务", 
				"类型", task.TaskType, 
				"区块", task.BlockNumber,
				"耗时", time.Since(startTime))
		} else {
			failCount++
			// 如果失败，重新加入队列，但降低优先级
			if task.Priority > 0 {
				task.Priority--
			}
			// 任务失败过多次则放弃
			if task.Priority > 0 {
				log.Debug("任务处理失败，重新加入队列", 
					"类型", task.TaskType, 
					"区块", task.BlockNumber,
					"优先级", task.Priority, 
					"错误", err)
				mv.addPendingTask(task)
			} else {
				log.Debug("任务处理失败次数过多，放弃任务", 
					"类型", task.TaskType, 
					"区块", task.BlockNumber)
			}
		}
		
		// 检查电池状态，如果电量过低则暂停处理
		if mv.BatteryAware && getBatteryLevel() < 15 && !isBatteryCharging() {
			log.Info("电量过低，暂停处理待处理任务", "剩余任务", len(tasks)-successCount-failCount)
			// 剩余任务重新加入队列
			mv.recoveryMutex.Lock()
			for i := successCount + failCount; i < len(tasks); i++ {
				mv.pendingTasks = append(mv.pendingTasks, tasks[i])
			}
			mv.recoveryMutex.Unlock()
			break
		}
	}
	
	log.Info("待处理任务处理完成", 
		"总数", len(tasks), 
		"成功", successCount, 
		"失败", failCount, 
		"重入队列", len(mv.pendingTasks))
	
	return nil
}

// 模拟区块提议功能
func (mv *MobileValidator) proposeBlock(blockHash common.Hash, blockNumber uint64) error {
	// 在实际实现中，这里应该有区块提议逻辑
	time.Sleep(200 * time.Millisecond)
	return nil
}

// 模拟区块最终确认功能
func (mv *MobileValidator) finalizeBlock(blockHash common.Hash, blockNumber uint64) error {
	// 在实际实现中，这里应该有区块最终确认逻辑
	time.Sleep(100 * time.Millisecond)
	return nil
}

// CreateCheckpoint 创建检查点，用于断点续传
func (mv *MobileValidator) CreateCheckpoint(blockNumber uint64, blockHash common.Hash) error {
	// 创建检查点数据
	checkpoint := struct {
		BlockNumber uint64
		BlockHash   common.Hash
		Timestamp   time.Time
		Tasks       []ValidatorTask
		Stats       ResourceStats
	}{
		BlockNumber: blockNumber,
		BlockHash:   blockHash,
		Timestamp:   time.Now(),
		Tasks:       mv.pendingTasks,
		Stats:       mv.resourceStats,
	}
	
	// 序列化检查点数据
	data, err := rlp.EncodeToBytes(checkpoint)
	if err != nil {
		return err
	}
	
	// 保存检查点数据
	mv.resumeData = data
	mv.lastCheckpointBlock = blockNumber
	mv.checkpointHash = blockHash
	
	log.Debug("创建验证者检查点", "区块", blockNumber, "哈希", blockHash.Hex())
	return nil
}

// RestoreFromCheckpoint 从检查点恢复
func (mv *MobileValidator) RestoreFromCheckpoint() error {
	if len(mv.resumeData) == 0 {
		return errors.New("没有可用的检查点数据")
	}
	
	// 解码检查点数据
	var checkpoint struct {
		BlockNumber uint64
		BlockHash   common.Hash
		Timestamp   time.Time
		Tasks       []ValidatorTask
		Stats       ResourceStats
	}
	
	if err := rlp.DecodeBytes(mv.resumeData, &checkpoint); err != nil {
		return err
	}
	
	// 检查检查点是否过期
	if time.Since(checkpoint.Timestamp) > 24*time.Hour {
		return errors.New("检查点数据已过期")
	}
	
	// 恢复状态
	mv.recoveryMutex.Lock()
	defer mv.recoveryMutex.Unlock()
	
	// 恢复任务队列
	mv.pendingTasks = checkpoint.Tasks
	
	// 恢复资源统计
	mv.resourceStats = checkpoint.Stats
	
	log.Info("从检查点恢复验证者状态", 
		"区块", checkpoint.BlockNumber, 
		"哈希", checkpoint.BlockHash.Hex(),
		"任务数", len(checkpoint.Tasks))
	
	return nil
}

// GetValidatorStatus 获取验证者状态信息
func (mv *MobileValidator) GetValidatorStatus() map[string]interface{} {
	return map[string]interface{}{
		"address":          mv.Address.Hex(),
		"stake":            mv.Stake.String(),
		"reputation":       mv.Reputation,
		"lastActive":       mv.LastActive,
		"pendingTaskCount": len(mv.pendingTasks),
		"storageLimit":     mv.MaxStorageGB,
		"bandwidthLimit":   mv.MaxBandwidthMB,
		"batteryAware":     mv.BatteryAware,
	}
}

// 增加验证者声誉
func (mv *MobileValidator) IncreaseReputation(value uint64) {
	mv.Reputation += value
}

// 减少验证者声誉
func (mv *MobileValidator) DecreaseReputation(value uint64) {
	if mv.Reputation > value {
		mv.Reputation -= value
	} else {
		mv.Reputation = 0
	}
} 