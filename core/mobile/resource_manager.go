// Copyright 2023 The Supur-Chain Authors
// This file is part of the Supur-Chain library.
//
// 移动设备资源调度管理器，优化极端环境下的性能

package mobile

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
)

// 设备状态类型
type DeviceState int

const (
	// 设备电量状态
	BatteryNormal DeviceState = iota // 电量正常
	BatteryLow                       // 低电量
	BatteryCritical                  // 极低电量
	
	// 网络状态
	NetworkStrong       // 强网络
	NetworkWeak         // 弱网络
	NetworkOffline      // 离线
	
	// 存储状态
	StorageNormal       // 存储正常
	StorageLow          // 存储不足
	
	// 处理器状态
	CPUNormal           // CPU正常
	CPUOverloaded       // CPU过载
	
	// 温度状态
	TemperatureNormal   // 温度正常
	TemperatureHigh     // 温度过高
)

// 资源调度优先级
type ResourcePriority int

const (
	PriorityLow ResourcePriority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

// 调度策略
type SchedulingPolicy int

const (
	PolicyBalanced SchedulingPolicy = iota // 平衡模式
	PolicyPowerSaving                      // 省电模式
	PolicyPerformance                      // 性能模式
	PolicyMinimal                          // 最小模式（极端环境）
)

// 资源限制配置
type ResourceLimits struct {
	MaxConcurrentTasks     int           // 最大并发任务数
	MaxNetworkBandwidth    int64         // 最大网络带宽（字节/秒）
	MaxCPUUsage            int           // 最大CPU使用率（百分比）
	MaxMemoryUsage         int64         // 最大内存使用量（字节）
	BackgroundSyncInterval time.Duration // 后台同步间隔
	PeerDiscoveryInterval  time.Duration // 节点发现间隔
	PruneStorageThreshold  int64         // 存储清理阈值（字节）
}

// 调度任务
type ScheduledTask struct {
	ID          string            // 任务ID
	Name        string            // 任务名称
	Priority    ResourcePriority  // 任务优先级
	State       string            // 任务状态
	Handler     func(context.Context) error  // 任务处理函数
	Interval    time.Duration     // 重复执行间隔（若为0则只执行一次）
	NextRun     time.Time         // 下次执行时间
	LastRun     time.Time         // 上次执行时间
	LastError   error             // 上次执行错误
	RetryCount  int               // 重试次数
	MaxRetries  int               // 最大重试次数
	Cancelled   bool              // 是否已取消
}

// 资源调度管理器
type ResourceManager struct {
	ctx               context.Context      // 上下文
	cancelFunc        context.CancelFunc   // 取消函数
	mu                sync.Mutex           // 互斥锁
	
	// 设备状态
	deviceState       map[DeviceState]bool // 设备各项状态
	currentPolicy     SchedulingPolicy     // 当前调度策略
	resourceLimits    ResourceLimits       // 资源限制
	
	// 任务调度
	tasks             map[string]*ScheduledTask // 已注册的任务
	taskQueue         []*ScheduledTask          // 任务队列
	activeTaskCount   int                       // 活跃任务数
	wg                sync.WaitGroup            // 等待组
	
	// 监控指标
	batteryLevel      int                       // 电池电量（0-100）
	networkStrength   int                       // 网络强度（0-100）
	storageAvailable  int64                     // 可用存储空间（字节）
	cpuUsage          int                       // CPU使用率（百分比）
	memoryUsage       int64                     // 内存使用量（字节）
	deviceTemperature int                       // 设备温度（摄氏度）
	
	// 指标
	metricTasksScheduled  metrics.Counter // 已调度任务计数
	metricTasksCompleted  metrics.Counter // 已完成任务计数
	metricTasksFailed     metrics.Counter // 失败任务计数
	metricBatteryLevel    metrics.Gauge   // 电池电量指标
	metricNetworkStrength metrics.Gauge   // 网络强度指标
}

// 创建新的资源调度管理器
func NewResourceManager() *ResourceManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	// 创建和注册指标
	metricTasksScheduled := metrics.NewCounter("mobile/tasks/scheduled")
	metricTasksCompleted := metrics.NewCounter("mobile/tasks/completed")
	metricTasksFailed := metrics.NewCounter("mobile/tasks/failed")
	metricBatteryLevel := metrics.NewGauge("mobile/battery/level")
	metricNetworkStrength := metrics.NewGauge("mobile/network/strength")
	
	manager := &ResourceManager{
		ctx:                ctx,
		cancelFunc:         cancel,
		deviceState:        make(map[DeviceState]bool),
		currentPolicy:      PolicyBalanced,
		tasks:              make(map[string]*ScheduledTask),
		taskQueue:          make([]*ScheduledTask, 0),
		metricTasksScheduled:  metricTasksScheduled,
		metricTasksCompleted:  metricTasksCompleted,
		metricTasksFailed:     metricTasksFailed,
		metricBatteryLevel:    metricBatteryLevel,
		metricNetworkStrength: metricNetworkStrength,
	}
	
	// 设置默认资源限制
	manager.resourceLimits = ResourceLimits{
		MaxConcurrentTasks:     5,
		MaxNetworkBandwidth:    1024 * 1024 * 5, // 5 MB/s
		MaxCPUUsage:            70,              // 70%
		MaxMemoryUsage:         1024 * 1024 * 1024 * 2, // 2 GB
		BackgroundSyncInterval: time.Minute * 5,
		PeerDiscoveryInterval:  time.Minute * 10,
		PruneStorageThreshold:  1024 * 1024 * 1024 * 5, // 5 GB
	}
	
	// 设置初始设备状态
	manager.deviceState[BatteryNormal] = true
	manager.deviceState[NetworkStrong] = true
	manager.deviceState[StorageNormal] = true
	manager.deviceState[CPUNormal] = true
	manager.deviceState[TemperatureNormal] = true
	
	return manager
}

// 启动资源管理器
func (rm *ResourceManager) Start() {
	log.Info("移动设备资源管理器启动")
	
	// 启动设备状态监控
	rm.wg.Add(1)
	go rm.monitorDeviceStatus()
	
	// 启动任务调度器
	rm.wg.Add(1)
	go rm.taskScheduler()
}

// 停止资源管理器
func (rm *ResourceManager) Stop() {
	rm.cancelFunc()
	rm.wg.Wait()
	log.Info("移动设备资源管理器已停止")
}

// 监控设备状态
func (rm *ResourceManager) monitorDeviceStatus() {
	defer rm.wg.Done()
	
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()
	
	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			rm.updateDeviceStatus()
			rm.adjustSchedulingPolicy()
		}
	}
}

// 更新设备状态（此处为模拟实现，实际应通过系统API获取）
func (rm *ResourceManager) updateDeviceStatus() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	// 模拟实现，实际应通过系统API获取
	// 电池状态
	rm.batteryLevel = getBatteryLevel()
	rm.metricBatteryLevel.Update(int64(rm.batteryLevel))
	
	if rm.batteryLevel < 5 {
		rm.deviceState[BatteryNormal] = false
		rm.deviceState[BatteryLow] = false
		rm.deviceState[BatteryCritical] = true
	} else if rm.batteryLevel < 15 {
		rm.deviceState[BatteryNormal] = false
		rm.deviceState[BatteryLow] = true
		rm.deviceState[BatteryCritical] = false
	} else {
		rm.deviceState[BatteryNormal] = true
		rm.deviceState[BatteryLow] = false
		rm.deviceState[BatteryCritical] = false
	}
	
	// 网络状态
	rm.networkStrength = getNetworkStrength()
	rm.metricNetworkStrength.Update(int64(rm.networkStrength))
	
	if rm.networkStrength <= 0 {
		rm.deviceState[NetworkStrong] = false
		rm.deviceState[NetworkWeak] = false
		rm.deviceState[NetworkOffline] = true
	} else if rm.networkStrength < 30 {
		rm.deviceState[NetworkStrong] = false
		rm.deviceState[NetworkWeak] = true
		rm.deviceState[NetworkOffline] = false
	} else {
		rm.deviceState[NetworkStrong] = true
		rm.deviceState[NetworkWeak] = false
		rm.deviceState[NetworkOffline] = false
	}
	
	// 存储状态
	rm.storageAvailable = getStorageAvailable()
	
	if rm.storageAvailable < 1024*1024*500 { // 500 MB
		rm.deviceState[StorageNormal] = false
		rm.deviceState[StorageLow] = true
	} else {
		rm.deviceState[StorageNormal] = true
		rm.deviceState[StorageLow] = false
	}
	
	// CPU状态
	rm.cpuUsage = getCPUUsage()
	
	if rm.cpuUsage > 80 {
		rm.deviceState[CPUNormal] = false
		rm.deviceState[CPUOverloaded] = true
	} else {
		rm.deviceState[CPUNormal] = true
		rm.deviceState[CPUOverloaded] = false
	}
	
	// 温度状态
	rm.deviceTemperature = getDeviceTemperature()
	
	if rm.deviceTemperature > 45 { // 45℃以上视为高温
		rm.deviceState[TemperatureNormal] = false
		rm.deviceState[TemperatureHigh] = true
	} else {
		rm.deviceState[TemperatureNormal] = true
		rm.deviceState[TemperatureHigh] = false
	}
}

// 根据设备状态调整调度策略
func (rm *ResourceManager) adjustSchedulingPolicy() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	oldPolicy := rm.currentPolicy
	
	// 极端情况：电量极低或温度过高
	if rm.deviceState[BatteryCritical] || rm.deviceState[TemperatureHigh] {
		rm.currentPolicy = PolicyMinimal
	} else if rm.deviceState[BatteryLow] || rm.deviceState[CPUOverloaded] {
		// 低电量或CPU过载：省电模式
		rm.currentPolicy = PolicyPowerSaving
	} else if rm.deviceState[NetworkOffline] {
		// 离线状态：最小模式
		rm.currentPolicy = PolicyMinimal
	} else if rm.deviceState[NetworkWeak] {
		// 弱网络：省电模式
		rm.currentPolicy = PolicyPowerSaving
	} else {
		// 正常情况：平衡模式
		rm.currentPolicy = PolicyBalanced
	}
	
	// 策略发生变化，调整资源限制
	if oldPolicy != rm.currentPolicy {
		rm.applyPolicyLimits()
		log.Info("调度策略已更改", 
			"oldPolicy", oldPolicy, 
			"newPolicy", rm.currentPolicy,
			"battery", rm.batteryLevel,
			"network", rm.networkStrength)
	}
}

// 应用策略限制
func (rm *ResourceManager) applyPolicyLimits() {
	switch rm.currentPolicy {
	case PolicyMinimal:
		// 最小模式：最低资源消耗
		rm.resourceLimits.MaxConcurrentTasks = 1
		rm.resourceLimits.MaxNetworkBandwidth = 1024 * 50 // 50 KB/s
		rm.resourceLimits.MaxCPUUsage = 20
		rm.resourceLimits.BackgroundSyncInterval = time.Hour
		rm.resourceLimits.PeerDiscoveryInterval = time.Hour * 2
	
	case PolicyPowerSaving:
		// 省电模式：降低资源消耗
		rm.resourceLimits.MaxConcurrentTasks = 2
		rm.resourceLimits.MaxNetworkBandwidth = 1024 * 500 // 500 KB/s
		rm.resourceLimits.MaxCPUUsage = 40
		rm.resourceLimits.BackgroundSyncInterval = time.Minute * 30
		rm.resourceLimits.PeerDiscoveryInterval = time.Minute * 30
	
	case PolicyBalanced:
		// 平衡模式：均衡性能和资源消耗
		rm.resourceLimits.MaxConcurrentTasks = 5
		rm.resourceLimits.MaxNetworkBandwidth = 1024 * 1024 * 2 // 2 MB/s
		rm.resourceLimits.MaxCPUUsage = 60
		rm.resourceLimits.BackgroundSyncInterval = time.Minute * 5
		rm.resourceLimits.PeerDiscoveryInterval = time.Minute * 10
	
	case PolicyPerformance:
		// 性能模式：最大性能
		rm.resourceLimits.MaxConcurrentTasks = 10
		rm.resourceLimits.MaxNetworkBandwidth = 1024 * 1024 * 10 // 10 MB/s
		rm.resourceLimits.MaxCPUUsage = 90
		rm.resourceLimits.BackgroundSyncInterval = time.Minute
		rm.resourceLimits.PeerDiscoveryInterval = time.Minute * 2
	}
}

// 获取当前调度策略
func (rm *ResourceManager) GetCurrentPolicy() SchedulingPolicy {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.currentPolicy
}

// 手动设置调度策略
func (rm *ResourceManager) SetPolicy(policy SchedulingPolicy) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	if rm.currentPolicy != policy {
		rm.currentPolicy = policy
		rm.applyPolicyLimits()
		log.Info("调度策略已手动更改", "newPolicy", policy)
	}
}

// 注册任务
func (rm *ResourceManager) RegisterTask(name string, priority ResourcePriority, handler func(context.Context) error) string {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	taskID := generateTaskID()
	task := &ScheduledTask{
		ID:       taskID,
		Name:     name,
		Priority: priority,
		Handler:  handler,
		State:    "registered",
	}
	
	rm.tasks[taskID] = task
	log.Debug("任务已注册", "id", taskID, "name", name, "priority", priority)
	
	return taskID
}

// 注册周期性任务
func (rm *ResourceManager) RegisterPeriodicTask(name string, priority ResourcePriority, interval time.Duration, handler func(context.Context) error) string {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	taskID := generateTaskID()
	task := &ScheduledTask{
		ID:       taskID,
		Name:     name,
		Priority: priority,
		Handler:  handler,
		Interval: interval,
		NextRun:  time.Now(),
		State:    "registered",
	}
	
	rm.tasks[taskID] = task
	log.Debug("周期性任务已注册", "id", taskID, "name", name, "priority", priority, "interval", interval)
	
	return taskID
}

// 启动任务
func (rm *ResourceManager) StartTask(taskID string) bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	task, exists := rm.tasks[taskID]
	if !exists {
		return false
	}
	
	if task.State != "registered" && task.State != "completed" && task.State != "failed" {
		return false // 任务已在运行或已取消
	}
	
	task.State = "queued"
	task.Cancelled = false
	rm.taskQueue = append(rm.taskQueue, task)
	rm.metricTasksScheduled.Inc(1)
	
	log.Debug("任务已启动", "id", taskID, "name", task.Name)
	return true
}

// 取消任务
func (rm *ResourceManager) CancelTask(taskID string) bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	task, exists := rm.tasks[taskID]
	if !exists {
		return false
	}
	
	task.Cancelled = true
	task.State = "cancelled"
	
	// 从队列中移除
	for i, t := range rm.taskQueue {
		if t.ID == taskID {
			rm.taskQueue = append(rm.taskQueue[:i], rm.taskQueue[i+1:]...)
			break
		}
	}
	
	log.Debug("任务已取消", "id", taskID, "name", task.Name)
	return true
}

// 任务调度器
func (rm *ResourceManager) taskScheduler() {
	defer rm.wg.Done()
	
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			rm.scheduleTasks()
		}
	}
}

// 调度任务
func (rm *ResourceManager) scheduleTasks() {
	rm.mu.Lock()
	
	// 检查是否可以启动新任务
	if rm.activeTaskCount >= rm.resourceLimits.MaxConcurrentTasks {
		rm.mu.Unlock()
		return
	}
	
	// 按优先级对任务队列排序
	// 这里使用简单的排序算法，实际应用中可以使用更高效的方法
	for i := 0; i < len(rm.taskQueue); i++ {
		for j := i + 1; j < len(rm.taskQueue); j++ {
			if rm.taskQueue[i].Priority < rm.taskQueue[j].Priority {
				rm.taskQueue[i], rm.taskQueue[j] = rm.taskQueue[j], rm.taskQueue[i]
			}
		}
	}
	
	// 找到可执行的任务
	var taskToRun *ScheduledTask
	var taskIndex int
	
	for i, task := range rm.taskQueue {
		// 检查任务是否已取消
		if task.Cancelled {
			continue
		}
		
		// 检查周期性任务是否到执行时间
		if task.Interval > 0 && time.Now().Before(task.NextRun) {
			continue
		}
		
		// 选择高优先级任务或已到时间的任务
		if task.Priority >= PriorityHigh || time.Now().After(task.NextRun) {
			taskToRun = task
			taskIndex = i
			break
		}
	}
	
	// 如果没有可执行的任务
	if taskToRun == nil {
		rm.mu.Unlock()
		return
	}
	
	// 从队列中移除任务（如果是一次性任务）
	if taskToRun.Interval == 0 {
		rm.taskQueue = append(rm.taskQueue[:taskIndex], rm.taskQueue[taskIndex+1:]...)
	}
	
	// 更新任务状态
	taskToRun.State = "running"
	taskToRun.LastRun = time.Now()
	
	// 根据周期计算下次执行时间
	if taskToRun.Interval > 0 {
		taskToRun.NextRun = time.Now().Add(taskToRun.Interval)
	}
	
	rm.activeTaskCount++
	rm.mu.Unlock()
	
	// 在协程中运行任务
	rm.wg.Add(1)
	go func(task *ScheduledTask) {
		defer rm.wg.Done()
		defer func() {
			rm.mu.Lock()
			rm.activeTaskCount--
			rm.mu.Unlock()
		}()
		
		log.Debug("执行任务", "id", task.ID, "name", task.Name)
		
		// 创建任务上下文
		taskCtx, cancel := context.WithTimeout(rm.ctx, time.Minute*10)
		defer cancel()
		
		// 执行任务
		err := task.Handler(taskCtx)
		
		rm.mu.Lock()
		defer rm.mu.Unlock()
		
		// 处理执行结果
		if err != nil {
			task.LastError = err
			task.RetryCount++
			
			if task.RetryCount <= task.MaxRetries {
				task.State = "retry"
				// 将任务加回队列（如果是一次性任务）
				if task.Interval == 0 {
					rm.taskQueue = append(rm.taskQueue, task)
				}
				log.Debug("任务失败，准备重试", "id", task.ID, "name", task.Name, "error", err, "retry", task.RetryCount)
			} else {
				task.State = "failed"
				rm.metricTasksFailed.Inc(1)
				log.Debug("任务失败，达到最大重试次数", "id", task.ID, "name", task.Name, "error", err)
			}
		} else {
			task.State = "completed"
			task.RetryCount = 0
			rm.metricTasksCompleted.Inc(1)
			log.Debug("任务完成", "id", task.ID, "name", task.Name)
			
			// 如果是周期性任务，检查是否需要重新加入队列
			if task.Interval > 0 && !task.Cancelled {
				// 已在上方设置了NextRun
				task.State = "queued"
			}
		}
	}(taskToRun)
}

// 生成任务ID
func generateTaskID() string {
	// 简单生成一个伪随机ID，实际应用中应使用更好的方法
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("task-%d", rand.Int63())
}

// 以下方法为模拟实现，实际应通过系统API获取
func getBatteryLevel() int {
	// 模拟实现，随机返回50-100之间的电量
	return 50 + rand.Intn(51)
}

func getNetworkStrength() int {
	// 模拟实现，随机返回0-100之间的网络强度
	return rand.Intn(101)
}

func getStorageAvailable() int64 {
	// 模拟实现，随机返回1-10GB的可用空间
	return int64(1+rand.Intn(10)) * 1024 * 1024 * 1024
}

func getCPUUsage() int {
	// 模拟实现，随机返回10-90之间的CPU使用率
	return 10 + rand.Intn(81)
}

func getDeviceTemperature() int {
	// 模拟实现，随机返回30-50之间的温度
	return 30 + rand.Intn(21)
} 