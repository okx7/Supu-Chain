// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

// GoroutineManager 提供对goroutine的统一管理，防止泄露
type GoroutineManager struct {
	mu             sync.Mutex                // 用于保护内部状态的互斥锁
	wg             sync.WaitGroup            // 等待所有goroutine完成
	routines       map[string]*routineInfo   // 跟踪所有活跃的goroutine
	cleanupTicker  *time.Ticker              // 定时清理ticker
	maxGoroutines  int                       // 最大允许的goroutine数量
	currentCount   atomic.Int32              // 当前活跃的goroutine数量
	quit           chan struct{}             // 关闭信号
	panicHandler   func(interface{})         // panic处理函数
	leakTimeout    time.Duration             // 判定为泄露的超时时间
	statsInterval  time.Duration             // 统计信息输出间隔
	enableMonitor  bool                      // 是否启用监控
}

// routineInfo 存储goroutine的相关信息
type routineInfo struct {
	id          string        // 唯一标识符
	name        string        // 名称
	startTime   time.Time     // 启动时间
	lastActive  time.Time     // 最后活动时间
	timeout     time.Duration // 超时时间
	isLongLived bool          // 是否是长期运行的goroutine
	done        chan struct{} // 完成信号
}

// NewGoroutineManager 创建一个新的goroutine管理器
func NewGoroutineManager(maxGoroutines int, leakTimeout time.Duration) *GoroutineManager {
	if maxGoroutines <= 0 {
		// 默认为系统CPU核心数的2倍
		maxGoroutines = runtime.NumCPU() * 2
	}
	
	if leakTimeout <= 0 {
		// 默认10分钟超时
		leakTimeout = 10 * time.Minute
	}
	
	gm := &GoroutineManager{
		routines:      make(map[string]*routineInfo),
		cleanupTicker: time.NewTicker(time.Minute),
		maxGoroutines: maxGoroutines,
		quit:          make(chan struct{}),
		leakTimeout:   leakTimeout,
		statsInterval: 5 * time.Minute,
		enableMonitor: true,
		panicHandler: func(r interface{}) {
			log.Error("Goroutine异常退出", "原因", r)
		},
	}
	
	go gm.monitorRoutines()
	return gm
}

// Go 启动一个受管理的goroutine
func (gm *GoroutineManager) Go(name string, fn func(), isLongLived bool, timeout time.Duration) error {
	// 检查是否超过最大goroutine数量限制（长期运行的goroutine不计入限制）
	if !isLongLived && gm.currentCount.Load() >= int32(gm.maxGoroutines) {
		return fmt.Errorf("超过最大goroutine限制 (当前: %d, 最大: %d)", 
			gm.currentCount.Load(), gm.maxGoroutines)
	}
	
	// 创建唯一ID，使用时间戳+名称
	id := fmt.Sprintf("%s-%d", name, time.Now().UnixNano())
	
	info := &routineInfo{
		id:          id,
		name:        name,
		startTime:   time.Now(),
		lastActive:  time.Now(),
		timeout:     timeout,
		isLongLived: isLongLived,
		done:        make(chan struct{}),
	}
	
	gm.mu.Lock()
	gm.routines[id] = info
	gm.mu.Unlock()
	
	if !isLongLived {
		gm.currentCount.Add(1)
	}
	gm.wg.Add(1)
	
	// 启动实际的goroutine
	go func() {
		defer func() {
			// 捕获panic
			if r := recover(); r != nil {
				gm.panicHandler(r)
			}
			
			// 完成时清理资源
			gm.mu.Lock()
			delete(gm.routines, id)
			gm.mu.Unlock()
			
			if !isLongLived {
				gm.currentCount.Add(-1)
			}
			close(info.done)
			gm.wg.Done()
		}()
		
		// 执行实际任务
		fn()
	}()
	
	return nil
}

// SetActive 更新goroutine的最后活动时间
func (gm *GoroutineManager) SetActive(id string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	
	if info, exists := gm.routines[id]; exists {
		info.lastActive = time.Now()
	}
}

// Wait 等待所有goroutine完成
func (gm *GoroutineManager) Wait() {
	gm.wg.Wait()
}

// Shutdown 关闭管理器，等待所有goroutine完成
func (gm *GoroutineManager) Shutdown() {
	close(gm.quit)
	gm.cleanupTicker.Stop()
	gm.wg.Wait()
}

// Count 返回当前活跃的goroutine数量
func (gm *GoroutineManager) Count() int {
	return int(gm.currentCount.Load())
}

// EnableMonitoring 启用或禁用监控
func (gm *GoroutineManager) EnableMonitoring(enable bool) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.enableMonitor = enable
}

// SetMaxGoroutines 设置最大goroutine数量
func (gm *GoroutineManager) SetMaxGoroutines(max int) {
	if max <= 0 {
		return
	}
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.maxGoroutines = max
}

// monitorRoutines 监控goroutine，定期检查泄露和输出统计信息
func (gm *GoroutineManager) monitorRoutines() {
	statsTimer := time.NewTicker(gm.statsInterval)
	defer statsTimer.Stop()
	
	for {
		select {
		case <-gm.cleanupTicker.C:
			if !gm.enableMonitor {
				continue
			}
			// 检查长时间未活动的goroutine
			now := time.Now()
			gm.mu.Lock()
			for id, info := range gm.routines {
				// 跳过长期运行的goroutine
				if info.isLongLived {
					continue
				}
				
				// 检查是否超时
				if info.timeout > 0 && now.Sub(info.startTime) > info.timeout {
					log.Warn("检测到可能的goroutine超时", 
						"名称", info.name, 
						"ID", id, 
						"运行时间", now.Sub(info.startTime),
						"超时设置", info.timeout)
				}
				
				// 检查是否长时间未活动（可能泄露）
				if now.Sub(info.lastActive) > gm.leakTimeout {
					log.Warn("检测到可能的goroutine泄露", 
						"名称", info.name, 
						"ID", id, 
						"未活动时间", now.Sub(info.lastActive))
				}
			}
			gm.mu.Unlock()
			
		case <-statsTimer.C:
			if !gm.enableMonitor {
				continue
			}
			// 输出统计信息
			gm.mu.Lock()
			log.Info("Goroutine管理统计", 
				"当前数量", gm.currentCount.Load(),
				"最大限制", gm.maxGoroutines,
				"跟踪实例数", len(gm.routines))
			gm.mu.Unlock()
			
		case <-gm.quit:
			return
		}
	}
}

// 全局Goroutine管理器实例
var (
	GlobalGoroutineManager     *GoroutineManager
	initGlobalManagerOnce      sync.Once
)

// GetGlobalGoroutineManager 获取全局Goroutine管理器实例
func GetGlobalGoroutineManager() *GoroutineManager {
	initGlobalManagerOnce.Do(func() {
		// 初始化全局管理器，支持最多1000个goroutine，10分钟泄露检测
		GlobalGoroutineManager = NewGoroutineManager(1000, 10*time.Minute)
	})
	return GlobalGoroutineManager
}

// SafeGo 使用全局管理器启动受控的goroutine
func SafeGo(name string, fn func()) {
	manager := GetGlobalGoroutineManager()
	err := manager.Go(name, fn, false, 0)
	if err != nil {
		log.Warn("启动goroutine失败", "名称", name, "错误", err)
	}
}

// SafeGoLongLived 启动长期运行的goroutine
func SafeGoLongLived(name string, fn func()) {
	manager := GetGlobalGoroutineManager()
	_ = manager.Go(name, fn, true, 0)
}

// SafeGoWithTimeout 启动带超时检测的goroutine
func SafeGoWithTimeout(name string, fn func(), timeout time.Duration) {
	manager := GetGlobalGoroutineManager()
	err := manager.Go(name, fn, false, timeout)
	if err != nil {
		log.Warn("启动goroutine失败", "名称", name, "错误", err)
	}
} 