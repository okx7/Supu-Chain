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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/fsnotify/fsnotify"
)

// HotConfig 支持热更新的配置管理器
type HotConfig struct {
	mu               sync.RWMutex      // 保护内部状态的锁
	config           map[string]interface{} // 配置数据
	configPath       string            // 配置文件路径
	watcher          *fsnotify.Watcher // 文件监控
	subscribers      map[string][]ConfigChangeCallback // 订阅者
	lastModified     time.Time         // 配置最后修改时间
	autoReloadEnabled bool             // 是否启用自动重载
	reloadInterval   time.Duration     // 重载检查间隔
	quit             chan struct{}     // 退出信号
}

// ConfigChangeCallback 配置变更回调函数类型
type ConfigChangeCallback func(key string, oldValue, newValue interface{})

// NewHotConfig 创建一个新的热配置管理器
func NewHotConfig(configPath string) (*HotConfig, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("创建文件监控失败: %v", err)
	}
	
	hc := &HotConfig{
		config:           make(map[string]interface{}),
		configPath:       configPath,
		watcher:          watcher,
		subscribers:      make(map[string][]ConfigChangeCallback),
		autoReloadEnabled: true,
		reloadInterval:   time.Second * 30,
		quit:             make(chan struct{}),
	}
	
	// 首次加载配置
	if err := hc.LoadConfig(); err != nil {
		// 如果配置文件不存在，创建一个空配置文件
		if os.IsNotExist(err) {
			if err := hc.SaveConfig(); err != nil {
				return nil, fmt.Errorf("创建配置文件失败: %v", err)
			}
		} else {
			return nil, fmt.Errorf("加载配置失败: %v", err)
		}
	}
	
	// 监控配置文件变化
	if err := watcher.Add(configPath); err != nil {
		return nil, fmt.Errorf("监控配置文件失败: %v", err)
	}
	
	// 启动配置文件监控
	go hc.watchConfig()
	
	// 启动定时重载检查
	go hc.periodicReload()
	
	return hc, nil
}

// LoadConfig 从文件加载配置
func (hc *HotConfig) LoadConfig() error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	file, err := os.Open(hc.configPath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	configData, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}
	
	// 确保配置文件不为空
	if len(configData) == 0 {
		hc.config = make(map[string]interface{})
		return nil
	}
	
	var newConfig map[string]interface{}
	if err := json.Unmarshal(configData, &newConfig); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}
	
	// 找出变化的配置并通知订阅者
	for key, newValue := range newConfig {
		oldValue, exists := hc.config[key]
		if !exists || !isEqual(oldValue, newValue) {
			hc.notifySubscribers(key, oldValue, newValue)
		}
	}
	
	// 找出被删除的配置
	for key, oldValue := range hc.config {
		if _, exists := newConfig[key]; !exists {
			hc.notifySubscribers(key, oldValue, nil)
		}
	}
	
	hc.config = newConfig
	fileInfo, err := file.Stat()
	if err == nil {
		hc.lastModified = fileInfo.ModTime()
	}
	
	log.Info("已加载热更新配置", "文件", hc.configPath, "配置项数", len(hc.config))
	return nil
}

// SaveConfig 保存配置到文件
func (hc *HotConfig) SaveConfig() error {
	hc.mu.RLock()
	configData, err := json.MarshalIndent(hc.config, "", "  ")
	hc.mu.RUnlock()
	
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}
	
	if err := os.WriteFile(hc.configPath, configData, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}
	
	log.Info("已保存热更新配置", "文件", hc.configPath)
	return nil
}

// Get 获取配置值
func (hc *HotConfig) Get(key string) (interface{}, bool) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	value, exists := hc.config[key]
	return value, exists
}

// GetString 获取字符串类型配置
func (hc *HotConfig) GetString(key string, defaultValue string) string {
	value, exists := hc.Get(key)
	if !exists {
		return defaultValue
	}
	
	strValue, ok := value.(string)
	if !ok {
		return defaultValue
	}
	return strValue
}

// GetInt 获取整数类型配置
func (hc *HotConfig) GetInt(key string, defaultValue int) int {
	value, exists := hc.Get(key)
	if !exists {
		return defaultValue
	}
	
	// 处理不同的数字类型
	switch v := value.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case json.Number:
		if intVal, err := v.Int64(); err == nil {
			return int(intVal)
		}
	}
	
	return defaultValue
}

// GetBool 获取布尔类型配置
func (hc *HotConfig) GetBool(key string, defaultValue bool) bool {
	value, exists := hc.Get(key)
	if !exists {
		return defaultValue
	}
	
	boolValue, ok := value.(bool)
	if !ok {
		return defaultValue
	}
	return boolValue
}

// GetFloat 获取浮点类型配置
func (hc *HotConfig) GetFloat(key string, defaultValue float64) float64 {
	value, exists := hc.Get(key)
	if !exists {
		return defaultValue
	}
	
	// 处理不同的数字类型
	switch v := value.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case json.Number:
		if floatVal, err := v.Float64(); err == nil {
			return floatVal
		}
	}
	
	return defaultValue
}

// Set 设置配置值
func (hc *HotConfig) Set(key string, value interface{}) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	oldValue, _ := hc.config[key]
	if !isEqual(oldValue, value) {
		hc.config[key] = value
		hc.notifySubscribersLocked(key, oldValue, value)
		
		// 自动保存配置到文件
		return hc.saveConfigLocked()
	}
	
	return nil
}

// 内部使用的保存方法，已持有锁
func (hc *HotConfig) saveConfigLocked() error {
	configData, err := json.MarshalIndent(hc.config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}
	
	if err := os.WriteFile(hc.configPath, configData, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}
	
	return nil
}

// Subscribe 订阅配置变更
func (hc *HotConfig) Subscribe(key string, callback ConfigChangeCallback) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	hc.subscribers[key] = append(hc.subscribers[key], callback)
}

// 通知订阅者，已持有锁
func (hc *HotConfig) notifySubscribersLocked(key string, oldValue, newValue interface{}) {
	callbacks, exists := hc.subscribers[key]
	if !exists {
		return
	}
	
	// 创建回调列表的副本，避免在锁内执行回调
	callbacksCopy := make([]ConfigChangeCallback, len(callbacks))
	copy(callbacksCopy, callbacks)
	
	// 异步通知订阅者
	go func() {
		for _, callback := range callbacksCopy {
			SafeGo(fmt.Sprintf("config-notify-%s", key), func() {
				callback(key, oldValue, newValue)
			})
		}
	}()
}

// 通知订阅者，未持有锁
func (hc *HotConfig) notifySubscribers(key string, oldValue, newValue interface{}) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	hc.notifySubscribersLocked(key, oldValue, newValue)
}

// watchConfig 监控配置文件变化
func (hc *HotConfig) watchConfig() {
	for {
		select {
		case event, ok := <-hc.watcher.Events:
			if !ok {
				return
			}
			
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				log.Info("检测到配置文件变更", "文件", hc.configPath)
				if err := hc.LoadConfig(); err != nil {
					log.Error("重载配置失败", "错误", err)
				}
			}
			
		case err, ok := <-hc.watcher.Errors:
			if !ok {
				return
			}
			log.Error("配置文件监控错误", "错误", err)
			
		case <-hc.quit:
			return
		}
	}
}

// periodicReload 定期检查配置文件变化
func (hc *HotConfig) periodicReload() {
	ticker := time.NewTicker(hc.reloadInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if !hc.autoReloadEnabled {
				continue
			}
			
			// 检查文件是否被修改
			fileInfo, err := os.Stat(hc.configPath)
			if err != nil {
				log.Error("检查配置文件状态失败", "错误", err)
				continue
			}
			
			hc.mu.RLock()
			lastMod := hc.lastModified
			hc.mu.RUnlock()
			
			// 如果文件被修改，重新加载
			if fileInfo.ModTime().After(lastMod) {
				log.Info("检测到配置文件变更(定期检查)", "文件", hc.configPath)
				if err := hc.LoadConfig(); err != nil {
					log.Error("重载配置失败", "错误", err)
				}
			}
			
		case <-hc.quit:
			return
		}
	}
}

// EnableAutoReload 启用或禁用自动重载
func (hc *HotConfig) EnableAutoReload(enable bool) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.autoReloadEnabled = enable
}

// SetReloadInterval 设置重载检查间隔
func (hc *HotConfig) SetReloadInterval(interval time.Duration) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.reloadInterval = interval
}

// Close 关闭配置管理器
func (hc *HotConfig) Close() error {
	close(hc.quit)
	return hc.watcher.Close()
}

// 判断两个值是否相等
func isEqual(a, b interface{}) bool {
	// 简单比较
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// 全局热配置管理器实例
var (
	GlobalHotConfig     *HotConfig
	initHotConfigOnce   sync.Once
)

// GetGlobalHotConfig 获取全局热配置管理器
func GetGlobalHotConfig() (*HotConfig, error) {
	var err error
	
	initHotConfigOnce.Do(func() {
		// 默认配置文件路径
		configPath := "./config/hot_config.json"
		
		// 确保配置目录存在
		configDir := "./config"
		if _, err := os.Stat(configDir); os.IsNotExist(err) {
			if err := os.MkdirAll(configDir, 0755); err != nil {
				log.Error("创建配置目录失败", "错误", err)
				return
			}
		}
		
		GlobalHotConfig, err = NewHotConfig(configPath)
		if err != nil {
			log.Error("初始化全局热配置失败", "错误", err)
		}
	})
	
	return GlobalHotConfig, err
} 