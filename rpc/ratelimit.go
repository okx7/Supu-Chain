// Copyright 2023 The go-ethereum Authors
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

package rpc

import (
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/time/rate"
)

// RateLimiter定义速率限制接口
type RateLimiter interface {
	// Allow检查请求是否允许通过速率限制器
	Allow(ip string, method string) bool
	
	// GetLimitInfo返回当前速率限制信息
	GetLimitInfo(ip string, method string) (limit, remaining float64, resetTime time.Time)
	
	// Close关闭速率限制器并释放资源
	Close()
}

// RateLimitConfig包含速率限制的配置选项
type RateLimitConfig struct {
	// Enabled指定是否启用速率限制
	Enabled bool
	
	// GlobalRPS限制所有IP的每秒请求总数
	GlobalRPS float64
	
	// IPRateLimit指定每个IP的限制
	IPRPS float64
	
	// IPBurst指定每个IP的突发请求限制
	IPBurst int
	
	// ExemptIPs列出不受速率限制影响的IP地址
	ExemptIPs []string
	
	// MethodLimits包含对特定方法的限制
	MethodLimits map[string]MethodLimit
}

// MethodLimit指定特定方法的速率限制
type MethodLimit struct {
	// RPS指定每秒请求数
	RPS float64
	
	// Burst指定突发请求数
	Burst int
}

// basicRateLimiter实现基于令牌桶的速率限制
type basicRateLimiter struct {
	config     RateLimitConfig
	globalLimiter *rate.Limiter
	ipLimiters map[string]*rate.Limiter
	methodLimiters map[string]map[string]*rate.Limiter // ip -> method -> limiter
	exemptIPs  map[string]bool
	mu         sync.RWMutex
	cleanTick  *time.Ticker
	quit       chan struct{}
}

// NewRateLimiter创建一个新的速率限制器
func NewRateLimiter(config RateLimitConfig) RateLimiter {
	if !config.Enabled {
		return &noopRateLimiter{}
	}
	
	// 创建全局限制器
	var globalLimiter *rate.Limiter
	if config.GlobalRPS > 0 {
		globalLimiter = rate.NewLimiter(rate.Limit(config.GlobalRPS), int(config.GlobalRPS*2))
	}
	
	// 处理豁免IP
	exemptIPs := make(map[string]bool)
	for _, ip := range config.ExemptIPs {
		exemptIPs[ip] = true
	}
	
	rl := &basicRateLimiter{
		config:     config,
		globalLimiter: globalLimiter,
		ipLimiters: make(map[string]*rate.Limiter),
		methodLimiters: make(map[string]map[string]*rate.Limiter),
		exemptIPs:  exemptIPs,
		cleanTick:  time.NewTicker(10 * time.Minute), // 每10分钟清理一次不活跃的限制器
		quit:       make(chan struct{}),
	}
	
	// 启动清理协程
	go rl.cleanLoop()
	
	return rl
}

// 定期清理不活跃的IP限制器
func (rl *basicRateLimiter) cleanLoop() {
	for {
		select {
		case <-rl.cleanTick.C:
			rl.cleanInactiveLimiters()
		case <-rl.quit:
			rl.cleanTick.Stop()
			return
		}
	}
}

// 清理超过1小时不活跃的限制器
func (rl *basicRateLimiter) cleanInactiveLimiters() {
	// 这里我们可以添加逻辑来清理长时间不活跃的IP限制器
	// 但为简单起见，我们保留所有限制器
	log.Debug("清理不活跃的速率限制器", "ip_limiters", len(rl.ipLimiters), "method_limiters", len(rl.methodLimiters))
}

// Allow检查请求是否被允许
func (rl *basicRateLimiter) Allow(ip string, method string) bool {
	// 检查IP是否豁免
	if rl.exemptIPs[ip] {
		return true
	}
	
	// 检查全局限制
	if rl.globalLimiter != nil && !rl.globalLimiter.Allow() {
		log.SecurityWarn("rpc", "全局速率限制触发", map[string]interface{}{
			"ip": ip,
			"method": method,
		})
		return false
	}
	
	// 检查IP限制
	if !rl.allowIP(ip) {
		log.SecurityWarn("rpc", "IP速率限制触发", map[string]interface{}{
			"ip": ip,
			"method": method,
		})
		return false
	}
	
	// 检查方法限制
	if !rl.allowMethod(ip, method) {
		log.SecurityWarn("rpc", "方法速率限制触发", map[string]interface{}{
			"ip": ip,
			"method": method,
		})
		return false
	}
	
	return true
}

// allowIP检查IP是否允许通过限制
func (rl *basicRateLimiter) allowIP(ip string) bool {
	if rl.config.IPRPS <= 0 {
		return true
	}
	
	rl.mu.RLock()
	limiter, exists := rl.ipLimiters[ip]
	rl.mu.RUnlock()
	
	if !exists {
		rl.mu.Lock()
		// 双重检查
		limiter, exists = rl.ipLimiters[ip]
		if !exists {
			limiter = rate.NewLimiter(rate.Limit(rl.config.IPRPS), rl.config.IPBurst)
			rl.ipLimiters[ip] = limiter
		}
		rl.mu.Unlock()
	}
	
	return limiter.Allow()
}

// allowMethod检查方法是否允许通过限制
func (rl *basicRateLimiter) allowMethod(ip, method string) bool {
	methodLimit, exists := rl.config.MethodLimits[method]
	if !exists {
		return true // 没有这个方法的特定限制
	}
	
	rl.mu.RLock()
	ipMethods, exists := rl.methodLimiters[ip]
	var limiter *rate.Limiter
	if exists {
		limiter = ipMethods[method]
	}
	rl.mu.RUnlock()
	
	if limiter == nil {
		rl.mu.Lock()
		ipMethods, exists = rl.methodLimiters[ip]
		if !exists {
			ipMethods = make(map[string]*rate.Limiter)
			rl.methodLimiters[ip] = ipMethods
		}
		
		limiter = ipMethods[method]
		if limiter == nil {
			limiter = rate.NewLimiter(rate.Limit(methodLimit.RPS), methodLimit.Burst)
			ipMethods[method] = limiter
		}
		rl.mu.Unlock()
	}
	
	return limiter.Allow()
}

// GetLimitInfo返回当前限制信息
func (rl *basicRateLimiter) GetLimitInfo(ip string, method string) (limit, remaining float64, resetTime time.Time) {
	// 方法限制优先，然后是IP限制
	methodLimit, hasMethodLimit := rl.config.MethodLimits[method]
	
	if hasMethodLimit {
		rl.mu.RLock()
		ipMethods, exists := rl.methodLimiters[ip]
		var limiter *rate.Limiter
		if exists {
			limiter = ipMethods[method]
		}
		rl.mu.RUnlock()
		
		if limiter != nil {
			// 基于令牌桶填充速率计算剩余令牌和重置时间
			tokens := limiter.Tokens()
			limit = float64(methodLimit.RPS)
			remaining = tokens
			if tokens < float64(methodLimit.Burst) {
				// 计算完全重置所需的时间
				tokensNeeded := float64(methodLimit.Burst) - tokens
				resetDuration := time.Duration(tokensNeeded / float64(methodLimit.RPS) * float64(time.Second))
				resetTime = time.Now().Add(resetDuration)
			} else {
				resetTime = time.Now()
			}
			return
		}
	}
	
	// 回退到IP限制
	if rl.config.IPRPS > 0 {
		rl.mu.RLock()
		limiter, exists := rl.ipLimiters[ip]
		rl.mu.RUnlock()
		
		if exists {
			tokens := limiter.Tokens()
			limit = float64(rl.config.IPRPS)
			remaining = tokens
			if tokens < float64(rl.config.IPBurst) {
				tokensNeeded := float64(rl.config.IPBurst) - tokens
				resetDuration := time.Duration(tokensNeeded / float64(rl.config.IPRPS) * float64(time.Second))
				resetTime = time.Now().Add(resetDuration)
			} else {
				resetTime = time.Now()
			}
			return
		}
		
		// 如果不存在限制器，返回默认限制
		return rl.config.IPRPS, rl.config.IPRPS, time.Now()
	}
	
	// 无限制
	return 0, 0, time.Now()
}

// Close关闭速率限制器
func (rl *basicRateLimiter) Close() {
	close(rl.quit)
}

// noopRateLimiter是一个空操作的速率限制器，始终允许所有请求
type noopRateLimiter struct{}

// Allow始终返回true
func (n *noopRateLimiter) Allow(ip string, method string) bool {
	return true
}

// GetLimitInfo返回无限制
func (n *noopRateLimiter) GetLimitInfo(ip string, method string) (limit, remaining float64, resetTime time.Time) {
	return 0, 0, time.Now()
}

// Close什么也不做
func (n *noopRateLimiter) Close() {}

// DefaultRateLimiter是默认的速率限制器实例
var DefaultRateLimiter RateLimiter = &noopRateLimiter{}

// InitDefaultRateLimiter初始化默认的速率限制器
func InitDefaultRateLimiter(config RateLimitConfig) {
	DefaultRateLimiter = NewRateLimiter(config)
}

// GetIPFromRequest尝试从请求中提取客户端IP地址
func GetIPFromRequest(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr // 可能没有端口部分
	}
	return host
} 