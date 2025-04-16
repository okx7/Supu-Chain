package mobile

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
	"os"
)

// BlockState 区块状态类型
type BlockState int

const (
	BlockStatePending   BlockState = iota // 待处理
	BlockStateVerified                    // 已验证
	BlockStateConfirmed                   // 已确认
	BlockStateRejected                    // 已拒绝
	BlockStateOrphan                      // 孤块
)

// BlockHeader 区块头结构
type BlockHeader struct {
	BlockHash       []byte // 区块哈希
	PrevBlockHash   []byte // 前一区块哈希
	Height          uint64 // 高度
	Timestamp       int64  // 时间戳
	MerkleRoot      []byte // 默克尔根
	Nonce           uint64 // 随机数
	Difficulty      uint32 // 难度
	Version         uint16 // 版本
	TransactionCount uint32 // 交易数量
}

// BlockInfo 区块信息
type BlockInfo struct {
	Header       *BlockHeader // 区块头
	State        BlockState   // 状态
	Size         uint32       // 大小（字节）
	ReceivedFrom string       // 接收来源
	ReceivedAt   time.Time    // 接收时间
	ProcessedAt  time.Time    // 处理时间
	RetryCount   int          // 重试次数
	LocalPath    string       // 本地路径
}

// OrphanBlock 孤块信息
type OrphanBlock struct {
	Info          *BlockInfo    // 区块信息
	MissingParent []byte        // 缺失的父区块哈希
	ExpiresAt     time.Time     // 过期时间
	DependentBlocks [][]byte    // 依赖此区块的其他区块
	Priority      int           // 处理优先级，数值越小优先级越高
	LastRetryTime time.Time     // 上次重试时间
	FailReason    string        // 失败原因
}

// SyncStatus 同步状态
type SyncStatus struct {
	IsSyncing        bool      // 是否正在同步
	SyncStartHeight  uint64    // 同步起始高度
	SyncTargetHeight uint64    // 同步目标高度
	CurrentHeight    uint64    // 当前高度
	LastBlockTime    time.Time // 最后区块时间
	SyncStartTime    time.Time // 同步开始时间
	SyncSpeed        float64   // 同步速度（区块/秒）
	PendingBlockCount int      // 待处理区块数量
	MissingBlockCount int      // 缺失区块数量
	DownloadedBytes  uint64    // 已下载字节数
	ProcessedBlocks  uint64    // 已处理区块数
	RejectedBlocks   uint64    // 已拒绝区块数
	FailedAttempts   int       // 失败尝试次数
	LastCheckpoint   uint64    // 最后检查点高度
	Checkpoints      []uint64  // 同步检查点列表
	SyncPaused       bool      // 同步是否暂停
	ResumeFrom       uint64    // 恢复同步的高度
	SyncErrors       []string  // 同步过程中的错误
	VerificationMode string    // 验证模式（完全/轻量）
}

// ChainStateConfig 链状态配置
type ChainStateConfig struct {
	MaxOrphanBlocks     int           // 最大孤块数量
	MaxOrphanBlockAge   time.Duration // 最大孤块存活时间
	OrphanExpireInterval time.Duration // 孤块过期检查间隔
	BlockCacheSize      int           // 区块缓存大小
	BlockCacheExpiry    time.Duration // 区块缓存过期时间
	MaxBlockSize        uint32        // 最大区块大小
	MaxRetryCount       int           // 最大重试次数
	RetryInterval       time.Duration // 重试间隔
	SmartRetryEnabled   bool          // 是否启用智能重试
	InitialRetryDelay   time.Duration // 初始重试延迟
	MaxRetryDelay       time.Duration // 最大重试延迟
	OrphanRetryInterval time.Duration // 孤块批量重试间隔
}

// ChainState 链状态
type ChainState struct {
	CurrentHeight uint64               // 当前高度
	CurrentHash   []byte               // 当前区块哈希
	LastUpdated   time.Time            // 最后更新时间
	PendingBlocks map[string]*BlockInfo // 待处理区块
	OrphanBlocks  map[string]*OrphanBlock // 孤块池
	BlockCache    LRUCacheInterface    // 区块缓存
	SyncStatus    *SyncStatus          // 同步状态
	mutex         sync.RWMutex         // 读写锁
	config        *ChainStateConfig    // 配置
	checkpointInterval uint64          // 检查点间隔
	syncCheckpoints map[uint64][]byte  // 检查点映射表（高度 -> 哈希）
	networkQuality int                 // 网络质量评估（0-100）
	downloadedBlocks map[uint64]string // 已下载区块映射（高度 -> 哈希）
	checkpointMutex sync.RWMutex       // 检查点互斥锁
}

// LRUCacheInterface 缓存接口
type LRUCacheInterface interface {
	Get(key string) (interface{}, bool)
	Put(key string, value interface{}, size int) bool
	Remove(key string) bool
	Len() int
	Keys() []string
	GetStats() map[string]interface{}
}

// LRUCacheEvictCallback 淘汰回调函数类型
type LRUCacheEvictCallback func(key string, value interface{})

// LRUCache 额外添加缓存优化参数
type LRUCache struct {
	capacity    int                      // 缓存容量
	items       map[string]*list.Element // 缓存项映射
	evictList   *list.List               // 淘汰列表
	mutex       sync.RWMutex             // 读写锁
	hits        int64                    // 命中次数
	misses      int64                    // 未命中次数
	totalGets   int64                    // 总获取次数
	totalSets   int64                    // 总设置次数
	totalEvicts int64                    // 总淘汰次数
	sizeBytes   int64                    // 缓存占用字节数
	maxBytes    int64                    // 最大字节数
	created     time.Time                // 创建时间
	onEvict     LRUCacheEvictCallback    // 淘汰回调
	adaptiveMode bool                    // 自适应模式
	hitRateThreshold float64             // 命中率阈值
	expansionFactor float64              // 扩展因子
	shrinkFactor float64                 // 收缩因子
	lastResize time.Time                 // 上次调整大小时间
	resizeInterval time.Duration         // 调整大小间隔
}

// entry 缓存条目
type entry struct {
	key       string      // 键
	value     interface{} // 值
	size      int         // 大小
	createdAt time.Time   // 创建时间
	accessAt  time.Time   // 访问时间
	hitCount  int         // 命中次数
}

// NewLRUCache 创建优化的LRU缓存
func NewLRUCache(capacity int, maxBytes int64, onEvict LRUCacheEvictCallback) *LRUCache {
	return &LRUCache{
		capacity:    capacity,
		items:     make(map[string]*list.Element),
		evictList: list.New(),
		maxBytes:  maxBytes,
		created:   time.Now(),
		onEvict:   onEvict,
		adaptiveMode: true,               // 默认启用自适应模式
		hitRateThreshold: 0.8,            // 80%命中率阈值
		expansionFactor: 1.5,             // 扩容50%
		shrinkFactor: 0.7,                // 缩容30%
		lastResize: time.Now(),
		resizeInterval: 10 * time.Minute, // 10分钟调整一次大小
	}
}

// Get 获取缓存值
func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.totalGets++
	
	if ent, ok := c.items[key]; ok {
		// 命中缓存，将条目移到列表前端
		c.evictList.MoveToFront(ent)
		e := ent.Value.(*entry)
		e.accessAt = time.Now()
		e.hitCount++
		c.hits++
		return e.value, true
	}
	
	// 未命中缓存
	c.misses++
	return nil, false
}

// Put 添加缓存项
func (c *LRUCache) Put(key string, value interface{}, size int) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.totalSets++
	
	// 检查键是否已存在
	if ent, ok := c.items[key]; ok {
		// 更新现有条目
		c.evictList.MoveToFront(ent)
		e := ent.Value.(*entry)
		oldSize := e.size
		e.value = value
		e.size = size
		e.accessAt = time.Now()
		
		// 更新大小统计
		c.sizeBytes = c.sizeBytes - int64(oldSize) + int64(size)
		
		// 如果超出大小限制，需要淘汰
		c.evictIfNeeded()
		return true
	}
	
	// 创建新条目
	now := time.Now()
	e := &entry{
		key:       key,
		value:     value,
		size:      size,
		createdAt: now,
		accessAt:  now,
	}
	
	// 将新条目添加到列表前端
	element := c.evictList.PushFront(e)
	c.items[key] = element
	c.sizeBytes += int64(size)
	
	// 如果超出容量或大小限制，需要淘汰
	c.evictIfNeeded()
	return true
}

// evictIfNeeded 按需淘汰缓存项
func (c *LRUCache) evictIfNeeded() {
	// 检查容量限制
	for c.evictList.Len() > c.capacity {
		c.removeOldest()
	}
	
	// 检查大小限制
	if c.maxBytes > 0 {
		for c.sizeBytes > c.maxBytes && c.evictList.Len() > 0 {
			c.removeOldest()
		}
	}
}

// removeOldest 移除最老的缓存项
func (c *LRUCache) removeOldest() {
	if c.evictList.Len() == 0 {
		return
	}
	
	// 获取最老的条目
	element := c.evictList.Back()
	e := element.Value.(*entry)
	
	// 从链表和映射中移除
	c.evictList.Remove(element)
	delete(c.items, e.key)
	
	// 更新统计信息
	c.sizeBytes -= int64(e.size)
	c.totalEvicts++
	
	// 调用淘汰回调（如果有）
	if c.onEvict != nil {
		c.onEvict(e.key, e.value)
	}
}

// Remove 移除指定的缓存项
func (c *LRUCache) Remove(key string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	if ent, ok := c.items[key]; ok {
		e := ent.Value.(*entry)
		c.evictList.Remove(ent)
		delete(c.items, key)
		c.sizeBytes -= int64(e.size)
		
		// 调用淘汰回调（如果有）
		if c.onEvict != nil {
			c.onEvict(e.key, e.value)
		}
		
		return true
	}
	
	return false
}

// Len 获取缓存项数量
func (c *LRUCache) Len() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.evictList.Len()
}

// Clear 清空缓存
func (c *LRUCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// 如果有淘汰回调，处理每个缓存项
	if c.onEvict != nil {
		for _, v := range c.items {
			e := v.Value.(*entry)
			c.onEvict(e.key, e.value)
		}
	}
	
	// 重置所有字段
	c.items = make(map[string]*list.Element)
	c.evictList = list.New()
	c.sizeBytes = 0
	c.totalEvicts += int64(c.evictList.Len())
}

// Keys 获取所有键
func (c *LRUCache) Keys() []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	keys := make([]string, 0, len(c.items))
	for k := range c.items {
		keys = append(keys, k)
	}
	
	return keys
}

// GetStats 获取缓存统计信息
func (c *LRUCache) GetStats() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	// 计算命中率
	hitRate := float64(0)
	if c.totalGets > 0 {
		hitRate = float64(c.hits) / float64(c.totalGets) * 100
	}
	
	// 返回统计信息
	return map[string]interface{}{
		"capacity":     c.capacity,
		"size":         c.evictList.Len(),
		"max_bytes":    c.maxBytes,
		"bytes_used":   c.sizeBytes,
		"hit_count":    c.hits,
		"miss_count":   c.misses,
		"hit_rate":     fmt.Sprintf("%.2f%%", hitRate),
		"get_count":    c.totalGets,
		"set_count":    c.totalSets,
		"evict_count":  c.totalEvicts,
		"created_at":   c.created.Format(time.RFC3339),
		"uptime":       time.Since(c.created).String(),
		"memory_usage": fmt.Sprintf("%.2f%%", float64(c.sizeBytes)/float64(c.maxBytes)*100),
	}
}

// OptimizeCache 根据使用情况自动调整缓存大小
func (c *LRUCache) OptimizeCache() {
	if !c.adaptiveMode {
		return
	}
	
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// 检查是否达到调整间隔
	if time.Since(c.lastResize) < c.resizeInterval {
		return
	}
	
	// 计算命中率
	hitRate := float64(0)
	if c.totalGets > 0 {
		hitRate = float64(c.hits) / float64(c.totalGets)
	}
	
	// 计算使用率
	usageRate := float64(c.sizeBytes) / float64(c.maxBytes)
	
	// 根据命中率和使用率调整缓存大小
	newCapacity := c.capacity
	
	// 命中率高，容量接近上限，考虑扩容
	if hitRate >= c.hitRateThreshold && usageRate > 0.9 {
		newCapacity = int(float64(c.capacity) * c.expansionFactor)
		
		// 记录日志
		fmt.Printf("缓存命中率高 (%.2f%%)，使用率高 (%.2f%%)，扩容至 %d 项\n", 
			hitRate*100, usageRate*100, newCapacity)
	} 
	// 命中率低，使用率低，考虑缩容
	else if hitRate < c.hitRateThreshold/2 && usageRate < 0.5 && c.capacity > 100 {
		newTempCapacity := int(float64(c.capacity) * c.shrinkFactor)
		// 确保不会缩得太小
		if newTempCapacity >= 100 {
			newCapacity = newTempCapacity
			
			// 记录日志
			fmt.Printf("缓存命中率低 (%.2f%%)，使用率低 (%.2f%%)，缩容至 %d 项\n", 
				hitRate*100, usageRate*100, newCapacity)
		}
	}
	
	// 调整容量
	if newCapacity != c.capacity {
		c.capacity = newCapacity
		c.lastResize = time.Now()
		
		// 如果当前项数超过新容量，需要淘汰
		for c.evictList.Len() > c.capacity {
			c.removeOldest()
		}
	}
	
	// 重置统计
	c.hits = 0
	c.misses = 0
	c.totalGets = 0
	c.totalSets = 0
}

// PrioritizedCacheStorage 优先级缓存存储
type PrioritizedCacheStorage struct {
	hotCache  *LRUCache             // 热点缓存（频繁访问的块）
	coldCache *LRUCache             // 冷缓存（不常访问的块）
	accessCount map[string]int      // 访问计数
	promotionThreshold int          // 晋升阈值
	demotionThreshold int           // 降级阈值
	mutex     sync.RWMutex          // 读写锁
}

// NewPrioritizedCacheStorage 创建新的优先级缓存存储
func NewPrioritizedCacheStorage(hotCapacity, coldCapacity int, hotMaxBytes, coldMaxBytes int64) *PrioritizedCacheStorage {
	hotCache := NewLRUCache(hotCapacity, hotMaxBytes, nil)
	coldCache := NewLRUCache(coldCapacity, coldMaxBytes, nil)
	
	return &PrioritizedCacheStorage{
		hotCache:  hotCache,
		coldCache: coldCache,
		accessCount: make(map[string]int),
		promotionThreshold: 3,  // 访问3次后晋升到热缓存
		demotionThreshold: 1,   // 1天内无访问则降级到冷缓存
	}
}

// Get 获取缓存项
func (p *PrioritizedCacheStorage) Get(key string) (interface{}, bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	// 先检查热缓存
	if value, found := p.hotCache.Get(key); found {
		// 更新访问计数
		p.accessCount[key]++
		return value, true
	}
	
	// 再检查冷缓存
	if value, found := p.coldCache.Get(key); found {
		// 更新访问计数
		count := p.accessCount[key] + 1
		p.accessCount[key] = count
		
		// 检查是否应该晋升到热缓存
		if count >= p.promotionThreshold {
			// 从冷缓存中移除
			p.coldCache.Remove(key)
			
			// 添加到热缓存
			p.hotCache.Put(key, value, 0)
			
			// 重置计数
			p.accessCount[key] = 0
		}
		
		return value, true
	}
	
	return nil, false
}

// Put 添加缓存项
func (p *PrioritizedCacheStorage) Put(key string, value interface{}, size int) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	// 默认添加到冷缓存
	p.coldCache.Put(key, value, size)
	p.accessCount[key] = 0
	return true
}

// Remove 移除缓存项
func (p *PrioritizedCacheStorage) Remove(key string) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	// 从热缓存和冷缓存中移除
	hotRemoved := p.hotCache.Remove(key)
	coldRemoved := p.coldCache.Remove(key)
	
	// 清除访问计数
	delete(p.accessCount, key)
	
	return hotRemoved || coldRemoved
}

// Len 获取缓存项总数
func (p *PrioritizedCacheStorage) Len() int {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	return p.hotCache.Len() + p.coldCache.Len()
}

// Keys 获取所有键
func (p *PrioritizedCacheStorage) Keys() []string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	hotKeys := p.hotCache.Keys()
	coldKeys := p.coldCache.Keys()
	
	// 合并两个切片
	allKeys := make([]string, 0, len(hotKeys)+len(coldKeys))
	allKeys = append(allKeys, hotKeys...)
	allKeys = append(allKeys, coldKeys...)
	
	return allKeys
}

// GetStats 获取缓存统计信息
func (p *PrioritizedCacheStorage) GetStats() map[string]interface{} {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	hotStats := p.hotCache.GetStats()
	coldStats := p.coldCache.GetStats()
	
	// 合并统计信息
	stats := map[string]interface{}{
		"hot_cache": hotStats,
		"cold_cache": coldStats,
		"total_size": p.hotCache.Len() + p.coldCache.Len(),
		"promotion_threshold": p.promotionThreshold,
		"demotion_threshold": p.demotionThreshold,
	}
	
	return stats
}

// ScheduleCacheCleanup 定期清理和优化缓存
func (cs *ChainState) ScheduleCacheCleanup() {
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		
		for range ticker.C {
			// 运行缓存优化
			if cache, ok := cs.BlockCache.(*LRUCache); ok && cache.adaptiveMode {
				cache.OptimizeCache()
				
				// 获取缓存统计
				stats := cache.GetStats()
				fmt.Printf("缓存优化完成 - 容量: %v, 使用项数: %v, 命中率: %v\n", 
					stats["capacity"], stats["size"], stats["hit_rate"])
			}
			
			// 清理过期孤块
			cs.cleanupExpiredOrphanBlocks()
			
			// 重试处理孤块
			if cs.config.SmartRetryEnabled {
				retried := cs.RetryOrphanBlocks()
				if retried > 0 {
					fmt.Printf("定期清理过程中重试处理了 %d 个孤块\n", retried)
				}
			}
		}
	}()
}

// UpdateChainStateWithCache 更新ChainState以使用优化缓存
func UpdateChainStateWithCache(cs *ChainState) {
	// 创建优先级缓存
	if cs.config.BlockCacheSize > 0 {
		hotCacheSize := cs.config.BlockCacheSize / 3  // 1/3用于热缓存
		coldCacheSize := cs.config.BlockCacheSize - hotCacheSize // 2/3用于冷缓存
		
		priorityCache := NewPrioritizedCacheStorage(
			hotCacheSize, 
			coldCacheSize,
			int64(cs.config.BlockCacheExpiry.Seconds()) * 1000000, // 热缓存最大字节数
			int64(cs.config.BlockCacheExpiry.Seconds()) * 2000000, // 冷缓存最大字节数
		)
		
		// 将现有缓存数据迁移到新缓存
		if cs.BlockCache != nil {
			for _, key := range cs.BlockCache.Keys() {
				if value, found := cs.BlockCache.Get(key); found {
					priorityCache.Put(key, value, 0)
				}
			}
		}
		
		// 替换缓存
		cs.BlockCache = priorityCache
	}
	
	// 启动缓存清理和优化
	cs.ScheduleCacheCleanup()
}

// NewChainState 创建新的链状态
func NewChainState(config *ChainStateConfig) *ChainState {
	if config == nil {
		config = &ChainStateConfig{
			MaxOrphanBlocks:      100,
			MaxOrphanBlockAge:    1 * time.Hour,
			OrphanExpireInterval: 10 * time.Minute,
			BlockCacheSize:       1000,
			BlockCacheExpiry:     24 * time.Hour,
			MaxBlockSize:         1024 * 1024 * 10, // 10MB
			MaxRetryCount:        3,
			RetryInterval:        30 * time.Second,
			SmartRetryEnabled:    true,              // 启用智能重试
			InitialRetryDelay:    5 * time.Second,   // 初始延迟5秒
			MaxRetryDelay:        5 * time.Minute,   // 最大延迟5分钟
			OrphanRetryInterval:  2 * time.Minute,   // 每2分钟批量重试
		}
	}
	
	// 创建区块缓存，驱逐时记录日志
	blockCache := NewLRUCache(config.BlockCacheSize, int64(config.BlockCacheExpiry.Seconds())*1000000, func(key string, value interface{}) {
		fmt.Printf("区块从缓存中驱逐: %s\n", key)
	})
	
	state := &ChainState{
		CurrentHeight: 0,
		CurrentHash:   nil,
		LastUpdated:   time.Now(),
		PendingBlocks: make(map[string]*BlockInfo),
		OrphanBlocks:  make(map[string]*OrphanBlock),
		BlockCache:    blockCache,
		SyncStatus: &SyncStatus{
			IsSyncing:     false,
			LastBlockTime: time.Now(),
			Checkpoints:   make([]uint64, 0),
		},
		config: config,
		checkpointInterval: 100, // 每100个区块设置一个检查点
		syncCheckpoints: make(map[uint64][]byte),
		networkQuality: 100, // 初始网络质量为最高
		downloadedBlocks: make(map[uint64]string),
	}
	
	// 启动孤块过期检查
	go state.startOrphanBlockCleanup()
	
	// 启动孤块自动重试
	if config.SmartRetryEnabled {
		go state.startOrphanBlockRetry()
	}
	
	// 使用优化的缓存策略
	UpdateChainStateWithCache(state)
	
	return state
}

// startOrphanBlockCleanup 启动孤块过期检查
func (cs *ChainState) startOrphanBlockCleanup() {
	ticker := time.NewTicker(cs.config.OrphanExpireInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		cs.cleanupExpiredOrphanBlocks()
	}
}

// startOrphanBlockRetry 启动孤块定期自动重试机制
func (cs *ChainState) startOrphanBlockRetry() {
	ticker := time.NewTicker(cs.config.OrphanRetryInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		retried := cs.RetryOrphanBlocks()
		if retried > 0 {
			fmt.Printf("自动重试处理了 %d 个孤块\n", retried)
		}
	}
}

// cleanupExpiredOrphanBlocks 清理过期孤块
func (cs *ChainState) cleanupExpiredOrphanBlocks() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	
	now := time.Now()
	expiredCount := 0
	
	for hash, orphan := range cs.OrphanBlocks {
		if now.After(orphan.ExpiresAt) {
			// 记录日志
			fmt.Printf("孤块过期移除：%s (高度: %d, 存活时间: %s, 重试次数: %d)\n", 
				hash, orphan.Info.Header.Height, 
				now.Sub(orphan.Info.ReceivedAt).String(), 
				orphan.Info.RetryCount)
				
			delete(cs.OrphanBlocks, hash)
			expiredCount++
		}
	}
	
	if expiredCount > 0 {
		fmt.Printf("已清理 %d 个过期孤块\n", expiredCount)
	}
}

// ProcessNewBlock 处理新区块
func (cs *ChainState) ProcessNewBlock(blockData []byte, source string) (*BlockInfo, error) {
	// 解析区块头
	header, err := parseBlockHeader(blockData)
	if err != nil {
		return nil, fmt.Errorf("解析区块头失败: %v", err)
	}
	
	// 计算区块哈希
	blockHash := calculateBlockHash(header)
	
	// 检查区块大小
	if uint32(len(blockData)) > cs.config.MaxBlockSize {
		return nil, fmt.Errorf("区块超过最大大小限制: %d > %d", len(blockData), cs.config.MaxBlockSize)
	}
	
	// 检查是否已存在
	hashStr := fmt.Sprintf("%x", blockHash)
	
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	
	// 检查是否在缓存中
	if cached, exists := cs.BlockCache.Get(hashStr); exists {
		return cached.(*BlockInfo), nil
	}
	
	// 检查是否在待处理队列
	if block, exists := cs.PendingBlocks[hashStr]; exists {
		return block, nil
	}
	
	// 检查是否是孤块
	if orphan, exists := cs.OrphanBlocks[hashStr]; exists {
		return orphan.Info, nil
	}
	
	// 创建区块信息
	blockInfo := &BlockInfo{
		Header:       header,
		State:        BlockStatePending,
		Size:         uint32(len(blockData)),
		ReceivedFrom: source,
		ReceivedAt:   time.Now(),
		RetryCount:   0,
	}
	
	// 检查是否有父区块
	prevHashStr := fmt.Sprintf("%x", header.PrevBlockHash)
	
	// 如果有父区块或是创世区块，添加到待处理队列
	if cs.CurrentHash == nil || // 创世区块
	   bytes.Equal(header.PrevBlockHash, cs.CurrentHash) || // 是当前区块的子区块
	   cs.BlockCache.Get(prevHashStr) != nil || // 父区块在缓存中
	   cs.PendingBlocks[prevHashStr] != nil { // 父区块在待处理队列
		
		cs.PendingBlocks[hashStr] = blockInfo
		
		// 如果此区块是某些孤块的父区块，将它们移到待处理队列
		cs.processOrphansByParent(blockHash)
		
		return blockInfo, nil
	}
	
	// 否则，是孤块
	orphanBlock := &OrphanBlock{
		Info:          blockInfo,
		MissingParent: header.PrevBlockHash,
		ExpiresAt:     time.Now().Add(cs.config.MaxOrphanBlockAge),
		DependentBlocks: [][]byte{},
	}
	
	// 检查孤块池是否已满
	if len(cs.OrphanBlocks) >= cs.config.MaxOrphanBlocks {
		// 移除最老的孤块
		cs.removeOldestOrphanBlock()
	}
	
	// 添加到孤块池
	cs.OrphanBlocks[hashStr] = orphanBlock
	blockInfo.State = BlockStateOrphan
	
	return blockInfo, nil
}

// parseBlockHeader 解析区块头
func parseBlockHeader(blockData []byte) (*BlockHeader, error) {
	// 示例实现，实际应根据区块格式解析
	if len(blockData) < 80 {
		return nil, fmt.Errorf("区块数据太短，不足以包含头部")
	}
	
	// 创建一个简单的头部，实际中应详细解析
	header := &BlockHeader{}
	
	// 使用SHA-256计算区块哈希
	hash := sha256.Sum256(blockData[:80])
	header.BlockHash = hash[:]
	
	// 解析其他字段...
	// 这里为了示例简化，仅提取了部分字段
	reader := bytes.NewReader(blockData[:80])
	
	// 读取版本、前一区块哈希等
	binary.Read(reader, binary.LittleEndian, &header.Version)
	header.PrevBlockHash = make([]byte, 32)
	reader.Read(header.PrevBlockHash)
	header.MerkleRoot = make([]byte, 32)
	reader.Read(header.MerkleRoot)
	binary.Read(reader, binary.LittleEndian, &header.Timestamp)
	binary.Read(reader, binary.LittleEndian, &header.Difficulty)
	binary.Read(reader, binary.LittleEndian, &header.Nonce)
	
	return header, nil
}

// calculateBlockHash 计算区块哈希
func calculateBlockHash(header *BlockHeader) []byte {
	// 如果已经有哈希，直接返回
	if header.BlockHash != nil {
		return header.BlockHash
	}
	
	// 创建缓冲区以序列化头部
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, header.Version)
	buf.Write(header.PrevBlockHash)
	buf.Write(header.MerkleRoot)
	binary.Write(buf, binary.LittleEndian, header.Timestamp)
	binary.Write(buf, binary.LittleEndian, header.Difficulty)
	binary.Write(buf, binary.LittleEndian, header.Nonce)
	
	// 计算SHA-256哈希
	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}

// processOrphansByParent 处理以某个块为父块的孤块
func (cs *ChainState) processOrphansByParent(parentHash []byte) {
	parentHashStr := fmt.Sprintf("%x", parentHash)
	
	// 找出所有以该区块为父块的孤块
	for hashStr, orphan := range cs.OrphanBlocks {
		orphanParentHashStr := fmt.Sprintf("%x", orphan.MissingParent)
		
		if orphanParentHashStr == parentHashStr {
			// 将孤块移到待处理队列
			cs.PendingBlocks[hashStr] = orphan.Info
			orphan.Info.State = BlockStatePending
			
			// 从孤块池中移除
			delete(cs.OrphanBlocks, hashStr)
			
			// 递归处理以该孤块为父块的其他孤块
			cs.processOrphansByParent(orphan.Info.Header.BlockHash)
		}
	}
}

// removeOldestOrphanBlock 移除最老的孤块
func (cs *ChainState) removeOldestOrphanBlock() {
	var oldestHash string
	var oldestTime time.Time
	
	// 首次迭代设置初始值
	for hash, orphan := range cs.OrphanBlocks {
		oldestHash = hash
		oldestTime = orphan.Info.ReceivedAt
		break
	}
	
	// 寻找最老的孤块
	for hash, orphan := range cs.OrphanBlocks {
		if orphan.Info.ReceivedAt.Before(oldestTime) {
			oldestHash = hash
			oldestTime = orphan.Info.ReceivedAt
		}
	}
	
	// 移除最老的孤块
	if oldestHash != "" {
		delete(cs.OrphanBlocks, oldestHash)
	}
}

// UpdateBlockState 更新区块状态
func (cs *ChainState) UpdateBlockState(blockHash []byte, state BlockState) error {
	hashStr := fmt.Sprintf("%x", blockHash)
	
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	
	// 检查待处理队列
	if block, exists := cs.PendingBlocks[hashStr]; exists {
		block.State = state
		block.ProcessedAt = time.Now()
		
		// 如果已确认，更新当前链状态
		if state == BlockStateConfirmed {
			cs.CurrentHeight = block.Header.Height
			cs.CurrentHash = block.Header.BlockHash
			cs.LastUpdated = time.Now()
			
			// 更新同步状态
			if cs.SyncStatus.IsSyncing {
				cs.SyncStatus.CurrentHeight = block.Header.Height
				cs.SyncStatus.LastBlockTime = time.Now()
				cs.SyncStatus.ProcessedBlocks++
				
				// 计算同步速度
				elapsedSeconds := time.Since(cs.SyncStatus.SyncStartTime).Seconds()
				if elapsedSeconds > 0 {
					cs.SyncStatus.SyncSpeed = float64(cs.SyncStatus.ProcessedBlocks) / elapsedSeconds
				}
				
				// 检查是否同步完成
				if block.Header.Height >= cs.SyncStatus.SyncTargetHeight {
					cs.SyncStatus.IsSyncing = false
				}
			}
			
			// 添加到缓存
			cs.BlockCache.Put(hashStr, block, int(block.Size))
			
			// 从待处理队列中移除
			delete(cs.PendingBlocks, hashStr)
		} else if state == BlockStateRejected {
			// 从待处理队列中移除
			delete(cs.PendingBlocks, hashStr)
			
			// 更新同步状态
			if cs.SyncStatus.IsSyncing {
				cs.SyncStatus.RejectedBlocks++
			}
		}
		
		return nil
	}
	
	// 检查孤块池
	if orphan, exists := cs.OrphanBlocks[hashStr]; exists {
		orphan.Info.State = state
		orphan.Info.ProcessedAt = time.Now()
		
		// 如果已确认或已拒绝，从孤块池中移除
		if state == BlockStateConfirmed || state == BlockStateRejected {
			delete(cs.OrphanBlocks, hashStr)
		}
		
		return nil
	}
	
	return fmt.Errorf("未找到指定哈希的区块: %x", blockHash)
}

// StartSync 开始同步
func (cs *ChainState) StartSync(targetHeight uint64) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	
	// 如果同步已暂停，恢复同步
	if cs.SyncStatus.SyncPaused {
		cs.SyncStatus.SyncPaused = false
	}
	
	// 设置同步状态
	cs.SyncStatus.IsSyncing = true
	cs.SyncStatus.SyncStartHeight = cs.CurrentHeight
	cs.SyncStatus.SyncTargetHeight = targetHeight
	cs.SyncStatus.CurrentHeight = cs.CurrentHeight
	cs.SyncStatus.SyncStartTime = time.Now()
	cs.SyncStatus.ProcessedBlocks = 0
	cs.SyncStatus.RejectedBlocks = 0
	cs.SyncStatus.DownloadedBytes = 0
	cs.SyncStatus.PendingBlockCount = len(cs.PendingBlocks)
	cs.SyncStatus.MissingBlockCount = int(targetHeight - cs.CurrentHeight)
	cs.SyncStatus.FailedAttempts = 0
	cs.SyncStatus.SyncErrors = make([]string, 0)
	
	// 添加起始检查点
	if cs.CurrentHeight > 0 {
		cs.AddCheckpoint(cs.CurrentHeight, cs.CurrentHash)
	}
	
	fmt.Printf("开始同步: 当前高度 %d, 目标高度 %d\n", cs.CurrentHeight, targetHeight)
}

// GetSyncProgress 获取同步进度
func (cs *ChainState) GetSyncProgress() (float64, *SyncStatus) {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	
	if !cs.SyncStatus.IsSyncing {
		return 100.0, cs.SyncStatus
	}
	
	totalBlocks := cs.SyncStatus.SyncTargetHeight - cs.SyncStatus.SyncStartHeight
	if totalBlocks == 0 {
		return 100.0, cs.SyncStatus
	}
	
	processedBlocks := cs.CurrentHeight - cs.SyncStatus.SyncStartHeight
	progress := float64(processedBlocks) / float64(totalBlocks) * 100.0
	
	return math.Min(progress, 100.0), cs.SyncStatus
}

// GetStats 获取状态统计
func (cs *ChainState) GetStats() map[string]interface{} {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	
	stats := map[string]interface{}{
		"current_height":      cs.CurrentHeight,
		"last_updated":        cs.LastUpdated,
		"pending_block_count": len(cs.PendingBlocks),
		"orphan_block_count":  len(cs.OrphanBlocks),
		"block_cache_size":    cs.BlockCache.Len(),
		"is_syncing":          cs.SyncStatus.IsSyncing,
	}
	
	if cs.SyncStatus.IsSyncing {
		progress, _ := cs.GetSyncProgress()
		stats["sync_progress"] = progress
		stats["sync_speed"] = cs.SyncStatus.SyncSpeed
		stats["estimated_completion"] = cs.estimateSyncCompletion()
	}
	
	return stats
}

// estimateSyncCompletion 估计同步完成时间
func (cs *ChainState) estimateSyncCompletion() time.Time {
	if !cs.SyncStatus.IsSyncing || cs.SyncStatus.SyncSpeed <= 0 {
		return time.Time{}
	}
	
	remainingBlocks := cs.SyncStatus.SyncTargetHeight - cs.CurrentHeight
	remainingSeconds := float64(remainingBlocks) / cs.SyncStatus.SyncSpeed
	
	return time.Now().Add(time.Duration(remainingSeconds) * time.Second)
}

// RetryOrphanBlocks 重试处理孤块
func (cs *ChainState) RetryOrphanBlocks() int {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	
	retried := 0
	now := time.Now()
	
	// 按照高度排序孤块，优先处理低高度的孤块
	type orphanWithPriority struct {
		hash    string
		orphan  *OrphanBlock
		priority int64  // 负值表示更高优先级
	}
	
	prioritizedOrphans := make([]orphanWithPriority, 0, len(cs.OrphanBlocks))
	
	// 计算每个孤块的优先级
	for hash, orphan := range cs.OrphanBlocks {
		// 优先级计算：高度越低、重试次数越少、年龄越大越优先
		height := int64(orphan.Info.Header.Height)
		retryCount := int64(orphan.Info.RetryCount)
		ageSeconds := int64(now.Sub(orphan.Info.ReceivedAt).Seconds())
		
		// 优先级计算公式（值越小优先级越高）
		priority := height - (ageSeconds / 60) + (retryCount * 10)
		
		prioritizedOrphans = append(prioritizedOrphans, orphanWithPriority{
			hash:     hash,
			orphan:   orphan,
			priority: priority,
		})
	}
	
	// 按优先级排序
	sort.Slice(prioritizedOrphans, func(i, j int) bool {
		return prioritizedOrphans[i].priority < prioritizedOrphans[j].priority
	})
	
	// 智能重试处理
	for _, item := range prioritizedOrphans {
		hash := item.hash
		orphan := item.orphan
		
		// 检查是否达到最大重试次数
		if orphan.Info.RetryCount >= cs.config.MaxRetryCount {
			continue
		}
		
		// 使用指数退避算法计算下一次重试时间
		var nextRetryDelay time.Duration
		if cs.config.SmartRetryEnabled {
			// 指数退避: initialDelay * 2^retryCount, 但不超过maxDelay
			retryCount := orphan.Info.RetryCount
			nextRetryDelay = cs.config.InitialRetryDelay * time.Duration(1<<uint(retryCount))
			if nextRetryDelay > cs.config.MaxRetryDelay {
				nextRetryDelay = cs.config.MaxRetryDelay
			}
		} else {
			nextRetryDelay = cs.config.RetryInterval
		}
		
		// 检查是否到达重试时间
		if orphan.Info.ProcessedAt.Add(nextRetryDelay).After(now) {
			continue
		}
		
		// 检查父区块是否现在可用
		prevHashStr := fmt.Sprintf("%x", orphan.MissingParent)
		
		if bytes.Equal(orphan.MissingParent, cs.CurrentHash) || // 父区块是当前头
		   cs.BlockCache.Get(prevHashStr) != nil || // 父区块在缓存中
		   cs.PendingBlocks[prevHashStr] != nil { // 父区块在待处理队列
			
			// 将孤块移到待处理队列
			cs.PendingBlocks[hash] = orphan.Info
			orphan.Info.State = BlockStatePending
			orphan.Info.RetryCount++
			orphan.Info.ProcessedAt = now
			
			// 从孤块池中移除
			delete(cs.OrphanBlocks, hash)
			
			// 处理以该区块为父区块的其他孤块
			cs.processOrphansByParent(orphan.Info.Header.BlockHash)
			
			retried++
			
			fmt.Printf("孤块处理成功：%s (高度: %d, 重试次数: %d)\n", 
				hash, orphan.Info.Header.Height, orphan.Info.RetryCount)
		}
	}
	
	return retried
}

// ResetState 重置链状态
func (cs *ChainState) ResetState() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	
	cs.CurrentHeight = 0
	cs.CurrentHash = nil
	cs.LastUpdated = time.Now()
	cs.PendingBlocks = make(map[string]*BlockInfo)
	cs.OrphanBlocks = make(map[string]*OrphanBlock)
	cs.BlockCache.Clear()
	
	cs.SyncStatus = &SyncStatus{
		IsSyncing:     false,
		LastBlockTime: time.Now(),
	}
}

// GetOrphanBlockStats 获取孤块统计信息
func (cs *ChainState) GetOrphanBlockStats() map[string]interface{} {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	
	// 计算各种统计信息
	totalOrphans := len(cs.OrphanBlocks)
	heightGroups := make(map[uint64]int)
	retryGroups := make(map[int]int)
	ageGroups := make(map[string]int)
	
	now := time.Now()
	oldestTime := now
	newestTime := time.Time{}
	totalRetries := 0
	
	for _, orphan := range cs.OrphanBlocks {
		// 按高度分组
		height := orphan.Info.Header.Height
		heightGroups[height]++
		
		// 按重试次数分组
		retryCount := orphan.Info.RetryCount
		retryGroups[retryCount]++
		totalRetries += retryCount
		
		// 按年龄分组
		age := now.Sub(orphan.Info.ReceivedAt)
		var ageGroup string
		switch {
		case age < 5*time.Minute:
			ageGroup = "< 5分钟"
		case age < 30*time.Minute:
			ageGroup = "5-30分钟"
		case age < 1*time.Hour:
			ageGroup = "30分钟-1小时"
		case age < 3*time.Hour:
			ageGroup = "1-3小时"
		default:
			ageGroup = "> 3小时"
		}
		ageGroups[ageGroup]++
		
		// 更新最老和最新时间
		if orphan.Info.ReceivedAt.Before(oldestTime) {
			oldestTime = orphan.Info.ReceivedAt
		}
		if orphan.Info.ReceivedAt.After(newestTime) {
			newestTime = orphan.Info.ReceivedAt
		}
	}
	
	// 计算平均重试次数
	avgRetries := 0.0
	if totalOrphans > 0 {
		avgRetries = float64(totalRetries) / float64(totalOrphans)
	}
	
	return map[string]interface{}{
		"总孤块数": totalOrphans,
		"按高度分布": heightGroups,
		"按重试次数分布": retryGroups,
		"按年龄分布": ageGroups,
		"平均重试次数": avgRetries,
		"最老孤块年龄": now.Sub(oldestTime).String(),
		"最新孤块年龄": now.Sub(newestTime).String(),
	}
}

// AddCheckpoint 添加同步检查点
func (cs *ChainState) AddCheckpoint(height uint64, blockHash []byte) {
	cs.checkpointMutex.Lock()
	defer cs.checkpointMutex.Unlock()
	
	// 记录检查点
	hashCopy := make([]byte, len(blockHash))
	copy(hashCopy, blockHash)
	cs.syncCheckpoints[height] = hashCopy
	
	// 更新最后检查点高度
	if height > cs.SyncStatus.LastCheckpoint {
		cs.SyncStatus.LastCheckpoint = height
		
		// 添加到检查点列表
		cs.SyncStatus.Checkpoints = append(cs.SyncStatus.Checkpoints, height)
		
		// 按高度排序检查点
		sort.Slice(cs.SyncStatus.Checkpoints, func(i, j int) bool {
			return cs.SyncStatus.Checkpoints[i] < cs.SyncStatus.Checkpoints[j]
		})
	}
	
	fmt.Printf("添加检查点：高度 %d, 哈希 %x\n", height, blockHash)
}

// VerifyCheckpoint 验证检查点
func (cs *ChainState) VerifyCheckpoint(height uint64, blockHash []byte) (bool, error) {
	cs.checkpointMutex.RLock()
	defer cs.checkpointMutex.RUnlock()
	
	// 查找对应高度的检查点
	if checkpointHash, exists := cs.syncCheckpoints[height]; exists {
		// 比较哈希值
		if bytes.Equal(checkpointHash, blockHash) {
			return true, nil
		}
		return false, fmt.Errorf("检查点验证失败：高度 %d, 预期哈希 %x, 实际哈希 %x", 
			height, checkpointHash, blockHash)
	}
	
	// 该高度没有检查点
	return true, nil
}

// SaveSyncState 保存同步状态以支持断点续传
func (cs *ChainState) SaveSyncState() ([]byte, error) {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	
	// 构建同步状态
	syncState := map[string]interface{}{
		"current_height":     cs.CurrentHeight,
		"current_hash":       cs.CurrentHash,
		"sync_start_height":  cs.SyncStatus.SyncStartHeight,
		"sync_target_height": cs.SyncStatus.SyncTargetHeight,
		"last_checkpoint":    cs.SyncStatus.LastCheckpoint,
		"checkpoints":        cs.SyncStatus.Checkpoints,
		"downloaded_blocks":  cs.downloadedBlocks,
		"timestamp":          time.Now().Unix(),
	}
	
	// 序列化为JSON
	data, err := json.Marshal(syncState)
	if err != nil {
		return nil, fmt.Errorf("序列化同步状态失败: %v", err)
	}
	
	return data, nil
}

// LoadSyncState 从保存的状态恢复同步
func (cs *ChainState) LoadSyncState(data []byte) error {
	// 解析同步状态
	var syncState map[string]interface{}
	err := json.Unmarshal(data, &syncState)
	if err != nil {
		return fmt.Errorf("解析同步状态失败: %v", err)
	}
	
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	
	// 恢复基本字段
	if val, ok := syncState["current_height"].(float64); ok {
		cs.CurrentHeight = uint64(val)
	}
	
	if val, ok := syncState["current_hash"].([]byte); ok {
		cs.CurrentHash = val
	}
	
	// 恢复同步状态
	if val, ok := syncState["sync_start_height"].(float64); ok {
		cs.SyncStatus.SyncStartHeight = uint64(val)
	}
	
	if val, ok := syncState["sync_target_height"].(float64); ok {
		cs.SyncStatus.SyncTargetHeight = uint64(val)
	}
	
	// 恢复检查点
	if val, ok := syncState["last_checkpoint"].(float64); ok {
		cs.SyncStatus.LastCheckpoint = uint64(val)
	}
	
	if checkpoints, ok := syncState["checkpoints"].([]interface{}); ok {
		cs.SyncStatus.Checkpoints = make([]uint64, 0, len(checkpoints))
		for _, cp := range checkpoints {
			if val, ok := cp.(float64); ok {
				cs.SyncStatus.Checkpoints = append(cs.SyncStatus.Checkpoints, uint64(val))
			}
		}
	}
	
	// 恢复已下载区块
	if blocks, ok := syncState["downloaded_blocks"].(map[string]interface{}); ok {
		cs.downloadedBlocks = make(map[uint64]string)
		for heightStr, hashVal := range blocks {
			var height uint64
			var hash string
			
			if _, err := fmt.Sscanf(heightStr, "%d", &height); err == nil {
				if hashStr, ok := hashVal.(string); ok {
					cs.downloadedBlocks[height] = hashStr
				}
			}
		}
	}
	
	fmt.Printf("恢复同步状态成功: 当前高度 %d, 目标高度 %d, 检查点数 %d\n",
		cs.CurrentHeight, cs.SyncStatus.SyncTargetHeight, len(cs.SyncStatus.Checkpoints))
	
	return nil
}

// PauseSyncProcess 暂停同步过程
func (cs *ChainState) PauseSyncProcess() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	
	if cs.SyncStatus.IsSyncing {
		cs.SyncStatus.SyncPaused = true
		cs.SyncStatus.ResumeFrom = cs.CurrentHeight
		fmt.Printf("同步已暂停，当前高度: %d\n", cs.CurrentHeight)
	}
}

// ResumeSyncProcess 恢复同步过程
func (cs *ChainState) ResumeSyncProcess() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	
	if cs.SyncStatus.SyncPaused {
		cs.SyncStatus.SyncPaused = false
		
		// 如果有恢复点，从恢复点开始
		if cs.SyncStatus.ResumeFrom > 0 {
			fmt.Printf("从高度 %d 恢复同步...\n", cs.SyncStatus.ResumeFrom)
		}
	}
}

// UpdateNetworkQuality 根据下载和验证情况更新网络质量评估
func (cs *ChainState) UpdateNetworkQuality(successRate float64, downloadSpeed float64) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	
	// 基于成功率和下载速度计算网络质量
	// 成功率占70%，下载速度占30%
	quality := int(successRate*70 + math.Min(1.0, downloadSpeed/1000000)*30)
	
	// 限制在0-100范围内
	if quality < 0 {
		quality = 0
	} else if quality > 100 {
		quality = 100
	}
	
	cs.networkQuality = quality
}

// GetNetworkQuality 获取网络质量评估
func (cs *ChainState) GetNetworkQuality() int {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	
	return cs.networkQuality
}

// RecordBlockDownloaded 记录区块已下载
func (cs *ChainState) RecordBlockDownloaded(height uint64, blockHash string) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	
	cs.downloadedBlocks[height] = blockHash
	
	// 如果是检查点高度，添加检查点
	if height % cs.checkpointInterval == 0 {
		hashBytes, _ := hex.DecodeString(blockHash)
		cs.AddCheckpoint(height, hashBytes)
	}
}

// IsBlockDownloaded 检查区块是否已下载
func (cs *ChainState) IsBlockDownloaded(height uint64) (string, bool) {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	
	hash, exists := cs.downloadedBlocks[height]
	return hash, exists
}

// GetSyncProgressDetails 获取详细同步进度
func (cs *ChainState) GetSyncProgressDetails() map[string]interface{} {
	progress, status := cs.GetSyncProgress()
	
	// 获取更多同步细节
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	
	// 计算各区间完成比例
	heightRanges := make(map[string]float64)
	
	if status.SyncTargetHeight > status.SyncStartHeight {
		totalRange := status.SyncTargetHeight - status.SyncStartHeight
		chunkSize := totalRange / 10
		
		for i := uint64(0); i < 10; i++ {
			startHeight := status.SyncStartHeight + i*chunkSize
			endHeight := status.SyncStartHeight + (i+1)*chunkSize
			if endHeight > status.SyncTargetHeight {
				endHeight = status.SyncTargetHeight
			}
			
			// 统计这个区间内有多少区块已下载
			var downloadedInRange uint64 = 0
			for height := startHeight; height <= endHeight; height++ {
				if _, exists := cs.downloadedBlocks[height]; exists {
					downloadedInRange++
				}
			}
			
			// 计算该区间完成比例
			rangeTotal := endHeight - startHeight
			var rangeProgress float64 = 0
			if rangeTotal > 0 {
				rangeProgress = float64(downloadedInRange) / float64(rangeTotal) * 100
			}
			
			// 格式化区间名称
			rangeName := fmt.Sprintf("%d-%d", startHeight, endHeight)
			heightRanges[rangeName] = rangeProgress
		}
	}
	
	return map[string]interface{}{
		"总进度": progress,
		"当前高度": status.CurrentHeight,
		"目标高度": status.SyncTargetHeight,
		"待处理区块": status.PendingBlockCount,
		"已处理区块": status.ProcessedBlocks,
		"已拒绝区块": status.RejectedBlocks,
		"同步速度": status.SyncSpeed,
		"网络质量": cs.networkQuality,
		"同步检查点": status.Checkpoints,
		"最后检查点": status.LastCheckpoint,
		"区间完成度": heightRanges,
		"已用时间": time.Since(status.SyncStartTime).String(),
		"预计剩余时间": cs.estimateRemainingTime(),
		"同步是否暂停": status.SyncPaused,
		"同步错误": status.SyncErrors,
	}
}

// estimateRemainingTime 估计剩余同步时间
func (cs *ChainState) estimateRemainingTime() string {
	if !cs.SyncStatus.IsSyncing || cs.SyncStatus.SyncSpeed <= 0 {
		return "未知"
	}
	
	remainingBlocks := cs.SyncStatus.SyncTargetHeight - cs.CurrentHeight
	remainingSeconds := float64(remainingBlocks) / cs.SyncStatus.SyncSpeed
	
	// 根据网络质量调整估计时间
	adjustedSeconds := remainingSeconds * (100.0 / float64(cs.networkQuality))
	
	duration := time.Duration(adjustedSeconds) * time.Second
	
	// 格式化时间
	hours := int(duration.Hours())
	minutes := int(duration.Minutes()) % 60
	seconds := int(duration.Seconds()) % 60
	
	if hours > 0 {
		return fmt.Sprintf("%d时%d分%d秒", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%d分%d秒", minutes, seconds)
	}
	
	return fmt.Sprintf("%d秒", seconds)
}

// OrphanBlockManager 孤立区块管理器
type OrphanBlockManager struct {
	orphans       map[string]*OrphanBlock   // 孤立区块映射
	parentIndex   map[string][]string       // 父区块到孤立区块的映射
	mutex         sync.RWMutex              // 读写锁
	maxOrphans    int                        // 最大孤立区块数量
	expireTime    time.Duration              // 过期时间
	lastPruneTime time.Time                  // 上次清理时间
	statsCounter  *OrphanStats               // 统计计数器
}

// OrphanBlock 孤立区块结构
type OrphanBlock struct {
	BlockHash      string                   // 区块哈希
	ParentHash     string                   // 父区块哈希
	BlockData      []byte                   // 区块数据
	ReceivedTime   time.Time                // 接收时间
	RetryCount     int                      // 重试次数
	LastRetryTime  time.Time                // 上次重试时间
	Source         string                   // 来源节点
}

// OrphanStats 孤立区块统计
type OrphanStats struct {
	TotalReceived  int64                    // 总接收数
	TotalProcessed int64                    // 总处理数
	TotalExpired   int64                    // 总过期数
	TotalRejected  int64                    // 总拒绝数
	MaxOrphansHeld int                      // 最大持有数
}

// NewOrphanBlockManager 创建新的孤立区块管理器
func NewOrphanBlockManager(maxOrphans int, expireTime time.Duration) *OrphanBlockManager {
	return &OrphanBlockManager{
		orphans:       make(map[string]*OrphanBlock),
		parentIndex:   make(map[string][]string),
		maxOrphans:    maxOrphans,
		expireTime:    expireTime,
		lastPruneTime: time.Now(),
		statsCounter:  &OrphanStats{},
	}
}

// AddOrphanBlock 添加孤立区块
func (om *OrphanBlockManager) AddOrphanBlock(block *OrphanBlock) bool {
	om.mutex.Lock()
	defer om.mutex.Unlock()
	
	// 检查是否已存在
	if _, exists := om.orphans[block.BlockHash]; exists {
		return false
	}
	
	// 如果达到最大数量，先清理一些
	if len(om.orphans) >= om.maxOrphans {
		om.pruneExpiredOrphans()
		
		// 如果仍然达到最大数量，移除最旧的
		if len(om.orphans) >= om.maxOrphans {
			om.removeOldestOrphan()
		}
	}
	
	// 添加到孤立区块映射
	om.orphans[block.BlockHash] = block
	
	// 更新父区块索引
	parentHashes, exists := om.parentIndex[block.ParentHash]
	if !exists {
		parentHashes = []string{}
	}
	om.parentIndex[block.ParentHash] = append(parentHashes, block.BlockHash)
	
	// 更新统计
	om.statsCounter.TotalReceived++
	if len(om.orphans) > om.statsCounter.MaxOrphansHeld {
		om.statsCounter.MaxOrphansHeld = len(om.orphans)
	}
	
	return true
}

// GetOrphanBlock 获取孤立区块
func (om *OrphanBlockManager) GetOrphanBlock(blockHash string) *OrphanBlock {
	om.mutex.RLock()
	defer om.mutex.RUnlock()
	
	return om.orphans[blockHash]
}

// removeOldestOrphan 移除最老的孤立区块
func (om *OrphanBlockManager) removeOldestOrphan() {
	var oldestTime time.Time
	var oldestHash string
	
	// 找出最老的孤立区块
	for hash, block := range om.orphans {
		if oldestHash == "" || block.ReceivedTime.Before(oldestTime) {
			oldestHash = hash
			oldestTime = block.ReceivedTime
		}
	}
	
	// 如果找到，则移除
	if oldestHash != "" {
		om.RemoveOrphan(oldestHash)
	}
}

// RetryAllOrphans 尝试重新处理所有孤立区块
func (om *OrphanBlockManager) RetryAllOrphans(processFunc func([]byte) bool) int {
	om.mutex.RLock()
	
	// 将所有孤立区块的哈希复制到一个切片
	orphanHashes := make([]string, 0, len(om.orphans))
	for hash := range om.orphans {
		orphanHashes = append(orphanHashes, hash)
	}
	
	om.mutex.RUnlock()
	
	// 尝试处理所有孤立区块
	processedCount := 0
	for _, hash := range orphanHashes {
		if om.ProcessOrphanBlock(hash, processFunc) {
			processedCount++
		}
	}
	
	return processedCount
}

// ScheduleOrphanRetry 定期尝试处理孤立区块
func (om *OrphanBlockManager) ScheduleOrphanRetry(interval time.Duration, processFunc func([]byte) bool) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		
		for {
			<-ticker.C
			om.RetryAllOrphans(processFunc)
			om.pruneExpiredOrphans()
		}
	}()
}

// GetOrphanStats 获取孤立区块统计
func (om *OrphanBlockManager) GetOrphanStats() OrphanStats {
	om.mutex.RLock()
	defer om.mutex.RUnlock()
	
	// 克隆统计数据
	stats := *om.statsCounter
	stats.MaxOrphansHeld = len(om.orphans) // 更新当前持有数
	
	return stats
}

// StateSyncManager 状态同步管理器
type StateSyncManager struct {
	syncTasks      map[string]*SyncTask      // 同步任务映射
	taskQueue      []*SyncTask               // 任务队列
	taskMutex      sync.RWMutex              // 任务互斥锁
	maxTasks       int                       // 最大任务数
	checkpointDir  string                    // 检查点目录
	networkMgr     *P2PSecurityManager       // 网络安全管理器
	maxRetries     int                       // 最大重试次数
	retryInterval  time.Duration             // 重试间隔
	taskTimeout    time.Duration             // 任务超时时间
	running        bool                      // 是否运行中
	stopChan       chan bool                 // 停止信号
}

// SyncTask 同步任务
type SyncTask struct {
	TaskID         string                    // 任务ID
	StartBlock     uint64                    // 起始区块
	EndBlock       uint64                    // 结束区块
	CurrentBlock   uint64                    // 当前区块
	PeerID         string                    // 对等节点ID
	State          SyncTaskState             // 任务状态
	Progress       float64                   // 进度百分比
	CreatedAt      time.Time                 // 创建时间
	LastUpdatedAt  time.Time                 // 最后更新时间
	RetryCount     int                       // 重试次数
	Checkpoints    []uint64                  // 检查点列表
	ChunkSize      uint64                    // 块大小
	VerifyHashes   bool                      // 是否验证哈希
	Priority       int                       // 优先级
}

// SyncTaskState 同步任务状态
type SyncTaskState int

const (
	SyncTaskPending   SyncTaskState = iota // 等待中
	SyncTaskRunning                        // 运行中
	SyncTaskPaused                         // 暂停
	SyncTaskCompleted                      // 完成
	SyncTaskFailed                         // 失败
)

// NewStateSyncManager 创建新的状态同步管理器
func NewStateSyncManager(checkpointDir string, networkMgr *P2PSecurityManager, maxTasks int) *StateSyncManager {
	return &StateSyncManager{
		syncTasks:     make(map[string]*SyncTask),
		taskQueue:     make([]*SyncTask, 0),
		maxTasks:      maxTasks,
		checkpointDir: checkpointDir,
		networkMgr:    networkMgr,
		maxRetries:    3,
		retryInterval: 30 * time.Second,
		taskTimeout:   10 * time.Minute,
		stopChan:      make(chan bool, 1),
	}
}

// CreateSyncTask 创建同步任务
func (sm *StateSyncManager) CreateSyncTask(startBlock, endBlock uint64, peerID string, chunkSize uint64, verifyHashes bool, priority int) string {
	sm.taskMutex.Lock()
	defer sm.taskMutex.Unlock()
	
	// 生成任务ID
	taskID := fmt.Sprintf("sync-%s-%d-%d", peerID, startBlock, time.Now().UnixNano())
	
	// 计算检查点
	checkpoints := sm.calculateCheckpoints(startBlock, endBlock, chunkSize)
	
	// 创建任务
	task := &SyncTask{
		TaskID:        taskID,
		StartBlock:    startBlock,
		EndBlock:      endBlock,
		CurrentBlock:  startBlock,
		PeerID:        peerID,
		State:         SyncTaskPending,
		Progress:      0.0,
		CreatedAt:     time.Now(),
		LastUpdatedAt: time.Now(),
		RetryCount:    0,
		Checkpoints:   checkpoints,
		ChunkSize:     chunkSize,
		VerifyHashes:  verifyHashes,
		Priority:      priority,
	}
	
	// 添加到任务映射和队列
	sm.syncTasks[taskID] = task
	sm.insertTaskByPriority(task)
	
	return taskID
}

// calculateCheckpoints 计算检查点列表
func (sm *StateSyncManager) calculateCheckpoints(startBlock, endBlock, chunkSize uint64) []uint64 {
	checkpoints := make([]uint64, 0)
	
	// 至少要有一个检查点（起始位置）
	checkpoints = append(checkpoints, startBlock)
	
	// 根据块大小添加检查点
	for block := startBlock + chunkSize; block < endBlock; block += chunkSize {
		checkpoints = append(checkpoints, block)
	}
	
	// 确保终点也是一个检查点
	if checkpoints[len(checkpoints)-1] != endBlock {
		checkpoints = append(checkpoints, endBlock)
	}
	
	return checkpoints
}

// insertTaskByPriority 按优先级插入任务
func (sm *StateSyncManager) insertTaskByPriority(task *SyncTask) {
	// 如果队列为空，直接添加
	if len(sm.taskQueue) == 0 {
		sm.taskQueue = append(sm.taskQueue, task)
		return
	}
	
	// 按优先级插入（高优先级靠前）
	for i, t := range sm.taskQueue {
		if task.Priority > t.Priority {
			// 插入到当前位置
			sm.taskQueue = append(sm.taskQueue[:i], append([]*SyncTask{task}, sm.taskQueue[i:]...)...)
			return
		}
	}
	
	// 如果没有找到更高优先级，添加到末尾
	sm.taskQueue = append(sm.taskQueue, task)
}

// Start 启动同步管理器
func (sm *StateSyncManager) Start() {
	if sm.running {
		return
	}
	
	sm.running = true
	
	// 启动任务处理循环
	go sm.processTasksLoop()
	
	// 启动检查点保存循环
	go sm.checkpointLoop()
}

// Stop 停止同步管理器
func (sm *StateSyncManager) Stop() {
	if !sm.running {
		return
	}
	
	sm.running = false
	sm.stopChan <- true
	
	// 保存所有任务状态
	sm.saveAllTaskCheckpoints()
}

// processTasksLoop 任务处理循环
func (sm *StateSyncManager) processTasksLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-sm.stopChan:
			return
		case <-ticker.C:
			sm.processPendingTasks()
			sm.retryFailedTasks()
		}
	}
}

// processPendingTasks 处理待处理的任务
func (sm *StateSyncManager) processPendingTasks() {
	sm.taskMutex.Lock()
	defer sm.taskMutex.Unlock()
	
	// 计算当前正在运行的任务数
	runningCount := 0
	for _, task := range sm.syncTasks {
		if task.State == SyncTaskRunning {
			runningCount++
		}
	}
	
	// 如果已经达到最大任务数，不再处理新任务
	if runningCount >= sm.maxTasks {
		return
	}
	
	// 处理等待中的任务（按优先级顺序）
	tasksToStart := sm.maxTasks - runningCount
	startedTasks := 0
	
	for i := 0; i < len(sm.taskQueue) && startedTasks < tasksToStart; i++ {
		task := sm.taskQueue[i]
		if task.State == SyncTaskPending {
			// 更新任务状态
			task.State = SyncTaskRunning
			task.LastUpdatedAt = time.Now()
			
			// 启动任务（在新的goroutine中）
			go sm.runTask(task.TaskID)
			
			startedTasks++
		}
	}
}

// retryFailedTasks 重试失败的任务
func (sm *StateSyncManager) retryFailedTasks() {
	sm.taskMutex.Lock()
	defer sm.taskMutex.Unlock()
	
	now := time.Now()
	
	for _, task := range sm.syncTasks {
		// 只处理失败状态的任务
		if task.State != SyncTaskFailed {
			continue
		}
		
		// 检查是否可以重试
		if task.RetryCount < sm.maxRetries && 
		   now.Sub(task.LastUpdatedAt) >= sm.retryInterval {
			// 更新任务状态
			task.State = SyncTaskPending
			task.RetryCount++
			task.LastUpdatedAt = now
			
			// 重新插入任务队列
			sm.insertTaskByPriority(task)
		}
	}
}

// saveTaskCheckpoint 保存任务检查点
func (sm *StateSyncManager) saveTaskCheckpoint(taskID string) error {
	sm.taskMutex.RLock()
	task, exists := sm.syncTasks[taskID]
	sm.taskMutex.RUnlock()
	
	if !exists {
		return fmt.Errorf("任务不存在: %s", taskID)
	}
	
	// 创建检查点目录（如果不存在）
	checkpointPath := fmt.Sprintf("%s/%s", sm.checkpointDir, taskID)
	os.MkdirAll(checkpointPath, 0755)
	
	// 准备检查点数据
	checkpointData := map[string]interface{}{
		"task_id":       task.TaskID,
		"start_block":   task.StartBlock,
		"end_block":     task.EndBlock,
		"current_block": task.CurrentBlock,
		"peer_id":       task.PeerID,
		"state":         int(task.State),
		"progress":      task.Progress,
		"retry_count":   task.RetryCount,
		"checkpoints":   task.Checkpoints,
		"updated_at":    time.Now().Unix(),
	}
	
	// 序列化为JSON
	data, err := json.Marshal(checkpointData)
	if err != nil {
		return fmt.Errorf("序列化检查点数据失败: %v", err)
	}
	
	// 写入文件
	checkpointFile := fmt.Sprintf("%s/checkpoint.json", checkpointPath)
	return os.WriteFile(checkpointFile, data, 0644)
}

// loadTaskCheckpoint 加载任务检查点
func (sm *StateSyncManager) loadTaskCheckpoint(taskID string) (*SyncTask, error) {
	checkpointFile := fmt.Sprintf("%s/%s/checkpoint.json", sm.checkpointDir, taskID)
	
	// 读取文件
	data, err := os.ReadFile(checkpointFile)
	if err != nil {
		return nil, fmt.Errorf("读取检查点文件失败: %v", err)
	}
	
	// 解析JSON
	var checkpointData map[string]interface{}
	if err := json.Unmarshal(data, &checkpointData); err != nil {
		return nil, fmt.Errorf("解析检查点数据失败: %v", err)
	}
	
	// 创建任务对象
	task := &SyncTask{
		TaskID:       checkpointData["task_id"].(string),
		StartBlock:   uint64(checkpointData["start_block"].(float64)),
		EndBlock:     uint64(checkpointData["end_block"].(float64)),
		CurrentBlock: uint64(checkpointData["current_block"].(float64)),
		PeerID:       checkpointData["peer_id"].(string),
		State:        SyncTaskState(int(checkpointData["state"].(float64))),
		Progress:     checkpointData["progress"].(float64),
		RetryCount:   int(checkpointData["retry_count"].(float64)),
		LastUpdatedAt: time.Now(),
	}
	
	// 解析检查点列表
	checkpointsData := checkpointData["checkpoints"].([]interface{})
	task.Checkpoints = make([]uint64, len(checkpointsData))
	for i, cp := range checkpointsData {
		task.Checkpoints[i] = uint64(cp.(float64))
	}
	
	return task, nil
}

// saveAllTaskCheckpoints 保存所有任务检查点
func (sm *StateSyncManager) saveAllTaskCheckpoints() {
	sm.taskMutex.RLock()
	taskIDs := make([]string, 0, len(sm.syncTasks))
	for taskID := range sm.syncTasks {
		taskIDs = append(taskIDs, taskID)
	}
	sm.taskMutex.RUnlock()
	
	// 逐个保存检查点
	for _, taskID := range taskIDs {
		sm.saveTaskCheckpoint(taskID)
	}
}

// checkpointLoop 检查点保存循环
func (sm *StateSyncManager) checkpointLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-sm.stopChan:
			return
		case <-ticker.C:
			sm.saveAllTaskCheckpoints()
		}
	}
}

// runTask 运行同步任务
func (sm *StateSyncManager) runTask(taskID string) {
	// 获取任务
	sm.taskMutex.RLock()
	task, exists := sm.syncTasks[taskID]
	if !exists {
		sm.taskMutex.RUnlock()
		return
	}
	sm.taskMutex.RUnlock()
	
	// 定义处理函数
	processBlock := func(blockNum uint64) bool {
		// 请求区块数据（实际应用中需要实现网络请求）
		// 这里使用P2PSecurityManager发送安全消息来获取区块
		requestData := fmt.Sprintf(`{"method":"getBlock","params":["%d"]}`, blockNum)
		
		// 获取区块数据（实际应用中需要实现）
		_, err := sm.networkMgr.SendSecureMessageWithRetry(
			task.PeerID,
			1, // 假设1代表区块请求
			[]byte(requestData),
			PriorityNormal,
			fmt.Sprintf("sync-%s-%d", taskID, blockNum),
		)
		
		if err != nil {
			// 请求失败，任务失败
			sm.taskMutex.Lock()
			task.State = SyncTaskFailed
			task.LastUpdatedAt = time.Now()
			sm.taskMutex.Unlock()
			return false
		}
		
		// 这里简化处理，实际应用中需要处理响应并验证区块
		time.Sleep(100 * time.Millisecond) // 模拟处理时间
		
		// 更新任务进度
		sm.taskMutex.Lock()
		task.CurrentBlock = blockNum
		task.Progress = float64(blockNum-task.StartBlock) / float64(task.EndBlock-task.StartBlock) * 100
		task.LastUpdatedAt = time.Now()
		
		// 检查任务是否完成
		isCompleted := blockNum >= task.EndBlock
		if isCompleted {
			task.State = SyncTaskCompleted
			task.Progress = 100.0
		}
		sm.taskMutex.Unlock()
		
		// 到达检查点或任务完成时保存检查点
		if isCompleted || sm.isCheckpoint(task, blockNum) {
			sm.saveTaskCheckpoint(taskID)
		}
		
		return !isCompleted // 如果任务完成则返回false停止处理
	}
	
	// 从当前区块开始处理
	currentBlock := task.CurrentBlock
	for currentBlock <= task.EndBlock {
		// 检查任务是否被暂停或停止
		sm.taskMutex.RLock()
		state := task.State
		sm.taskMutex.RUnlock()
		
		if state != SyncTaskRunning {
			break
		}
		
		// 处理当前区块
		continueProcessing := processBlock(currentBlock)
		if !continueProcessing {
			break
		}
		
		currentBlock++
	}
}

// isCheckpoint 检查是否是检查点
func (sm *StateSyncManager) isCheckpoint(task *SyncTask, blockNum uint64) bool {
	for _, cp := range task.Checkpoints {
		if cp == blockNum {
			return true
		}
	}
	return false
}

// ResumeTask 恢复任务
func (sm *StateSyncManager) ResumeTask(taskID string) error {
	sm.taskMutex.Lock()
	defer sm.taskMutex.Unlock()
	
	task, exists := sm.syncTasks[taskID]
	if !exists {
		return fmt.Errorf("任务不存在: %s", taskID)
	}
	
	if task.State != SyncTaskPaused && task.State != SyncTaskFailed {
		return fmt.Errorf("任务状态不允许恢复: %d", task.State)
	}
	
	// 更新状态为待处理
	task.State = SyncTaskPending
	task.LastUpdatedAt = time.Now()
	
	// 重新加入队列
	sm.insertTaskByPriority(task)
	
	return nil
}

// StateVerifier 状态校验器
type StateVerifier struct {
	blockHashes    map[uint64]string   // 区块高度到哈希的映射
	merkleRoots    map[uint64]string   // 区块高度到Merkle根的映射
	stateRoots     map[uint64]string   // 区块高度到状态根的映射
	verifiedBlocks map[uint64]bool     // 已验证的区块集合
	mutex          sync.RWMutex        // 读写锁
}

// NewStateVerifier 创建新的状态校验器
func NewStateVerifier() *StateVerifier {
	return &StateVerifier{
		blockHashes:    make(map[uint64]string),
		merkleRoots:    make(map[uint64]string),
		stateRoots:     make(map[uint64]string),
		verifiedBlocks: make(map[uint64]bool),
	}
}

// RegisterBlockHash 注册区块哈希
func (sv *StateVerifier) RegisterBlockHash(height uint64, hash string) {
	sv.mutex.Lock()
	defer sv.mutex.Unlock()
	sv.blockHashes[height] = hash
}

// RegisterMerkleRoot 注册Merkle根
func (sv *StateVerifier) RegisterMerkleRoot(height uint64, root string) {
	sv.mutex.Lock()
	defer sv.mutex.Unlock()
	sv.merkleRoots[height] = root
}

// RegisterStateRoot 注册状态根
func (sv *StateVerifier) RegisterStateRoot(height uint64, root string) {
	sv.mutex.Lock()
	defer sv.mutex.Unlock()
	sv.stateRoots[height] = root
}

// VerifyBlock 验证区块完整性
func (sv *StateVerifier) VerifyBlock(height uint64, blockData []byte) (bool, error) {
	sv.mutex.RLock()
	expectedHash, hashExists := sv.blockHashes[height]
	expectedMerkleRoot, merkleExists := sv.merkleRoots[height]
	sv.mutex.RUnlock()
	
	// 如果没有期望的哈希或Merkle根，无法验证
	if !hashExists && !merkleExists {
		return false, fmt.Errorf("无验证数据可用于区块 %d", height)
	}
	
	// 计算区块哈希
	blockHash := fmt.Sprintf("%x", sha256.Sum256(blockData))
	
	// 如果有期望的哈希，进行验证
	if hashExists && blockHash != expectedHash {
		return false, fmt.Errorf("区块哈希不匹配: 期望 %s, 实际 %s", expectedHash, blockHash)
	}
	
	// 如果有期望的Merkle根，解析区块并验证
	if merkleExists {
		// 这里简化处理，实际应用中需要解析区块并提取Merkle根
		// 然后与期望的Merkle根进行比较
		
		// merkleRoot := extractMerkleRoot(blockData)
		// if merkleRoot != expectedMerkleRoot {
		//     return false, fmt.Errorf("Merkle根不匹配: 期望 %s, 实际 %s", expectedMerkleRoot, merkleRoot)
		// }
	}
	
	// 验证通过，标记为已验证
	sv.mutex.Lock()
	sv.verifiedBlocks[height] = true
	sv.mutex.Unlock()
	
	return true, nil
}

// VerifyStateConsistency 验证状态一致性
func (sv *StateVerifier) VerifyStateConsistency(startHeight, endHeight uint64) (bool, []uint64, error) {
	sv.mutex.RLock()
	defer sv.mutex.RUnlock()
	
	missingBlocks := make([]uint64, 0)
	
	// 检查连续性
	for height := startHeight; height <= endHeight; height++ {
		if _, verified := sv.verifiedBlocks[height]; !verified {
			missingBlocks = append(missingBlocks, height)
		}
	}
	
	if len(missingBlocks) > 0 {
		return false, missingBlocks, fmt.Errorf("状态不完整: 缺少 %d 个区块", len(missingBlocks))
	}
	
	// 检查状态根一致性（如果可用）
	// 实际应用中可能需要更复杂的逻辑来验证状态转换的正确性
	
	return true, nil, nil
}

// GetVerificationProgress 获取验证进度
func (sv *StateVerifier) GetVerificationProgress(startHeight, endHeight uint64) float64 {
	sv.mutex.RLock()
	defer sv.mutex.RUnlock()
	
	if startHeight > endHeight {
		return 100.0
	}
	
	totalBlocks := endHeight - startHeight + 1
	verifiedCount := 0
	
	for height := startHeight; height <= endHeight; height++ {
		if _, verified := sv.verifiedBlocks[height]; verified {
			verifiedCount++
		}
	}
	
	return float64(verifiedCount) / float64(totalBlocks) * 100.0
}

// P2PStateSyncAPI P2P状态同步API
type P2PStateSyncAPI struct {
	syncManager      *StateSyncManager     // 同步管理器
	orphanManager    *OrphanBlockManager   // 孤立区块管理器
	stateVerifier    *StateVerifier        // 状态校验器
	p2pManager       *P2PSecurityManager   // P2P安全管理器
	dataCache        *LRUCache             // 数据缓存
	checkpointDir    string                // 检查点目录
	syncInProgress   bool                  // 是否正在同步
	mutex            sync.RWMutex          // 读写锁
}

// NewP2PStateSyncAPI 创建新的P2P状态同步API
func NewP2PStateSyncAPI(p2pManager *P2PSecurityManager, checkpointDir string) *P2PStateSyncAPI {
	// 创建LRU缓存
	dataCache := NewLRUCache(1000, 100*1024*1024)
	
	// 创建孤立区块管理器
	orphanManager := NewOrphanBlockManager(500, 30*time.Minute)
	
	// 创建状态校验器
	stateVerifier := NewStateVerifier()
	
	// 创建同步管理器
	syncManager := NewStateSyncManager(checkpointDir, p2pManager, 5)
	
	api := &P2PStateSyncAPI{
		syncManager:    syncManager,
		orphanManager:  orphanManager,
		stateVerifier:  stateVerifier,
		p2pManager:     p2pManager,
		dataCache:      dataCache,
		checkpointDir:  checkpointDir,
		syncInProgress: false,
	}
	
	// 启动孤立区块重试
	orphanManager.ScheduleOrphanRetry(5*time.Minute, api.ProcessOrphanBlock)
	
	return api
}

// Start 启动同步
func (api *P2PStateSyncAPI) Start() {
	api.mutex.Lock()
	defer api.mutex.Unlock()
	
	if api.syncInProgress {
		return
	}
	
	api.syncInProgress = true
	api.syncManager.Start()
}

// Stop 停止同步
func (api *P2PStateSyncAPI) Stop() {
	api.mutex.Lock()
	defer api.mutex.Unlock()
	
	if !api.syncInProgress {
		return
	}
	
	api.syncInProgress = false
	api.syncManager.Stop()
}

// StartSync 开始同步指定范围的区块
func (api *P2PStateSyncAPI) StartSync(peerID string, startBlock, endBlock uint64, verifyHashes bool) string {
	api.mutex.Lock()
	defer api.mutex.Unlock()
	
	// 确保同步已启动
	if !api.syncInProgress {
		api.Start()
	}
	
	// 创建同步任务
	return api.syncManager.CreateSyncTask(startBlock, endBlock, peerID, 100, verifyHashes, 1)
}

// ProcessOrphanBlock 处理孤立区块
func (api *P2PStateSyncAPI) ProcessOrphanBlock(blockData []byte) bool {
	// 解析区块高度（实际应用中需要解析区块数据）
	// 这里简化处理
	if len(blockData) < 8 {
		return false
	}
	
	// 假设前8字节是区块高度
	height := binary.BigEndian.Uint64(blockData[:8])
	
	// 验证区块
	verified, err := api.stateVerifier.VerifyBlock(height, blockData)
	if err != nil || !verified {
		return false
	}
	
	// 缓存区块
	api.dataCache.Add(fmt.Sprintf("block-%d", height), blockData, len(blockData))
	
	return true
}

// ReportOrphanBlock 报告孤立区块
func (api *P2PStateSyncAPI) ReportOrphanBlock(blockHash, parentHash string, blockData []byte, source string) bool {
	orphanBlock := &OrphanBlock{
		BlockHash:     blockHash,
		ParentHash:    parentHash,
		BlockData:     blockData,
		ReceivedTime:  time.Now(),
		RetryCount:    0,
		LastRetryTime: time.Time{},
		Source:        source,
	}
	
	return api.orphanManager.AddOrphanBlock(orphanBlock)
}

// GetSyncStatus 获取同步状态
func (api *P2PStateSyncAPI) GetSyncStatus() map[string]interface{} {
	api.mutex.RLock()
	defer api.mutex.RUnlock()
	
	orphanStats := api.orphanManager.GetOrphanStats()
	cacheStats := api.dataCache.GetStats()
	
	// 统计正在运行的任务
	runningTasks := 0
	completedTasks := 0
	
	api.syncManager.taskMutex.RLock()
	for _, task := range api.syncManager.syncTasks {
		if task.State == SyncTaskRunning {
			runningTasks++
		} else if task.State == SyncTaskCompleted {
			completedTasks++
		}
	}
	api.syncManager.taskMutex.RUnlock()
	
	return map[string]interface{}{
		"sync_in_progress":  api.syncInProgress,
		"running_tasks":     runningTasks,
		"completed_tasks":   completedTasks,
		"orphan_blocks":     orphanStats.MaxOrphansHeld,
		"processed_orphans": orphanStats.TotalProcessed,
		"cache_hit_rate":    cacheStats["hit_rate"],
		"cache_usage":       cacheStats["memory_usage"],
	}
}