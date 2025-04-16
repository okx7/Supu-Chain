package mobile

import (
	"container/list"
	"fmt"
	"sync"
	"time"
)

// LRUCache LRU缓存实现
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
	onEvict     func(key string, value interface{}) // 淘汰回调
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

// NewLRUCache 创建新的LRU缓存
func NewLRUCache(capacity int, maxBytes int64) *LRUCache {
	return &LRUCache{
		capacity:  capacity,
		items:     make(map[string]*list.Element),
		evictList: list.New(),
		maxBytes:  maxBytes,
		created:   time.Now(),
	}
}

// SetEvictCallback 设置淘汰回调
func (c *LRUCache) SetEvictCallback(callback func(key string, value interface{})) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.onEvict = callback
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

// Add 添加缓存项
func (c *LRUCache) Add(key string, value interface{}, size int) bool {
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

// SizeBytes 获取缓存占用字节数
func (c *LRUCache) SizeBytes() int64 {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.sizeBytes
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

// Values 获取所有值
func (c *LRUCache) Values() []interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	values := make([]interface{}, 0, len(c.items))
	for _, v := range c.items {
		e := v.Value.(*entry)
		values = append(values, e.value)
	}
	
	return values
}

// Entries 获取所有条目
func (c *LRUCache) Entries() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	entries := make(map[string]interface{}, len(c.items))
	for k, v := range c.items {
		e := v.Value.(*entry)
		entries[k] = e.value
	}
	
	return entries
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

// TTLCache 带过期时间的缓存
type TTLCache struct {
	cache       *LRUCache           // 底层LRU缓存
	expiration  map[string]time.Time // 过期时间映射
	mutex       sync.RWMutex         // 读写锁
	defaultTTL  time.Duration        // 默认过期时间
	cleanupTick time.Duration        // 清理周期
	stopCh      chan struct{}        // 停止通道
}

// NewTTLCache 创建新的TTL缓存
func NewTTLCache(capacity int, maxBytes int64, defaultTTL time.Duration) *TTLCache {
	c := &TTLCache{
		cache:       NewLRUCache(capacity, maxBytes),
		expiration:  make(map[string]time.Time),
		defaultTTL:  defaultTTL,
		cleanupTick: time.Minute,
		stopCh:      make(chan struct{}),
	}
	
	// 启动自动清理协程
	go c.startCleanup()
	
	return c
}

// Set 设置缓存项
func (c *TTLCache) Set(key string, value interface{}, size int) {
	c.SetWithTTL(key, value, size, c.defaultTTL)
}

// SetWithTTL 设置带过期时间的缓存项
func (c *TTLCache) SetWithTTL(key string, value interface{}, size int, ttl time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// 添加到底层缓存
	c.cache.Add(key, value, size)
	
	// 设置过期时间
	if ttl > 0 {
		c.expiration[key] = time.Now().Add(ttl)
	}
}

// Get 获取缓存项
func (c *TTLCache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	
	// 检查是否已过期
	if expiry, found := c.expiration[key]; found && time.Now().After(expiry) {
		c.mutex.RUnlock()
		c.Remove(key) // 过期则移除
		return nil, false
	}
	
	c.mutex.RUnlock()
	
	// 从底层缓存获取
	return c.cache.Get(key)
}

// Remove 移除缓存项
func (c *TTLCache) Remove(key string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// 从过期时间映射移除
	delete(c.expiration, key)
	
	// 从底层缓存移除
	return c.cache.Remove(key)
}

// Clear 清空缓存
func (c *TTLCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.expiration = make(map[string]time.Time)
	c.cache.Clear()
}

// Len 获取缓存项数量
func (c *TTLCache) Len() int {
	return c.cache.Len()
}

// SetDefaultTTL 设置默认过期时间
func (c *TTLCache) SetDefaultTTL(ttl time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.defaultTTL = ttl
}

// GetStats 获取缓存统计信息
func (c *TTLCache) GetStats() map[string]interface{} {
	c.mutex.RLock()
	expiredCount := 0
	now := time.Now()
	
	// 计算已过期项数
	for _, expiry := range c.expiration {
		if now.After(expiry) {
			expiredCount++
		}
	}
	c.mutex.RUnlock()
	
	// 获取基础缓存统计
	stats := c.cache.GetStats()
	stats["expired_count"] = expiredCount
	stats["ttl_keys"] = len(c.expiration)
	stats["default_ttl"] = c.defaultTTL.String()
	
	return stats
}

// SetCleanupInterval 设置清理间隔
func (c *TTLCache) SetCleanupInterval(interval time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cleanupTick = interval
}

// startCleanup 启动清理协程
func (c *TTLCache) startCleanup() {
	ticker := time.NewTicker(c.cleanupTick)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCh:
			return
		}
	}
}

// cleanup 清理过期项
func (c *TTLCache) cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	now := time.Now()
	expiredKeys := make([]string, 0)
	
	// 找出所有过期键
	for key, expiry := range c.expiration {
		if now.After(expiry) {
			expiredKeys = append(expiredKeys, key)
		}
	}
	
	// 删除过期项
	for _, key := range expiredKeys {
		delete(c.expiration, key)
		c.cache.Remove(key)
	}
}

// Stop 停止TTL缓存
func (c *TTLCache) Stop() {
	close(c.stopCh)
}

// PriorityCache 优先级缓存
type PriorityCache struct {
	highPriority *LRUCache     // 高优先级缓存
	lowPriority  *LRUCache     // 低优先级缓存
	mutex        sync.RWMutex  // 读写锁
}

// NewPriorityCache 创建新的优先级缓存
func NewPriorityCache(highCapacity, lowCapacity int, highMaxBytes, lowMaxBytes int64) *PriorityCache {
	return &PriorityCache{
		highPriority: NewLRUCache(highCapacity, highMaxBytes),
		lowPriority:  NewLRUCache(lowCapacity, lowMaxBytes),
	}
}

// Get 获取缓存项
func (c *PriorityCache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	// 先从高优先级缓存查找
	if val, found := c.highPriority.Get(key); found {
		return val, true
	}
	
	// 再从低优先级缓存查找
	if val, found := c.lowPriority.Get(key); found {
		return val, true
	}
	
	return nil, false
}

// Add 添加缓存项
func (c *PriorityCache) Add(key string, value interface{}, size int, highPriority bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	if highPriority {
		// 添加到高优先级缓存
		c.highPriority.Add(key, value, size)
		
		// 如果低优先级缓存也有此项，移除
		c.lowPriority.Remove(key)
	} else {
		// 如果高优先级缓存已有此项，不添加到低优先级
		if _, found := c.highPriority.Get(key); found {
			return
		}
		
		// 添加到低优先级缓存
		c.lowPriority.Add(key, value, size)
	}
}

// Promote 提升缓存项优先级
func (c *PriorityCache) Promote(key string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// 检查低优先级缓存
	if val, found := c.lowPriority.Get(key); found {
		// 从条目获取大小
		for _, element := range c.lowPriority.items {
			e := element.Value.(*entry)
			if e.key == key {
				// 移除低优先级缓存项
				c.lowPriority.Remove(key)
				
				// 添加到高优先级缓存
				c.highPriority.Add(key, val, e.size)
				return true
			}
		}
	}
	
	return false
}

// Demote 降低缓存项优先级
func (c *PriorityCache) Demote(key string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// 检查高优先级缓存
	if val, found := c.highPriority.Get(key); found {
		// 从条目获取大小
		for _, element := range c.highPriority.items {
			e := element.Value.(*entry)
			if e.key == key {
				// 移除高优先级缓存项
				c.highPriority.Remove(key)
				
				// 添加到低优先级缓存
				c.lowPriority.Add(key, val, e.size)
				return true
			}
		}
	}
	
	return false
}

// Remove 移除缓存项
func (c *PriorityCache) Remove(key string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// 尝试从两个缓存中移除
	removed1 := c.highPriority.Remove(key)
	removed2 := c.lowPriority.Remove(key)
	
	return removed1 || removed2
}

// Clear 清空缓存
func (c *PriorityCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.highPriority.Clear()
	c.lowPriority.Clear()
}

// GetStats 获取缓存统计信息
func (c *PriorityCache) GetStats() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	highStats := c.highPriority.GetStats()
	lowStats := c.lowPriority.GetStats()
	
	// 合并统计信息
	stats := map[string]interface{}{
		"high_priority": highStats,
		"low_priority":  lowStats,
		"total_size":    c.highPriority.Len() + c.lowPriority.Len(),
		"total_bytes":   c.highPriority.SizeBytes() + c.lowPriority.SizeBytes(),
	}
	
	return stats
} 