# Supur链API变更日志

本文档记录Supur链API的重要变更，帮助开发者了解API的演进和优化方向。

## 2025年4月更新

### 移动端网络弹性模块优化

#### 消息处理安全增强

**变更内容**：
- 将消息类型白名单定义重构为常量数组，提高可维护性和安全性
- 引入`VALID_MESSAGE_TYPES`常量数组替代硬编码的消息类型映射
- 优化`isValidMessageType`函数，提升消息类型验证的效率

**示例代码**：
```go
// 新增常量数组定义
var VALID_MESSAGE_TYPES = []uint8{
    MessageTypeBlockRequest,
    MessageTypeBlockResponse,
    MessageTypeTxRequest,
    MessageTypeTxResponse,
    MessageTypeSync,
    MessageTypeControl,
    MessageTypeDiscovery,
    MessageTypeHeartbeat,
    MessageTypeStateRequest,
    MessageTypeStateResponse,
}

// 动态生成消息类型映射，提高查询效率
var validMessageTypes = func() map[uint8]bool {
    types := make(map[uint8]bool)
    for _, t := range VALID_MESSAGE_TYPES {
        types[t] = true
    }
    return types
}()

// 优化的消息类型验证函数
func (nr *NetworkResilience) isValidMessageType(msgType uint8) bool {
    return validMessageTypes[msgType]
}
```

**影响**：
- 提高代码可维护性，新增消息类型时只需在一处更新
- 改进安全性，所有消息类型验证通过统一的常量集合处理
- 优化性能，使用预生成的映射提高查询效率

### 安全管理模块优化

#### 加密随机数缓存机制

**变更说明**：
- `SecureStorage`结构已使用TTL缓存来管理nonce，防止重放攻击
- 设置默认nonce缓存生存期为24小时，每小时自动清理过期项
- 简化`cleanupNonceCache`和`StartCleanupRoutine`函数，依赖缓存自动清理机制

**实现细节**：
```go
// SecureStorage结构优化
type SecureStorage struct {
    encryptionKey []byte
    nonceCache    *cache.Cache       // 使用TTL缓存代替sync.Map
    nonceTTL      time.Duration      // nonce生存时间
    mu            sync.RWMutex       // 读写锁
}

// 优化的初始化函数
func NewSecureStorage(encryptionKey []byte) *SecureStorage {
    return &SecureStorage{
        encryptionKey: encryptionKey,
        nonceTTL:      24 * time.Hour, // 默认nonce有效期为24小时
        nonceCache:    cache.New(24*time.Hour, 1*time.Hour), // 创建缓存，默认过期时间24小时，每1小时清理一次过期项
    }
}
```

**影响**：
- 解决了潜在的内存泄漏问题，避免长期运行时nonce缓存无限增长
- 提高系统安全性，自动清理过期的nonce记录
- 减少手动资源管理需求，依赖成熟的缓存机制

### 资源管理模块优化

#### 类型断言安全增强

**变更说明**：
- 优化`GetResourceMode`函数，增加类型断言失败保护
- 添加详细的错误日志，便于问题诊断
- 提供默认返回值，确保功能稳定性

**实现细节**：
```go
// 优化的资源模式获取函数
func (rm *ResourceManager) GetResourceMode() ResourceMode {
    // 使用Load方法安全地读取currentMode
    mode := rm.currentMode.Load()
    if mode == nil {
        return ResourceModeLow // 默认为低功耗模式
    }
    if mode, ok := mode.(ResourceMode); ok {
        return mode
    }
    log.Error("资源模式类型断言失败")
    return ResourceModeLow // 默认为低功耗模式
}
```

**影响**：
- 提高代码健壮性，防止类型断言失败导致的崩溃
- 优化错误处理，添加明确的错误日志
- 确保功能连续性，即使在异常情况下也能提供默认行为

### 移动设备可信度评分

**变更说明**：
- 将设备评分维度拆分为安全评分、网络质量评分、性能评分和一致性评分
- 各维度使用权重计算总体评分，增强评分精确性
- 支持详细的评分报告，便于分析设备可信状态

**实现细节**：
```go
// MobileValidator结构优化
type MobileValidator struct {
    SecurityScore    float64 // 安全评分(0-100)
    NetworkScore     float64 // 网络评分(0-100)
    PerformanceScore float64 // 性能评分(0-100)
    ConsistencyScore float64 // 一致性评分(0-100)
    TotalScore       float64 // 总体评分(0-100)
    // ...其他字段
}

// 总分计算权重
const (
    WeightSecurity   = 0.35  // 安全评分权重
    WeightNetwork    = 0.25  // 网络评分权重
    WeightPerformance = 0.25  // 性能评分权重
    WeightConsistency = 0.15  // 一致性评分权重
)
```

**影响**：
- 提高设备可信度评估的准确性和灵活性
- 支持基于多维度的可信度评估和分析
- 为轻量级设备提供更公平的评分机制

---

本文档持续更新，反映Supur链API的最新变更。如有疑问，请通过[开发者社区论坛](https://t.me/SupurChain)联系我们。 