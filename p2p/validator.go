package p2p

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
	
	"github.com/supur-chain/core/log"
	"github.com/supur-chain/core/metrics"
)

// MessageType 定义P2P网络中的消息类型
type MessageType uint16

const (
	MessageTypeUnknown    MessageType = 0     // 未知消息类型
	MessageTypeHandshake  MessageType = 1     // 握手消息
	MessageTypeBlock      MessageType = 2     // 区块消息
	MessageTypeTx         MessageType = 3     // 交易消息
	MessageTypePing       MessageType = 4     // Ping消息
	MessageTypePong       MessageType = 5     // Pong消息
	MessageTypePeers      MessageType = 6     // 节点列表消息
	MessageTypeConsensus  MessageType = 7     // 共识消息
)

// ValidationResult 表示消息验证的结果
type ValidationResult struct {
	Valid     bool      // 消息是否有效
	Error     error     // 验证失败原因
	Timestamp time.Time // 验证时间戳
}

// MessageValidator 接口定义了消息验证器的基本功能
type MessageValidator interface {
	Validate(msgType MessageType, data []byte) ValidationResult // 验证消息格式
	RegisterValidator(msgType MessageType, validator func([]byte) error) // 注册自定义验证器
}

// P2PMessageValidator 实现了MessageValidator接口
type P2PMessageValidator struct {
	validators     map[MessageType]func([]byte) error // 消息类型对应的验证函数
	mutex          sync.RWMutex                       // 读写锁保护map
	defaultMaxSize int                                // 默认最大消息大小
	metrics        *ValidationMetrics                 // 验证指标统计
}

// ValidationMetrics 用于收集验证相关的指标
type ValidationMetrics struct {
	TotalMessages     metrics.Counter // 总消息数
	ValidMessages     metrics.Counter // 有效消息数
	InvalidMessages   metrics.Counter // 无效消息数
	ValidationTime    metrics.Timer   // 验证耗时
	ByMessageType     map[MessageType]metrics.Counter // 按消息类型统计
}

// NewP2PMessageValidator 创建一个新的P2P消息验证器
func NewP2PMessageValidator(defaultMaxSize int) *P2PMessageValidator {
	if defaultMaxSize <= 0 {
		defaultMaxSize = 1024 * 1024 // 默认1MB
	}
	
	metrics := &ValidationMetrics{
		TotalMessages:   metrics.NewCounter("p2p_messages_total"),
		ValidMessages:   metrics.NewCounter("p2p_messages_valid"),
		InvalidMessages: metrics.NewCounter("p2p_messages_invalid"),
		ValidationTime:  metrics.NewTimer("p2p_validation_time"),
		ByMessageType:   make(map[MessageType]metrics.Counter),
	}
	
	validator := &P2PMessageValidator{
		validators:     make(map[MessageType]func([]byte) error),
		defaultMaxSize: defaultMaxSize,
		metrics:        metrics,
	}
	
	// 注册默认验证器
	validator.registerDefaultValidators()
	
	return validator
}

// 注册默认验证器
func (v *P2PMessageValidator) registerDefaultValidators() {
	// 握手消息验证
	v.RegisterValidator(MessageTypeHandshake, func(data []byte) error {
		if len(data) < 8 {
			return errors.New("握手消息长度不足")
		}
		// 验证版本号格式
		version := binary.BigEndian.Uint32(data[0:4])
		if version == 0 {
			return errors.New("无效的版本号")
		}
		return nil
	})
	
	// 区块消息验证
	v.RegisterValidator(MessageTypeBlock, func(data []byte) error {
		if len(data) < 100 {
			return errors.New("区块数据长度不足")
		}
		// 验证区块头格式
		// ... 更多区块验证逻辑 ...
		return nil
	})
	
	// 交易消息验证
	v.RegisterValidator(MessageTypeTx, func(data []byte) error {
		if len(data) < 20 {
			return errors.New("交易数据长度不足")
		}
		// 验证交易签名和格式
		// ... 更多交易验证逻辑 ...
		return nil
	})
	
	// Ping消息验证
	v.RegisterValidator(MessageTypePing, func(data []byte) error {
		if len(data) != 8 {
			return errors.New("Ping消息长度必须为8字节")
		}
		return nil
	})
	
	// Pong消息验证
	v.RegisterValidator(MessageTypePong, func(data []byte) error {
		if len(data) != 8 {
			return errors.New("Pong消息长度必须为8字节")
		}
		return nil
	})
}

// RegisterValidator 注册一个针对特定消息类型的验证器
func (v *P2PMessageValidator) RegisterValidator(msgType MessageType, validator func([]byte) error) {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	
	v.validators[msgType] = validator
	
	// 初始化此消息类型的计数器
	if _, exists := v.metrics.ByMessageType[msgType]; !exists {
		v.metrics.ByMessageType[msgType] = metrics.NewCounter(fmt.Sprintf("p2p_messages_type_%d", msgType))
	}
}

// Validate 验证消息格式
func (v *P2PMessageValidator) Validate(msgType MessageType, data []byte) ValidationResult {
	start := time.Now()
	result := ValidationResult{
		Valid:     false,
		Timestamp: start,
	}
	
	// 统计总消息数
	v.metrics.TotalMessages.Inc(1)
	
	// 按消息类型统计
	if counter, exists := v.metrics.ByMessageType[msgType]; exists {
		counter.Inc(1)
	}
	
	// 基本长度检查
	if len(data) > v.defaultMaxSize {
		result.Error = fmt.Errorf("消息超过最大长度限制: %d > %d", len(data), v.defaultMaxSize)
		v.metrics.InvalidMessages.Inc(1)
		v.metrics.ValidationTime.Update(time.Since(start))
		
		log.Warn("P2P消息验证失败: 消息过大", 
			"类型", msgType, 
			"大小", len(data), 
			"最大限制", v.defaultMaxSize)
		return result
	}
	
	// 获取此消息类型的验证器
	v.mutex.RLock()
	validator, exists := v.validators[msgType]
	v.mutex.RUnlock()
	
	if !exists {
		result.Error = fmt.Errorf("未知的消息类型: %d", msgType)
		v.metrics.InvalidMessages.Inc(1)
		v.metrics.ValidationTime.Update(time.Since(start))
		
		log.Warn("P2P消息验证失败: 未知类型", "类型", msgType)
		return result
	}
	
	// 执行验证
	if err := validator(data); err != nil {
		result.Error = err
		v.metrics.InvalidMessages.Inc(1)
		v.metrics.ValidationTime.Update(time.Since(start))
		
		log.Warn("P2P消息验证失败", "类型", msgType, "错误", err.Error())
		return result
	}
	
	// 验证通过
	result.Valid = true
	v.metrics.ValidMessages.Inc(1)
	v.metrics.ValidationTime.Update(time.Since(start))
	return result
}

// GetValidationStats 返回验证统计信息
func (v *P2PMessageValidator) GetValidationStats() map[string]interface{} {
	stats := map[string]interface{}{
		"total_messages":   v.metrics.TotalMessages.Count(),
		"valid_messages":   v.metrics.ValidMessages.Count(),
		"invalid_messages": v.metrics.InvalidMessages.Count(),
		"by_type":          make(map[string]int64),
	}
	
	for msgType, counter := range v.metrics.ByMessageType {
		stats["by_type"].(map[string]int64)[fmt.Sprintf("%d", msgType)] = counter.Count()
	}
	
	return stats
} 