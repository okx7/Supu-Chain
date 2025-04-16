// Copyright 2023 The Supur-Chain Authors
// This file is part of the Supur-Chain library.
//
// 安全监控模块，提供对区块链运行时安全的监控与告警功能

package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
)

// 安全事件类型定义
type SecurityEventType int

const (
	// 区块相关安全事件
	BlockReorg SecurityEventType = iota + 1 // 区块重组事件
	LongFork                                // 长分叉事件
	UnexpectedDifficulty                    // 非预期难度变化
	
	// 交易相关安全事件
	TxSpam                  // 交易垃圾攻击
	HighGasPriceTx          // 异常高Gas价格交易
	GasTokenBurn            // Gas代币销毁攻击
	
	// 网络相关安全事件
	PeerBan                 // 节点封禁事件
	PeerFlood               // 节点洪水攻击
	
	// 资源相关安全事件
	DiskSpaceLow            // 磁盘空间不足
	MemoryPressure          // 内存压力过大
	CPUOverload             // CPU过载
)

// 安全事件优先级
type SecurityPriority int

const (
	Low SecurityPriority = iota + 1
	Medium
	High
	Critical
)

// 安全事件结构
type SecurityEvent struct {
	Type        SecurityEventType  // 事件类型
	Priority    SecurityPriority   // 事件优先级
	Description string             // 事件描述
	Data        interface{}        // 事件相关数据
	Time        time.Time          // 事件时间
}

// 事件处理器接口
type EventHandler interface {
	HandleEvent(event *SecurityEvent) error
}

// 告警配置
type AlertConfig struct {
	Enabled            bool              // 是否启用告警
	MinPriority        SecurityPriority  // 最小告警优先级
	Throttle           time.Duration     // 告警节流时间
	Endpoints          []string          // 告警端点
	IncludeEventTypes  []SecurityEventType // 包含的事件类型
	ExcludeEventTypes  []SecurityEventType // 排除的事件类型
}

// 监控配置
type MonitorConfig struct {
	BlockMonitorInterval   time.Duration  // 区块监控间隔
	TxPoolMonitorInterval  time.Duration  // 交易池监控间隔
	PeerMonitorInterval    time.Duration  // 节点监控间隔
	ResourceMonitorInterval time.Duration // 资源监控间隔
	MaxReorgLength         uint64         // 最大允许重组长度
	MaxForkLength          uint64         // 最大允许分叉长度
	TxSpamThreshold        int            // 交易垃圾攻击阈值
	LowDiskSpaceThreshold  uint64         // 磁盘空间不足阈值
	AlertConfig            AlertConfig    // 告警配置
}

// 默认监控配置
var DefaultMonitorConfig = MonitorConfig{
	BlockMonitorInterval:    time.Second * 5,
	TxPoolMonitorInterval:   time.Second * 10,
	PeerMonitorInterval:     time.Second * 30,
	ResourceMonitorInterval: time.Minute,
	MaxReorgLength:          3,
	MaxForkLength:           5,
	TxSpamThreshold:         1000,
	LowDiskSpaceThreshold:   1024 * 1024 * 1024 * 10, // 10GB
	AlertConfig: AlertConfig{
		Enabled:     true,
		MinPriority: Medium,
		Throttle:    time.Minute * 5,
		Endpoints:   []string{"log"},
	},
}

// 安全监控服务
type Monitor struct {
	ctx        context.Context      // 上下文
	cancelFunc context.CancelFunc   // 取消函数
	config     MonitorConfig        // 监控配置
	handlers   []EventHandler       // 事件处理器
	blockchain ChainReader          // 区块链读取器
	txpool     TxPoolReader         // 交易池读取器
	p2p        PeerManager          // P2P管理器
	eventCh    chan *SecurityEvent  // 事件通道
	wg         sync.WaitGroup       // 等待组
	
	// 指标
	metricEvents    metrics.Counter   // 事件计数
	metricsByType   map[SecurityEventType]metrics.Counter // 按类型的事件计数
	metricsByPrio   map[SecurityPriority]metrics.Counter  // 按优先级的事件计数
}

// 区块链读取接口
type ChainReader interface {
	CurrentHeader() *types.Header
	GetHeaderByHash(hash common.Hash) *types.Header
	GetHeaderByNumber(number uint64) *types.Header
	SubscribeChainHeadEvent(ch chan<- types.ChainHeadEvent) event.Subscription
}

// 交易池读取接口
type TxPoolReader interface {
	Stats() (int, int) // 待处理和排队中的交易数
	Content() (map[common.Address]types.Transactions, map[common.Address]types.Transactions)
}

// P2P管理接口
type PeerManager interface {
	PeerCount() int
	Peers() []string
}

// 创建新的安全监控服务
func NewMonitor(config MonitorConfig, blockchain ChainReader, txpool TxPoolReader, p2p PeerManager) *Monitor {
	ctx, cancel := context.WithCancel(context.Background())
	
	// 创建和注册指标
	metricEvents := metrics.NewCounter("security/events")
	metricsByType := make(map[SecurityEventType]metrics.Counter)
	metricsByPrio := make(map[SecurityPriority]metrics.Counter)
	
	for i := BlockReorg; i <= CPUOverload; i++ {
		metricsByType[i] = metrics.NewCounter(fmt.Sprintf("security/events/type/%d", i))
	}
	
	for i := Low; i <= Critical; i++ {
		metricsByPrio[i] = metrics.NewCounter(fmt.Sprintf("security/events/priority/%d", i))
	}
	
	return &Monitor{
		ctx:            ctx,
		cancelFunc:     cancel,
		config:         config,
		handlers:       make([]EventHandler, 0),
		blockchain:     blockchain,
		txpool:         txpool,
		p2p:            p2p,
		eventCh:        make(chan *SecurityEvent, 100),
		metricEvents:   metricEvents,
		metricsByType:  metricsByType,
		metricsByPrio:  metricsByPrio,
	}
}

// 注册事件处理器
func (m *Monitor) RegisterHandler(handler EventHandler) {
	m.handlers = append(m.handlers, handler)
}

// 启动监控服务
func (m *Monitor) Start() error {
	log.Info("安全监控服务启动")
	
	// 启动事件处理循环
	m.wg.Add(1)
	go m.processEvents()
	
	// 启动区块监控
	m.wg.Add(1)
	go m.monitorBlocks()
	
	// 启动交易池监控
	m.wg.Add(1)
	go m.monitorTxPool()
	
	// 启动P2P监控
	m.wg.Add(1)
	go m.monitorPeers()
	
	// 启动资源监控
	m.wg.Add(1)
	go m.monitorResources()
	
	return nil
}

// 停止监控服务
func (m *Monitor) Stop() {
	m.cancelFunc()
	m.wg.Wait()
	close(m.eventCh)
	log.Info("安全监控服务已停止")
}

// 发布安全事件
func (m *Monitor) PublishEvent(eventType SecurityEventType, priority SecurityPriority, desc string, data interface{}) {
	event := &SecurityEvent{
		Type:        eventType,
		Priority:    priority,
		Description: desc,
		Data:        data,
		Time:        time.Now(),
	}
	
	select {
	case m.eventCh <- event:
		// 事件已发送
	default:
		log.Warn("安全事件通道已满，事件被丢弃", "type", eventType, "priority", priority)
	}
}

// 事件处理循环
func (m *Monitor) processEvents() {
	defer m.wg.Done()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case event := <-m.eventCh:
			// 更新指标
			m.metricEvents.Inc(1)
			m.metricsByType[event.Type].Inc(1)
			m.metricsByPrio[event.Priority].Inc(1)
			
			// 记录事件
			log.Info("安全事件", 
				"type", event.Type, 
				"priority", event.Priority, 
				"desc", event.Description,
				"time", event.Time)
			
			// 处理事件
			for _, handler := range m.handlers {
				if err := handler.HandleEvent(event); err != nil {
					log.Error("处理安全事件失败", "handler", handler, "error", err)
				}
			}
		}
	}
}

// 区块监控
func (m *Monitor) monitorBlocks() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.BlockMonitorInterval)
	defer ticker.Stop()
	
	// 订阅区块头事件
	headCh := make(chan types.ChainHeadEvent, 10)
	sub := m.blockchain.SubscribeChainHeadEvent(headCh)
	defer sub.Unsubscribe()
	
	var lastHeader *types.Header
	forkCount := uint64(0)
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			// 定期检查
		case ev := <-headCh:
			header := ev.Block.Header()
			
			// 第一个区块头
			if lastHeader == nil {
				lastHeader = header
				continue
			}
			
			// 检查区块连续性
			if header.Number.Uint64() != lastHeader.Number.Uint64()+1 {
				// 可能发生了重组
				if header.Number.Uint64() <= lastHeader.Number.Uint64() {
					reorgLength := lastHeader.Number.Uint64() - header.Number.Uint64() + 1
					
					if reorgLength >= m.config.MaxReorgLength {
						m.PublishEvent(
							BlockReorg,
							High,
							fmt.Sprintf("检测到大型区块重组，长度: %d", reorgLength),
							map[string]interface{}{
								"oldBlock": lastHeader.Number.Uint64(),
								"newBlock": header.Number.Uint64(),
								"length":   reorgLength,
							},
						)
					}
				}
			}
			
			// 检查父区块哈希值
			if header.ParentHash != lastHeader.Hash() {
				forkCount++
				
				if forkCount >= m.config.MaxForkLength {
					m.PublishEvent(
						LongFork,
						Medium,
						fmt.Sprintf("检测到长分叉，长度: %d", forkCount),
						map[string]interface{}{
							"currentBlock": header.Number.Uint64(),
							"parent":       header.ParentHash.String(),
							"expected":     lastHeader.Hash().String(),
						},
					)
				}
			} else {
				forkCount = 0
			}
			
			lastHeader = header
		}
	}
}

// 交易池监控
func (m *Monitor) monitorTxPool() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.TxPoolMonitorInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			// 检查交易池状态
			pending, queued := m.txpool.Stats()
			
			// 交易垃圾攻击检测
			if pending > m.config.TxSpamThreshold {
				m.PublishEvent(
					TxSpam,
					Medium,
					fmt.Sprintf("交易池拥堵，待处理交易数: %d", pending),
					map[string]interface{}{
						"pending": pending,
						"queued":  queued,
					},
				)
			}
			
			// 检查交易gas价格
			pendingContent, _ := m.txpool.Content()
			for _, txs := range pendingContent {
				for _, tx := range txs {
					// 异常高gas价格检测
					if tx.GasPrice().Uint64() > 1000000000000 { // 1000 Gwei
						m.PublishEvent(
							HighGasPriceTx,
							Low,
							"检测到异常高Gas价格交易",
							map[string]interface{}{
								"txHash":   tx.Hash().String(),
								"from":     tx.From().Hex(),
								"gasPrice": tx.GasPrice().String(),
							},
						)
					}
				}
			}
		}
	}
}

// P2P网络监控
func (m *Monitor) monitorPeers() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.PeerMonitorInterval)
	defer ticker.Stop()
	
	var lastPeerCount int
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			// 检查节点数量
			currentPeerCount := m.p2p.PeerCount()
			
			// 节点数量急剧下降
			if lastPeerCount > 0 && currentPeerCount < lastPeerCount/2 && lastPeerCount > 10 {
				m.PublishEvent(
					PeerBan,
					High,
					fmt.Sprintf("节点数量急剧下降，从 %d 降至 %d", lastPeerCount, currentPeerCount),
					map[string]interface{}{
						"before": lastPeerCount,
						"after":  currentPeerCount,
					},
				)
			}
			
			lastPeerCount = currentPeerCount
		}
	}
}

// 资源监控
func (m *Monitor) monitorResources() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.ResourceMonitorInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			// 这里可以接入系统监控
			// 为了示例，我们简单地检查磁盘空间
			freeSpace := getDiskFreeSpace()
			if freeSpace < m.config.LowDiskSpaceThreshold {
				m.PublishEvent(
					DiskSpaceLow,
					High,
					fmt.Sprintf("磁盘空间不足，剩余: %d MB", freeSpace/1024/1024),
					map[string]interface{}{
						"freeSpace": freeSpace,
						"threshold": m.config.LowDiskSpaceThreshold,
					},
				)
			}
		}
	}
}

// 获取磁盘可用空间（示例实现，实际需要根据系统API获取）
func getDiskFreeSpace() uint64 {
	// 示例实现，实际应通过系统API获取
	return 1024 * 1024 * 1024 * 100 // 假设100GB可用空间
} 