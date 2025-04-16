// package mobile 包含移动端相关功能
package mobile

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// 桥接状态
type BridgeStatus int

const (
	BridgeStatusPending BridgeStatus = iota // 等待中
	BridgeStatusInitiated                    // 已发起
	BridgeStatusConfirmed                    // 已确认
	BridgeStatusFinalized                    // 已完成
	BridgeStatusFailed                       // 失败
)

// 桥接记录
type BridgeRecord struct {
	ID                string      // 唯一标识符
	SourceChain       ChainType   // 源链
	DestinationChain  ChainType   // 目标链
	Asset             string      // 资产地址
	Amount            *big.Int    // 数量
	Sender            string      // 发送者
	Recipient         string      // 接收者
	SourceTxHash      string      // 源链交易哈希
	DestinationTxHash string      // 目标链交易哈希
	Status            BridgeStatus // 状态
	CreatedAt         time.Time   // 创建时间
	UpdatedAt         time.Time   // 更新时间
	ErrorMessage      string      // 错误信息
}

// 桥接服务接口
type BridgeService interface {
	// 将资产从源链桥接到目标链
	BridgeAsset(ctx context.Context, sourceChain, destChain ChainType, asset, recipient string, amount *big.Int) (*BridgeRecord, error)
	
	// 获取桥接记录
	GetBridgeRecord(id string) (*BridgeRecord, error)
	
	// 获取所有桥接记录
	GetAllBridgeRecords() ([]*BridgeRecord, error)
	
	// 从桥接合约取回资产
	ClaimAsset(ctx context.Context, recordID string) error
	
	// 获取源链的交易状态
	GetSourceTxStatus(recordID string) (TransactionStatus, error)
	
	// 获取目标链的交易状态
	GetDestinationTxStatus(recordID string) (TransactionStatus, error)
}

// 标准桥接服务
type StandardBridgeService struct {
	adapterFactory *ChainAdapterFactory // 链适配器工厂
	bridgeConfig   *BridgeConfig       // 桥接配置
	records        map[string]*BridgeRecord // 桥接记录
	mu             sync.RWMutex        // 读写锁
}

// 创建新的标准桥接服务
func NewStandardBridgeService(adapterFactory *ChainAdapterFactory, bridgeConfig *BridgeConfig) *StandardBridgeService {
	return &StandardBridgeService{
		adapterFactory: adapterFactory,
		bridgeConfig:   bridgeConfig,
		records:        make(map[string]*BridgeRecord),
	}
}

// 生成唯一ID
func generateUniqueID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// 将资产从源链桥接到目标链
func (s *StandardBridgeService) BridgeAsset(ctx context.Context, sourceChain, destChain ChainType, asset, recipient string, amount *big.Int) (*BridgeRecord, error) {
	// 验证链支持
	if !s.bridgeConfig.IsChainSupported(sourceChain) {
		return nil, fmt.Errorf("源链不受支持: %v", sourceChain)
	}
	
	if !s.bridgeConfig.IsChainSupported(destChain) {
		return nil, fmt.Errorf("目标链不受支持: %v", destChain)
	}
	
	// 获取源链适配器
	sourceAdapter, err := s.adapterFactory.GetAdapter(sourceChain)
	if err != nil {
		return nil, fmt.Errorf("获取源链适配器失败: %v", err)
	}
	
	// 创建桥接记录
	record := &BridgeRecord{
		ID:               generateUniqueID(),
		SourceChain:      sourceChain,
		DestinationChain: destChain,
		Asset:            asset,
		Amount:           amount,
		Recipient:        recipient,
		Status:           BridgeStatusPending,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	
	// 存储记录
	s.mu.Lock()
	s.records[record.ID] = record
	s.mu.Unlock()
	
	// 异步执行桥接操作
	go func() {
		// 获取发送者地址
		sender, err := sourceAdapter.GetWalletAddress()
		if err != nil {
			s.updateRecordStatus(record.ID, BridgeStatusFailed, "", fmt.Sprintf("获取钱包地址失败: %v", err))
			return
		}
		record.Sender = sender
		
		// 执行桥接交易
		var txHash string
		if asset == "0x0000000000000000000000000000000000000000" {
			// 桥接原生代币
			txHash, err = s.bridgeNativeToken(ctx, sourceAdapter, destChain, recipient, amount)
		} else {
			// 桥接ERC20代币
			txHash, err = s.bridgeERC20Token(ctx, sourceAdapter, destChain, asset, recipient, amount)
		}
		
		if err != nil {
			s.updateRecordStatus(record.ID, BridgeStatusFailed, "", fmt.Sprintf("桥接失败: %v", err))
			return
		}
		
		// 更新源交易哈希
		s.updateRecordStatus(record.ID, BridgeStatusInitiated, txHash, "")
		
		// 监控源交易确认
		go s.monitorSourceTransaction(ctx, record.ID)
	}()
	
	return record, nil
}

// 桥接原生代币
func (s *StandardBridgeService) bridgeNativeToken(ctx context.Context, adapter ChainAdapter, destChain ChainType, recipient string, amount *big.Int) (string, error) {
	// 编码桥接调用
	callData, err := EncodeBridgeETH(destChain, recipient)
	if err != nil {
		return "", fmt.Errorf("编码桥接调用失败: %v", err)
	}
	
	// 发送交易
	return adapter.SendTransaction(s.bridgeConfig.BridgeContract, amount, callData, s.bridgeConfig.GasLimit)
}

// 桥接ERC20代币
func (s *StandardBridgeService) bridgeERC20Token(ctx context.Context, adapter ChainAdapter, destChain ChainType, token, recipient string, amount *big.Int) (string, error) {
	// 首先批准桥接合约使用代币
	approveCallData, err := EncodeApproveERC20(s.bridgeConfig.BridgeContract, amount)
	if err != nil {
		return "", fmt.Errorf("编码授权调用失败: %v", err)
	}
	
	// 发送授权交易
	approveTxHash, err := adapter.SendTransaction(token, big.NewInt(0), approveCallData, s.bridgeConfig.GasLimit)
	if err != nil {
		return "", fmt.Errorf("授权交易失败: %v", err)
	}
	
	// 等待授权交易确认
	for {
		status, err := adapter.GetTransactionStatus(approveTxHash)
		if err != nil {
			return "", fmt.Errorf("获取授权交易状态失败: %v", err)
		}
		
		if status == TransactionStatusConfirmed {
			break
		} else if status == TransactionStatusFailed {
			return "", errors.New("授权交易失败")
		}
		
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(5 * time.Second):
			// 继续等待
		}
	}
	
	// 编码桥接调用
	bridgeCallData, err := EncodeBridgeERC20(destChain, recipient, token, amount)
	if err != nil {
		return "", fmt.Errorf("编码桥接调用失败: %v", err)
	}
	
	// 发送桥接交易
	return adapter.SendTransaction(s.bridgeConfig.BridgeContract, big.NewInt(0), bridgeCallData, s.bridgeConfig.GasLimit)
}

// 更新记录状态
func (s *StandardBridgeService) updateRecordStatus(id string, status BridgeStatus, txHash, errorMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if record, exists := s.records[id]; exists {
		record.Status = status
		record.UpdatedAt = time.Now()
		
		if errorMsg != "" {
			record.ErrorMessage = errorMsg
		}
		
		if txHash != "" {
			if record.SourceTxHash == "" {
				record.SourceTxHash = txHash
			} else {
				record.DestinationTxHash = txHash
			}
		}
	}
}

// 监控源交易
func (s *StandardBridgeService) monitorSourceTransaction(ctx context.Context, recordID string) {
	s.mu.RLock()
	record, exists := s.records[recordID]
	s.mu.RUnlock()
	
	if !exists {
		return
	}
	
	sourceAdapter, err := s.adapterFactory.GetAdapter(record.SourceChain)
	if err != nil {
		s.updateRecordStatus(recordID, BridgeStatusFailed, "", fmt.Sprintf("获取源链适配器失败: %v", err))
		return
	}
	
	for {
		status, err := sourceAdapter.GetTransactionStatus(record.SourceTxHash)
		if err != nil {
			s.updateRecordStatus(recordID, BridgeStatusFailed, "", fmt.Sprintf("获取源交易状态失败: %v", err))
			return
		}
		
		if status == TransactionStatusConfirmed {
			s.updateRecordStatus(recordID, BridgeStatusConfirmed, "", "")
			
			// 源交易已确认，监控目标链上的认领/接收
			go s.monitorDestinationTransaction(ctx, recordID)
			return
		} else if status == TransactionStatusFailed {
			s.updateRecordStatus(recordID, BridgeStatusFailed, "", "源交易失败")
			return
		}
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
			// 继续监控
		}
	}
}

// 监控目标交易
func (s *StandardBridgeService) monitorDestinationTransaction(ctx context.Context, recordID string) {
	// 此处应实现目标链上的事件监听，以确认资产已成功接收
	// 由于这需要特定于桥接协议的实现，这里只提供一个基本框架
	
	// 在实际实现中，您可能需要:
	// 1. 查询桥接合约的事件日志
	// 2. 解析事件数据
	// 3. 确认资产已被接收
	// 4. 更新记录状态为已完成
	
	// 这里简单地将状态设置为已完成（仅作演示）
	time.Sleep(30 * time.Second) // 模拟等待
	s.updateRecordStatus(recordID, BridgeStatusFinalized, "", "")
}

// 获取桥接记录
func (s *StandardBridgeService) GetBridgeRecord(id string) (*BridgeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	record, exists := s.records[id]
	if !exists {
		return nil, fmt.Errorf("未找到ID为 %s 的桥接记录", id)
	}
	
	return record, nil
}

// 获取所有桥接记录
func (s *StandardBridgeService) GetAllBridgeRecords() ([]*BridgeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	records := make([]*BridgeRecord, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, record)
	}
	
	return records, nil
}

// 从桥接合约取回资产
func (s *StandardBridgeService) ClaimAsset(ctx context.Context, recordID string) error {
	s.mu.RLock()
	record, exists := s.records[recordID]
	s.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("未找到ID为 %s 的桥接记录", recordID)
	}
	
	if record.Status != BridgeStatusConfirmed {
		return fmt.Errorf("记录状态(%v)不适合认领资产", record.Status)
	}
	
	// 获取目标链适配器
	destAdapter, err := s.adapterFactory.GetAdapter(record.DestinationChain)
	if err != nil {
		return fmt.Errorf("获取目标链适配器失败: %v", err)
	}
	
	// 生成证明数据（实际应用中需要实现）
	proofData, err := GenerateProofData(record.SourceChain, record.SourceTxHash, record.Recipient, record.Amount)
	if err != nil {
		return fmt.Errorf("生成证明数据失败: %v", err)
	}
	
	// 编码认领调用
	callData, err := EncodeClaimTokens(record.SourceChain, proofData)
	if err != nil {
		return fmt.Errorf("编码认领调用失败: %v", err)
	}
	
	// 发送认领交易
	txHash, err := destAdapter.SendTransaction(s.bridgeConfig.BridgeContract, big.NewInt(0), callData, s.bridgeConfig.GasLimit)
	if err != nil {
		return fmt.Errorf("发送认领交易失败: %v", err)
	}
	
	// 更新记录
	s.updateRecordStatus(recordID, BridgeStatusInitiated, txHash, "")
	
	// 监控认领交易
	go s.monitorClaimTransaction(ctx, recordID)
	
	return nil
}

// 监控认领交易
func (s *StandardBridgeService) monitorClaimTransaction(ctx context.Context, recordID string) {
	s.mu.RLock()
	record, exists := s.records[recordID]
	s.mu.RUnlock()
	
	if !exists {
		return
	}
	
	destAdapter, err := s.adapterFactory.GetAdapter(record.DestinationChain)
	if err != nil {
		s.updateRecordStatus(recordID, BridgeStatusFailed, "", fmt.Sprintf("获取目标链适配器失败: %v", err))
		return
	}
	
	for {
		status, err := destAdapter.GetTransactionStatus(record.DestinationTxHash)
		if err != nil {
			s.updateRecordStatus(recordID, BridgeStatusFailed, "", fmt.Sprintf("获取目标交易状态失败: %v", err))
			return
		}
		
		if status == TransactionStatusConfirmed {
			s.updateRecordStatus(recordID, BridgeStatusFinalized, "", "")
			return
		} else if status == TransactionStatusFailed {
			s.updateRecordStatus(recordID, BridgeStatusFailed, "", "目标交易失败")
			return
		}
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
			// 继续监控
		}
	}
}

// 获取源链的交易状态
func (s *StandardBridgeService) GetSourceTxStatus(recordID string) (TransactionStatus, error) {
	s.mu.RLock()
	record, exists := s.records[recordID]
	s.mu.RUnlock()
	
	if !exists {
		return TransactionStatusPending, fmt.Errorf("未找到ID为 %s 的桥接记录", recordID)
	}
	
	if record.SourceTxHash == "" {
		return TransactionStatusPending, nil
	}
	
	sourceAdapter, err := s.adapterFactory.GetAdapter(record.SourceChain)
	if err != nil {
		return TransactionStatusPending, fmt.Errorf("获取源链适配器失败: %v", err)
	}
	
	return sourceAdapter.GetTransactionStatus(record.SourceTxHash)
}

// 获取目标链的交易状态
func (s *StandardBridgeService) GetDestinationTxStatus(recordID string) (TransactionStatus, error) {
	s.mu.RLock()
	record, exists := s.records[recordID]
	s.mu.RUnlock()
	
	if !exists {
		return TransactionStatusPending, fmt.Errorf("未找到ID为 %s 的桥接记录", recordID)
	}
	
	if record.DestinationTxHash == "" {
		return TransactionStatusPending, nil
	}
	
	destAdapter, err := s.adapterFactory.GetAdapter(record.DestinationChain)
	if err != nil {
		return TransactionStatusPending, fmt.Errorf("获取目标链适配器失败: %v", err)
	}
	
	return destAdapter.GetTransactionStatus(record.DestinationTxHash)
} 