package mobile

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// StateManagerAPI 状态管理器API
type StateManagerAPI struct {
	stateManager *ChainState // 链状态管理器
}

// BlockData 区块数据结构
type BlockData struct {
	BlockHash     string            // 区块哈希
	PrevBlockHash string            // 前一区块哈希
	Height        uint64            // 高度
	Timestamp     int64             // 时间戳
	Size          uint32            // 大小
	StateStr      string            // 状态字符串
	State         int               // 状态值
	ReceivedFrom  string            // 接收来源
	ReceivedAt    string            // 接收时间
	ProcessedAt   string            // 处理时间
	IsOrphan      bool              // 是否是孤块
	MissingParent string            // 缺失的父区块哈希（如果是孤块）
	RetryCount    int               // 重试次数
	ExtraInfo     map[string]string // 额外信息
}

// SyncProgressInfo 同步进度信息
type SyncProgressInfo struct {
	Progress            float64 // 同步进度（0-100%）
	CurrentHeight       uint64  // 当前高度
	TargetHeight        uint64  // 目标高度
	IsSyncing           bool    // 是否正在同步
	SyncSpeed           float64 // 同步速度（区块/秒）
	EstimatedCompletion string  // 预计完成时间
	RemainingBlocks     uint64  // 剩余区块数
	ProcessedBlocks     uint64  // 已处理区块数
	RejectedBlocks      uint64  // 已拒绝区块数
	PendingBlocks       int     // 待处理区块数
	DownloadedBytes     uint64  // 已下载字节数
	StartTime           string  // 开始时间
	ElapsedTime         string  // 已用时间
}

// NewStateManagerAPI 创建状态管理器API
func NewStateManagerAPI(config *ChainStateConfig) *StateManagerAPI {
	return &StateManagerAPI{
		stateManager: NewChainState(config),
	}
}

// ReceiveBlock 接收区块
func (api *StateManagerAPI) ReceiveBlock(blockData []byte, source string) (string, error) {
	// 处理新区块
	blockInfo, err := api.stateManager.ProcessNewBlock(blockData, source)
	if err != nil {
		return "", err
	}
	
	// 将区块哈希转换为十六进制字符串
	blockHashHex := hex.EncodeToString(blockInfo.Header.BlockHash)
	
	return blockHashHex, nil
}

// GetBlockInfo 获取区块信息
func (api *StateManagerAPI) GetBlockInfo(blockHashHex string) (*BlockData, error) {
	// 解码区块哈希
	blockHash, err := hex.DecodeString(blockHashHex)
	if err != nil {
		return nil, fmt.Errorf("无效的区块哈希格式: %v", err)
	}
	
	// 构建区块信息
	blockData, err := api.buildBlockData(blockHash)
	if err != nil {
		return nil, err
	}
	
	return blockData, nil
}

// buildBlockData 构建区块数据
func (api *StateManagerAPI) buildBlockData(blockHash []byte) (*BlockData, error) {
	api.stateManager.mutex.RLock()
	defer api.stateManager.mutex.RUnlock()
	
	hashStr := fmt.Sprintf("%x", blockHash)
	
	// 检查待处理队列
	if block, exists := api.stateManager.PendingBlocks[hashStr]; exists {
		return api.buildBlockDataFromInfo(block, false, ""), nil
	}
	
	// 检查孤块池
	if orphan, exists := api.stateManager.OrphanBlocks[hashStr]; exists {
		return api.buildBlockDataFromInfo(orphan.Info, true, fmt.Sprintf("%x", orphan.MissingParent)), nil
	}
	
	// 检查缓存
	if cached, exists := api.stateManager.BlockCache.Get(hashStr); exists {
		block := cached.(*BlockInfo)
		return api.buildBlockDataFromInfo(block, false, ""), nil
	}
	
	return nil, fmt.Errorf("未找到区块: %x", blockHash)
}

// buildBlockDataFromInfo 从BlockInfo构建BlockData
func (api *StateManagerAPI) buildBlockDataFromInfo(info *BlockInfo, isOrphan bool, missingParent string) *BlockData {
	// 状态字符串映射
	stateStrings := map[BlockState]string{
		BlockStatePending:   "待处理",
		BlockStateVerified:  "已验证",
		BlockStateConfirmed: "已确认",
		BlockStateRejected:  "已拒绝",
		BlockStateOrphan:    "孤块",
	}
	
	// 构建额外信息
	extraInfo := make(map[string]string)
	if info.LocalPath != "" {
		extraInfo["local_path"] = info.LocalPath
	}
	
	// 格式化时间
	receivedAt := info.ReceivedAt.Format(time.RFC3339)
	processedAt := ""
	if !info.ProcessedAt.IsZero() {
		processedAt = info.ProcessedAt.Format(time.RFC3339)
	}
	
	return &BlockData{
		BlockHash:     hex.EncodeToString(info.Header.BlockHash),
		PrevBlockHash: hex.EncodeToString(info.Header.PrevBlockHash),
		Height:        info.Header.Height,
		Timestamp:     info.Header.Timestamp,
		Size:          info.Size,
		StateStr:      stateStrings[info.State],
		State:         int(info.State),
		ReceivedFrom:  info.ReceivedFrom,
		ReceivedAt:    receivedAt,
		ProcessedAt:   processedAt,
		IsOrphan:      isOrphan,
		MissingParent: missingParent,
		RetryCount:    info.RetryCount,
		ExtraInfo:     extraInfo,
	}
}

// UpdateBlockState 更新区块状态
func (api *StateManagerAPI) UpdateBlockState(blockHashHex string, newState int) error {
	// 解码区块哈希
	blockHash, err := hex.DecodeString(blockHashHex)
	if err != nil {
		return fmt.Errorf("无效的区块哈希格式: %v", err)
	}
	
	// 更新区块状态
	err = api.stateManager.UpdateBlockState(blockHash, BlockState(newState))
	if err != nil {
		return err
	}
	
	return nil
}

// GetPendingBlocks 获取待处理区块
func (api *StateManagerAPI) GetPendingBlocks() ([]string, error) {
	api.stateManager.mutex.RLock()
	defer api.stateManager.mutex.RUnlock()
	
	// 获取所有待处理区块的哈希
	pendingHashes := make([]string, 0, len(api.stateManager.PendingBlocks))
	for hash := range api.stateManager.PendingBlocks {
		pendingHashes = append(pendingHashes, hash)
	}
	
	return pendingHashes, nil
}

// GetOrphanBlocks 获取孤块
func (api *StateManagerAPI) GetOrphanBlocks() ([]string, error) {
	api.stateManager.mutex.RLock()
	defer api.stateManager.mutex.RUnlock()
	
	// 获取所有孤块的哈希
	orphanHashes := make([]string, 0, len(api.stateManager.OrphanBlocks))
	for hash := range api.stateManager.OrphanBlocks {
		orphanHashes = append(orphanHashes, hash)
	}
	
	return orphanHashes, nil
}

// RetryOrphanBlocks 重试处理孤块
func (api *StateManagerAPI) RetryOrphanBlocks() int {
	return api.stateManager.RetryOrphanBlocks()
}

// StartSync 开始同步
func (api *StateManagerAPI) StartSync(targetHeight uint64) bool {
	api.stateManager.StartSync(targetHeight)
	return true
}

// GetSyncProgress 获取同步进度
func (api *StateManagerAPI) GetSyncProgress() (*SyncProgressInfo, error) {
	progress, status := api.stateManager.GetSyncProgress()
	
	// 计算剩余区块
	remainingBlocks := uint64(0)
	if status.SyncTargetHeight > status.CurrentHeight {
		remainingBlocks = status.SyncTargetHeight - status.CurrentHeight
	}
	
	// 预计完成时间
	estimatedCompletion := ""
	if status.IsSyncing && status.SyncSpeed > 0 {
		secondsRemaining := float64(remainingBlocks) / status.SyncSpeed
		estimatedTime := time.Now().Add(time.Duration(secondsRemaining) * time.Second)
		estimatedCompletion = estimatedTime.Format(time.RFC3339)
	}
	
	// 计算已用时间
	elapsedTime := ""
	if !status.SyncStartTime.IsZero() {
		duration := time.Since(status.SyncStartTime)
		hours := int(duration.Hours())
		minutes := int(duration.Minutes()) % 60
		seconds := int(duration.Seconds()) % 60
		elapsedTime = fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
	}
	
	return &SyncProgressInfo{
		Progress:            progress,
		CurrentHeight:       status.CurrentHeight,
		TargetHeight:        status.SyncTargetHeight,
		IsSyncing:           status.IsSyncing,
		SyncSpeed:           status.SyncSpeed,
		EstimatedCompletion: estimatedCompletion,
		RemainingBlocks:     remainingBlocks,
		ProcessedBlocks:     status.ProcessedBlocks,
		RejectedBlocks:      status.RejectedBlocks,
		PendingBlocks:       status.PendingBlockCount,
		DownloadedBytes:     status.DownloadedBytes,
		StartTime:           status.SyncStartTime.Format(time.RFC3339),
		ElapsedTime:         elapsedTime,
	}, nil
}

// GetCacheStats 获取缓存统计
func (api *StateManagerAPI) GetCacheStats() map[string]interface{} {
	return api.stateManager.BlockCache.GetStats()
}

// GetChainStats 获取链统计
func (api *StateManagerAPI) GetChainStats() map[string]interface{} {
	return api.stateManager.GetStats()
}

// ResetState 重置状态
func (api *StateManagerAPI) ResetState() bool {
	api.stateManager.ResetState()
	return true
}

// ExportChainInfo 导出链信息
func (api *StateManagerAPI) ExportChainInfo() (string, error) {
	api.stateManager.mutex.RLock()
	defer api.stateManager.mutex.RUnlock()
	
	// 构建导出信息
	info := map[string]interface{}{
		"current_height": api.stateManager.CurrentHeight,
		"current_hash":   fmt.Sprintf("%x", api.stateManager.CurrentHash),
		"last_updated":   api.stateManager.LastUpdated,
		"pending_count":  len(api.stateManager.PendingBlocks),
		"orphan_count":   len(api.stateManager.OrphanBlocks),
		"cache_size":     api.stateManager.BlockCache.Len(),
		"sync_status":    api.stateManager.SyncStatus,
	}
	
	// 序列化为JSON
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化链信息失败: %v", err)
	}
	
	return string(data), nil
} 