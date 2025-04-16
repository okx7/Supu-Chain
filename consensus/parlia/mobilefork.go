package parlia

import (
	"bytes"
	"math/big"
	"time"
	
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// MobileForkParams 移动端分叉参数
type MobileForkParams struct {
	// 效率相关
	FastFinality            bool            // 快速确认性
	BlockInterval           uint64          // 区块间隔(秒)
	ValidatorSetSize        uint64          // 验证者集合大小
	EpochLength             uint64          // 纪元长度
	
	// 资源优化
	LowPowerMode            bool            // 低功耗模式
	LightVerification       bool            // 轻量验证
	BatchProcessing         bool            // 批处理
	
	// 移动端友好特性
	MobileValidatorReward   *big.Int        // 移动验证者奖励
	BatteryAwareConsensus   bool            // 电池感知共识
	NetworkAwareConsensus   bool            // 网络感知共识
	StorageAwareConsensus   bool            // 存储感知共识
	
	// 激励机制
	MobileParticipationBonus *big.Int       // 移动参与奖励
	DataContributionReward   *big.Int       // 数据贡献奖励
	LowPowerReward           *big.Int       // 低功耗奖励
	
	// 自适应机制
	AdaptiveValidation      bool            // 自适应验证
	DynamicBlockSize        bool            // 动态区块大小
	DynamicCommitteeSize    bool            // 动态委员会大小
}

// MobileForkInfo 移动端分叉信息
type MobileForkInfo struct {
	Name      string          // 分叉名称
	Block     uint64          // 分叉区块高度
	Timestamp uint64          // 分叉时间戳
	FeatureID uint64          // 特性ID
	Params    MobileForkParams // 分叉参数
}

// 移动端分叉列表
var (
	// MobileFork1 第一个移动端友好分叉
	MobileFork1 = &MobileForkInfo{
		Name:      "MobileFork1",
		Block:     1500000, // 示例区块高度
		Timestamp: 0,       // 按区块高度触发，不按时间戳
		FeatureID: 1,
		Params: MobileForkParams{
			FastFinality:            true,
			BlockInterval:           3,            // 3秒出块
			ValidatorSetSize:        21,           // 21个验证者
			EpochLength:             200,          // 200个区块一个纪元
			LowPowerMode:            true,
			LightVerification:       true,
			BatchProcessing:         true,
			MobileValidatorReward:   big.NewInt(2e18), // 2个代币
			BatteryAwareConsensus:   true,
			NetworkAwareConsensus:   true,
			StorageAwareConsensus:   true,
			MobileParticipationBonus: big.NewInt(5e17), // 0.5个代币
			DataContributionReward:   big.NewInt(1e18), // 1个代币
			LowPowerReward:           big.NewInt(3e17), // 0.3个代币
			AdaptiveValidation:       true,
			DynamicBlockSize:         true,
			DynamicCommitteeSize:     false,
		},
	}
	
	// MobileFork2 第二个移动端友好分叉
	MobileFork2 = &MobileForkInfo{
		Name:      "MobileFork2",
		Block:     2000000, // 示例区块高度
		Timestamp: 0,       // 按区块高度触发，不按时间戳
		FeatureID: 2,
		Params: MobileForkParams{
			FastFinality:            true,
			BlockInterval:           2,            // 2秒出块
			ValidatorSetSize:        31,           // 31个验证者
			EpochLength:             300,          // 300个区块一个纪元
			LowPowerMode:            true,
			LightVerification:       true,
			BatchProcessing:         true,
			MobileValidatorReward:   big.NewInt(3e18), // 3个代币
			BatteryAwareConsensus:   true,
			NetworkAwareConsensus:   true,
			StorageAwareConsensus:   true,
			MobileParticipationBonus: big.NewInt(8e17), // 0.8个代币
			DataContributionReward:   big.NewInt(15e17), // 1.5个代币
			LowPowerReward:           big.NewInt(5e17), // 0.5个代币
			AdaptiveValidation:       true,
			DynamicBlockSize:         true,
			DynamicCommitteeSize:     true,
		},
	}
)

// getActiveMobileFork 获取激活的移动端分叉
func (p *Parlia) getActiveMobileFork(number uint64, timestamp uint64) *MobileForkInfo {
	if number >= MobileFork2.Block || (MobileFork2.Timestamp > 0 && timestamp >= MobileFork2.Timestamp) {
		return MobileFork2
	}
	if number >= MobileFork1.Block || (MobileFork1.Timestamp > 0 && timestamp >= MobileFork1.Timestamp) {
		return MobileFork1
	}
	return nil
}

// isMobileForkActive 检查移动端分叉是否激活
func (p *Parlia) isMobileForkActive(fork *MobileForkInfo, number uint64, timestamp uint64) bool {
	if fork == nil {
		return false
	}
	return number >= fork.Block || (fork.Timestamp > 0 && timestamp >= fork.Timestamp)
}

// validateMobileConsensusParameters 验证移动端共识参数
func (p *Parlia) validateMobileConsensusParameters(header *types.Header, parents []*types.Header, validator common.Address) error {
	number := header.Number.Uint64()
	timestamp := header.Time
	
	mobileFork := p.getActiveMobileFork(number, timestamp)
	if mobileFork == nil {
		return nil // 没有激活的移动端分叉
	}
	
	// 检查区块间隔
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[0]
	}
	if parent != nil && mobileFork.Params.BlockInterval > 0 {
		minBlockTime := parent.Time + mobileFork.Params.BlockInterval
		if header.Time < minBlockTime {
			return errInvalidBlockTime
		}
	}
	
	// 如果启用了动态区块大小
	if mobileFork.Params.DynamicBlockSize {
		// 根据网络状况调整区块大小
		networkCondition := p.getNetworkCondition()
		if networkCondition == "poor" && header.GasLimit > params.GenesisGasLimit/2 {
			return errBlockGasLimitTooHigh
		}
	}
	
	// 其他移动特定验证...
	
	return nil
}

// getNetworkCondition 获取网络状况
func (p *Parlia) getNetworkCondition() string {
	// 这里应该实际检测网络状况
	// 简化实现，返回固定值
	return "good"
}

// getMobileValidatorReward 获取移动验证者奖励
func (p *Parlia) getMobileValidatorReward(header *types.Header, state StateDB) *big.Int {
	number := header.Number.Uint64()
	timestamp := header.Time
	
	mobileFork := p.getActiveMobileFork(number, timestamp)
	if mobileFork == nil {
		return big.NewInt(0) // 没有激活的移动端分叉
	}
	
	reward := new(big.Int).Set(mobileFork.Params.MobileValidatorReward)
	
	// 如果是移动验证者，增加奖励
	validator := p.getValidator(header, state)
	if p.isMobileValidator(validator) {
		// 基础移动奖励
		reward.Add(reward, mobileFork.Params.MobileParticipationBonus)
		
		// 如果处于低功耗模式，增加低功耗奖励
		if p.isLowPowerValidator(validator) && mobileFork.Params.LowPowerMode {
			reward.Add(reward, mobileFork.Params.LowPowerReward)
		}
		
		// 如果有数据贡献，增加数据贡献奖励
		if p.hasDataContribution(validator, header) {
			reward.Add(reward, mobileFork.Params.DataContributionReward)
		}
	}
	
	return reward
}

// isMobileValidator 判断是否为移动验证者
func (p *Parlia) isMobileValidator(validator common.Address) bool {
	// 在实际实现中，应该检查验证者类型
	// 这里简化实现，通过地址前缀判断
	return bytes.HasPrefix(validator.Bytes(), []byte{0x99})
}

// isLowPowerValidator 判断是否为低功耗验证者
func (p *Parlia) isLowPowerValidator(validator common.Address) bool {
	// 在实际实现中，应该检查验证者的功耗状态
	// 这里简化实现，通过地址前缀判断
	return bytes.HasPrefix(validator.Bytes(), []byte{0x98})
}

// hasDataContribution 判断是否有数据贡献
func (p *Parlia) hasDataContribution(validator common.Address, header *types.Header) bool {
	// 在实际实现中，应该检查验证者的数据贡献
	// 这里简化实现，假设所有验证者都有贡献
	return true
}

// getValidator 获取区块验证者
func (p *Parlia) getValidator(header *types.Header, state StateDB) common.Address {
	// 在实际实现中，应该从状态或区块中获取验证者
	// 这里简化实现，返回固定地址
	return common.HexToAddress("0x9900000000000000000000000000000000000000")
}

// applyMobileFork 应用移动端分叉
func (p *Parlia) applyMobileFork(config *params.ChainConfig, header *types.Header, state StateDB) error {
	number := header.Number.Uint64()
	timestamp := header.Time
	
	// 检查是否需要应用移动端分叉
	mobileFork := p.getActiveMobileFork(number, timestamp)
	if mobileFork == nil {
		return nil
	}
	
	// 记录分叉激活
	log.Info("应用移动端共识分叉", 
		"分叉", mobileFork.Name, 
		"区块", number,
		"时间戳", timestamp,
		"特性ID", mobileFork.FeatureID)
	
	// 根据分叉参数调整系统设置
	if mobileFork.Params.FastFinality {
		// 设置快速确认性参数
		p.setFastFinality(mobileFork.Params.BlockInterval)
	}
	
	if mobileFork.Params.AdaptiveValidation {
		// 设置自适应验证
		p.setAdaptiveValidation(mobileFork.Params.DynamicCommitteeSize)
	}
	
	// 应用其他移动端特定设置...
	
	return nil
}

// setFastFinality 设置快速确认性
func (p *Parlia) setFastFinality(blockInterval uint64) {
	// 在实际实现中，应该设置相应的参数
	log.Debug("设置快速确认性", "区块间隔", blockInterval)
}

// setAdaptiveValidation 设置自适应验证
func (p *Parlia) setAdaptiveValidation(dynamicCommitteeSize bool) {
	// 在实际实现中，应该设置相应的参数
	log.Debug("设置自适应验证", "动态委员会大小", dynamicCommitteeSize)
}

// 其他移动端特定函数...

// 以下是移动端优化的区块验证和生成函数

// verifyMobileHeader 验证移动端区块头
func (p *Parlia) verifyMobileHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header, verify bool) error {
	// 标准区块头验证
	err := p.verifyHeader(chain, header, parents, verify)
	if err != nil {
		return err
	}
	
	// 移动端特定验证
	number := header.Number.Uint64()
	timestamp := header.Time
	
	mobileFork := p.getActiveMobileFork(number, timestamp)
	if mobileFork == nil {
		return nil // 没有激活的移动端分叉
	}
	
	// 获取区块验证者
	state, err := chain.StateAt(parents[0].Root)
	if err != nil {
		return err
	}
	
	validator := p.getValidator(header, state)
	
	// 移动端共识参数验证
	return p.validateMobileConsensusParameters(header, parents, validator)
}

// finalizeMobileBlock 完成移动端区块
func (p *Parlia) finalizeMobileBlock(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction) error {
	// 标准区块完成
	err := p.finalize(chain, header, state, txs, nil)
	if err != nil {
		return err
	}
	
	// 移动端特定逻辑
	number := header.Number.Uint64()
	timestamp := header.Time
	
	mobileFork := p.getActiveMobileFork(number, timestamp)
	if mobileFork == nil {
		return nil // 没有激活的移动端分叉
	}
	
	// 获取验证者
	validator := p.getValidator(header, *state)
	
	// 计算移动验证者奖励
	reward := p.getMobileValidatorReward(header, *state)
	
	// 分配奖励
	if reward.Sign() > 0 {
		(*state).AddBalance(validator, reward)
		log.Debug("分配移动验证者奖励", 
			"验证者", validator.Hex(), 
			"奖励", reward.String(),
			"区块", number)
	}
	
	// 应用移动端分叉
	return p.applyMobileFork(chain.Config(), header, *state)
} 