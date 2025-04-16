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
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/log"
)

// 隐私级别枚举
type PrivacyLevel int

const (
	PrivacyLevelStandard    PrivacyLevel = 0 // 标准模式，不使用隐私功能
	PrivacyLevelBasic       PrivacyLevel = 1 // 基础隐私，混淆地址
	PrivacyLevelEnhanced    PrivacyLevel = 2 // 增强隐私，加密部分交易数据
	PrivacyLevelFull        PrivacyLevel = 3 // 完全隐私，全部采用加密和零知识证明
)

// PrivacyConfig 隐私功能配置
type PrivacyConfig struct {
	// 隐私级别控制
	privacyLevel atomic.Int32 // 当前隐私级别
	
	// 地区合规设置
	regionCompliance map[string]RegionComplianceConfig // 不同地区的合规配置
	
	// 加密相关设置
	useZeroKnowledge       bool // 是否使用零知识证明
	useRingSignatures      bool // 是否使用环签名
	useStealthAddresses    bool // 是否使用隐匿地址
	useDeterministicKeys   bool // 是否使用确定性密钥派生
	
	// 数据保留设置
	dataRetentionPeriod  int64 // 数据保留期(秒)
	dataExportEnabled    bool  // 是否允许导出加密数据
	
	// 备份与恢复设置
	backupPrivateData    bool  // 是否备份私有数据
	
	// 审计设置
	auditLogEnabled      bool  // 是否启用审计日志
	auditLogRetention    int64 // 审计日志保留期(秒)
	
	// 访问控制
	accessControlEnabled bool  // 是否启用访问控制
	
	// 合规管控
	forceDecryptForAuthorities bool // 是否强制为管控机构解密
	enableLegalCompliance      bool // 是否启用法律合规性功能
	
	mu sync.RWMutex
}

// RegionComplianceConfig 区域合规配置
type RegionComplianceConfig struct {
	MaxPrivacyLevel      PrivacyLevel // 最大允许的隐私级别
	RequireKYC           bool         // 是否要求KYC认证
	RequireAML           bool         // 是否要求反洗钱合规
	DataRetentionPeriod  int64        // 数据保留期(秒)
	MandatoryAuditLog    bool         // 是否强制要求审计日志
	AllowStealthAddress  bool         // 是否允许隐匿地址
	AllowZeroKnowledge   bool         // 是否允许零知识证明
	ComplianceAuthorities []string     // 合规监管机构列表
}

// 预定义的区域合规配置
var predefinedRegionCompliance = map[string]RegionComplianceConfig{
	"international": {
		MaxPrivacyLevel:      PrivacyLevelFull,
		RequireKYC:           false,
		RequireAML:           false,
		DataRetentionPeriod:  0, // 无限期
		MandatoryAuditLog:    false,
		AllowStealthAddress:  true,
		AllowZeroKnowledge:   true,
		ComplianceAuthorities: []string{},
	},
	"eu": {
		MaxPrivacyLevel:      PrivacyLevelEnhanced,
		RequireKYC:           true,
		RequireAML:           true,
		DataRetentionPeriod:  63072000, // 2年
		MandatoryAuditLog:    true,
		AllowStealthAddress:  true,
		AllowZeroKnowledge:   true,
		ComplianceAuthorities: []string{"EU-AUTHORITY"},
	},
	"us": {
		MaxPrivacyLevel:      PrivacyLevelBasic,
		RequireKYC:           true,
		RequireAML:           true,
		DataRetentionPeriod:  94608000, // 3年
		MandatoryAuditLog:    true,
		AllowStealthAddress:  false,
		AllowZeroKnowledge:   false,
		ComplianceAuthorities: []string{"US-AUTHORITY"},
	},
	"cn": {
		MaxPrivacyLevel:      PrivacyLevelStandard,
		RequireKYC:           true,
		RequireAML:           true,
		DataRetentionPeriod:  157680000, // 5年
		MandatoryAuditLog:    true,
		AllowStealthAddress:  false,
		AllowZeroKnowledge:   false,
		ComplianceAuthorities: []string{"CN-AUTHORITY"},
	},
}

// NewPrivacyConfig 创建新的隐私配置
func NewPrivacyConfig() *PrivacyConfig {
	pc := &PrivacyConfig{
		regionCompliance:       make(map[string]RegionComplianceConfig),
		useZeroKnowledge:       true,
		useRingSignatures:      true,
		useStealthAddresses:    true,
		useDeterministicKeys:   true,
		dataRetentionPeriod:    0, // 无限期
		dataExportEnabled:      true,
		backupPrivateData:      true,
		auditLogEnabled:        true,
		auditLogRetention:      31536000, // 1年
		accessControlEnabled:   true,
		forceDecryptForAuthorities: false,
		enableLegalCompliance:      false,
	}
	
	// 设置默认隐私级别
	pc.privacyLevel.Store(int32(PrivacyLevelStandard))
	
	// 加载预定义的区域合规配置
	for region, config := range predefinedRegionCompliance {
		pc.regionCompliance[region] = config
	}
	
	return pc
}

// SetPrivacyLevel 设置隐私级别
func (pc *PrivacyConfig) SetPrivacyLevel(level PrivacyLevel) {
	pc.privacyLevel.Store(int32(level))
	log.Info("隐私级别已更新", "级别", level)
}

// GetPrivacyLevel 获取当前隐私级别
func (pc *PrivacyConfig) GetPrivacyLevel() PrivacyLevel {
	return PrivacyLevel(pc.privacyLevel.Load())
}

// ApplyRegionCompliance 应用特定地区的合规配置
func (pc *PrivacyConfig) ApplyRegionCompliance(region string) bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	
	config, exists := pc.regionCompliance[region]
	if !exists {
		log.Error("未找到指定地区的合规配置", "地区", region)
		return false
	}
	
	// 应用地区合规配置
	pc.SetPrivacyLevel(config.MaxPrivacyLevel)
	pc.useZeroKnowledge = config.AllowZeroKnowledge
	pc.useStealthAddresses = config.AllowStealthAddress
	pc.dataRetentionPeriod = config.DataRetentionPeriod
	pc.auditLogEnabled = config.MandatoryAuditLog
	pc.enableLegalCompliance = true
	
	// 如果地区要求强制合规，则设置相应的标志
	if len(config.ComplianceAuthorities) > 0 {
		pc.forceDecryptForAuthorities = true
	}
	
	log.Info("已应用地区合规配置", 
		"地区", region, 
		"隐私级别", config.MaxPrivacyLevel,
		"允许零知识证明", config.AllowZeroKnowledge,
		"允许隐匿地址", config.AllowStealthAddress)
	
	return true
}

// IsFeatureEnabled 检查特定隐私功能是否启用
func (pc *PrivacyConfig) IsFeatureEnabled(feature string) bool {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	
	currentLevel := pc.GetPrivacyLevel()
	
	switch feature {
	case "zero_knowledge":
		return pc.useZeroKnowledge && currentLevel >= PrivacyLevelFull
	case "ring_signatures":
		return pc.useRingSignatures && currentLevel >= PrivacyLevelEnhanced
	case "stealth_addresses":
		return pc.useStealthAddresses && currentLevel >= PrivacyLevelBasic
	case "encrypted_transactions":
		return currentLevel >= PrivacyLevelEnhanced
	case "audit_log":
		return pc.auditLogEnabled
	case "data_export":
		return pc.dataExportEnabled
	default:
		return false
	}
}

// EnableFeature 启用特定隐私功能
func (pc *PrivacyConfig) EnableFeature(feature string, enable bool) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	
	switch feature {
	case "zero_knowledge":
		pc.useZeroKnowledge = enable
	case "ring_signatures":
		pc.useRingSignatures = enable
	case "stealth_addresses":
		pc.useStealthAddresses = enable
	case "audit_log":
		pc.auditLogEnabled = enable
	case "data_export":
		pc.dataExportEnabled = enable
	case "backup_private_data":
		pc.backupPrivateData = enable
	case "access_control":
		pc.accessControlEnabled = enable
	case "force_decrypt":
		pc.forceDecryptForAuthorities = enable
	case "legal_compliance":
		pc.enableLegalCompliance = enable
	}
	
	log.Info("隐私功能状态已更新", "功能", feature, "状态", enable)
}

// IsAuthorityDecryptionEnabled 检查是否启用了为权威机构解密的功能
func (pc *PrivacyConfig) IsAuthorityDecryptionEnabled() bool {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.forceDecryptForAuthorities
}

// GetSupportedRegions 获取支持的区域列表
func (pc *PrivacyConfig) GetSupportedRegions() []string {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	
	regions := make([]string, 0, len(pc.regionCompliance))
	for region := range pc.regionCompliance {
		regions = append(regions, region)
	}
	
	return regions
}

// AddCustomRegion 添加自定义区域合规配置
func (pc *PrivacyConfig) AddCustomRegion(region string, config RegionComplianceConfig) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	
	pc.regionCompliance[region] = config
	log.Info("已添加自定义区域合规配置", "区域", region)
}

// GetDataRetentionPeriod 获取数据保留期
func (pc *PrivacyConfig) GetDataRetentionPeriod() int64 {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.dataRetentionPeriod
}

// SetDataRetentionPeriod 设置数据保留期
func (pc *PrivacyConfig) SetDataRetentionPeriod(seconds int64) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.dataRetentionPeriod = seconds
}

// IsLegalComplianceEnabled 检查是否启用法律合规性
func (pc *PrivacyConfig) IsLegalComplianceEnabled() bool {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.enableLegalCompliance
}

// 全局隐私配置实例
var (
	GlobalPrivacyConfig *PrivacyConfig
	initPrivacyOnce     sync.Once
)

// GetGlobalPrivacyConfig 获取全局隐私配置实例
func GetGlobalPrivacyConfig() *PrivacyConfig {
	initPrivacyOnce.Do(func() {
		GlobalPrivacyConfig = NewPrivacyConfig()
	})
	return GlobalPrivacyConfig
} 