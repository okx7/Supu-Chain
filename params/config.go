// Copyright 2016 The go-ethereum Authors
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

package params

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params/forks"
)

// Genesis hashes to enforce below configs on.
var (
	MainnetGenesisHash = common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")

	BSCGenesisHash    = common.HexToHash("0x0d21840abff46b96c84b2ac9e10e4f5cdaeb5693cb665db62a2f3b02d2d57b5b")
	ChapelGenesisHash = common.HexToHash("0x6d3c66c5357ec91d5c43af47e234a939b22557cbb552dc45bebbceeed90fbe34")
	RialtoGenesisHash = common.HexToHash("0xee835a629f9cf5510b48b6ba41d69e0ff7d6ef10f977166ef939db41f59f5501")
	
	// Supur链创世哈希
	SupurGenesisHash = common.HexToHash("0x3c4fbee1d83cc66400f2d3fc026d2df719b0e008234b8f0d26cbdf15325932c8")
)

func newUint64(val uint64) *uint64 { return &val }

// 默认移动端配置参数
var (
	// 移动端默认同步模式配置
	DefaultMobileSyncConfig = &MobileSyncConfig{
		LightMode:               true,   // 默认开启轻节点同步模式
		IncrementalSync:         true,   // 默认开启增量同步
		SnapshotSyncEnabled:     true,   // 默认开启快照同步
		StatePruningEnabled:     true,   // 状态裁剪，减少存储需求
		MaxSyncPeers:            5,      // 最大同步节点数
		MinSyncPeers:            2,      // 最小同步节点数
		SyncFrequencyOnBattery:  30,     // 电池模式下同步频率（分钟）
		SyncFrequencyOnCharging: 5,      // 充电模式下同步频率（分钟）
		MaxBlockSize:            2097152, // 最大区块大小（2MB）
		// 极致轻量化配置
		HeaderOnlySync:          false,  // 默认不启用仅同步区块头模式
		StateRootVerificationOnly: false, // 默认不启用仅验证状态根模式
		ZKProofVerification:    false,  // 默认不启用零知识证明验证
		MerkleProofVerification: true,   // 默认启用Merkle证明验证
		OfflineFirstEnabled:     true,   // 离线优先模式，允许在无网络情况下使用缓存数据
		MaxHeaderBatchSize:      100,    // 最大区块头批量同步数
		DynamicSyncFrequency:    true,   // 动态调整同步频率
		DeltaSyncEnabled:        true,   // 增量状态同步
	}

	// 移动端资源管理配置
	DefaultMobileResourceConfig = &MobileResourceConfig{
		LowBatteryThreshold:     20,     // 低电量阈值（百分比）
		BatteryOptimizationMode: true,   // 默认开启电池优化
		NetworkTypeAwareness:    true,   // 默认开启网络类型感知
		DataSavingMode:          false,  // 默认关闭数据节省模式
		MaxCPUUsage:             50,     // 最大CPU使用率（百分比）
		MaxMemoryUsage:          200,    // 最大内存使用（MB）
		MaxStorageUsage:         1024,   // 最大存储使用（MB）
		BackgroundModeEnabled:   true,   // 后台模式启用
		// 增强资源管理配置
		AdaptiveResourceAllocation: true, // 自适应资源分配
		SleepModeEnabled:        true,   // 休眠模式支持
		NetworkPrioritization:   true,   // 网络资源优先级管理
		PerformanceProfile:      1,      // 性能配置文件（0：极致省电，1：均衡，2：高性能）
		IoTModeEnabled:          false,  // IoT设备模式（更极致的资源限制）
		DataCompressionLevel:    7,      // 数据压缩级别（1-9，越高压缩率越高）
		PeriodicMaintenance:     true,   // 定期维护（垃圾回收、缓存清理等）
	}

	// 移动端安全配置
	DefaultMobileSecurityConfig = &MobileSecurityConfig{
		TEEEnabled:              false,  // 默认关闭可信执行环境
		BiometricAuthRequired:   false,  // 默认不要求生物识别认证
		HardwareKeyStoreEnabled: true,   // 默认启用硬件密钥存储
		AutoLockTimeout:         5,      // 自动锁定超时（分钟）
		SecureEnclaveSupport:    true,   // 支持安全飞地（如苹果的Secure Enclave）
		// 增强安全配置
		MPCWalletEnabled:        false,  // 多方计算钱包支持
		SocialRecoveryEnabled:   true,   // 社交恢复支持
		ThresholdSignatures:     false,  // 门限签名支持
		SecureBackupEnabled:     true,   // 安全备份支持
		AntiPhishingProtection:  true,   // 防钓鱼保护
		RealTimeSecurityAuditing: false, // 实时安全审计
		LocalEncryptionEnabled:  true,   // 本地数据加密
		SecureElementIntegration: true,  // 安全元件集成
		BiometricTransactionConfirmation: false, // 交易生物识别确认
	}

	// 移动端P2P网络配置
	DefaultMobileP2PConfig = &MobileP2PConfig{
		EnableQUIC:            true,    // 启用QUIC协议
			EnableNATTraversal:    true,    // 启用NAT穿透
			MaxInboundConnections: 10,      // 最大入站连接数
			MaxOutboundConnections: 5,      // 最大出站连接数
			PeerDiscoveryMode:     1,       // 0: 不发现, 1: 轻量发现, 2: 完全发现
			DiscoveryInterval:     60,      // 发现间隔（秒）
			EnableWebRTC:          false,   // 是否启用WebRTC协议
			DisconnectOnSleep:     true,    // 设备休眠时是否断开连接
			// 增强网络配置
			EnableBluetooth:       false,   // 启用蓝牙发现和连接
			EnableWifiDirect:      false,   // 启用WiFi直连
			ResumeDownloadEnabled: true,    // 启用断点续传
			WeakNetworkTolerance:  true,    // 弱网容错
			ProxySupport:          true,    // 代理支持
			CircuitBreakingEnabled: true,   // 熔断机制
			AdaptiveTimeout:       true,    // 自适应超时
			PrioritizedSyncing:    true,    // 优先级同步（重要数据优先）
			MeshNetworkingEnabled: false,   // 网格网络支持
			LowPowerBroadcast:     true,    // 低功耗广播
	}

	// 移动端特定的ParliaConfig配置
	DefaultMobileParliaConfig = &ParliaConfig{
		// 针对移动端优化的PoSA配置
		MobileOptimized:      true,     // 移动端优化开关
		LightValidation:      true,     // 轻量级验证模式
		ShardingEnabled:      false,    // 分片支持（未来规划）
		ValidatorSetSize:     21,       // 验证人集合大小
		MinStakeAmount:       big.NewInt(100000000000000000), // 最小质押数量
		// 移动端激励机制配置
		MobileValidatorRewards: true,   // 移动验证者额外奖励
		BatteryAwareStaking:    true,   // 电池感知质押（充电时更活跃）
		DataContributionRewards: true,  // 数据贡献奖励
		ResourceSharingRewards:  true,  // 资源共享奖励
		ParticipationCredits:   true,   // 参与积分系统
	}

	// 隐私交易配置
	DefaultPrivacyConfig = &PrivacyConfig{
		PrivateTransactionsEnabled: false, // 隐私交易开关
		ZKTransactionsEnabled:     false,  // 零知识证明交易
		AnonymousTransactions:     false,  // 匿名交易
		ConfidentialAssets:        false,  // 保密资产
		EndToEndEncryption:        true,   // 端到端加密
		MetadataProtection:        true,   // 元数据保护
		MixerSupport:              false,  // 混币器支持
		StealthAddressesEnabled:   false,  // 隐形地址支持
		RingSignaturesEnabled:     false,  // 环签名支持
		ZeroKnowledgeProofType:    "groth16", // ZK证明类型 (groth16, bulletproofs, plonk等)
	}

	// 开发者工具链配置
	DefaultDevToolsConfig = &DevToolsConfig{
		SDKEnabled:              true,   // SDK支持
		DAppTemplatesEnabled:    true,   // DApp模板支持
		APIDocumentation:        true,   // API文档
		MobileDebuggerEnabled:   true,   // 移动调试器
		MobileTestnetSupport:    true,   // 移动测试网支持
		DevOnboardingSupport:    true,   // 开发者引导支持
		APICompatibilityMode:    "full", // API兼容性模式 (minimal, standard, full)
		SimulatorEnabled:        true,   // 模拟器支持
		AnalyticsEnabled:        true,   // 分析工具支持
		LocalDevEnvironment:     true,   // 本地开发环境
	}

	// 性能监控配置
	DefaultPerformanceMonitorConfig = &PerformanceMonitorConfig{
		Enabled:                 true,   // 启用性能监控
		BatteryMonitoring:       true,   // 电池监控
		NetworkMonitoring:       true,   // 网络监控
		StorageMonitoring:       true,   // 存储监控
		CPUMonitoring:           true,   // CPU监控
		MemoryMonitoring:        true,   // 内存监控
		TelemetryEnabled:        false,  // 遥测数据收集（匿名）
		AutoTuningEnabled:       true,   // 自动调优
		PerformanceReporting:    false,  // 性能报告
		UserFeedbackEnabled:     true,   // 用户反馈收集
		DiagnosticMode:          false,  // 诊断模式
	}

	// Layer2配置
	DefaultLayer2Config = &Layer2Config{
		Enabled:                 false,  // 默认不启用Layer2
		Type:                    "rollup", // Layer2类型：rollup, plasma, validium等
		MobileOptimized:         true,   // 移动优化
		DirectDeposit:           true,   // 直接充值支持
		FastWithdrawals:         true,   // 快速提现
		BatchSubmissionInterval: 10,     // 批量提交间隔（分钟）
		LocalVerification:       true,   // 本地验证
		StateValidation:         true,   // 状态验证
		FraudProofVerification:  true,   // 欺诈证明验证
		ValidityProofVerification: false, // 有效性证明验证（ZK-Rollup）
		CrossLayerMessageLimit:  50,     // 跨层消息限制
	}
)

// 更新Supur链配置，增加新的移动端优化特性
var SupurChainConfig = &ChainConfig{
	ChainID:             big.NewInt(776),       // 自定义Supur链的链ID
	HomesteadBlock:      big.NewInt(0),
	EIP150Block:         big.NewInt(0),
	EIP155Block:         big.NewInt(0),
	EIP158Block:         big.NewInt(0),
	ByzantiumBlock:      big.NewInt(0),
	ConstantinopleBlock: big.NewInt(0),
	PetersburgBlock:     big.NewInt(0),
	IstanbulBlock:       big.NewInt(0),
	MuirGlacierBlock:    big.NewInt(0),
	RamanujanBlock:      big.NewInt(0),
	NielsBlock:          big.NewInt(0),
	MirrorSyncBlock:     big.NewInt(0),         // 从区块0开始启用所有特性
	BrunoBlock:          big.NewInt(0),
	EulerBlock:          big.NewInt(0),
	NanoBlock:           big.NewInt(0),
	MoranBlock:          big.NewInt(0),
	GibbsBlock:          big.NewInt(0),
	PlanckBlock:         big.NewInt(0),
	LubanBlock:          big.NewInt(0),
	PlatoBlock:          big.NewInt(0),
	BerlinBlock:         big.NewInt(0),
	LondonBlock:         big.NewInt(0),
	HertzBlock:          big.NewInt(0),
	HertzfixBlock:       big.NewInt(0),
	ShanghaiTime:        newUint64(0),          // 时间设为0表示从创世块开始就启用
	KeplerTime:          newUint64(0),
	FeynmanTime:         newUint64(0),
	FeynmanFixTime:      newUint64(0),
	CancunTime:          newUint64(0),
	HaberTime:           newUint64(0),
	HaberFixTime:        newUint64(0),
	BohrTime:            newUint64(0),
	PascalTime:          newUint64(0),
	PragueTime:          newUint64(0),
	LorentzTime:         newUint64(0),

	// 使用针对移动端优化的Parlia共识配置
	Parlia: DefaultMobileParliaConfig,

	BlobScheduleConfig: &BlobScheduleConfig{
		Cancun: DefaultCancunBlobConfig,
		Prague: DefaultPragueBlobConfigBSC,
	},
	
	// 移动端特定配置
	MobileSync:     DefaultMobileSyncConfig,     // 移动端同步配置
	MobileResource: DefaultMobileResourceConfig, // 移动端资源管理
	MobileSecurity: DefaultMobileSecurityConfig, // 移动端安全配置
	MobileP2P:      DefaultMobileP2PConfig,      // 移动端P2P网络配置
	
	// 超轻量节点标识
	UltraLightClient: true,                      // 启用超轻量客户端模式
	
	// 分片相关配置
	ShardingEnabled: false,                      // 默认不启用分片
	ShardCount:      4,                          // 分片数量，仅在ShardingEnabled为true时有效
	
	// Layer2相关配置 - 升级版
	Layer2Enabled:   false,                      // 默认不启用Layer2
	Layer2Type:      "rollup",                   // Layer2类型：rollup, plasma, validium等
	Layer2Config:    DefaultLayer2Config,        // 详细Layer2配置
	
	// ZK证明支持
	ZKProofEnabled:  false,                      // 默认不启用零知识证明
	ZKProofType:     "snark",                    // 零知识证明类型：snark, stark等
	
	// 新增配置
	PrivacyConfig:   DefaultPrivacyConfig,       // 隐私交易配置
	DevTools:        DefaultDevToolsConfig,      // 开发者工具链配置
	PerformanceMonitor: DefaultPerformanceMonitorConfig, // 性能监控配置
	
	// EVM兼容性配置
	EVMCompatibilityMode: "full",                // EVM兼容性模式（full, partial, custom）
	
	// 社区治理配置
	MobileGovernanceEnabled: true,               // 移动端治理支持
	LightGovernanceProposals: true,              // 轻量级治理提案
	GovernanceVotingPower: "stake+activity",     // 治理投票权重（stake, activity, combined）
}

// ChainConfig扩展，添加新字段
type ChainConfig struct {
	ChainID *big.Int `json:"chainId"` // chainId identifies the current chain and is used for replay protection

	HomesteadBlock *big.Int `json:"homesteadBlock,omitempty"` // Homestead switch block (nil = no fork, 0 = already homestead)

	DAOForkBlock   *big.Int `json:"daoForkBlock,omitempty"`   // TheDAO hard-fork switch block (nil = no fork)
	DAOForkSupport bool     `json:"daoForkSupport,omitempty"` // Whether the nodes supports or opposes the DAO hard-fork

	// EIP150 implements the Gas price changes (https://github.com/ethereum/EIPs/issues/150)
	EIP150Block *big.Int `json:"eip150Block,omitempty"` // EIP150 HF block (nil = no fork)
	EIP155Block *big.Int `json:"eip155Block,omitempty"` // EIP155 HF block
	EIP158Block *big.Int `json:"eip158Block,omitempty"` // EIP158 HF block

	ByzantiumBlock      *big.Int `json:"byzantiumBlock,omitempty"`      // Byzantium switch block (nil = no fork, 0 = already on byzantium)
	ConstantinopleBlock *big.Int `json:"constantinopleBlock,omitempty"` // Constantinople switch block (nil = no fork, 0 = already activated)
	PetersburgBlock     *big.Int `json:"petersburgBlock,omitempty"`     // Petersburg switch block (nil = same as Constantinople)
	IstanbulBlock       *big.Int `json:"istanbulBlock,omitempty"`       // Istanbul switch block (nil = no fork, 0 = already on istanbul)
	MuirGlacierBlock    *big.Int `json:"muirGlacierBlock,omitempty"`    // Eip-2384 (bomb delay) switch block (nil = no fork, 0 = already activated)
	BerlinBlock         *big.Int `json:"berlinBlock,omitempty"`         // Berlin switch block (nil = no fork, 0 = already on berlin)
	YoloV3Block         *big.Int `json:"yoloV3Block,omitempty"`         // YOLO v3: Gas repricings TODO @holiman add EIP references
	CatalystBlock       *big.Int `json:"catalystBlock,omitempty"`       // Catalyst switch block (nil = no fork, 0 = already on catalyst)
	LondonBlock         *big.Int `json:"londonBlock,omitempty"`         // London switch block (nil = no fork, 0 = already on london)
	ArrowGlacierBlock   *big.Int `json:"arrowGlacierBlock,omitempty"`   // Eip-4345 (bomb delay) switch block (nil = no fork, 0 = already activated)
	GrayGlacierBlock    *big.Int `json:"grayGlacierBlock,omitempty"`    // Eip-5133 (bomb delay) switch block (nil = no fork, 0 = already activated)
	MergeNetsplitBlock  *big.Int `json:"mergeNetsplitBlock,omitempty"`  // Virtual fork after The Merge to use as a network splitter

	// Fork scheduling was switched from blocks to timestamps here

	ShanghaiTime   *uint64 `json:"shanghaiTime,omitempty"`   // Shanghai switch time (nil = no fork, 0 = already on shanghai)
	KeplerTime     *uint64 `json:"keplerTime,omitempty"`     // Kepler switch time (nil = no fork, 0 = already activated)
	FeynmanTime    *uint64 `json:"feynmanTime,omitempty"`    // Feynman switch time (nil = no fork, 0 = already activated)
	FeynmanFixTime *uint64 `json:"feynmanFixTime,omitempty"` // FeynmanFix switch time (nil = no fork, 0 = already activated)
	CancunTime     *uint64 `json:"cancunTime,omitempty"`     // Cancun switch time (nil = no fork, 0 = already on cancun)
	HaberTime      *uint64 `json:"haberTime,omitempty"`      // Haber switch time (nil = no fork, 0 = already on haber)
	HaberFixTime   *uint64 `json:"haberFixTime,omitempty"`   // HaberFix switch time (nil = no fork, 0 = already on haberFix)
	BohrTime       *uint64 `json:"bohrTime,omitempty"`       // Bohr switch time (nil = no fork, 0 = already on bohr)
	PascalTime     *uint64 `json:"pascalTime,omitempty"`     // Pascal switch time (nil = no fork, 0 = already on pascal)
	PragueTime     *uint64 `json:"pragueTime,omitempty"`     // Prague switch time (nil = no fork, 0 = already on prague)
	OsakaTime      *uint64 `json:"osakaTime,omitempty"`      // Osaka switch time (nil = no fork, 0 = already on osaka)
	LorentzTime    *uint64 `json:"lorentzTime,omitempty"`    // Lorentz switch time (nil = no fork, 0 = already on lorentz)
	VerkleTime     *uint64 `json:"verkleTime,omitempty"`     // Verkle switch time (nil = no fork, 0 = already on verkle)

	// TerminalTotalDifficulty is the amount of total difficulty reached by
	// the network that triggers the consensus upgrade.
	TerminalTotalDifficulty *big.Int `json:"terminalTotalDifficulty,omitempty"`

	// prysm still use it, can't remove it
	TerminalTotalDifficultyPassed bool `json:"terminalTotalDifficultyPassed,omitempty"`

	DepositContractAddress common.Address `json:"depositContractAddress,omitempty"`

	// EnableVerkleAtGenesis is a flag that specifies whether the network uses
	// the Verkle tree starting from the genesis block. If set to true, the
	// genesis state will be committed using the Verkle tree, eliminating the
	// need for any Verkle transition later.
	//
	// This is a temporary flag only for verkle devnet testing, where verkle is
	// activated at genesis, and the configured activation date has already passed.
	//
	// In production networks (mainnet and public testnets), verkle activation
	// always occurs after the genesis block, making this flag irrelevant in
	// those cases.
	EnableVerkleAtGenesis bool `json:"enableVerkleAtGenesis,omitempty"`

	RamanujanBlock  *big.Int `json:"ramanujanBlock,omitempty"`  // ramanujanBlock switch block (nil = no fork, 0 = already activated)
	NielsBlock      *big.Int `json:"nielsBlock,omitempty"`      // nielsBlock switch block (nil = no fork, 0 = already activated)
	MirrorSyncBlock *big.Int `json:"mirrorSyncBlock,omitempty"` // mirrorSyncBlock switch block (nil = no fork, 0 = already activated)
	BrunoBlock      *big.Int `json:"brunoBlock,omitempty"`      // brunoBlock switch block (nil = no fork, 0 = already activated)
	EulerBlock      *big.Int `json:"eulerBlock,omitempty"`      // eulerBlock switch block (nil = no fork, 0 = already activated)
	GibbsBlock      *big.Int `json:"gibbsBlock,omitempty"`      // gibbsBlock switch block (nil = no fork, 0 = already activated)
	NanoBlock       *big.Int `json:"nanoBlock,omitempty"`       // nanoBlock switch block (nil = no fork, 0 = already activated)
	MoranBlock      *big.Int `json:"moranBlock,omitempty"`      // moranBlock switch block (nil = no fork, 0 = already activated)
	PlanckBlock     *big.Int `json:"planckBlock,omitempty"`     // planckBlock switch block (nil = no fork, 0 = already activated)
	LubanBlock      *big.Int `json:"lubanBlock,omitempty"`      // lubanBlock switch block (nil = no fork, 0 = already activated)
	PlatoBlock      *big.Int `json:"platoBlock,omitempty"`      // platoBlock switch block (nil = no fork, 0 = already activated)
	HertzBlock      *big.Int `json:"hertzBlock,omitempty"`      // hertzBlock switch block (nil = no fork, 0 = already activated)
	HertzfixBlock   *big.Int `json:"hertzfixBlock,omitempty"`   // hertzfixBlock switch block (nil = no fork, 0 = already activated)

	// Various consensus engines
	Ethash             *EthashConfig       `json:"ethash,omitempty"`
	Clique             *CliqueConfig       `json:"clique,omitempty"`
	Parlia             *ParliaConfig       `json:"parlia,omitempty"`
	BlobScheduleConfig *BlobScheduleConfig `json:"blobSchedule,omitempty"`

	// 移动端特定配置
	MobileSync     *MobileSyncConfig     `json:"mobileSync,omitempty"`     // 移动端同步配置
	MobileResource *MobileResourceConfig `json:"mobileResource,omitempty"` // 移动端资源管理
	MobileSecurity *MobileSecurityConfig `json:"mobileSecurity,omitempty"` // 移动端安全配置
	MobileP2P      *MobileP2PConfig      `json:"mobileP2P,omitempty"`      // 移动端P2P网络配置
	
	// 超轻量节点相关配置
	UltraLightClient bool `json:"ultraLightClient,omitempty"` // 是否为超轻量客户端模式
	
	// 分片相关配置
	ShardingEnabled bool `json:"shardingEnabled,omitempty"` // 是否启用分片
	ShardCount      uint `json:"shardCount,omitempty"`      // 分片数量
	
	// Layer2相关配置
	Layer2Enabled bool   `json:"layer2Enabled,omitempty"` // 是否启用Layer2
	Layer2Type    string `json:"layer2Type,omitempty"`    // Layer2类型：rollup, plasma, validium等
	Layer2Config  *Layer2Config `json:"layer2Config,omitempty"` // 详细Layer2配置
	
	// ZK证明支持
	ZKProofEnabled bool   `json:"zkProofEnabled,omitempty"` // 是否启用零知识证明
	ZKProofType    string `json:"zkProofType,omitempty"`    // 零知识证明类型：snark, stark等
	
	// 新增配置项
	PrivacyConfig   *PrivacyConfig   `json:"privacyConfig,omitempty"`   // 隐私交易配置
	DevTools        *DevToolsConfig  `json:"devTools,omitempty"`        // 开发者工具链配置
	PerformanceMonitor *PerformanceMonitorConfig `json:"performanceMonitor,omitempty"` // 性能监控配置
	
	// EVM兼容性配置
	EVMCompatibilityMode string `json:"evmCompatibilityMode,omitempty"` // EVM兼容性模式
	
	// 社区治理配置
	MobileGovernanceEnabled bool   `json:"mobileGovernanceEnabled,omitempty"` // 移动端治理支持
	LightGovernanceProposals bool  `json:"lightGovernanceProposals,omitempty"` // 轻量级治理提案
	GovernanceVotingPower    string `json:"governanceVotingPower,omitempty"`    // 治理投票权重模式
}

// MobileSyncConfig 扩展，添加极致轻量化相关配置
type MobileSyncConfig struct {
	LightMode               bool   `json:"lightMode"`                // 是否使用轻量级同步模式
	IncrementalSync         bool   `json:"incrementalSync"`          // 是否使用增量同步
	SnapshotSyncEnabled     bool   `json:"snapshotSyncEnabled"`      // 是否启用快照同步
	StatePruningEnabled     bool   `json:"statePruningEnabled"`      // 是否启用状态裁剪
	MaxSyncPeers            int    `json:"maxSyncPeers"`             // 最大同步节点数
	MinSyncPeers            int    `json:"minSyncPeers"`             // 最小同步节点数
	SyncFrequencyOnBattery  int    `json:"syncFrequencyOnBattery"`   // 电池模式下同步频率（分钟）
	SyncFrequencyOnCharging int    `json:"syncFrequencyOnCharging"`  // 充电模式下同步频率（分钟）
	MaxBlockSize            uint64 `json:"maxBlockSize"`             // 最大区块大小（字节）
	// 极致轻量化配置
	HeaderOnlySync          bool   `json:"headerOnlySync"`           // 是否仅同步区块头
	StateRootVerificationOnly bool `json:"stateRootVerificationOnly"` // 是否仅验证状态根
	ZKProofVerification     bool   `json:"zkProofVerification"`      // 是否使用零知识证明验证
	MerkleProofVerification bool   `json:"merkleProofVerification"`  // 是否使用Merkle证明验证
	OfflineFirstEnabled     bool   `json:"offlineFirstEnabled"`      // 是否启用离线优先模式
	MaxHeaderBatchSize      int    `json:"maxHeaderBatchSize"`       // 最大区块头批量同步数
	DynamicSyncFrequency    bool   `json:"dynamicSyncFrequency"`     // 是否动态调整同步频率
	DeltaSyncEnabled        bool   `json:"deltaSyncEnabled"`         // 增量状态同步
}

// MobileResourceConfig 扩展，添加更多资源管理选项
type MobileResourceConfig struct {
	LowBatteryThreshold     int    `json:"lowBatteryThreshold"`      // 低电量阈值（百分比）
	BatteryOptimizationMode bool   `json:"batteryOptimizationMode"`  // 是否开启电池优化
	NetworkTypeAwareness    bool   `json:"networkTypeAwareness"`     // 是否开启网络类型感知
	DataSavingMode          bool   `json:"dataSavingMode"`           // 是否开启数据节省模式
	MaxCPUUsage             int    `json:"maxCpuUsage"`              // 最大CPU使用率（百分比）
	MaxMemoryUsage          int    `json:"maxMemoryUsage"`           // 最大内存使用（MB）
	MaxStorageUsage         int    `json:"maxStorageUsage"`          // 最大存储使用（MB）
	BackgroundModeEnabled   bool   `json:"backgroundModeEnabled"`    // 是否启用后台模式
	// 增强资源管理
	AdaptiveResourceAllocation bool `json:"adaptiveResourceAllocation"` // 自适应资源分配
	SleepModeEnabled        bool   `json:"sleepModeEnabled"`         // 休眠模式支持
	NetworkPrioritization   bool   `json:"networkPrioritization"`    // 网络资源优先级管理
	PerformanceProfile      int    `json:"performanceProfile"`       // 性能配置文件
	IoTModeEnabled          bool   `json:"iotModeEnabled"`           // IoT设备模式
	DataCompressionLevel    int    `json:"dataCompressionLevel"`     // 数据压缩级别
	PeriodicMaintenance     bool   `json:"periodicMaintenance"`      // 定期维护
}

// MobileSecurityConfig 扩展，添加分布式密钥管理和安全增强选项
type MobileSecurityConfig struct {
	TEEEnabled              bool   `json:"teeEnabled"`               // 是否启用可信执行环境
	BiometricAuthRequired   bool   `json:"biometricAuthRequired"`    // 是否要求生物识别认证
	HardwareKeyStoreEnabled bool   `json:"hardwareKeyStoreEnabled"`  // 是否启用硬件密钥存储
	AutoLockTimeout         int    `json:"autoLockTimeout"`          // 自动锁定超时（分钟）
	SecureEnclaveSupport    bool   `json:"secureEnclaveSupport"`     // 是否支持安全飞地
	// 增强安全选项
	MPCWalletEnabled        bool   `json:"mpcWalletEnabled"`         // 多方计算钱包
	SocialRecoveryEnabled   bool   `json:"socialRecoveryEnabled"`    // 社交恢复
	ThresholdSignatures     bool   `json:"thresholdSignatures"`      // 门限签名
	SecureBackupEnabled     bool   `json:"secureBackupEnabled"`      // 安全备份
	AntiPhishingProtection  bool   `json:"antiPhishingProtection"`   // 防钓鱼保护
	RealTimeSecurityAuditing bool  `json:"realTimeSecurityAuditing"` // 实时安全审计
	LocalEncryptionEnabled  bool   `json:"localEncryptionEnabled"`   // 本地数据加密
	SecureElementIntegration bool  `json:"secureElementIntegration"` // 安全元件集成
	BiometricTransactionConfirmation bool `json:"biometricTransactionConfirmation"` // 交易生物识别确认
}

// MobileP2PConfig 扩展，添加更多P2P网络优化选项
type MobileP2PConfig struct {
	EnableQUIC            bool   `json:"enableQUIC"`               // 是否启用QUIC协议
	EnableNATTraversal    bool   `json:"enableNATTraversal"`       // 是否启用NAT穿透
	MaxInboundConnections int    `json:"maxInboundConnections"`    // 最大入站连接数
	MaxOutboundConnections int   `json:"maxOutboundConnections"`   // 最大出站连接数
	PeerDiscoveryMode     int    `json:"peerDiscoveryMode"`        // 节点发现模式
	DiscoveryInterval     int    `json:"discoveryInterval"`        // 发现间隔（秒）
	EnableWebRTC          bool   `json:"enableWebRTC"`             // 是否启用WebRTC协议
	DisconnectOnSleep     bool   `json:"disconnectOnSleep"`        // 设备休眠时是否断开连接
	// 增强P2P选项
	EnableBluetooth       bool   `json:"enableBluetooth"`          // 是否启用蓝牙
	EnableWifiDirect      bool   `json:"enableWifiDirect"`         // 是否启用WiFi直连
	ResumeDownloadEnabled bool   `json:"resumeDownloadEnabled"`    // 是否启用断点续传
	WeakNetworkTolerance  bool   `json:"weakNetworkTolerance"`     // 是否启用弱网容错
	ProxySupport          bool   `json:"proxySupport"`             // 是否支持代理
	CircuitBreakingEnabled bool  `json:"circuitBreakingEnabled"`   // 是否启用熔断机制
	AdaptiveTimeout       bool   `json:"adaptiveTimeout"`          // 是否启用自适应超时
	PrioritizedSyncing    bool   `json:"prioritizedSyncing"`       // 是否启用优先级同步
	MeshNetworkingEnabled bool   `json:"meshNetworkingEnabled"`    // 是否启用网格网络
	LowPowerBroadcast     bool   `json:"lowPowerBroadcast"`        // 是否启用低功耗广播
}

// ParliaConfig 扩展，添加移动端激励相关配置
type ParliaConfig struct {
	// 针对移动端优化的PoSA配置
	MobileOptimized bool     `json:"mobileOptimized,omitempty"` // 移动端优化开关
	LightValidation bool     `json:"lightValidation,omitempty"` // 轻量级验证模式
	ShardingEnabled bool     `json:"shardingEnabled,omitempty"` // 分片支持
	ValidatorSetSize int     `json:"validatorSetSize,omitempty"` // 验证人集合大小
	MinStakeAmount *big.Int `json:"minStakeAmount,omitempty"` // 最小质押数量
	// 移动端激励相关配置
	MobileValidatorRewards bool `json:"mobileValidatorRewards,omitempty"` // 移动验证者奖励
	BatteryAwareStaking   bool `json:"batteryAwareStaking,omitempty"`    // 电池感知质押
	DataContributionRewards bool `json:"dataContributionRewards,omitempty"` // 数据贡献奖励
	ResourceSharingRewards bool `json:"resourceSharingRewards,omitempty"`  // 资源共享奖励
	ParticipationCredits  bool `json:"participationCredits,omitempty"`   // 参与积分系统
}

// 新增隐私交易配置
type PrivacyConfig struct {
	PrivateTransactionsEnabled bool   `json:"privateTransactionsEnabled"` // 隐私交易开关
	ZKTransactionsEnabled     bool   `json:"zkTransactionsEnabled"`     // 零知识证明交易
	AnonymousTransactions     bool   `json:"anonymousTransactions"`     // 匿名交易
	ConfidentialAssets        bool   `json:"confidentialAssets"`        // 保密资产
	EndToEndEncryption        bool   `json:"endToEndEncryption"`        // 端到端加密
	MetadataProtection        bool   `json:"metadataProtection"`        // 元数据保护
	MixerSupport              bool   `json:"mixerSupport"`              // 混币器支持
	StealthAddressesEnabled   bool   `json:"stealthAddressesEnabled"`   // 隐形地址支持
	RingSignaturesEnabled     bool   `json:"ringSignaturesEnabled"`     // 环签名支持
	ZeroKnowledgeProofType    string `json:"zeroKnowledgeProofType"`    // ZK证明类型
}

// 新增开发者工具链配置
type DevToolsConfig struct {
	SDKEnabled              bool   `json:"sdkEnabled"`              // SDK支持
	DAppTemplatesEnabled    bool   `json:"dappTemplatesEnabled"`    // DApp模板支持
	APIDocumentation        bool   `json:"apiDocumentation"`        // API文档
	MobileDebuggerEnabled   bool   `json:"mobileDebuggerEnabled"`   // 移动调试器
	MobileTestnetSupport    bool   `json:"mobileTestnetSupport"`    // 移动测试网支持
	DevOnboardingSupport    bool   `json:"devOnboardingSupport"`    // 开发者引导支持
	APICompatibilityMode    string `json:"apiCompatibilityMode"`    // API兼容性模式
	SimulatorEnabled        bool   `json:"simulatorEnabled"`        // 模拟器支持
	AnalyticsEnabled        bool   `json:"analyticsEnabled"`        // 分析工具支持
	LocalDevEnvironment     bool   `json:"localDevEnvironment"`     // 本地开发环境
}

// 新增性能监控配置
type PerformanceMonitorConfig struct {
	Enabled                 bool   `json:"enabled"`                 // 是否启用
	BatteryMonitoring       bool   `json:"batteryMonitoring"`       // 电池监控
	NetworkMonitoring       bool   `json:"networkMonitoring"`       // 网络监控
	StorageMonitoring       bool   `json:"storageMonitoring"`       // 存储监控
	CPUMonitoring           bool   `json:"cpuMonitoring"`           // CPU监控
	MemoryMonitoring        bool   `json:"memoryMonitoring"`        // 内存监控
	TelemetryEnabled        bool   `json:"telemetryEnabled"`        // 遥测数据收集
	AutoTuningEnabled       bool   `json:"autoTuningEnabled"`       // 自动调优
	PerformanceReporting    bool   `json:"performanceReporting"`    // 性能报告
	UserFeedbackEnabled     bool   `json:"userFeedbackEnabled"`     // 用户反馈
	DiagnosticMode          bool   `json:"diagnosticMode"`          // 诊断模式
}

// 新增Layer2详细配置
type Layer2Config struct {
	Enabled                 bool   `json:"enabled"`                 // 是否启用
	Type                    string `json:"type"`                    // Layer2类型
	MobileOptimized         bool   `json:"mobileOptimized"`         // 移动优化
	DirectDeposit           bool   `json:"directDeposit"`           // 直接充值
	FastWithdrawals         bool   `json:"fastWithdrawals"`         // 快速提现
	BatchSubmissionInterval int    `json:"batchSubmissionInterval"` // 批量提交间隔
	LocalVerification       bool   `json:"localVerification"`       // 本地验证
	StateValidation         bool   `json:"stateValidation"`         // 状态验证
	FraudProofVerification  bool   `json:"fraudProofVerification"`  // 欺诈证明验证
	ValidityProofVerification bool  `json:"validityProofVerification"` // 有效性证明验证
	CrossLayerMessageLimit  int    `json:"crossLayerMessageLimit"`  // 跨层消息限制
}

// String方法增强，展示更多移动端特性信息
func (c *ChainConfig) Description() string {
	var banner string

	// 创建基本网络配置输出
	network := NetworkNames[c.ChainID.String()]
	if network == "" {
		network = "unknown"
	}
	banner += fmt.Sprintf("Chain ID:  %v (%s)\n", c.ChainID, network)
	switch {
	case c.Parlia != nil:
		if c.Parlia.MobileOptimized {
			banner += "Consensus: Mobile-Optimized Parlia (lightweight proof-of-staked-authority)\n"
		} else {
			banner += "Consensus: Parlia (proof-of-staked-authority)\n"
		}
	case c.Ethash != nil:
		banner += "Consensus: Beacon (proof-of-stake), merged from Ethash (proof-of-work)\n"
	case c.Clique != nil:
		banner += "Consensus: Beacon (proof-of-stake), merged from Clique (proof-of-authority)\n"
	default:
		banner += "Consensus: unknown\n"
	}
	
	// 添加移动端特定信息
	if c.UltraLightClient {
		banner += "Client Mode: Ultra Light (mobile-optimized)\n"
	}
	
	if c.ShardingEnabled {
		banner += fmt.Sprintf("Sharding: Enabled (shards: %d)\n", c.ShardCount)
	}
	
	if c.Layer2Enabled {
		banner += fmt.Sprintf("Layer2: Enabled (type: %s)\n", c.Layer2Type)
	}
	
	if c.ZKProofEnabled {
		banner += fmt.Sprintf("ZK Proofs: Enabled (type: %s)\n", c.ZKProofType)
	}
	
	if c.MobileSync != nil {
		syncMode := "Light"
		if c.MobileSync.HeaderOnlySync {
			syncMode = "Ultra-Light (Headers Only)"
		} else if c.MobileSync.SnapshotSyncEnabled {
			syncMode += "+Snapshot"
		}
		if c.MobileSync.IncrementalSync {
			syncMode += "+Incremental"
		}
		if c.MobileSync.ZKProofVerification {
			syncMode += "+ZK"
		}
		banner += fmt.Sprintf("Mobile Sync: %s\n", syncMode)
	}

	// 添加隐私特性信息
	if c.PrivacyConfig != nil && c.PrivacyConfig.PrivateTransactionsEnabled {
		banner += "Privacy: Enabled (";
		privacyFeatures := []string{}
		if c.PrivacyConfig.ZKTransactionsEnabled {
			privacyFeatures = append(privacyFeatures, "ZK-Tx")
		}
		if c.PrivacyConfig.AnonymousTransactions {
			privacyFeatures = append(privacyFeatures, "Anonymous")
		}
		if c.PrivacyConfig.ConfidentialAssets {
			privacyFeatures = append(privacyFeatures, "Conf-Assets")
		}
		banner += strings.Join(privacyFeatures, ", ") + ")\n"
	}

	// 添加移动端治理信息
	if c.MobileGovernanceEnabled {
		banner += fmt.Sprintf("Mobile Governance: Enabled (voting power: %s)\n", c.GovernanceVotingPower)
	}

	// 添加安全特性信息
	if c.MobileSecurity != nil {
		securityFeatures := []string{}
		if c.MobileSecurity.TEEEnabled {
			securityFeatures = append(securityFeatures, "TEE")
		}
		if c.MobileSecurity.MPCWalletEnabled {
			securityFeatures = append(securityFeatures, "MPC")
		}
		if c.MobileSecurity.BiometricAuthRequired {
			securityFeatures = append(securityFeatures, "Biometric")
		}
		if c.MobileSecurity.SocialRecoveryEnabled {
			securityFeatures = append(securityFeatures, "Social-Recovery")
		}
		if len(securityFeatures) > 0 {
			banner += "Security: " + strings.Join(securityFeatures, ", ") + "\n"
		}
	}

	return banner
}

// IsUltraLightMode 判断是否处于超轻量模式
func (c *ChainConfig) IsUltraLightMode() bool {
	return c.UltraLightClient && 
		  c.MobileSync != nil && 
		  (c.MobileSync.HeaderOnlySync || c.MobileSync.StateRootVerificationOnly)
}

// SupportsPrivateTransactions 判断是否支持隐私交易
func (c *ChainConfig) SupportsPrivateTransactions() bool {
	return c.PrivacyConfig != nil && c.PrivacyConfig.PrivateTransactionsEnabled
}

// SupportsMPCWallet 判断是否支持MPC钱包
func (c *ChainConfig) SupportsMPCWallet() bool {
	return c.MobileSecurity != nil && c.MobileSecurity.MPCWalletEnabled
}

// SupportsLayer2 判断是否支持Layer2
func (c *ChainConfig) SupportsLayer2() bool {
	return c.Layer2Enabled && c.Layer2Config != nil && c.Layer2Config.Enabled
}

// IsShardingEnabled 判断是否启用分片
func (c *ChainConfig) IsShardingEnabled() bool {
	return c.ShardingEnabled
}

// GetMobileRewardMultiplier 获取移动端验证者奖励倍数
func (c *ChainConfig) GetMobileRewardMultiplier() float64 {
	if c.Parlia != nil && c.Parlia.MobileValidatorRewards {
		return 1.2 // 移动验证者获得20%额外奖励
	}
	return 1.0
}

// GetDevToolsConfig 获取开发者工具链配置
func (c *ChainConfig) GetDevToolsConfig() *DevToolsConfig {
	if c.DevTools == nil {
		return DefaultDevToolsConfig
	}
	return c.DevTools
}

// GetPerformanceMonitorConfig 获取性能监控配置
func (c *ChainConfig) GetPerformanceMonitorConfig() *PerformanceMonitorConfig {
	if c.PerformanceMonitor == nil {
		return DefaultPerformanceMonitorConfig
	}
	return c.PerformanceMonitor
}

// GetPrivacyConfig 获取隐私交易配置
func (c *ChainConfig) GetPrivacyConfig() *PrivacyConfig {
	if c.PrivacyConfig == nil {
		return DefaultPrivacyConfig
	}
	return c.PrivacyConfig
}

// GetLayer2Config 获取Layer2配置
func (c *ChainConfig) GetLayer2Config() *Layer2Config {
	if c.Layer2Config == nil {
		return DefaultLayer2Config
	}
	return c.Layer2Config
}

// IsEVMCompatible 判断是否与EVM兼容
func (c *ChainConfig) IsEVMCompatible() bool {
	return c.EVMCompatibilityMode == "full" || c.EVMCompatibilityMode == "partial"
}
