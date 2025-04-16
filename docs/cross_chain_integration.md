# 跨链集成与标准化开发指南

本文档提供如何使用Supur链的跨链功能与主流区块链生态（如以太坊、Layer2、第三方钱包）进行集成的详细指南。

## 目录

- [支持的区块链网络](#支持的区块链网络)
- [链适配器接口](#链适配器接口)
- [桥接资产流程](#桥接资产流程)
- [钱包集成](#钱包集成)
- [Layer2集成](#layer2集成)
- [开发示例](#开发示例)
- [最佳实践](#最佳实践)

## 支持的区块链网络

Supur链目前支持与以下区块链网络进行跨链交互：

| 链类型 | 说明 | 链ID |
|-------|------|------|
| 以太坊 (Ethereum) | 以太坊主网 | 1 |
| Supur | Supur链 | 37887 |
| Polygon | Polygon主网 | 137 |
| Arbitrum | Arbitrum One | 42161 |
| Optimism | Optimism主网 | 10 |
| BSC | 币安智能链 | 56 |
| Avalanche | Avalanche C-Chain | 43114 |
| zkSync Era | zkSync Era | 324 |

## 链适配器接口

所有链适配器都实现了标准的`ChainAdapter`接口，提供统一的方法来与不同的区块链交互：

```go
type ChainAdapter interface {
    // 基础信息方法
    GetChainType() ChainType                  // 获取链类型
    GetChainID() int64                        // 获取链ID
    IsConnected() bool                        // 检查是否已连接
    GetConnectionInfo() map[string]interface{} // 获取连接信息
    
    // 账户相关方法
    GetAddress() string                       // 获取当前地址
    GetBalance() (*big.Int, error)            // 获取余额
    SignData(data []byte) ([]byte, error)     // 签名数据
    
    // 交易相关方法
    SendTransaction(to string, amount *big.Int, data []byte) (string, error) // 发送交易
    GetTransactionStatus(txHash string) (string, error)                      // 获取交易状态
    EstimateGas(to string, data []byte) (uint64, error)                      // 估算Gas费用
    
    // 跨链资产桥接方法
    BridgeAsset(targetChain ChainType, to string, amount *big.Int) (string, error) // 资产桥接
    ClaimAsset(sourceChain ChainType, proofData []byte) (string, error)            // 资产认领
    
    // 事件和数据查询方法
    QueryEvents(contractAddr string, eventSig string, fromBlock, toBlock int64) ([]map[string]interface{}, error) // 查询事件
    CallContract(contractAddr string, data []byte) ([]byte, error)                                           // 调用合约
}
```

## 桥接资产流程

### 从Supur链到其他链

1. 获取Supur链适配器
2. 调用`BridgeAsset`方法，指定目标链、接收地址和金额
3. 监控交易状态
4. 如果目标链需要手动认领，则在目标链上调用`ClaimAsset`方法

### 从其他链到Supur链

1. 获取源链适配器
2. 调用源链适配器的`BridgeAsset`方法，指定Supur链作为目标链
3. 监控源链交易状态
4. 如果需要在Supur链上手动认领，则获取证明数据并调用Supur链适配器的`ClaimAsset`方法

## 钱包集成

### WalletConnect集成

Supur链支持通过WalletConnect协议与第三方钱包集成：

```go
// 创建WalletConnect适配器
callbacks := WalletConnectCallbacks{
    OnConnected: func(address string) {
        fmt.Printf("钱包已连接：%s\n", address)
    },
    OnDisconnected: func() {
        fmt.Println("钱包已断开连接")
    },
}
walletAdapter := NewWalletConnectAdapter(ChainTypeSupur, callbacks)

// 连接到钱包
err := walletAdapter.Connect("wc:...")
if err != nil {
    // 处理错误
}

// 使用钱包发送交易
txHash, err := walletAdapter.SendTransaction(to, amount, data)
```

## Layer2集成

### Optimism集成

```go
// 创建Optimism适配器
config := &AdapterConfig{
    RpcURL: "https://mainnet.optimism.io",
    L1RpcURL: "https://mainnet.infura.io/v3/YOUR-API-KEY",
    L2StandardBridgeAddress: "0x4200000000000000000000000000000000000010",
}
optimismAdapter, err := NewOptimismAdapter(config)

// 从Optimism(L2)提款到以太坊(L1)
txHash, err := optimismAdapter.WithdrawToL1(ethAddress, amount)
```

### zkSync集成

```go
// 创建zkSync适配器
config := &AdapterConfig{
    RpcURL: "https://mainnet.era.zksync.io",
    L1RpcURL: "https://mainnet.infura.io/v3/YOUR-API-KEY",
    ZkSyncBridgeAddress: "0x32400084c286cf3e17e7b677ea9583e60a000324",
}
zkSyncAdapter, err := NewZkSyncAdapter(config)

// 从以太坊(L1)存款ETH到zkSync
txHash, err := zkSyncAdapter.DepositETHToZkSync(amount)

// 从zkSync提款到以太坊(L1)
txHash, err := zkSyncAdapter.WithdrawFromZkSync(amount)
```

## 开发示例

### 跨链资产转移示例

```go
package main

import (
    "context"
    "fmt"
    "math/big"
    "time"
    
    "github.com/supur-chain/mobile"
)

func main() {
    // 初始化链适配器工厂
    factory := mobile.NewChainAdapterFactory()
    
    // 创建源链(Supur)适配器
    supurConfig := &mobile.AdapterConfig{
        RpcURL: "https://rpc.supur.com",
        PrivateKey: "YOUR-PRIVATE-KEY",
    }
    supurAdapter, err := factory.GetAdapter(mobile.ChainTypeSupur, supurConfig)
    if err != nil {
        panic(err)
    }
    
    // 创建目标链(以太坊)适配器
    ethConfig := &mobile.AdapterConfig{
        RpcURL: "https://mainnet.infura.io/v3/YOUR-API-KEY",
        PrivateKey: "YOUR-PRIVATE-KEY",
    }
    ethAdapter, err := factory.GetAdapter(mobile.ChainTypeEthereum, ethConfig)
    if err != nil {
        panic(err)
    }
    
    // 桥接资产从Supur到以太坊
    amount := big.NewInt(1000000000000000000) // 1 ETH
    recipientAddr := "0xYourEthereumAddress"
    
    txHash, err := supurAdapter.BridgeAsset(mobile.ChainTypeEthereum, recipientAddr, amount)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("桥接交易已发送，交易哈希：%s\n", txHash)
    
    // 监控交易状态
    for {
        status, err := supurAdapter.GetTransactionStatus(txHash)
        if err != nil {
            fmt.Printf("获取交易状态失败：%v\n", err)
        } else {
            fmt.Printf("交易状态：%s\n", status)
            if status == "success" {
                break
            } else if status == "failed" {
                fmt.Println("交易失败")
                return
            }
        }
        
        time.Sleep(5 * time.Second)
    }
    
    fmt.Println("源链交易已确认，请等待目标链确认...")
}
```

## 最佳实践

1. **错误处理** - 确保适当处理所有错误，特别是跨链交互中的错误。

2. **交易监控** - 实现可靠的交易监控机制，确保能够检测到交易的成功或失败。

3. **资金安全** - 在跨链交互前，验证所有地址和金额是否正确。

4. **气体费用估算** - 为交易提供足够的气体费用，特别是在网络拥堵时期。

5. **重试机制** - 实现交易重试机制，处理因网络问题导致的临时失败。

6. **事件日志** - 记录所有跨链交互的事件，以便后续调试和审计。

7. **测试网络** - 在将应用部署到主网之前，在测试网络上彻底测试跨链功能。

8. **版本兼容性** - 关注各种链协议的更新，确保您的跨链交互代码与最新版本兼容。 