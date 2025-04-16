# Supur链快速入门指南

这篇快速入门指南将帮助您在几分钟内设置和运行一个基本的Supur链应用。

## 前置条件

- [Go](https://golang.org/) 1.18或更高版本
- [Node.js](https://nodejs.org/) 14或更高版本（用于Web应用）
- [Git](https://git-scm.com/)

## 第一步：安装Supur链SDK

### Go语言

```bash
# 安装Go SDK
go get github.com/supur-chain/sdk
```

### JavaScript/TypeScript

```bash
# 安装JavaScript/TypeScript SDK
npm install @supur-chain/sdk
```

## 第二步：创建基础应用

我们提供了一个项目脚手架工具，帮助您快速创建应用骨架：

```bash
# 安装脚手架工具
npm install -g @supur-chain/create-app

# 创建一个新项目
supur-create-app my-first-dapp
cd my-first-dapp

# 安装依赖
npm install
```

## 第三步：连接到Supur链网络

### 使用Go SDK

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/supur-chain/sdk"
)

func main() {
    // 创建客户端配置
    config := sdk.Config{
        NodeURL: "https://testnet-rpc.supur.com", // 测试网RPC地址
        ChainID: 37888,                           // 测试网链ID
    }
    
    // 初始化客户端
    client, err := sdk.NewClient(config)
    if err != nil {
        log.Fatalf("初始化客户端失败: %v", err)
    }
    
    // 获取当前区块高度
    blockNumber, err := client.BlockNumber()
    if err != nil {
        log.Fatalf("获取区块高度失败: %v", err)
    }
    
    fmt.Printf("当前区块高度: %d\n", blockNumber)
}
```

### 使用JavaScript SDK

```javascript
// 导入SDK
const { SupurClient } = require('@supur-chain/sdk');

// 创建客户端
const client = new SupurClient({
  nodeUrl: 'https://testnet-rpc.supur.com', // 测试网RPC地址
  chainId: 37888,                          // 测试网链ID
});

// 获取当前区块高度
async function getBlockNumber() {
  try {
    const blockNumber = await client.getBlockNumber();
    console.log(`当前区块高度: ${blockNumber}`);
  } catch (error) {
    console.error('获取区块高度失败:', error);
  }
}

getBlockNumber();
```

## 第四步：创建账户和发送交易

### 使用Go SDK

```go
// 创建新账户
account, err := client.CreateAccount()
if err != nil {
    log.Fatalf("创建账户失败: %v", err)
}
fmt.Printf("新账户地址: %s\n", account.Address)

// 从私钥导入账户
privateKey := "0xYourPrivateKey"
importedAccount, err := client.ImportAccount(privateKey)
if err != nil {
    log.Fatalf("导入账户失败: %v", err)
}
fmt.Printf("导入账户地址: %s\n", importedAccount.Address)

// 发送交易
tx := &sdk.Transaction{
    To:    "0xRecipientAddress",
    Value: sdk.ToWei("0.01"), // 发送0.01 SUPUR
}
txHash, err := client.SendTransaction(tx)
if err != nil {
    log.Fatalf("发送交易失败: %v", err)
}
fmt.Printf("交易已发送，交易哈希: %s\n", txHash)
```

### 使用JavaScript SDK

```javascript
// 创建新账户
const account = client.createAccount();
console.log(`新账户地址: ${account.address}`);

// 从私钥导入账户
const privateKey = '0xYourPrivateKey';
const importedAccount = client.importAccount(privateKey);
console.log(`导入账户地址: ${importedAccount.address}`);

// 发送交易
async function sendTransaction() {
  try {
    const txHash = await client.sendTransaction({
      to: '0xRecipientAddress',
      value: client.toWei('0.01'), // 发送0.01 SUPUR
    });
    console.log(`交易已发送，交易哈希: ${txHash}`);
    
    // 等待交易确认
    const receipt = await client.waitForTransaction(txHash);
    console.log('交易已确认:', receipt);
  } catch (error) {
    console.error('发送交易失败:', error);
  }
}

sendTransaction();
```

## 第五步：与智能合约交互

### 使用Go SDK

```go
// 智能合约ABI
const abi = `[{"inputs":[],"name":"get","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"x","type":"uint256"}],"name":"set","outputs":[],"stateMutability":"nonpayable","type":"function"}]`

// 合约地址
const contractAddress = "0xYourContractAddress"

// 创建合约实例
contract, err := client.NewContract(abi, contractAddress)
if err != nil {
    log.Fatalf("创建合约实例失败: %v", err)
}

// 调用合约方法（读取）
var result int64
err = contract.Call("get", nil, &result)
if err != nil {
    log.Fatalf("调用合约方法失败: %v", err)
}
fmt.Printf("当前值: %d\n", result)

// 发送合约交易（写入）
txHash, err := contract.Send("set", 42)
if err != nil {
    log.Fatalf("发送合约交易失败: %v", err)
}
fmt.Printf("交易已发送，交易哈希: %s\n", txHash)
```

### 使用JavaScript SDK

```javascript
// 智能合约ABI
const abi = [
  {
    "inputs": [],
    "name": "get",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "uint256", "name": "x", "type": "uint256"}],
    "name": "set",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  }
];

// 合约地址
const contractAddress = '0xYourContractAddress';

// 创建合约实例
const contract = client.getContract(abi, contractAddress);

// 与合约交互
async function interactWithContract() {
  try {
    // 调用合约方法（读取）
    const result = await contract.methods.get().call();
    console.log(`当前值: ${result}`);
    
    // 发送合约交易（写入）
    const tx = await contract.methods.set(42).send();
    console.log(`交易已发送，交易哈希: ${tx.transactionHash}`);
  } catch (error) {
    console.error('与合约交互失败:', error);
  }
}

interactWithContract();
```

## 下一步

恭喜！您已经成功完成了Supur链的基础应用开发。接下来，您可以：

1. 探索更复杂的[示例项目](https://github.com/supur-chain/sdk-examples)
2. 阅读完整的[SDK文档](../developer_sdk.md)
3. 参加[互动式教程](../developer_sdk.md#互动式教程)
4. 加入[开发者社区](https://t.me/SupurChain)寻求帮助和分享经验

## 常见问题

### 如何获取测试网代币？

访问[Supur测试网水龙头](https://faucet.supur.com)获取免费的测试代币。

### 我可以在移动设备上运行Supur链应用吗？

是的，Supur链专为移动设备设计，提供了Android和iOS的原生SDK。详见[移动应用集成](../developer_sdk.md#移动应用集成)。

### 在哪里可以获取技术支持？

加入我们的[Telegram开发者社区](https://t.me/SupurChain)或在[GitHub](https://github.com/supur-chain/sdk/issues)上提交问题。 