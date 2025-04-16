# Supur移动区块链开发者指南

欢迎使用Supur移动区块链开发者指南！本文档将帮助您了解Supur的核心概念，并指导您快速开始构建应用程序。

> 加入我们的社区获取更多帮助: [https://t.me/SupurChain](https://t.me/SupurChain)

## 目录

- [概述](#概述)
- [开发环境设置](#开发环境设置)
- [核心概念](#核心概念)
- [智能合约开发](#智能合约开发)
- [移动端集成](#移动端集成)
- [Web应用集成](#web应用集成)
- [高级主题](#高级主题)
- [常见问题](#常见问题)
- [API参考](#api参考)

## 概述

Supur是专为移动设备和物联网环境设计的区块链平台，它具有以下特点：

- **轻量级设计**：极低的资源消耗，适合在移动设备上运行
- **高性能**：3000+ TPS，3秒出块时间
- **移动友好**：专为移动设备优化的API和SDK
- **多语言支持**：Solidity、Move和WebAssembly智能合约

## 开发环境设置

### 必备工具

1. **安装Go**（1.20+）
   ```bash
   # macOS
   brew install go
   
   # Ubuntu
   sudo apt update
   sudo apt install golang-go
   ```

2. **安装Node.js**（用于Web3开发）
   ```bash
   # macOS
   brew install node
   
   # Ubuntu
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt install -y nodejs
   ```

3. **安装Supur开发工具包**
   ```bash
   go install github.com/supur-chain/supur-cli@latest
   ```

### 设置本地开发节点

1. **克隆仓库**
   ```bash
   git clone https://github.com/supur-chain/supur-chain.git
   cd supur-chain
   ```

2. **编译Supur**
   ```bash
   make all
   ```

3. **初始化开发节点**
   ```bash
   # 创建数据目录
   mkdir -p devnet
   
   # 初始化节点
   ./build/bin/geth --datadir devnet init genesis.json
   
   # 创建开发账户
   ./build/bin/geth --datadir devnet account new
   ```

4. **启动开发节点**
   ```bash
   ./build/bin/geth --datadir devnet --networkid 776 --http --http.api "eth,net,web3,debug" --http.corsdomain "*" --ws --ws.api "eth,net,web3" --ws.origins "*" --dev --dev.period 1
   ```

## 核心概念

### 账户系统

Supur使用与以太坊兼容的账户系统：

- **外部拥有账户(EOA)**：由用户控制的账户，有私钥
- **合约账户**：由代码控制，没有私钥

### 交易

在Supur上，交易具有以下字段：

- `nonce`：发送方账户的交易计数
- `gasPrice`：发送方愿意支付的每单位gas的价格
- `gasLimit`：交易允许使用的最大gas量
- `to`：接收方地址
- `value`：转账金额
- `data`：包含合约调用数据或部署代码
- `signature`：发送方的签名

### 共识机制

Supur使用改进的PoSA（权益证明授权）共识，关键特性：

- **低能耗**：比传统PoW降低99%能耗
- **快速确认**：3秒出块时间，6秒单次确认，15秒最终确认
- **验证者轮换**：动态验证者集合，防止中心化

## 智能合约开发

### Solidity合约

1. **安装开发工具**
   ```bash
   npm install -g truffle
   ```

2. **创建新项目**
   ```bash
   mkdir my-supur-dapp
   cd my-supur-dapp
   truffle init
   ```

3. **编写简单合约**

   创建文件 `contracts/SimpleStorage.sol`:
   ```solidity
   // SPDX-License-Identifier: MIT
   pragma solidity ^0.8.0;
   
   contract SimpleStorage {
       uint256 private value;
       
       event ValueChanged(uint256 newValue);
       
       function store(uint256 newValue) public {
           value = newValue;
           emit ValueChanged(newValue);
       }
       
       function retrieve() public view returns (uint256) {
           return value;
       }
   }
   ```

4. **配置部署网络**

   编辑 `truffle-config.js`:
   ```javascript
   module.exports = {
     networks: {
       development: {
         host: "127.0.0.1",
         port: 8545,
         network_id: "*"
       },
       supur: {
         host: "127.0.0.1",
         port: 8545,
         network_id: 776
       }
     },
     compilers: {
       solc: {
         version: "0.8.17"
       }
     }
   };
   ```

5. **编译与部署**
   ```bash
   truffle compile
   truffle migrate --network supur
   ```

### Move智能合约

Supur也支持Move语言开发智能合约，以下是基本步骤：

1. **安装Move CLI**
   ```bash
   cargo install --git https://github.com/supur-chain/supur-move-cli.git
   ```

2. **创建新Move项目**
   ```bash
   supur-move new my_project
   cd my_project
   ```

3. **编写简单的Move模块**

   创建文件 `sources/Counter.move`:
   ```move
   module Counter {
       struct CounterData has key {
           value: u64,
       }
       
       public fun init(account: &signer) {
           move_to(account, CounterData { value: 0 });
       }
       
       public fun increment(account: &signer) acquires CounterData {
           let counter = borrow_global_mut<CounterData>(address_of(account));
           counter.value = counter.value + 1;
       }
       
       public fun get_value(addr: address): u64 acquires CounterData {
           let counter = borrow_global<CounterData>(addr);
           counter.value
       }
   }
   ```

4. **编译和部署Move模块**
   ```bash
   supur-move build
   supur-move deploy --network supur
   ```

## 移动端集成

### Android集成

1. **添加依赖**

   在`build.gradle`中添加：
   ```groovy
   implementation 'io.supur:supur-android-sdk:1.0.0'
   ```

2. **初始化SDK**
   ```kotlin
   import io.supur.sdk.SupurSDK
   
   // 应用启动时初始化
   SupurSDK.init(context, "https://rpc.supur.io")
   
   // 创建钱包
   val wallet = SupurSDK.createWallet()
   
   // 或导入已有钱包
   val importedWallet = SupurSDK.importWallet("私钥或助记词")
   ```

3. **发送交易**
   ```kotlin
   // 转账
   val txHash = SupurSDK.sendTransaction(
       fromAddress = wallet.address,
       toAddress = "0x接收地址",
       amount = "1.5",  // SPR数量
       onSuccess = { hash -> 
           Log.d("Supur", "交易已发送: $hash") 
       },
       onError = { error -> 
           Log.e("Supur", "交易失败: ${error.message}") 
       }
   )
   
   // 合约调用
   val contract = SupurSDK.loadContract(
       contractAddress = "0x合约地址",
       contractABI = "合约ABI字符串"
   )
   
   contract.call(
       function = "store",
       params = listOf(42),
       onSuccess = { /* 处理成功 */ },
       onError = { /* 处理错误 */ }
   )
   ```

### iOS集成

1. **安装SDK**

   在`Podfile`中添加：
   ```ruby
   pod 'SupurSDK', '~> 1.0.0'
   ```

2. **初始化SDK**
   ```swift
   import SupurSDK
   
   // 应用启动时初始化
   SupurSDK.initialize(withEndpoint: "https://rpc.supur.io")
   
   // 创建钱包
   let wallet = try SupurSDK.createWallet()
   
   // 或导入已有钱包
   let importedWallet = try SupurSDK.importWallet(privateKey: "私钥或助记词")
   ```

3. **发送交易**
   ```swift
   // 转账
   SupurSDK.sendTransaction(
       from: wallet.address,
       to: "0x接收地址",
       amount: "1.5",  // SPR数量
       completion: { result in
           switch result {
           case .success(let txHash):
               print("交易已发送: \(txHash)")
           case .failure(let error):
               print("交易失败: \(error.localizedDescription)")
           }
       }
   )
   
   // 合约调用
   let contract = SupurSDK.loadContract(
       at: "0x合约地址",
       abi: "合约ABI字符串"
   )
   
   try contract.call(
       method: "store",
       parameters: [42],
       completion: { result in
           // 处理结果
       }
   )
   ```

## Web应用集成

### 使用Web3.js

1. **安装Web3.js**
   ```bash
   npm install web3
   ```

2. **连接到Supur网络**
   ```javascript
   const Web3 = require('web3');
   const web3 = new Web3('https://rpc.supur.io');
   
   // 检查连接
   web3.eth.net.isListening()
       .then(() => console.log('已连接到Supur网络'))
       .catch(e => console.log('连接失败:', e));
   ```

3. **创建账户和发送交易**
   ```javascript
   // 创建新账户
   const account = web3.eth.accounts.create();
   console.log('新账户地址:', account.address);
   console.log('新账户私钥:', account.privateKey);
   
   // 导入已有账户
   const importedAccount = web3.eth.accounts.privateKeyToAccount('0x私钥');
   
   // 发送交易
   web3.eth.accounts.signTransaction({
       to: '0x接收地址',
       value: web3.utils.toWei('1', 'ether'),
       gas: 21000,
   }, importedAccount.privateKey)
   .then(signedTx => web3.eth.sendSignedTransaction(signedTx.rawTransaction))
   .then(receipt => console.log('交易成功:', receipt))
   .catch(err => console.error('交易失败:', err));
   ```

4. **智能合约交互**
   ```javascript
   // 合约ABI
   const contractABI = [...]; // 合约ABI数组
   const contractAddress = '0x合约地址';
   
   // 创建合约实例
   const contract = new web3.eth.Contract(contractABI, contractAddress);
   
   // 调用合约函数
   contract.methods.store(42).send({
       from: importedAccount.address,
       gas: 100000
   })
   .then(receipt => console.log('存储成功:', receipt))
   .catch(error => console.error('存储失败:', error));
   
   // 读取合约状态
   contract.methods.retrieve().call()
       .then(value => console.log('存储的值:', value))
       .catch(error => console.error('读取失败:', error));
   ```

### 使用ethers.js

1. **安装ethers.js**
   ```bash
   npm install ethers
   ```

2. **连接到Supur网络**
   ```javascript
   const { ethers } = require('ethers');
   const provider = new ethers.providers.JsonRpcProvider('https://rpc.supur.io');
   ```

3. **创建钱包和发送交易**
   ```javascript
   // 创建随机钱包
   const wallet = ethers.Wallet.createRandom().connect(provider);
   console.log('钱包地址:', wallet.address);
   console.log('钱包私钥:', wallet.privateKey);
   
   // 从私钥导入钱包
   const importedWallet = new ethers.Wallet('0x私钥', provider);
   
   // 发送交易
   importedWallet.sendTransaction({
       to: '0x接收地址',
       value: ethers.utils.parseEther('1.0') // 1 SPR
   })
   .then(tx => {
       console.log('交易已发送:', tx.hash);
       return tx.wait(); // 等待交易确认
   })
   .then(receipt => console.log('交易已确认:', receipt))
   .catch(error => console.error('交易失败:', error));
   ```

4. **智能合约交互**
   ```javascript
   // 合约ABI和地址
   const contractABI = [...]; // 合约ABI数组
   const contractAddress = '0x合约地址';
   
   // 创建合约实例
   const contract = new ethers.Contract(
       contractAddress,
       contractABI,
       importedWallet // 使用钱包作为签名者
   );
   
   // 调用合约写入函数
   contract.store(42)
       .then(tx => tx.wait())
       .then(receipt => console.log('存储成功:', receipt))
       .catch(error => console.error('存储失败:', error));
   
   // 调用合约读取函数
   contract.retrieve()
       .then(value => console.log('存储的值:', value.toString()))
       .catch(error => console.error('读取失败:', error));
   ```

## 高级主题

### 隐私交易

Supur支持可选的隐私交易功能：

```javascript
// 使用Web3.js发送隐私交易
const privateTransaction = {
    from: account.address,
    to: '0x接收地址',
    value: web3.utils.toWei('1', 'ether'),
    gas: 21000,
    // 隐私交易特有参数
    privateFor: ['接收方公钥'],
    privateFrom: '发送方公钥'
};

web3.eth.accounts.signTransaction(privateTransaction, account.privateKey)
    .then(signed => web3.eth.sendSignedTransaction(signed.rawTransaction))
    .then(receipt => console.log('隐私交易已发送:', receipt));
```

### 跨链通信

Supur提供与其他链的互操作性：

```javascript
// 初始化跨链客户端
const crossChainClient = new SupurSDK.CrossChain({
    supurRPC: 'https://rpc.supur.io',
    ethereumRPC: 'https://mainnet.infura.io/v3/YOUR_API_KEY'
});

// 从Supur发送资产到以太坊
crossChainClient.bridgeToEthereum({
    from: wallet.address,
    to: '0x以太坊接收地址',
    amount: '1.0', // SPR数量
    onSuccess: (txHash) => console.log('跨链交易已提交:', txHash),
    onError: (error) => console.error('跨链交易失败:', error)
});
```

## 常见问题

### 交易失败怎么办？

1. **检查gas设置**：确保提供了足够的gas
2. **检查nonce**：交易nonce必须按顺序递增
3. **检查余额**：确保账户有足够的SPR支付交易费用
4. **网络拥堵**：在高峰期提高gasPrice以加快确认

### 如何提高合约安全性？

1. **使用标准库**：优先使用OpenZeppelin等经过审计的库
2. **限制访问控制**：使用访问控制修饰符
3. **避免重入攻击**：使用ReentrancyGuard或检查-效果-交互模式
4. **进行安全审计**：部署前请专业安全团队审计代码

### 开发资源

- [官方文档](https://docs.supur.io)
- [GitHub仓库](https://github.com/supur-chain)
- [示例项目](https://github.com/supur-chain/examples)
- [Telegram社区](https://t.me/SupurChain)

## API参考

Supur提供了丰富的API接口，支持与区块链网络进行交互。详细的API文档请参考：

- [API参考文档](./api-reference.md) - 提供所有API的详细说明和使用示例
- [API变更日志](./api-changelog.md) - 记录API的变更历史，帮助开发者适应API变化

我们建议开发者定期查阅API变更日志，以便及时了解API的更新和优化。

---

有问题？加入我们的社区寻求帮助：[https://t.me/SupurChain](https://t.me/SupurChain) 