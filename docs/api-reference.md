# Supur移动区块链API参考文档

本文档提供Supur移动区块链的完整API参考。通过这些API，开发者可以与区块链进行交互，查询数据，发送交易，部署智能合约等。

> 如需帮助，请加入我们的社区：[https://t.me/SupurChain](https://t.me/SupurChain)

## 目录

- [JSON-RPC接口](#json-rpc接口)
- [WebSocket接口](#websocket接口)
- [REST API](#rest-api)
- [移动端SDK接口](#移动端sdk接口)
- [合约交互](#合约交互)
- [示例代码](#示例代码)

## JSON-RPC接口

### 基础信息
- 端点：`http://<节点IP>:8545`
- 示例URL: `http://localhost:8545`
- 内容类型: `application/json`

### WebSocket接口
- 端点：`ws://<节点IP>:8546`
- 示例URL: `ws://localhost:8546`

### 标准方法

#### eth命名空间

##### eth_blockNumber
返回最新区块的编号。

**参数**：无

**返回值**：区块编号的十六进制字符串

**示例请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "eth_blockNumber",
  "params": [],
  "id": 1
}
```

**示例响应**：
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x3d0a00"
}
```

##### eth_getBalance
返回指定地址的余额。

**参数**：
1. 账户地址
2. 区块号或标识符("latest", "earliest", "pending")

**返回值**：十六进制数字字符串，表示Wei为单位的余额

**示例请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "eth_getBalance",
  "params": ["0x407d73d8a49eeb85d32cf465507dd71d507100c1", "latest"],
  "id": 1
}
```

**示例响应**：
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x0234c8a3397aab58"
}
```

##### eth_sendTransaction
发送交易到网络。

**参数**：
1. 交易对象：
   - `from`: 发送账户地址
   - `to`: 接收账户地址(可选，合约创建时为空)
   - `gas`: Gas限制(可选)
   - `gasPrice`: Gas价格(可选)
   - `value`: 转账金额(可选)
   - `data`: 交易数据(可选)
   - `nonce`: 交易顺序号(可选)

**返回值**：交易哈希

**示例请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "eth_sendTransaction",
  "params": [{
    "from": "0xb60e8dd61c5d32be8058bb8eb970870f07233155",
    "to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
    "gas": "0x76c0",
    "gasPrice": "0x9184e72a000",
    "value": "0x9184e72a",
    "data": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675"
  }],
  "id": 1
}
```

**示例响应**：
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0xe670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331"
}
```

##### eth_call
执行智能合约调用，不产生区块链交易。

**参数**：
1. 交易对象(同eth_sendTransaction)
2. 区块号或标识符

**返回值**：返回合约执行结果的十六进制字符串

**示例请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "eth_call",
  "params": [
    {
      "to": "0x6b175474e89094c44da98b954eedeac495271d0f",
      "data": "0x70a08231000000000000000000000000b60e8dd61c5d32be8058bb8eb970870f07233155"
    },
    "latest"
  ],
  "id": 1
}
```

**示例响应**：
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"
}
```

##### eth_getTransactionByHash
通过交易哈希获取交易信息。

**参数**：
1. 交易哈希

**返回值**：交易对象或null(如果没找到)

**示例请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "eth_getTransactionByHash",
  "params": ["0xe670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331"],
  "id": 1
}
```

**示例响应**：
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "blockHash": "0x5d15649e25d8e32c51a25a3abe0c6c16c3679f64d8aff9deac36077eea2e5c23",
    "blockNumber": "0x3d0a00",
    "from": "0xb60e8dd61c5d32be8058bb8eb970870f07233155",
    "gas": "0x76c0",
    "gasPrice": "0x9184e72a000",
    "hash": "0xe670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331",
    "input": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675",
    "nonce": "0x0",
    "to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
    "transactionIndex": "0x0",
    "value": "0x9184e72a",
    "v": "0x25",
    "r": "0x1b5e176d927f8e9ab405058b2d2457392da3e20f328b16ddabcebc33eaac5fea",
    "s": "0x4ba69724e8f69de52f0125ad8b3c5c2cef33019bac3249e2c0a2192766d1721c"
  }
}
```

#### net命名空间

##### net_version
返回当前网络ID。

**参数**：无

**返回值**：网络ID的字符串

**示例请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "net_version",
  "params": [],
  "id": 1
}
```

**示例响应**：
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "776"
}
```

##### net_listening
返回节点是否正在监听网络连接。

**参数**：无

**返回值**：布尔值

**示例请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "net_listening",
  "params": [],
  "id": 1
}
```

**示例响应**：
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": true
}
```

#### web3命名空间

##### web3_clientVersion
返回节点客户端版本。

**参数**：无

**返回值**：当前客户端版本的字符串

**示例请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "web3_clientVersion",
  "params": [],
  "id": 1
}
```

**示例响应**：
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "Supur Mobile/v1.0.0/linux-amd64/go1.20.3"
}
```

#### supur命名空间（Supur专有）

##### supur_getPeerCount
返回连接到节点的对等节点数量。

**参数**：无

**返回值**：十六进制的数量字符串

**示例请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "supur_getPeerCount",
  "params": [],
  "id": 1
}
```

**示例响应**：
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x19"
}
```

##### supur_validator
返回当前验证者的相关信息。

**参数**：无

**返回值**：验证者信息对象

**示例请求**：
```json
{
  "jsonrpc": "2.0",
  "method": "supur_validator",
  "params": [],
  "id": 1
}
```

**示例响应**：
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "address": "0x5b9da121caae6510440031dd329b93814a3ac11e",
    "totalBlocks": "0x432a",
    "isActive": true,
    "nextBlockTime": "0x61bc8fa0"
  }
}
```

## REST API

Supur还提供了更简单易用的REST API接口，适合移动应用开发。

### 基础路径

`https://<节点URL>/api/v1/`

### 认证

API支持两种认证方式：

1. **API密钥认证**：在HTTP头中添加`X-API-Key`
2. **JWT认证**：在HTTP头中添加`Authorization: Bearer <token>`

### 端点列表

#### GET /account/{address}/balance
获取账户余额

**参数**：
- `address`: 账户地址

**响应**：
```json
{
  "status": "success",
  "data": {
    "address": "0x5b9da121caae6510440031dd329b93814a3ac11e",
    "balance": "1500000000000000000",
    "balanceFormatted": "1.5 SPR"
  }
}
```

#### GET /transaction/{hash}
获取交易详情

**参数**：
- `hash`: 交易哈希

**响应**：
```json
{
  "status": "success",
  "data": {
    "hash": "0xa1b2c3...",
    "from": "0x1234...",
    "to": "0x5678...",
    "value": "1000000000000000000",
    "valueFormatted": "1 SPR",
    "gasUsed": "21000",
    "gasPrice": "2000000000",
    "blockNumber": 123456,
    "timestamp": 1632145200,
    "status": "confirmed",
    "confirmations": 24
  }
}
```

#### POST /transaction/send
发送交易

**请求体**：
```json
{
  "from": "0x1234...",
  "to": "0x5678...",
  "value": "1000000000000000000",
  "gas": 21000,
  "gasPrice": "2000000000",
  "data": "0x",
  "privateKey": "0xabcd..." // 或使用签名后的交易数据
}
```

**响应**：
```json
{
  "status": "success",
  "data": {
    "hash": "0xa1b2c3...",
    "blockNumber": null,
    "status": "pending"
  }
}
```

#### GET /contract/{address}/call
调用合约方法

**参数**：
- `address`: 合约地址
- `method`: 方法名
- `params`: JSON编码的参数数组(可选)

**响应**：
```json
{
  "status": "success",
  "data": {
    "result": "0x000000000000000000000000000000000000000000000000000000000000002a"
  }
}
```

## 移动端SDK接口

Supur为Android和iOS提供原生SDK，以下是主要API接口：

### Android SDK

```kotlin
// 初始化SDK
SupurSDK.init(context: Context, rpcUrl: String)

// 创建钱包
val wallet: Wallet = SupurSDK.createWallet()

// 导入钱包
val wallet: Wallet = SupurSDK.importWallet(privateKey: String)
val wallet: Wallet = SupurSDK.importWalletFromMnemonic(mnemonic: String)

// 获取余额
SupurSDK.getBalance(address: String, callback: (BigInteger?, Throwable?) -> Unit)

// 发送交易
SupurSDK.sendTransaction(
    from: String,
    to: String,
    amount: String,
    onSuccess: (String) -> Unit, // 交易哈希
    onError: (Throwable) -> Unit
)

// 智能合约交互
val contract = SupurSDK.loadContract(address: String, abi: String)
contract.call(
    function: String,
    params: List<Any>,
    onSuccess: (Any?) -> Unit,
    onError: (Throwable) -> Unit
)
```

### iOS SDK

```swift
// 初始化SDK
SupurSDK.initialize(withEndpoint: String)

// 创建钱包
let wallet = try SupurSDK.createWallet()

// 导入钱包
let wallet = try SupurSDK.importWallet(privateKey: String)
let wallet = try SupurSDK.importWalletFromMnemonic(mnemonic: String)

// 获取余额
SupurSDK.getBalance(for: String) { result in
    switch result {
    case .success(let balance):
        print("余额: \(balance)")
    case .failure(let error):
        print("错误: \(error)")
    }
}

// 发送交易
SupurSDK.sendTransaction(
    from: String,
    to: String,
    amount: String,
    completion: (Result<String, Error>) -> Void
)

// 智能合约交互
let contract = SupurSDK.loadContract(at: String, abi: String)
contract.call(
    method: String,
    parameters: [Any],
    completion: (Result<Any, Error>) -> Void
)
```

## 合约交互

### 使用Web3.js库

```javascript
const Web3 = require('web3');
const web3 = new Web3('http://localhost:8545');

// 获取账户
const accounts = await web3.eth.getAccounts();

// 部署合约
const Contract = new web3.eth.Contract(abi);
const contract = await Contract.deploy({
    data: bytecode,
    arguments: [arg1, arg2]
}).send({
    from: accounts[0],
    gas: 1500000
});

// 调用合约方法
const result = await contract.methods.myMethod(param1, param2).call();

// 发送交易到合约
await contract.methods.myMethod(param1, param2).send({
    from: accounts[0],
    gas: 1000000
});

// 监听合约事件
contract.events.MyEvent({
    fromBlock: 0
}, (error, event) => {
    console.log(event);
});
```

### 使用ethers.js库

```javascript
const { ethers } = require('ethers');
const provider = new ethers.providers.JsonRpcProvider('http://localhost:8545');

// 获取钱包
const wallet = new ethers.Wallet(privateKey, provider);

// 部署合约
const factory = new ethers.ContractFactory(abi, bytecode, wallet);
const contract = await factory.deploy(arg1, arg2);
await contract.deployed();

// 调用合约方法
const result = await contract.myMethod(param1, param2);

// 监听合约事件
contract.on("MyEvent", (param1, param2, event) => {
    console.log(param1, param2, event);
});
```

## 示例代码

### 基本转账示例

```javascript
const Web3 = require('web3');
const web3 = new Web3('http://localhost:8545');

async function transfer() {
    // 获取账户
    const accounts = await web3.eth.getAccounts();
    const sender = accounts[0];
    const receiver = '0x1234567890123456789012345678901234567890';
    
    // 检查余额
    const balance = await web3.eth.getBalance(sender);
    console.log(`发送方余额: ${web3.utils.fromWei(balance, 'ether')} SPR`);
    
    // 发送交易
    const receipt = await web3.eth.sendTransaction({
        from: sender,
        to: receiver,
        value: web3.utils.toWei('1', 'ether'),
        gas: 21000
    });
    
    console.log(`交易已确认: ${receipt.transactionHash}`);
}

transfer().catch(console.error);
```

### 智能合约部署与交互

```javascript
const Web3 = require('web3');
const web3 = new Web3('http://localhost:8545');

// 简单的存储合约ABI
const contractABI = [
    {
        "inputs": [],
        "name": "retrieve",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"name": "num", "type": "uint256"}],
        "name": "store",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
];

// 合约字节码
const contractBytecode = "0x608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100a1565b60405180910390f35b610073600480360381019061006e91906100ed565b61007e565b005b60008054905090565b8060008190555050565b6000819050919050565b61009b81610088565b82525050565b60006020820190506100b66000830184610092565b92915050565b600080fd5b6100ca81610088565b81146100d557600080fd5b50565b6000813590506100e7816100c1565b92915050565b600060208284031215610103576101026100bc565b5b6000610111848285016100d8565b9150509291505056fea2646970667358221220223a34922c39ccd6b5f26b2e04e2c5dd3ce5468e169572241e370b420c8b3d7564736f6c634300080d0033";

async function deployAndInteract() {
    // 获取账户
    const accounts = await web3.eth.getAccounts();
    const deployer = accounts[0];
    
    console.log(`使用账户 ${deployer} 部署合约`);
    
    // 部署合约
    const contract = new web3.eth.Contract(contractABI);
    const deployTx = contract.deploy({
        data: contractBytecode
    });
    
    const gas = await deployTx.estimateGas();
    const deployedContract = await deployTx.send({
        from: deployer,
        gas
    });
    
    console.log(`合约已部署至地址: ${deployedContract.options.address}`);
    
    // 存储值
    await deployedContract.methods.store(42).send({
        from: deployer
    });
    console.log('已存储值: 42');
    
    // 检索值
    const value = await deployedContract.methods.retrieve().call();
    console.log(`已检索值: ${value}`);
}

deployAndInteract().catch(console.error);
```

## 社区资源

- Telegram社区：[https://t.me/SupurChain](https://t.me/SupurChain)
- API文档在线版：[https://docs.supur.io/api-reference](https://docs.supur.io/api-reference)
- 开发者示例库：[https://github.com/supur-chain/examples](https://github.com/supur-chain/examples)
- 问题反馈：[https://github.com/supur-chain/supur-chain/issues](https://github.com/supur-chain/supur-chain/issues)

---

如有问题，请加入我们的社区获取支持：[https://t.me/SupurChain](https://t.me/SupurChain) 