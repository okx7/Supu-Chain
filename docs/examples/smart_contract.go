package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/supur-chain/sdk"
	"github.com/supur-chain/sdk/contracts"
)

// SimpleToken合约ABI的简化版本
const simpleTokenABI = `[
	{
		"inputs": [
			{"internalType": "string", "name": "name_", "type": "string"},
			{"internalType": "string", "name": "symbol_", "type": "string"},
			{"internalType": "uint256", "name": "initialSupply_", "type": "uint256"}
		],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [
			{"internalType": "address", "name": "account", "type": "address"}
		],
		"name": "balanceOf",
		"outputs": [
			{"internalType": "uint256", "name": "", "type": "uint256"}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{"internalType": "address", "name": "to", "type": "address"},
			{"internalType": "uint256", "name": "amount", "type": "uint256"}
		],
		"name": "transfer",
		"outputs": [
			{"internalType": "bool", "name": "", "type": "bool"}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]`

// SimpleToken合约字节码
const simpleTokenBytecode = "0x60806040523480156200001157600080fd5b5060405162000c8a38038062000c8a83398181016040528101906200003791906200028a565b828281600390805190602001906200005192919062000179565b5080600490805190602001906200006a92919062000179565b5050506200008233826200008a60201b60201c565b5050506200046a565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415620000fd576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401620000f49062000362565b60405180910390fd5b62000111600083836200020360201b60201c565b806002600082825462000125919062000384565b92505081905550806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055508173ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef83604051620001dc91906200038e565b60405180910390a362000202600083836200020860201b60201c565b5050565b505050565b505050565b82805462000187906200040a565b90600052602060002090601f016020900481019282620001ab57600085556200021c565b82601f10620001c657805160ff19168380011785556200021c565b828001600101855582156200021c579182015b828111156200021b578251825591602001919060010190620001d9565b5b5090506200022b91906200022f565b5090565b5b808211156200024a576000816000905550600101620002305b5090565b6000620002656200025f8462000398565b6200036f565b9050828152602081018484840111156200027e57600080fd5b6200028b8482856200040a565b509392505050565b600080600060608486031215620002a057600080fd5b600084013567ffffffffffffffff811115620002bb57600080fd5b620002c9868287016200024e565b935050602084013567ffffffffffffffff811115620002e757600080fd5b620002f5868287016200024e565b92505060406200030886828701620003ab565b9150509250925092565b600062000321601f8362000384565b91507f45524332303a206d696e7420746f20746865207a65726f2061646472657373006000830152602082019050919050565b6200035c8162000393565b82525050565b600060208201905081810360008301526200037d8162000312565b9050919050565b6000620003918262000393565b9392505050565b90565b600081519050919050565b6000620003a58262000393565b9050919050565b600062000380826200039d565b60006002820490506001821680620004235750835182818301111562000422576000805260206000209050919050565b5b600182039150819050919050565b600082825260208201905092915050565b600081519050919050565b60005b838110156200044957808201518184015260208101905062000428565b83811115620004595760008282525060200191505b50919050565b61081080620004836000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c8063a9059cbb1461003b578063dd62ed3e1461006b575b600080fd5b610055600480360381019061005091906104c3565b61009b565b6040516100629190610546565b60405180910390f35b61008560048036038101906100809190610477565b6100bc565b6040516100929190610561565b60405180910390f35b60006100ae6100a9610143565b838361014b565b6001905092915050565b6000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b600033905090565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1614156101bb576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101b29061065c565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16141561022b576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610222906106be565b60405180910390fd5b80600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925836040516103099190610561565b60405180910390a3505050565b6000813590506103268161072a565b92915050565b60008135905061033b81610741565b92915050565b60006020828403121561035357600080fd5b600061036184828501610317565b91505092915050565b6000806040838503121561037d57600080fd5b600061038b85828601610317565b925050602061039c85828601610317565b9150509250929050565b600080604083850312156103b957600080fd5b60006103c785828601610317565b92505060206103d88582860161032c565b9150509250929050565b60006103ee8261057c565b6103f88185610587565b9350610408818560208601610670565b61041181610719565b840191505092915050565b600061042960118361059d565b915061043482610732565b602082019050919050565b600061044c60128361059d565b91506104578261075b565b602082019050919050565b610468816105ee565b82525050565b610477816105ee565b82525050565b6000806040838503121561048a57600080fd5b600061049885828601610317565b92505060206104a985828601610317565b9150509250929050565b6000602082840312156104c557600080fd5b60006104d38482850161032c565b91505092915050565b600060208201905061051a600083018461046e565b92915050565b600060608201905061053560008301866104e3565b818103602083015261054781856103e3565b905061055660408301846104e3565b949350505050565b6000602082019050610573600083018461046e565b92915050565b600081519050919050565b600082825260208201905092915050565b600082825260208201905092915050565b600082825260208201905092915050565b60006105c8826105ce565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b6000610603826105bd565b9050919050565b600061061582610505565b9050919050565b6000610627826105bd565b9050919050565b6000610639826105bd565b9050919050565b600061064b82610505565b9050919050565b600061065682610640565b9050919050565b6000602082019050818103600083015261067681610441565b9050919050565b6000602082019050818103600083015261069681610418565b9050919050565b600060208201905061069e600083018461046e565b92915050565b60006020820190506106b9600083018461046e565b92915050565b600060208201905081810360008301526106d881610441565b9050919050565b600060208201905081810360008301526106f881610418565b9050919050565b6000610709610714565b905061071582826106ee565b919050565b6000610720826105ce565b9050919050565b6000819050919050565b610733816105c7565b811461073e57600080fd5b50565b61074a81610592565b811461075557600080fd5b50565bfe"

func main() {
	// 初始化SDK
	config := sdk.Config{
		NodeURL:  "https://rpc.supur.com",
		ChainID:  37887,
		LogLevel: "info",
	}
	client, err := sdk.NewClient(config)
	if err != nil {
		log.Fatalf("创建SDK客户端失败: %v", err)
	}

	// 导入钱包
	// privateKey := "您的私钥" // 实际应用中，私钥应从安全存储中获取
	// wallet, err := client.ImportWalletFromPrivateKey(privateKey)
	wallet, err := client.CreateWallet() // 仅用于演示
	if err != nil {
		log.Fatalf("导入钱包失败: %v", err)
	}

	// 部署SimpleToken合约
	tokenName := "MyToken"
	tokenSymbol := "MTK"
	initialSupply := sdk.EtherToWei(1000000) // 1,000,000 tokens

	fmt.Println("部署SimpleToken合约...")
	tokenAddress, err := deploySimpleToken(client, wallet, tokenName, tokenSymbol, initialSupply)
	if err != nil {
		log.Fatalf("部署合约失败: %v", err)
	}
	fmt.Printf("SimpleToken合约已部署至: %s\n", tokenAddress)

	// 等待一下，确保合约部署完成
	time.Sleep(5 * time.Second)

	// 与合约交互
	// 1. 获取代币余额
	balance, err := getTokenBalance(client, tokenAddress, wallet.GetAddress())
	if err != nil {
		log.Fatalf("获取代币余额失败: %v", err)
	}
	fmt.Printf("账户 %s 的代币余额: %s %s\n", wallet.GetAddress(), sdk.WeiToEther(balance).String(), tokenSymbol)

	// 2. 转移代币
	recipientAddress := "0xRecipientAddress" // 在实际应用中替换为有效地址
	transferAmount := sdk.EtherToWei(100)    // 转移100个代币

	fmt.Printf("转移 %s %s 到 %s...\n", sdk.WeiToEther(transferAmount).String(), tokenSymbol, recipientAddress)
	
	// 注释下面的代码，因为示例中使用的收件人地址无效
	// err = transferTokens(client, wallet, tokenAddress, recipientAddress, transferAmount)
	// if err != nil {
	//     log.Fatalf("转移代币失败: %v", err)
	// }
	// fmt.Println("代币转移成功！")

	fmt.Println("合约交互示例完成。")
}

// 部署SimpleToken合约
func deploySimpleToken(client *sdk.Client, wallet *sdk.Wallet, name, symbol string, initialSupply *big.Int) (string, error) {
	ctx := context.Background()

	// 加载合约ABI和字节码
	contractABI, err := sdk.NewABI(simpleTokenABI)
	if err != nil {
		return "", fmt.Errorf("解析合约ABI失败: %v", err)
	}

	// 编码构造函数参数
	constructorArgs, err := contractABI.EncodeConstructor([]interface{}{name, symbol, initialSupply})
	if err != nil {
		return "", fmt.Errorf("编码构造函数参数失败: %v", err)
	}

	// 组合字节码和构造函数参数
	deployData := append([]byte(simpleTokenBytecode), constructorArgs...)

	// 创建部署交易
	tx := sdk.NewTransaction().
		SetTo("").  // 部署合约时地址为空
		SetValue(big.NewInt(0)).
		SetData(deployData)

	// 估算Gas
	gasLimit, err := client.EstimateGas(ctx, tx)
	if err != nil {
		return "", fmt.Errorf("估算Gas失败: %v", err)
	}
	tx.SetGasLimit(gasLimit * 2) // 为安全起见，将Gas限制乘以2

	// 获取Gas价格
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return "", fmt.Errorf("获取Gas价格失败: %v", err)
	}
	tx.SetGasPrice(gasPrice)

	// 获取nonce
	nonce, err := client.GetPendingNonce(ctx, wallet.GetAddress())
	if err != nil {
		return "", fmt.Errorf("获取nonce失败: %v", err)
	}
	tx.SetNonce(nonce)

	// 签名交易
	signedTx, err := wallet.SignTransaction(tx)
	if err != nil {
		return "", fmt.Errorf("签名交易失败: %v", err)
	}

	// 发送交易
	txHash, err := client.SendTransaction(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("发送交易失败: %v", err)
	}

	// 等待交易被确认
	fmt.Println("等待合约部署确认...")
	receipt, err := waitForTransaction(client, txHash)
	if err != nil {
		return "", fmt.Errorf("等待交易确认失败: %v", err)
	}

	if receipt.Status != 1 {
		return "", fmt.Errorf("合约部署失败，交易状态: %d", receipt.Status)
	}

	return receipt.ContractAddress, nil
}

// 获取代币余额
func getTokenBalance(client *sdk.Client, tokenAddress, accountAddress string) (*big.Int, error) {
	ctx := context.Background()

	// 加载合约ABI
	contractABI, err := sdk.NewABI(simpleTokenABI)
	if err != nil {
		return nil, fmt.Errorf("解析合约ABI失败: %v", err)
	}

	// 编码函数调用
	callData, err := contractABI.EncodeMethod("balanceOf", []interface{}{
		common.HexToAddress(accountAddress),
	})
	if err != nil {
		return nil, fmt.Errorf("编码函数调用失败: %v", err)
	}

	// 创建调用消息
	msg := sdk.CallMsg{
		To:   tokenAddress,
		Data: callData,
	}

	// 执行合约调用
	result, err := client.CallContract(ctx, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("调用合约失败: %v", err)
	}

	// 解码结果
	var balance *big.Int
	err = contractABI.DecodeOutput("balanceOf", result, &balance)
	if err != nil {
		return nil, fmt.Errorf("解码结果失败: %v", err)
	}

	return balance, nil
}

// 转移代币
func transferTokens(client *sdk.Client, wallet *sdk.Wallet, tokenAddress, recipientAddress string, amount *big.Int) error {
	ctx := context.Background()

	// 加载合约ABI
	contractABI, err := sdk.NewABI(simpleTokenABI)
	if err != nil {
		return fmt.Errorf("解析合约ABI失败: %v", err)
	}

	// 编码函数调用
	callData, err := contractABI.EncodeMethod("transfer", []interface{}{
		common.HexToAddress(recipientAddress),
		amount,
	})
	if err != nil {
		return fmt.Errorf("编码函数调用失败: %v", err)
	}

	// 创建交易
	tx := sdk.NewTransaction().
		SetTo(tokenAddress).
		SetValue(big.NewInt(0)).
		SetData(callData)

	// 估算Gas
	gasLimit, err := client.EstimateGas(ctx, tx)
	if err != nil {
		return fmt.Errorf("估算Gas失败: %v", err)
	}
	tx.SetGasLimit(gasLimit)

	// 获取Gas价格
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return fmt.Errorf("获取Gas价格失败: %v", err)
	}
	tx.SetGasPrice(gasPrice)

	// 获取nonce
	nonce, err := client.GetPendingNonce(ctx, wallet.GetAddress())
	if err != nil {
		return fmt.Errorf("获取nonce失败: %v", err)
	}
	tx.SetNonce(nonce)

	// 签名交易
	signedTx, err := wallet.SignTransaction(tx)
	if err != nil {
		return fmt.Errorf("签名交易失败: %v", err)
	}

	// 发送交易
	txHash, err := client.SendTransaction(ctx, signedTx)
	if err != nil {
		return fmt.Errorf("发送交易失败: %v", err)
	}

	// 等待交易被确认
	fmt.Println("等待交易确认...")
	receipt, err := waitForTransaction(client, txHash)
	if err != nil {
		return fmt.Errorf("等待交易确认失败: %v", err)
	}

	if receipt.Status != 1 {
		return fmt.Errorf("交易失败，状态: %d", receipt.Status)
	}

	return nil
}

// 等待交易确认
func waitForTransaction(client *sdk.Client, txHash string) (*sdk.TransactionReceipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	for {
		receipt, err := client.GetTransactionReceipt(ctx, txHash)
		if err == nil && receipt != nil {
			return receipt, nil
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("等待交易超时")
		case <-time.After(2 * time.Second):
			// 继续等待
		}
	}
} 