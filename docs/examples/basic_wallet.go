package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/supur-chain/sdk"
)

func main() {
	// 初始化SDK配置
	config := sdk.Config{
		NodeURL:  "https://rpc.supur.com",
		ChainID:  37887,
		LogLevel: "info",
	}

	// 创建SDK客户端
	client, err := sdk.NewClient(config)
	if err != nil {
		log.Fatalf("创建SDK客户端失败: %v", err)
	}

	// 创建或导入钱包
	wallet, err := createOrImportWallet(client)
	if err != nil {
		log.Fatalf("钱包操作失败: %v", err)
	}

	// 获取钱包地址
	address := wallet.GetAddress()
	fmt.Printf("钱包地址: %s\n", address)

	// 获取账户余额
	balance, err := client.GetBalance(context.Background(), address)
	if err != nil {
		log.Fatalf("获取余额失败: %v", err)
	}
	fmt.Printf("账户余额: %s SUPUR\n", sdk.WeiToEther(balance).String())

	// 发送交易示例
	// sendTransaction(client, wallet)

	// 监听新区块
	listenToNewBlocks(client)
}

// 创建或导入钱包
func createOrImportWallet(client *sdk.Client) (*sdk.Wallet, error) {
	// 选项1: 创建新钱包
	wallet, err := client.CreateWallet()
	if err != nil {
		return nil, fmt.Errorf("创建钱包失败: %v", err)
	}

	// 打印助记词（实际应用中应安全存储）
	mnemonic, err := wallet.GetMnemonic()
	if err != nil {
		return nil, fmt.Errorf("获取助记词失败: %v", err)
	}
	fmt.Printf("请安全保存您的助记词: %s\n", mnemonic)

	// 选项2: 从助记词导入钱包
	// wallet, err := client.ImportWalletFromMnemonic("your mnemonic phrase here")
	// if err != nil {
	//     return nil, fmt.Errorf("从助记词导入钱包失败: %v", err)
	// }

	// 选项3: 从私钥导入钱包
	// wallet, err := client.ImportWalletFromPrivateKey("your private key here")
	// if err != nil {
	//     return nil, fmt.Errorf("从私钥导入钱包失败: %v", err)
	// }

	return wallet, nil
}

// 发送交易
func sendTransaction(client *sdk.Client, wallet *sdk.Wallet) {
	// 创建交易对象
	tx := sdk.NewTransaction().
		SetTo("0xRecipientAddress").
		SetValue(sdk.EtherToWei(0.01)). // 0.01 SUPUR
		SetData([]byte{})

	// 估算Gas费用
	gasLimit, err := client.EstimateGas(context.Background(), tx)
	if err != nil {
		log.Fatalf("估算Gas失败: %v", err)
	}
	tx.SetGasLimit(gasLimit)

	// 获取当前Gas价格
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("获取Gas价格失败: %v", err)
	}
	tx.SetGasPrice(gasPrice)

	// 获取nonce
	nonce, err := client.GetPendingNonce(context.Background(), wallet.GetAddress())
	if err != nil {
		log.Fatalf("获取nonce失败: %v", err)
	}
	tx.SetNonce(nonce)

	// 签名交易
	signedTx, err := wallet.SignTransaction(tx)
	if err != nil {
		log.Fatalf("签名交易失败: %v", err)
	}

	// 发送交易
	txHash, err := client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatalf("发送交易失败: %v", err)
	}
	fmt.Printf("交易已发送，Hash: %s\n", txHash)

	// 等待交易确认
	fmt.Println("等待交易确认...")
	receipt, err := waitForTransaction(client, txHash)
	if err != nil {
		log.Fatalf("获取交易收据失败: %v", err)
	}

	if receipt.Status == 1 {
		fmt.Println("交易成功！")
	} else {
		fmt.Println("交易失败！")
	}
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

// 监听新区块
func listenToNewBlocks(client *sdk.Client) {
	fmt.Println("开始监听新区块...")
	
	// 创建区块订阅
	subscription, err := client.SubscribeNewBlocks(context.Background())
	if err != nil {
		log.Fatalf("订阅区块失败: %v", err)
	}
	defer subscription.Unsubscribe()

	// 处理接收到的区块
	for {
		select {
		case err := <-subscription.Err():
			log.Fatalf("订阅出错: %v", err)
		case block := <-subscription.Blocks():
			fmt.Printf("收到新区块: %d, Hash: %s, 交易数: %d\n",
				block.Number, block.Hash, len(block.Transactions))
		}
	}
} 