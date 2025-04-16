# Supur移动区块链安装指南

本文档将指导您安装和配置Supur移动区块链节点。无论您是希望运行验证者节点、全节点还是轻节点，本指南都将提供详细的步骤。

> 如需帮助，请加入我们的社区：[https://t.me/SupurChain](https://t.me/SupurChain)

## 目录

- [系统要求](#系统要求)
- [安装准备](#安装准备)
- [安装方法](#安装方法)
  - [二进制安装](#二进制安装)
  - [源码编译](#源码编译)
  - [Docker安装](#docker安装)
- [节点类型配置](#节点类型配置)
  - [全节点配置](#全节点配置)
  - [验证者节点配置](#验证者节点配置)
  - [轻节点配置](#轻节点配置)
- [网络设置](#网络设置)
- [安全配置](#安全配置)
- [启动节点](#启动节点)
- [节点维护](#节点维护)
- [常见问题](#常见问题)

## 系统要求

### 全节点

- **CPU**: 4核及以上
- **内存**: 8GB及以上
- **存储**: 500GB+ SSD (推荐NVMe SSD)
- **网络**: 固定IP，10Mbps+带宽
- **操作系统**: Ubuntu 20.04+ / Debian 11+ / CentOS 8+ / macOS 12+

### 验证者节点

- **CPU**: 8核及以上
- **内存**: 16GB及以上
- **存储**: 1TB+ SSD (必须使用NVMe SSD)
- **网络**: 固定IP，100Mbps+带宽，低延迟
- **操作系统**: Ubuntu 20.04+ / Debian 11+

### 轻节点

- **CPU**: 2核及以上
- **内存**: 4GB及以上
- **存储**: 50GB+ SSD
- **网络**: 稳定网络连接

## 安装准备

### Ubuntu/Debian准备

```bash
# 更新系统包
sudo apt update && sudo apt upgrade -y

# 安装必要依赖
sudo apt install -y build-essential git curl wget jq

# 创建专用用户（可选，但推荐）
sudo useradd -m -s /bin/bash supur
sudo usermod -aG sudo supur

# 切换到supur用户
sudo su - supur
```

### CentOS/RHEL准备

```bash
# 更新系统包
sudo dnf update -y

# 安装必要依赖
sudo dnf install -y git curl wget jq gcc gcc-c++ make

# 创建专用用户（可选，但推荐）
sudo useradd -m -s /bin/bash supur
sudo usermod -aG wheel supur

# 切换到supur用户
sudo su - supur
```

### macOS准备

```bash
# 安装Homebrew（如果尚未安装）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装必要依赖
brew install git curl wget jq go
```

### 安装Go语言

Supur区块链要求Go 1.20或更高版本。

```bash
# 下载并安装Go 1.20.5
wget https://go.dev/dl/go1.20.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz
rm go1.20.5.linux-amd64.tar.gz

# 配置环境变量
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
source ~/.bashrc

# 验证安装
go version
```

## 安装方法

### 二进制安装

从官方发布页下载最新的二进制文件是最简单的安装方法。

```bash
# 创建安装目录
mkdir -p ~/supur-chain && cd ~/supur-chain

# 下载最新发布版本
wget https://github.com/supur-chain/supur-chain/releases/download/v1.0.0/supur-linux-amd64.tar.gz

# 解压文件
tar -xzvf supur-linux-amd64.tar.gz

# 添加执行权限
chmod +x ./build/bin/*

# 验证安装
./build/bin/geth version
```

### 源码编译

从源码编译可以获得最新功能和修复。

```bash
# 克隆代码仓库
git clone https://github.com/supur-chain/supur-chain.git
cd supur-chain

# 编译
make geth

# 或编译所有工具
make all

# 验证安装
./build/bin/geth version
```

### Docker安装

使用Docker是在任何平台上快速启动节点的好方法。

```bash
# 拉取官方镜像
docker pull supurchain/supur:latest

# 创建数据目录
mkdir -p ~/supur-data

# 运行容器
docker run -d --name supur-node \
  -v ~/supur-data:/root/data \
  -p 8545:8545 -p 8546:8546 -p 30303:30303 \
  supurchain/supur:latest \
  --datadir /root/data
```

## 节点类型配置

### 全节点配置

全节点可以验证所有区块和交易，但不参与区块生成。

```bash
# 创建数据目录
mkdir -p ~/supur-chain/data

# 初始化链
./build/bin/geth --datadir ~/supur-chain/data init genesis.json

# 创建账户（可选）
./build/bin/geth --datadir ~/supur-chain/data account new

# 将密码保存到文件（如需自动解锁账户时使用）
echo "your-secure-password" > password.txt
chmod 600 password.txt
./build/bin/geth --datadir data account new --password password.txt
```

### 验证者节点配置

验证者节点参与区块生成和网络共识。

```bash
# 创建验证者账户
./build/bin/geth --datadir ~/supur-chain/data account new

# 记住生成的地址，之后将作为验证者地址使用
# 例如: 0x0000000000000000000000000000000000000000

# 初始化链
./build/bin/geth --datadir ~/supur-chain/data init genesis.json

# 将密码保存到文件（安全自动解锁）
echo "your-secure-validator-password" > ~/supur-chain/validator-password.txt
chmod 600 ~/supur-chain/validator-password.txt
```

### 轻节点配置

轻节点只下载区块头，不存储完整的区块链数据。

```bash
# 创建数据目录
mkdir -p ~/supur-chain/lightdata

# 初始化链
./build/bin/geth --datadir ~/supur-chain/lightdata init genesis.json
```

## 网络设置

### 防火墙配置

确保以下端口可用：

- **P2P网络**: TCP/UDP 30303
- **HTTP RPC**: TCP 8545（如开启）
- **WebSocket**: TCP 8546（如开启）
- **Discovery**: UDP 30303

Ubuntu/Debian防火墙设置:

```bash
# 安装ufw
sudo apt install -y ufw

# 设置默认规则
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 允许SSH
sudo ufw allow ssh

# 允许Supur节点端口
sudo ufw allow 30303/tcp
sudo ufw allow 30303/udp

# 如果需要开放RPC
sudo ufw allow 8545/tcp
sudo ufw allow 8546/tcp

# 启用防火墙
sudo ufw enable
```

## 安全配置

### 限制RPC访问

默认情况下，RPC接口仅允许本地访问。如果需要远程访问，建议使用反向代理（如Nginx）并配置TLS加密和访问控制。

Nginx配置示例:

```nginx
server {
    listen 443 ssl;
    server_name rpc.yournode.com;

    ssl_certificate /etc/letsencrypt/live/rpc.yournode.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/rpc.yournode.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8545;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        
        # 基本认证（可选）
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
```

## 启动节点

### 全节点启动

```bash
# 创建启动脚本
cat > ~/supur-chain/start-fullnode.sh << 'EOF'
#!/bin/bash

# 节点数据目录
DATA_DIR="$HOME/supur-chain/data"

# 日志目录
mkdir -p $DATA_DIR/logs

# 启动节点
$HOME/supur-chain/build/bin/geth \
  --datadir $DATA_DIR \
  --syncmode "full" \
  --networkid 776 \
  --http \
  --http.addr "127.0.0.1" \
  --http.port 8545 \
  --http.api "eth,net,web3,txpool" \
  --http.corsdomain "*" \
  --ws \
  --ws.addr "127.0.0.1" \
  --ws.port 8546 \
  --ws.api "eth,net,web3" \
  --ws.origins "*" \
  --port 30303 \
  --metrics \
  --metrics.addr "127.0.0.1" \
  --metrics.port 6060 \
  --cache 1024 \
  --verbosity 3 \
  &> $DATA_DIR/logs/node.log
EOF

# 添加执行权限
chmod +x ~/supur-chain/start-fullnode.sh

# 启动节点
~/supur-chain/start-fullnode.sh
```

### 验证者节点启动

```bash
# 创建启动脚本
cat > ~/supur-chain/start-validator.sh << 'EOF'
#!/bin/bash

# 节点数据目录
DATA_DIR="$HOME/supur-chain/data"

# 验证者地址（替换为您的地址）
VALIDATOR_ADDRESS="0x0000000000000000000000000000000000000000"

# 密码文件
PASSWORD_FILE="$HOME/supur-chain/validator-password.txt"

# 日志目录
mkdir -p $DATA_DIR/logs

# 启动验证者节点
$HOME/supur-chain/build/bin/geth \
  --datadir $DATA_DIR \
  --syncmode "full" \
  --networkid 776 \
  --mine \
  --miner.validator $VALIDATOR_ADDRESS \
  --unlock $VALIDATOR_ADDRESS \
  --password $PASSWORD_FILE \
  --allow-insecure-unlock \
  --http \
  --http.addr "127.0.0.1" \
  --http.port 8545 \
  --http.api "eth,net,web3,txpool" \
  --http.corsdomain "*" \
  --ws \
  --ws.addr "127.0.0.1" \
  --ws.port 8546 \
  --ws.api "eth,net,web3" \
  --ws.origins "*" \
  --port 30303 \
  --metrics \
  --metrics.addr "127.0.0.1" \
  --metrics.port 6060 \
  --cache 1024 \
  --verbosity 3 \
  &> $DATA_DIR/logs/node.log
EOF

# 添加执行权限
chmod +x ~/supur-chain/start-validator.sh

# 启动验证者节点
~/supur-chain/start-validator.sh
```

### 轻节点启动

```bash
# 创建启动脚本
cat > ~/supur-chain/start-lightnode.sh << 'EOF'
#!/bin/bash

# 节点数据目录
DATA_DIR="$HOME/supur-chain/lightdata"

# 日志目录
mkdir -p $DATA_DIR/logs

# 启动轻节点
$HOME/supur-chain/build/bin/geth \
  --datadir $DATA_DIR \
  --syncmode "light" \
  --networkid 776 \
  --http \
  --http.addr "127.0.0.1" \
  --http.port 8545 \
  --http.api "eth,net,web3" \
  --port 30303 \
  --cache 512 \
  --verbosity 3 \
  &> $DATA_DIR/logs/node.log
EOF

# 添加执行权限
chmod +x ~/supur-chain/start-lightnode.sh

# 启动轻节点
~/supur-chain/start-lightnode.sh
```

## 节点维护

### 创建系统服务

为确保节点在系统重启后自动启动，可以创建系统服务：

```bash
# 创建服务文件
sudo tee /etc/systemd/system/supur.service > /dev/null << 'EOF'
[Unit]
Description=Supur Chain Node
After=network.target
Wants=network.target

[Service]
Type=simple
User=supur
ExecStart=/home/supur/supur-chain/start-fullnode.sh
# 如果是验证者节点，请使用下面的行替代上面的行
# ExecStart=/home/supur/supur-chain/start-validator.sh
Restart=on-failure
RestartSec=10
LimitNOFILE=65535
LimitNPROC=4096

# 安全加固设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/home/supur/supur-chain/data

[Install]
WantedBy=multi-user.target
EOF

# 重新加载systemd配置
sudo systemctl daemon-reload

# 启用服务自启动
sudo systemctl enable supur

# 启动服务
sudo systemctl start supur

# 检查状态
sudo systemctl status supur
```

### 日志轮转

为防止日志文件过大，可以配置日志轮转：

```bash
sudo tee /etc/logrotate.d/supur > /dev/null << 'EOF'
/home/supur/supur-chain/data/logs/node.log {
    daily
    rotate 7
    compress
    delaycompress
    copytruncate
    missingok
    notifempty
    su supur supur
}
EOF
```

### 备份数据

定期备份密钥和重要配置：

```bash
# 备份账户密钥
mkdir -p ~/backups
cp -r ~/supur-chain/data/keystore ~/backups/keystore_$(date +%Y%m%d)

# 压缩并加密备份
tar -czf ~/backups/keystore_$(date +%Y%m%d).tar.gz ~/backups/keystore_$(date +%Y%m%d)
gpg -c ~/backups/keystore_$(date +%Y%m%d).tar.gz  # 将提示输入密码

# 删除未加密的备份
rm -rf ~/backups/keystore_$(date +%Y%m%d)
```

### 自动更新脚本

创建自动更新节点的脚本：

```bash
cat > ~/supur-chain/update.sh << 'EOF'
#!/bin/bash

# 停止节点
sudo systemctl stop supur

# 备份二进制文件
mv ~/supur-chain/build/bin/geth ~/supur-chain/build/bin/geth.backup

# 更新代码
cd ~/supur-chain
git pull

# 重新编译
make geth

# 检查新版本
NEW_VERSION=$(./build/bin/geth version | grep "Version:" | awk '{print $2}')
echo "Updated to version: $NEW_VERSION"

# 重启节点
sudo systemctl start supur

# 等待节点启动
sleep 10

# 检查节点是否正常运行
if pgrep -x "geth" > /dev/null; then
    echo "Node successfully restarted"
else
    echo "Node failed to restart, rolling back..."
    mv ~/supur-chain/build/bin/geth.backup ~/supur-chain/build/bin/geth
    sudo systemctl start supur
fi
EOF

# 添加执行权限
chmod +x ~/supur-chain/update.sh
```

## 高级配置

### 集群部署

对于需要高可用性的场景，可以配置多节点集群：

```bash
# 负载均衡设置示例（HAProxy）
sudo tee /etc/haproxy/haproxy.cfg > /dev/null << 'EOF'
frontend supur_frontend
    bind *:8545 ssl crt /etc/ssl/private/supur.pem
    mode http
    option forwardfor
    default_backend supur_backend

backend supur_backend
    mode http
    balance roundrobin
    option httpchk GET /
    http-check expect status 200
    server node1 10.0.0.1:8545 check
    server node2 10.0.0.2:8545 check backup
    server node3 10.0.0.3:8545 check backup
EOF

# 重启HAProxy
sudo systemctl restart haproxy
```

### 自动化部署

使用Ansible进行多节点自动化部署：

```yaml
# inventory.ini
[validators]
validator1 ansible_host=10.0.0.1
validator2 ansible_host=10.0.0.2

[fullnodes]
fullnode1 ansible_host=10.0.0.3
fullnode2 ansible_host=10.0.0.4

# playbook.yml
- name: Deploy Supur Chain Nodes
  hosts: all
  become: yes
  tasks:
    - name: Install dependencies
      apt:
        name: ['build-essential', 'git', 'curl', 'wget', 'jq']
        state: present
        update_cache: yes
      
    # 更多任务...

# 部署命令
ansible-playbook -i inventory.ini deploy-supur.yml
```

## 常见问题

### 无法同步区块链

**症状**: 节点启动但不同步区块。

**解决方案**:
1. 确认网络连接性：`telnet bootstrap.supur.io 30303`
2. 检查磁盘空间：`df -h`
3. 检查日志文件中的错误：`tail -100 ~/supur-chain/data/logs/node.log`
4. 尝试添加静态节点：
   ```bash
   echo '[
     "enode://public-key@ip:port",
     "enode://public-key@ip:port"
   ]' > ~/supur-chain/data/static-nodes.json
   ```

### 验证者节点未产生区块

**症状**: 验证者节点在线但未参与区块生成。

**解决方案**:
1. 确认账户已解锁：检查密码文件路径和权限
2. 验证地址是否正确：确保validator地址与配置匹配
3. 检查节点是否完全同步：使用RPC调用`eth_syncing`
4. 确认验证者激活状态：检查链上验证者合约状态

### RPC连接问题

**症状**: 无法通过RPC连接到节点。

**解决方案**:
1. 确认RPC已启用：检查启动参数中的`--http`标志
2. 检查IP和端口配置：确保`--http.addr`和`--http.port`设置正确
3. 验证防火墙规则：`sudo ufw status`
4. 尝试本地连接测试：`curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' http://127.0.0.1:8545`

## 社区支持

如果您在安装或运行Supur节点时遇到任何问题，请访问我们的社区获取帮助：

- Telegram社区：[https://t.me/SupurChain](https://t.me/SupurChain)
- 官方文档：[https://docs.supur.io](https://docs.supur.io)
- GitHub仓库：[https://github.com/supur-chain/supur-chain](https://github.com/supur-chain/supur-chain)

---

感谢您选择Supur移动区块链！如有任何问题，请随时在我们的社区[https://t.me/SupurChain](https://t.me/SupurChain)中提问。 