#!/bin/bash

# 启动Supur链节点脚本
# 安全的密码管理与RPC配置版本

# 确保目录存在
mkdir -p data/logs

# 安全检查：确保密码文件存在且权限正确
if [ ! -f password.txt ]; then
  echo "错误: 未找到密码文件 password.txt"
  echo "请创建密码文件：echo '您的密码' > password.txt"
  echo "并设置适当权限：chmod 600 password.txt"
  exit 1
fi

# 检查密码文件权限
PERMS=$(stat -c "%a" password.txt 2>/dev/null || stat -f "%p" password.txt 2>/dev/null)
if [[ "$PERMS" != "600" ]]; then
  echo "警告: 密码文件权限不安全，建议执行: chmod 600 password.txt"
  read -p "是否继续? (y/n): " CONFIRM
  if [[ "$CONFIRM" != "y" ]]; then
    exit 1
  fi
fi

# 验证者地址 - 请使用您自己的地址替换
VALIDATOR_ADDRESS="0x0000000000000000000000000000000000000000"

# 网络相关配置
P2P_PORT=30303
HTTP_PORT=8545
WS_PORT=8546
METRICS_PORT=6060

# 安全配置：限制API访问范围，仅允许特定域访问
HTTP_CORS="localhost,127.0.0.1"
WS_ORIGINS="localhost,127.0.0.1"

# 仅向本地网络开放RPC接口（更安全）
# 如需外部访问，请配置防火墙和反向代理
HTTP_ADDR="127.0.0.1"
WS_ADDR="127.0.0.1"

# 可选：如果需要外部访问，取消下面的注释
# HTTP_ADDR="0.0.0.0"
# WS_ADDR="0.0.0.0"

# 性能调优参数
CACHE=1024          # 缓存大小(MB)
GC_MODE=20          # 垃圾回收模式

# 日志文件
LOG_FILE="data/logs/node.log"

# 设置环境变量优化GC
export GOGC=$GC_MODE

echo "正在启动Supur链验证者节点..."
echo "验证者地址: $VALIDATOR_ADDRESS"
echo "HTTP-RPC端口: $HTTP_PORT"
echo "WS-RPC端口: $WS_PORT"
echo "P2P端口: $P2P_PORT"
echo "日志文件: $LOG_FILE"

# 启动节点作为验证者
./build/bin/geth \
  --datadir data \
  --syncmode "full" \
  --networkid 776 \
  --mine \
  --miner.validator $VALIDATOR_ADDRESS \
  --unlock $VALIDATOR_ADDRESS \
  --password password.txt \
  --allow-insecure-unlock \
  --http \
  --http.addr $HTTP_ADDR \
  --http.port $HTTP_PORT \
  --http.corsdomain "$HTTP_CORS" \
  --http.api "eth,net,web3" \
  --ws \
  --ws.addr $WS_ADDR \
  --ws.port $WS_PORT \
  --ws.origins "$WS_ORIGINS" \
  --ws.api "eth,net,web3" \
  --port $P2P_PORT \
  --metrics \
  --metrics.addr "127.0.0.1" \
  --metrics.port $METRICS_PORT \
  --cache $CACHE \
  --verbosity 3 \
  2>&1 | tee -a $LOG_FILE

# 注意：对于生产环境，考虑添加以下参数
# --maxpeers 50                 # 调整对等节点数量
# --txpool.globalslots 10240    # 增加交易池容量
# --txpool.accountslots 512     # 每个账户的交易槽位
# --nat "extip:公网IP"          # 如果节点在NAT后面 