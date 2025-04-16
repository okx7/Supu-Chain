# Supur链性能优化指南

本文档提供了针对Supur链节点在不同场景下的性能调优建议，特别是针对高吞吐量和生产环境。

## 硬件配置建议

### 验证者节点推荐配置
- CPU: 16核及以上，高时钟频率
- 内存: 64GB及以上
- 存储: 2TB NVMe SSD (4000+ IOPS)
- 网络: 1Gbps以上带宽，低延迟连接

### 全节点推荐配置
- CPU: 8核及以上
- 内存: 32GB及以上
- 存储: 1TB SSD
- 网络: 100Mbps以上带宽

## 操作系统优化

### Linux系统优化

1. 增加文件描述符限制:
```bash
# 在/etc/security/limits.conf中添加
* soft nofile 65535
* hard nofile 65535
```

2. 调整内核参数:
```bash
# 在/etc/sysctl.conf中添加
net.core.somaxconn = 1024
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 8096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
vm.max_map_count = 262144
```

3. 使用高性能调度器:
```bash
# 对于NVMe设备
echo 'none' > /sys/block/nvme0n1/queue/scheduler
```

### 数据存储优化

1. 使用XFS或ext4文件系统并适当调整挂载选项:
```bash
# 在/etc/fstab中
/dev/nvme0n1p1 /data xfs defaults,noatime,nodiratime,nobarrier 0 0
```

2. 分离数据目录和日志目录到不同的物理存储设备:
```bash
--datadir /ssd1/supur-data --logpath /ssd2/supur-logs
```

## Geth节点参数优化

### 内存和缓存调优

1. 增加缓存大小（根据可用内存调整）:
```bash
--cache 16384              # 16GB缓存
--cache.database 60        # 数据库缓存占比60%
--cache.trie 30            # Trie缓存占比30%
--cache.trie.journal ""    # 禁用trie缓存日志
```

2. 垃圾回收优化:
```bash
export GOGC=30             # 更积极的GC（小值意味着更积极的GC）
export GODEBUG=gctrace=1   # 输出GC统计信息以监控
```

### 交易池优化

对于高交易量的网络:
```bash
--txpool.globalslots 20480     # 全局交易槽位数
--txpool.accountslots 1024     # 每个账户的交易槽位
--txpool.globalqueue 10240     # 全局队列大小
--txpool.accountqueue 512      # 每个账户的队列大小
--txpool.pricelimit 1000000000 # 最低gas价格（wei）
```

### 网络参数优化

1. P2P网络优化:
```bash
--maxpeers 100             # 增加最大对等节点数
--maxpendpeers 50          # 最大待定连接数
--nat extip:1.2.3.4        # 外部IP配置（如果在NAT后面）
```

2. 减少不必要的RPC API:
```bash
--http.api "eth,net,web3"  # 仅开放必要的API
--ipcdisable                # 禁用IPC（如果不需要）
```

### 磁盘I/O优化

1. 禁用未使用的功能:
```bash
--nousb                   # 禁用USB钱包支持
--gcmode archive          # 归档模式（保留所有状态）
# 或
--gcmode full             # 标准模式（保留最近状态）
```

2. 周期性状态修剪:
```bash
# 定期运行修剪命令
./build/bin/geth --datadir data snapshot prune-state
```

### 高级优化（谨慎使用）

1. 针对验证者的特殊优化:
```bash
--mine.threads 4           # 验证线程数
--mine.recommit 2s         # 重组间隔
```

2. 数据库优化(leveldb/pebble参数):
```bash
--db.pebble.maxopenfiles=1024      # 最大打开文件数
--db.pebble.writeBufferSize=512    # 写缓冲区大小(MB)
--db.pebble.blockCacheSize=1024    # 块缓存大小(MB)
```

## 监控和调优

建立完善的监控系统是优化性能的关键。Supur链支持Prometheus和Grafana监控：

```bash
--metrics                  # 开启指标收集
--metrics.prometheus       # 启用Prometheus格式
--metrics.addr 127.0.0.1   # 指标服务绑定地址
--metrics.port 6060        # 指标服务端口
```

### 关键指标监控

1. 资源使用率:
   - CPU使用率
   - 内存使用率
   - 磁盘I/O
   - 网络带宽

2. 节点性能指标:
   - 区块同步状态
   - 交易处理速度
   - 对等节点数量
   - 交易池大小

3. 设置告警阈值，例如:
   - 磁盘空间低于20%
   - 内存使用率超过90%
   - 节点落后超过10个区块

## 多节点架构

对于生产环境，建议部署多节点架构:

1. 验证者节点（不对外开放RPC）
2. API节点（对外提供RPC服务）
3. 归档节点（保存完整历史数据）

使用负载均衡器（如Nginx、HAProxy）分发RPC请求到多个API节点：

```nginx
upstream supur_nodes {
    server 10.0.0.1:8545;
    server 10.0.0.2:8545;
    server 10.0.0.3:8545;
}

server {
    listen 80;
    server_name api.supur.chain;

    location / {
        proxy_pass http://supur_nodes;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## 故障排除

常见性能问题及解决方案:

1. **节点同步缓慢**
   - 增加缓存大小
   - 检查磁盘I/O性能
   - 确保网络连接稳定

2. **内存使用过高**
   - 减小缓存大小
   - 调整GC参数
   - 监控内存泄漏

3. **CPU使用率过高**
   - 检查是否有大量交易需要验证
   - 监控共识相关的CPU使用
   - 考虑增加CPU资源

4. **磁盘空间不足**
   - 定期修剪状态数据
   - 使用更大的存储设备
   - 监控磁盘空间使用趋势

## 优化实践案例

### 验证者节点优化配置示例

```bash
./build/bin/geth \
  --datadir /data/supur \
  --syncmode full \
  --networkid 776 \
  --mine \
  --miner.validator 0xYOUR_VALIDATOR_ADDRESS \
  --miner.threads 4 \
  --cache 16384 \
  --cache.database 60 \
  --cache.trie.journal "" \
  --txpool.globalslots 20480 \
  --txpool.accountslots 1024 \
  --maxpeers 100 \
  --metrics \
  --metrics.prometheus \
  --verbosity 3 \
  --port 30303
```

### API节点优化配置示例

```bash
./build/bin/geth \
  --datadir /data/supur \
  --syncmode full \
  --networkid 776 \
  --cache 16384 \
  --http \
  --http.api "eth,net,web3" \
  --http.addr 0.0.0.0 \
  --http.port 8545 \
  --http.vhosts "*" \
  --ws \
  --ws.api "eth,net,web3" \
  --ws.addr 0.0.0.0 \
  --ws.port 8546 \
  --maxpeers 50 \
  --metrics \
  --metrics.prometheus \
  --verbosity 3 \
  --port 30303
```

## 性能测试

在部署到生产环境前，建议进行全面的性能测试：

1. 交易吞吐量测试
   - 测量每秒可处理的交易数量
   - 测试不同复杂度的交易

2. 网络延迟测试
   - 测量交易确认时间
   - 测试不同地理位置的节点同步速度

3. 负载测试
   - 模拟高负载下的系统表现
   - 测量资源使用峰值

4. 长期稳定性测试
   - 持续运行系统至少一周
   - 监控性能退化情况

## 结论

优化Supur链节点性能是一个持续的过程，需要根据网络状况和实际负载不断调整。本指南提供的建议是一个起点，实际应用中应根据具体情况进行调整。

请记住，安全性始终是首要考虑因素，性能优化不应以牺牲安全性为代价。 