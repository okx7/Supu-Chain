# Supur链安全配置指南

本文档提供了Supur链节点的安全配置和最佳实践建议，帮助用户保护其节点和网络安全。

## 系统安全基础

### 操作系统安全强化

1. **保持系统更新**
   ```bash
   # Ubuntu/Debian
   sudo apt update && sudo apt upgrade -y
   
   # CentOS/RHEL
   sudo yum update -y
   ```

2. **最小化安装**
   - 仅安装必要的软件包
   - 禁用或卸载不需要的服务

3. **防火墙配置**
   ```bash
   # 使用UFW (Ubuntu)
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   sudo ufw allow ssh
   sudo ufw allow 30303/tcp # P2P端口
   sudo ufw allow 30303/udp # P2P端口
   # 仅允许特定IP访问RPC端口
   sudo ufw allow from 192.168.1.0/24 to any port 8545 proto tcp
   sudo ufw enable
   
   # 使用firewalld (CentOS/RHEL)
   sudo firewall-cmd --permanent --add-port=22/tcp
   sudo firewall-cmd --permanent --add-port=30303/tcp
   sudo firewall-cmd --permanent --add-port=30303/udp
   sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port protocol="tcp" port="8545" accept'
   sudo firewall-cmd --reload
   ```

4. **禁用root登录**
   - 编辑`/etc/ssh/sshd_config`
   ```
   PermitRootLogin no
   ```

5. **使用SSH密钥认证**
   ```bash
   # 生成SSH密钥
   ssh-keygen -t ed25519 -C "your_email@example.com"
   
   # 复制公钥到服务器
   ssh-copy-id user@server_ip
   
   # 禁用密码认证
   # 编辑/etc/ssh/sshd_config
   # PasswordAuthentication no
   ```

6. **定期安全审计**
   ```bash
   # 安装安全审计工具
   sudo apt install lynis
   # 运行审计
   sudo lynis audit system
   ```

### 文件系统安全

1. **设置适当文件权限**
   ```bash
   # 限制密码文件权限
   chmod 600 password.txt
   
   # 限制私钥文件权限
   chmod 600 data/keystore/*
   
   # 限制配置文件权限
   chmod 644 genesis.json
   ```

2. **启用磁盘加密**
   - 使用LUKS加密存储节点数据的磁盘
   ```bash
   # 安装加密工具
   sudo apt install cryptsetup
   
   # 创建加密分区
   sudo cryptsetup luksFormat /dev/sdb1
   
   # 打开加密分区
   sudo cryptsetup luksOpen /dev/sdb1 supur_data
   
   # 创建文件系统
   sudo mkfs.ext4 /dev/mapper/supur_data
   
   # 挂载
   sudo mount /dev/mapper/supur_data /data
   ```

3. **定期备份**
   - 创建定期备份脚本
   ```bash
   #!/bin/bash
   # 停止节点
   systemctl stop supur.service
   
   # 备份数据
   tar -czf /backup/supur-data-$(date +%Y%m%d).tar.gz /data/supur
   
   # 重启节点
   systemctl start supur.service
   ```

## Supur链节点安全

### 安全启动配置

1. **限制RPC接口绑定地址**
   ```bash
   # 仅允许本地访问
   --http.addr 127.0.0.1
   --ws.addr 127.0.0.1
   
   # 使用反向代理暴露服务
   ```

2. **启用TLS加密**
   ```bash
   # 生成自签名证书
   openssl req -x509 -nodes -newkey rsa:4096 -keyout server.key -out server.crt -days 365
   
   # 配置反向代理（Nginx）
   server {
       listen 443 ssl;
       server_name api.supur.chain;
       
       ssl_certificate /path/to/server.crt;
       ssl_certificate_key /path/to/server.key;
       
       location / {
           proxy_pass http://127.0.0.1:8545;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection "upgrade";
       }
   }
   ```

3. **限制API模块**
   ```bash
   # 仅启用必要的API
   --http.api "eth,net,web3"
   --ws.api "eth,net,web3"
   ```

4. **安全存储密码**
   - 使用环境变量或密钥管理服务
   ```bash
   # 使用安全的密码文件
   echo "strong_random_password" > password.txt
   chmod 600 password.txt
   
   # 启动节点时使用
   --password password.txt
   ```

5. **配置CORS限制**
   ```bash
   # 限制请求源
   --http.corsdomain "your-dapp-domain.com"
   --ws.origins "your-dapp-domain.com"
   ```

### 帐户安全

1. **分离验证者节点与RPC节点**
   - 验证者节点不应该对外开放RPC接口
   - 使用单独的RPC节点提供API服务

2. **定期轮换密钥**
   - 建立密钥轮换计划
   - 新密钥生效前确保备份

3. **冷钱包存储主要资金**
   - 验证者账户仅持有必要的资金
   - 主要资金保存在冷钱包中

4. **使用硬件钱包**
   ```bash
   # 支持Ledger/Trezor
   --usb
   ```

### 网络安全

1. **使用静态节点**
   ```bash
   # 创建静态节点配置文件
   echo '[
     "enode://pubkey1@ip1:port1",
     "enode://pubkey2@ip2:port2"
   ]' > data/static-nodes.json
   ```

2. **配置最大对等节点数量**
   ```bash
   --maxpeers 50
   ```

3. **启用节点发现限制**
   ```bash
   # 禁用节点发现
   --nodiscover
   
   # 仅连接到静态节点
   --staticpeers
   ```

4. **禁用不需要的服务**
   ```bash
   # 如果不需要RPC服务
   --ipcdisable
   ```

## API安全

### RPC安全

1. **访问控制**
   - 使用Nginx/HAProxy实现基本认证
   ```nginx
   location / {
       auth_basic "Restricted Access";
       auth_basic_user_file /etc/nginx/.htpasswd;
       proxy_pass http://127.0.0.1:8545;
   }
   ```

2. **API密钥认证**
   - 在前端代理层实现API密钥验证
   ```js
   // 简单的API密钥校验中间件
   app.use((req, res, next) => {
     const apiKey = req.headers['x-api-key'];
     if (!apiKey || !validApiKeys.includes(apiKey)) {
       return res.status(401).json({ error: 'Unauthorized' });
     }
     next();
   });
   ```

3. **请求限流**
   - 使用Nginx限制请求率
   ```nginx
   # 限制每个IP每秒请求数
   limit_req_zone $binary_remote_addr zone=rpc_limit:10m rate=10r/s;
   
   server {
       location / {
           limit_req zone=rpc_limit burst=20 nodelay;
           proxy_pass http://127.0.0.1:8545;
       }
   }
   ```

4. **响应数据过滤**
   - 过滤敏感信息
   - 限制返回数据大小

### WebSocket安全

1. **启用WebSocket TLS**
   ```bash
   # 通过反向代理
   server {
       listen 443 ssl;
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       
       location /ws {
           proxy_pass http://127.0.0.1:8546;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection "upgrade";
       }
   }
   ```

2. **实现连接超时**
   ```nginx
   # 设置超时
   proxy_read_timeout 60s;
   proxy_send_timeout 60s;
   ```

### IPC安全

1. **IPC文件权限**
   ```bash
   # 设置适当权限
   chmod 600 data/geth.ipc
   ```

2. **用户组限制**
   ```bash
   # 创建专用用户组
   sudo groupadd supur
   sudo usermod -a -G supur user1
   sudo usermod -a -G supur user2
   
   # 设置组权限
   sudo chgrp supur data/geth.ipc
   sudo chmod 660 data/geth.ipc
   ```

## 监控与审计

### 日志监控

1. **配置日志级别**
   ```bash
   --verbosity 3
   ```

2. **集中式日志管理**
   - 使用Filebeat收集日志
   ```yaml
   # filebeat.yml
   filebeat.inputs:
   - type: log
     enabled: true
     paths:
       - /data/supur/logs/*.log
   
   output.elasticsearch:
     hosts: ["elasticsearch:9200"]
   ```

3. **日志分析**
   - 使用ELK Stack分析日志
   - 设置异常检测规则

### 实时监控

1. **设置指标监控**
   ```bash
   # 启用Prometheus指标
   --metrics --metrics.prometheus
   ```

2. **使用Grafana创建监控面板**
   - 监控CPU、内存、磁盘使用率
   - 监控网络连接数
   - 监控交易池大小
   - 监控区块确认时间

3. **设置告警规则**
   ```yaml
   # prometheus告警规则
   groups:
   - name: supur-alerts
     rules:
     - alert: HighCPUUsage
       expr: rate(process_cpu_seconds_total[5m]) > 0.8
       for: 5m
       labels:
         severity: warning
       annotations:
         summary: "High CPU usage detected"
         description: "Node {{ $labels.instance }} has high CPU usage"
   ```

### 安全审计

1. **定期安全扫描**
   - 使用漏洞扫描工具
   - 检查开放端口
   - 检查配置文件安全性

2. **交易审计**
   - 监控可疑交易模式
   - 设置交易金额阈值告警

3. **代码审计**
   - 定期审计自定义代码
   - 确保依赖库及时更新

## 灾难恢复

### 备份策略

1. **定期备份节点数据**
   ```bash
   # 创建定时任务
   0 2 * * * /path/to/backup-script.sh
   ```

2. **异地备份**
   - 将备份存储在不同的地理位置
   - 使用加密传输和存储

3. **备份验证**
   - 定期测试恢复过程
   - 确保备份数据完整性

### 恢复流程

1. **文档化恢复流程**
   - 详细记录每个恢复步骤
   - 包括联系人和紧急流程

2. **制定RTO和RPO目标**
   - 确定可接受的恢复时间目标
   - 确定可接受的数据丢失点

3. **模拟灾难恢复演练**
   - 每季度进行一次演练
   - 验证流程有效性

## 多重安全架构

### 多层防御

1. **网络层**
   - 防火墙
   - DDoS防护
   - VPN访问

2. **应用层**
   - 认证/授权
   - 输入验证
   - 会话管理

3. **数据层**
   - 加密存储
   - 访问控制
   - 数据完整性校验

### 高可用配置

1. **负载均衡**
   ```nginx
   upstream supur_nodes {
       server 10.0.0.1:8545;
       server 10.0.0.2:8545;
       server 10.0.0.3:8545;
   }
   
   server {
       listen 443 ssl;
       server_name api.supur.chain;
       
       location / {
           proxy_pass http://supur_nodes;
       }
   }
   ```

2. **故障切换**
   - 热备节点配置
   - 自动化故障检测和切换

3. **地域分布**
   - 在不同地域部署节点
   - 确保网络弹性

## 安全运维实践

### 持续安全评估

1. **定期安全评估**
   - 每季度进行一次全面评估
   - 关注新发现的漏洞

2. **渗透测试**
   - 每半年进行一次渗透测试
   - 测试API安全性和认证机制

3. **代码安全审计**
   - 升级前进行代码审计
   - 检查自定义脚本和配置

### 安全更新管理

1. **制定补丁管理流程**
   - 测试环境验证
   - 生产环境部署计划
   - 回退计划

2. **自动化更新检测**
   - 监控官方仓库更新
   - 设置安全公告订阅

3. **记录变更**
   - 维护详细的更新日志
   - 记录配置变更

## 附录：安全检查清单

### 日常检查项目

- [ ] 检查系统日志中的异常
- [ ] 监控磁盘空间使用率
- [ ] 验证备份是否正常执行
- [ ] 检查节点同步状态
- [ ] 检查对等节点连接数
- [ ] 验证RPC接口响应正常

### 周度检查项目

- [ ] 检查系统更新
- [ ] 检查防火墙规则有效性
- [ ] 验证日志轮转是否正常
- [ ] 检查服务器资源使用趋势
- [ ] 验证告警系统工作正常

### 月度检查项目

- [ ] 全面安全审计
- [ ] 密码和密钥轮换评估
- [ ] 恢复演练
- [ ] 性能基准测试比较
- [ ] 检查证书有效期

## 结论

通过实施本文档中的安全建议，可以显著提高Supur链节点的安全性。安全是一个持续的过程，需要定期评估和改进。请定期查看官方文档和社区最佳实践，以保持节点的安全性。 