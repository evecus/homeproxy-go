# homeproxy-go

Debian/Linux 旁路由透明代理控制器，对齐 OpenWrt [homeproxy](https://github.com/immortalwrt/homeproxy) 的分流思路：

- **nftables**：中国大陆 IP 提前 return、LAN/WAN ACL、TProxy 劫持
- **sing-box**：DNS + 出站 + 域名/规则集路由
- **YAML 配置 + Web 面板**：路由模式、订阅导入、节点选择、黑白名单、启停

## 功能

| 能力 | 说明 |
|------|------|
| 路由模式 | `bypass_mainland_china` / `gfwlist` / `proxy_mainland_china` / `global` / `custom` |
| 透明代理 | TProxy（推荐）/ Redirect / TUN |
| 订阅 | 导入 URL、更新并合并节点、设为主节点 |
| 访问控制 | LAN 过滤模式、IP/MAC 黑白名单、域名强制代理/直连、WAN CIDR |
| Web UI | 概览启停、客户端、节点、订阅、访问控制、工具 |
| CI | GitHub Actions 多架构 Release |

## 依赖

- Linux（Debian 旁路由）
- [sing-box](https://github.com/SagerNet/sing-box) 可执行文件
- `nftables`、`iproute2`
- 内核 TProxy（`CONFIG_NETFILTER_XT_TARGET_TPROXY` 等）

## 快速开始

```bash
# 编译
go build -o bin/homeproxy ./cmd/homeproxy
# 或 make build

# 配置
sudo mkdir -p /etc/homeproxy /var/lib/homeproxy /var/run/homeproxy
sudo cp configs/config.example.yaml /etc/homeproxy/config.yaml
# 编辑节点 / 订阅 / LAN 网卡

# 校验
sudo homeproxy check -c /etc/homeproxy/config.yaml

# 生成 sing-box.json + nftables.nft 并启动（CLI）
sudo homeproxy generate -c /etc/homeproxy/config.yaml
sudo homeproxy update-resources -c /etc/homeproxy/config.yaml
sudo homeproxy setup-routing -c /etc/homeproxy/config.yaml
sudo homeproxy apply-nft -c /etc/homeproxy/config.yaml
# 或用 systemd：见 deploy/homeproxy.service

# Web 面板
sudo homeproxy serve -c /etc/homeproxy/config.yaml -l :8080
# 浏览器打开 http://旁路由IP:8080
# 可选 BasicAuth：-user admin -pass yourpassword
```

## Web 面板

1. **概览**：启用 / 停用 / 重启  
2. **客户端**：路由模式、透明代理方式、主节点、DNS、LAN 网卡  
3. **节点**：列表、设为主节点、删除、手动添加  
4. **订阅**：导入 URL、更新（可替换同前缀节点）  
5. **访问控制**：LAN 模式、IP/MAC、域名黑白名单、WAN CIDR  
6. **工具**：生成配置、应用 nft、更新中国 IP/GFW 列表、YAML 编辑  

保存 ACL 或更换主节点后建议点一次 **重启**。

## 配置摘要

```yaml
mode: bypass_mainland_china   # 路由模式
proxy:
  mode: tproxy
  main_node: "节点名"         # 或 urltest
  ipv6: false
dns:
  server: 8.8.8.8
  china_server: 223.5.5.5
nodes: []
subscriptions:
  - name: provider1
    url: https://...
    enabled: true
control:
  lan_interfaces: [eth1]
  lan_proxy_mode: all          # all | except_listed | listed_only
  lan_direct_ipv4: []
  lan_proxy_ipv4: []
  proxy_domains: []
  direct_domains: []
paths:
  data_dir: /var/lib/homeproxy
  run_dir: /var/run/homeproxy
  singbox_bin: sing-box
```

完整示例见 `configs/config.example.yaml`。

## 旁路由注意

- 主路由网关指向本机，或本机做网关  
- `control.lan_interfaces` 填接内网的网卡  
- TProxy 需要 `setup-routing` 安装 fwmark 策略路由  
- 停用时可用面板「停用」并勾选清理 nft  

## License

GPL-3.0（与 immortalwrt/homeproxy 思路对齐的独立实现）
