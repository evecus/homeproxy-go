# homeproxy-go

Debian/Linux 旁路由透明代理（对齐 OpenWrt homeproxy 思路）：nftables + sing-box + 可选 dnsmasq nftset + Web 面板。

## 已实现

- 路由模式：绕过大陆 / GFWList / 仅代理大陆 / 全局 / 自定义
- 透明代理：TProxy / Redirect / TUN
- dnsmasq nftset 精确 GFW（`dnsmasq.enabled`）
- 节点：ss/vmess/vless/trojan/hy2/tuic + WS/gRPC/HTTP 传输 + Reality + Flow + uTLS
- 订阅导入与定时更新、主节点/UDP 节点、URLTest
- 自定义路由规则、DNS 规则、额外 DNS（DoH/DoT）
- LAN ACL / 游戏模式 / 全局代理设备
- Server 入站（含证书路径）
- Clash API 流量与节点测速、日志 tail
- Web 面板启停与配置

## 快速开始

```bash
go build -o bin/homeproxy ./cmd/homeproxy
sudo mkdir -p /etc/homeproxy /var/lib/homeproxy /var/run/homeproxy
sudo cp configs/config.example.yaml /etc/homeproxy/config.yaml
sudo homeproxy update-resources -c /etc/homeproxy/config.yaml
sudo homeproxy generate -c /etc/homeproxy/config.yaml
sudo homeproxy serve -c /etc/homeproxy/config.yaml -l :8080
```

详见 `configs/config.example.yaml`。

## License

GPL-3.0
