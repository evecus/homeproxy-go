# homeproxy-go

Transparent proxy controller for **Debian / generic Linux side routers**, inspired by [OpenWrt homeproxy](https://github.com/immortalwrt/homeproxy).

It generates **sing-box** + **nftables** rules with the same routing modes:

| Mode | Behavior |
|------|----------|
| `bypass_mainland_china` | China IP/domains direct, rest via proxy (default) |
| `proxy_mainland_china` | Only China via proxy |
| `gfwlist` | Approximate GFW routing via geosite (no DNS nftset yet) |
| `global` | Everything via proxy |
| `custom` | Placeholder for user rules |

> DNS module (dnsmasq-style domain → nft set) is **not** included in this version. China IP bypass still works at the firewall layer; domain-level China/GFW handling uses sing-box geosite/geoip.

## Architecture

```
LAN → nftables (China IP return / TProxy mark)
         ↓
    sing-box (tproxy inbound + route + outbounds)
```

- **China IPv4/IPv6 lists** → nft sets → early `return` (never enter sing-box)
- **sing-box** handles protocol, DNS hijack port, geosite rules, nodes

## Requirements

- Linux with **nftables**
- [sing-box](https://github.com/SagerNet/sing-box) installed (`sing-box` in `PATH`)
- Root for applying nft rules and TProxy policy routing

## Quick start

```bash
# 1. Install binary (from release or build)
sudo install -Dm755 homeproxy-linux-amd64 /usr/local/bin/homeproxy

# 2. Config
sudo mkdir -p /etc/homeproxy /var/lib/homeproxy /var/run/homeproxy
sudo cp configs/config.example.yaml /etc/homeproxy/config.yaml
sudo $EDITOR /etc/homeproxy/config.yaml

# 3. Resource lists (China IP, GFW domains)
sudo homeproxy update-resources -c /etc/homeproxy/config.yaml

# 4. Generate + apply
sudo homeproxy generate -c /etc/homeproxy/config.yaml
sudo homeproxy setup-routing -c /etc/homeproxy/config.yaml
sudo homeproxy apply-nft -c /etc/homeproxy/config.yaml

# 5. Run sing-box
sudo sing-box run -c /var/run/homeproxy/sing-box.json
```

Or use the systemd unit under `deploy/homeproxy.service`.

## CLI

```
homeproxy generate          # write sing-box.json + nftables.nft
homeproxy apply-nft         # nft -f the generated file
homeproxy update-resources  # download china_ip / gfw list
homeproxy update-subs       # fetch subscriptions (print nodes)
homeproxy setup-routing     # ip rule/route for TProxy fwmark
homeproxy check             # validate YAML
```

## Build

```bash
git clone https://github.com/evecus/homeproxy-go.git
cd homeproxy-go
make build
# → bin/homeproxy
```

GitHub Actions builds multi-arch binaries on push/tag (`linux/amd64`, `arm64`, `armv7`, `386`).

## Side-router notes

1. Point LAN clients’ **gateway** (and ideally DNS) to this machine.
2. Enable IP forwarding: `sysctl -w net.ipv4.ip_forward=1`
3. Set `control.lan_interfaces` to your LAN NIC (e.g. `eth1`).
4. TProxy needs the policy routing installed by `setup-routing`.

## Config sketch

See [`configs/config.example.yaml`](configs/config.example.yaml).

Supported node types (share links / YAML): Shadowsocks, VMess, VLESS, Trojan, Hysteria2 (basic fields; extra sing-box keys via `extra` / `transport`).

## Roadmap

- [ ] Optional DNS module (domain → nft set)
- [ ] Full custom routing rules in YAML
- [ ] URLTest / selector UI helpers
- [ ] Auto subscription refresh daemon

## License

GPL-2.0-only (same spirit as homeproxy / ImmortalWrt packages).
