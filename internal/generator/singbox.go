package generator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/evecus/homeproxy-go/internal/config"
)

type SingBox struct{ Cfg *config.Config }

func NewSingBox(cfg *config.Config) *SingBox { return &SingBox{Cfg: cfg} }

func (s *SingBox) Generate() (map[string]any, error) {
	cfg := s.Cfg
	out := map[string]any{
		"log": map[string]any{"level": cfg.Log.Level, "timestamp": true},
	}
	out["dns"] = s.buildDNS()
	out["inbounds"] = s.buildInbounds()
	obs, err := s.buildOutbounds()
	if err != nil {
		return nil, err
	}
	out["outbounds"] = obs
	out["route"] = s.buildRoute()
	out["experimental"] = map[string]any{
		"cache_file": map[string]any{
			"enabled": true,
			"path":    filepath.Join(cfg.Paths.RunDir, "cache.db"),
		},
	}
	return out, nil
}

func (s *SingBox) Write(path string) error {
	obj, err := s.Generate()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func (s *SingBox) buildDNS() map[string]any {
	cfg := s.Cfg
	servers := []any{
		map[string]any{"tag": "default-dns", "address": "local", "detour": "direct-out"},
		map[string]any{"tag": "main-dns", "address": ensureDNSAddr(cfg.DNS.Server), "detour": "main-out", "strategy": cfg.DNS.Strategy},
	}
	rules := []any{}
	final := "main-dns"
	if cfg.Mode == config.ModeBypassMainlandChina {
		servers = append(servers, map[string]any{
			"tag": "china-dns", "address": ensureDNSAddr(cfg.DNS.ChinaServer), "detour": "direct-out",
		})
		rules = append(rules,
			map[string]any{"rule_set": "geosite-cn", "server": "china-dns"},
			map[string]any{"rule_set": "geoip-cn", "server": "china-dns"},
		)
	}
	return map[string]any{"servers": servers, "rules": rules, "final": final, "strategy": cfg.DNS.Strategy}
}

func (s *SingBox) buildInbounds() []any {
	cfg := s.Cfg
	inbounds := []any{
		map[string]any{"type": "direct", "tag": "dns-in", "listen": "::", "listen_port": cfg.DNS.ListenPort},
		map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "::", "listen_port": cfg.Proxy.MixedPort, "sniff": true, "sniff_override_destination": true},
	}
	switch cfg.Proxy.Mode {
	case config.ProxyTProxy:
		inbounds = append(inbounds, map[string]any{
			"type": "tproxy", "tag": "tproxy-in", "listen": "::", "listen_port": cfg.Proxy.TProxyPort,
			"network": "tcp,udp", "sniff": true, "sniff_override_destination": true,
		})
	case config.ProxyRedirect:
		inbounds = append(inbounds, map[string]any{
			"type": "redirect", "tag": "redirect-in", "listen": "::", "listen_port": cfg.Proxy.RedirectPort,
			"sniff": true, "sniff_override_destination": true,
		})
	case config.ProxyTUN:
		addrs := []string{cfg.Proxy.TUNAddr4}
		if cfg.Proxy.IPv6 {
			addrs = append(addrs, cfg.Proxy.TUNAddr6)
		}
		inbounds = append(inbounds, map[string]any{
			"type": "tun", "tag": "tun-in", "interface_name": cfg.Proxy.TUNName, "address": addrs,
			"mtu": cfg.Proxy.TUNMTU, "auto_route": false, "stack": "system", "sniff": true, "sniff_override_destination": true,
		})
	}
	return inbounds
}

func (s *SingBox) buildOutbounds() ([]any, error) {
	cfg := s.Cfg
	outbounds := []any{
		map[string]any{"type": "direct", "tag": "direct-out", "routing_mark": atoiSafe(cfg.Proxy.SelfMark)},
		map[string]any{"type": "block", "tag": "block-out"},
	}
	for _, n := range cfg.Nodes {
		obs, err := nodeToOutbound(&n, cfg.Proxy.SelfMark)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, obs)
	}
	if cfg.Proxy.MainNode == "urltest" {
		tags := []string{}
		for _, name := range cfg.Proxy.URLTestNodes {
			tags = append(tags, nodeTag(name))
		}
		if len(tags) == 0 {
			for _, n := range cfg.Nodes {
				tags = append(tags, nodeTag(n.Name))
			}
		}
		outbounds = append(outbounds, map[string]any{
			"type": "urltest", "tag": "main-out", "outbounds": tags,
			"interval": fmt.Sprintf("%ds", cfg.Proxy.URLTestInterval), "tolerance": cfg.Proxy.URLTestTolerance,
		})
	} else if cfg.Proxy.MainNode != "" {
		outbounds = append(outbounds, map[string]any{
			"type": "selector", "tag": "main-out",
			"outbounds": []string{nodeTag(cfg.Proxy.MainNode)}, "default": nodeTag(cfg.Proxy.MainNode),
		})
	} else if len(cfg.Nodes) > 0 {
		outbounds = append(outbounds, map[string]any{
			"type": "selector", "tag": "main-out",
			"outbounds": []string{nodeTag(cfg.Nodes[0].Name)}, "default": nodeTag(cfg.Nodes[0].Name),
		})
	} else {
		outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "main-out"})
	}
	return outbounds, nil
}

func (s *SingBox) buildRoute() map[string]any {
	cfg := s.Cfg
	rules := []any{map[string]any{"inbound": "dns-in", "action": "hijack-dns"}}
	ruleSets := []any{}
	if cfg.Mode == config.ModeBypassMainlandChina || cfg.Mode == config.ModeProxyMainlandChina || cfg.Mode == config.ModeGFWList {
		ruleSets = append(ruleSets,
			map[string]any{"type": "remote", "tag": "geoip-cn", "format": "binary",
				"url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", "download_detour": "main-out"},
			map[string]any{"type": "remote", "tag": "geosite-cn", "format": "binary",
				"url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-cn.srs", "download_detour": "main-out"},
			map[string]any{"type": "remote", "tag": "geosite-noncn", "format": "binary",
				"url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs", "download_detour": "main-out"},
		)
	}
	final := "main-out"
	switch cfg.Mode {
	case config.ModeBypassMainlandChina:
		rules = append(rules,
			map[string]any{"rule_set": "geosite-cn", "outbound": "direct-out"},
			map[string]any{"rule_set": "geoip-cn", "outbound": "direct-out"},
		)
	case config.ModeProxyMainlandChina:
		rules = append(rules,
			map[string]any{"rule_set": "geosite-cn", "outbound": "main-out"},
			map[string]any{"rule_set": "geoip-cn", "outbound": "main-out"},
		)
		final = "direct-out"
	case config.ModeGFWList:
		rules = append(rules,
			map[string]any{"rule_set": "geosite-noncn", "outbound": "main-out"},
			map[string]any{"rule_set": "geosite-cn", "outbound": "direct-out"},
			map[string]any{"rule_set": "geoip-cn", "outbound": "direct-out"},
		)
		final = "direct-out"
	case config.ModeGlobal:
		final = "main-out"
	}
	rules = append(rules, map[string]any{"ip_is_private": true, "outbound": "direct-out"})
	route := map[string]any{
		"rules": rules, "final": final, "auto_detect_interface": true,
		"default_domain_resolver": map[string]any{"server": "default-dns", "strategy": cfg.DNS.Strategy},
	}
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}
	return route
}

func nodeTag(name string) string {
	return "node-" + sanitizeTag(name)
}

func sanitizeTag(s string) string {
	s = strings.ReplaceAll(s, " ", "_")
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func nodeToOutbound(n *config.Node, selfMark string) (map[string]any, error) {
	obs := map[string]any{
		"tag": nodeTag(n.Name), "type": n.Type, "server": n.Server, "server_port": n.Port,
		"routing_mark": atoiSafe(selfMark),
	}
	switch strings.ToLower(n.Type) {
	case "shadowsocks":
		obs["method"] = n.Method
		obs["password"] = n.Password
	case "vmess", "vless":
		obs["uuid"] = n.UUID
	case "trojan", "hysteria2":
		obs["password"] = n.Password
	case "tuic":
		obs["uuid"] = n.UUID
		obs["password"] = n.Password
	}
	if n.TLS != nil && n.TLS.Enabled {
		tls := map[string]any{"enabled": true}
		if n.TLS.ServerName != "" {
			tls["server_name"] = n.TLS.ServerName
		}
		if n.TLS.Insecure {
			tls["insecure"] = true
		}
		obs["tls"] = tls
	}
	if n.Extra != nil {
		for k, v := range n.Extra {
			obs[k] = v
		}
	}
	return obs, nil
}

func ensureDNSAddr(s string) string {
	if strings.Contains(s, "://") {
		return s
	}
	return "udp://" + s
}

func atoiSafe(s string) any {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		var n int
		fmt.Sscanf(s, "%x", &n)
		return n
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		return n
	}
	return nil
}
