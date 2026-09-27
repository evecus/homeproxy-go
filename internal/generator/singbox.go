package generator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/evecus/homeproxy-go/internal/config"
)

// SingBox builds sing-box JSON config from homeproxy Config.
type SingBox struct {
	Cfg *config.Config
}

func NewSingBox(cfg *config.Config) *SingBox {
	return &SingBox{Cfg: cfg}
}

func (s *SingBox) Generate() (map[string]any, error) {
	cfg := s.Cfg
	out := map[string]any{
		"log": map[string]any{
			"level":     cfg.Log.Level,
			"timestamp": true,
		},
	}

	// DNS
	out["dns"] = s.buildDNS()

	// Inbounds
	out["inbounds"] = s.buildInbounds()

	// Outbounds
	outbounds, err := s.buildOutbounds()
	if err != nil {
		return nil, err
	}
	out["outbounds"] = outbounds

	// Route
	out["route"] = s.buildRoute()

	// Experimental cache (useful for geosite)
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
		map[string]any{
			"tag":             "default-dns",
			"address":         "local",
			"detour":          "direct-out",
			"address_strategy": cfg.DNS.Strategy,
		},
	}

	mainDNS := map[string]any{
		"tag":     "main-dns",
		"address": ensureDNSAddr(cfg.DNS.Server),
		"detour":  "main-out",
		"strategy": cfg.DNS.Strategy,
	}
	servers = append(servers, mainDNS)

	rules := []any{}
	final := "main-dns"

	switch cfg.Mode {
	case config.ModeBypassMainlandChina:
		servers = append(servers, map[string]any{
			"tag":     "china-dns",
			"address": ensureDNSAddr(cfg.DNS.ChinaServer),
			"detour":  "direct-out",
			"strategy": "prefer_ipv6",
		})
		rules = append(rules,
			map[string]any{
				"rule_set": "geosite-cn",
				"server":   "china-dns",
			},
			map[string]any{
				"type": "logical",
				"mode": "and",
				"rules": []any{
					map[string]any{"rule_set": "geosite-noncn", "invert": true},
					map[string]any{"rule_set": "geoip-cn"},
				},
				"server": "china-dns",
			},
		)
		final = "main-dns"
	case config.ModeGlobal, config.ModeGFWList, config.ModeProxyMainlandChina:
		final = "main-dns"
	default:
		final = "main-dns"
	}

	dns := map[string]any{
		"servers": servers,
		"rules":   rules,
		"final":   final,
		"strategy": cfg.DNS.Strategy,
	}
	if cfg.DNS.FakeIP {
		dns["fakeip"] = map[string]any{
			"enabled":     true,
			"inet4_range": cfg.DNS.FakeIPRange4,
			"inet6_range": cfg.DNS.FakeIPRange6,
		}
	}
	return dns
}

func (s *SingBox) buildInbounds() []any {
	cfg := s.Cfg
	inbounds := []any{
		map[string]any{
			"type":        "direct",
			"tag":         "dns-in",
			"listen":      "::",
			"listen_port": cfg.DNS.ListenPort,
		},
		map[string]any{
			"type":                      "mixed",
			"tag":                       "mixed-in",
			"listen":                    "::",
			"listen_port":               cfg.Proxy.MixedPort,
			"sniff":                     true,
			"sniff_override_destination": true,
			"set_system_proxy":          false,
		},
	}

	switch cfg.Proxy.Mode {
	case config.ProxyTProxy:
		inbounds = append(inbounds, map[string]any{
			"type":                      "tproxy",
			"tag":                       "tproxy-in",
			"listen":                    "::",
			"listen_port":               cfg.Proxy.TProxyPort,
			"network":                   "tcp,udp",
			"sniff":                     true,
			"sniff_override_destination": true,
		})
	case config.ProxyRedirect:
		inbounds = append(inbounds, map[string]any{
			"type":                      "redirect",
			"tag":                       "redirect-in",
			"listen":                    "::",
			"listen_port":               cfg.Proxy.RedirectPort,
			"sniff":                     true,
			"sniff_override_destination": true,
		})
	case config.ProxyTUN:
		addrs := []string{cfg.Proxy.TUNAddr4}
		if cfg.Proxy.IPv6 {
			addrs = append(addrs, cfg.Proxy.TUNAddr6)
		}
		inbounds = append(inbounds, map[string]any{
			"type":                      "tun",
			"tag":                       "tun-in",
			"interface_name":            cfg.Proxy.TUNName,
			"address":                   addrs,
			"mtu":                       cfg.Proxy.TUNMTU,
			"auto_route":                false,
			"stack":                     "system",
			"sniff":                     true,
			"sniff_override_destination": true,
		})
	}
	return inbounds
}

func (s *SingBox) buildOutbounds() ([]any, error) {
	cfg := s.Cfg
	outbounds := []any{
		map[string]any{
			"type":         "direct",
			"tag":          "direct-out",
			"routing_mark": atoiSafe(cfg.Proxy.SelfMark),
		},
		map[string]any{
			"type": "block",
			"tag":  "block-out",
		},
	}

	// User nodes
	for _, n := range cfg.Nodes {
		ob, err := nodeToOutbound(&n, cfg.Proxy.SelfMark)
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", n.Name, err)
		}
		outbounds = append(outbounds, ob)
	}

	// main-out selector / urltest
	mainTag := "main-out"
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
			"type":      "urltest",
			"tag":       mainTag,
			"outbounds": tags,
			"interval":  fmt.Sprintf("%ds", cfg.Proxy.URLTestInterval),
			"tolerance": cfg.Proxy.URLTestTolerance,
		})
	} else if cfg.Proxy.MainNode != "" {
		// selector wrapping single node, or direct reference via selector for flexibility
		outbounds = append(outbounds, map[string]any{
			"type":      "selector",
			"tag":       mainTag,
			"outbounds": []string{nodeTag(cfg.Proxy.MainNode)},
			"default":   nodeTag(cfg.Proxy.MainNode),
		})
	} else if len(cfg.Nodes) > 0 {
		outbounds = append(outbounds, map[string]any{
			"type":      "selector",
			"tag":       mainTag,
			"outbounds": []string{nodeTag(cfg.Nodes[0].Name)},
			"default":   nodeTag(cfg.Nodes[0].Name),
		})
	} else {
		// placeholder so config is valid; user must add nodes
		outbounds = append(outbounds, map[string]any{
			"type": "direct",
			"tag":  mainTag,
		})
	}

	return outbounds, nil
}

func (s *SingBox) buildRoute() map[string]any {
	cfg := s.Cfg
	rules := []any{
		map[string]any{
			"inbound": "dns-in",
			"action":  "hijack-dns",
		},
	}

	ruleSets := []any{}

	// Always useful remote rule-sets for China-aware modes
	if cfg.Mode == config.ModeBypassMainlandChina || cfg.Mode == config.ModeProxyMainlandChina || cfg.Mode == config.ModeGFWList {
		ruleSets = append(ruleSets,
			map[string]any{
				"type":            "remote",
				"tag":             "geoip-cn",
				"format":          "binary",
				"url":             "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
				"download_detour": "main-out",
			},
			map[string]any{
				"type":            "remote",
				"tag":             "geosite-cn",
				"format":          "binary",
				"url":             "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-cn.srs",
				"download_detour": "main-out",
			},
			map[string]any{
				"type":            "remote",
				"tag":             "geosite-noncn",
				"format":          "binary",
				"url":             "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs",
				"download_detour": "main-out",
			},
		)
	}

	// User domain black/white lists (highest priority after DNS hijack)
	if len(cfg.Control.DirectDomains) > 0 {
		rules = append(rules, map[string]any{
			"domain":   cfg.Control.DirectDomains,
			"outbound": "direct-out",
		})
	}
	if len(cfg.Control.ProxyDomains) > 0 {
		rules = append(rules, map[string]any{
			"domain":   cfg.Control.ProxyDomains,
			"outbound": "main-out",
		})
	}

	final := "main-out"

	switch cfg.Mode {
	case config.ModeBypassMainlandChina:
		// Domain/IP China → direct inside sing-box (firewall also bypasses CN CIDRs)
		rules = append(rules,
			map[string]any{"rule_set": "geosite-cn", "outbound": "direct-out"},
			map[string]any{"rule_set": "geoip-cn", "outbound": "direct-out"},
		)
		final = "main-out"
	case config.ModeProxyMainlandChina:
		rules = append(rules,
			map[string]any{"rule_set": "geosite-cn", "outbound": "main-out"},
			map[string]any{"rule_set": "geoip-cn", "outbound": "main-out"},
		)
		final = "direct-out"
	case config.ModeGFWList:
		// Without dedicated DNS nftset, approximate with non-CN geosite → proxy
		rules = append(rules,
			map[string]any{"rule_set": "geosite-noncn", "outbound": "main-out"},
			map[string]any{"rule_set": "geosite-cn", "outbound": "direct-out"},
			map[string]any{"rule_set": "geoip-cn", "outbound": "direct-out"},
		)
		final = "direct-out"
	case config.ModeGlobal:
		final = "main-out"
	case config.ModeCustom:
		final = "main-out"
		// custom rules can be extended later from YAML
	}

	// private IPs always direct
	rules = append(rules, map[string]any{
		"ip_is_private": true,
		"outbound":      "direct-out",
	})

	route := map[string]any{
		"rules":                rules,
		"rule_set":             ruleSets,
		"final":                final,
		"auto_detect_interface": true,
		"default_domain_resolver": map[string]any{
			"server":   "default-dns",
			"strategy": cfg.DNS.Strategy,
		},
	}
	if len(ruleSets) == 0 {
		delete(route, "rule_set")
	}
	return route
}

func nodeTag(name string) string {
	return "node-" + sanitizeTag(name)
}

func sanitizeTag(s string) string {
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
	return s
}

func nodeToOutbound(n *config.Node, selfMark string) (map[string]any, error) {
	tag := nodeTag(n.Name)
	ob := map[string]any{
		"tag":          tag,
		"type":         n.Type,
		"server":       n.Server,
		"server_port":  n.Port,
		"routing_mark": atoiSafe(selfMark),
	}

	switch strings.ToLower(n.Type) {
	case "shadowsocks":
		ob["method"] = n.Method
		ob["password"] = n.Password
	case "vmess", "vless":
		ob["uuid"] = n.UUID
		if n.Network != "" {
			ob["network"] = n.Network
		}
	case "trojan":
		ob["password"] = n.Password
	case "hysteria2":
		ob["password"] = n.Password
	case "tuic":
		ob["uuid"] = n.UUID
		ob["password"] = n.Password
	default:
		// allow unknown types via Extra
	}

	if n.TLS != nil && n.TLS.Enabled {
		tls := map[string]any{
			"enabled": true,
		}
		if n.TLS.ServerName != "" {
			tls["server_name"] = n.TLS.ServerName
		}
		if n.TLS.Insecure {
			tls["insecure"] = true
		}
		if len(n.TLS.ALPN) > 0 {
			tls["alpn"] = n.TLS.ALPN
		}
		if n.TLS.UTLS != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": n.TLS.UTLS}
		}
		ob["tls"] = tls
	}

	if n.Transport != nil {
		for k, v := range n.Transport {
			ob[k] = v
		}
	}
	if n.Extra != nil {
		for k, v := range n.Extra {
			ob[k] = v
		}
	}
	return ob, nil
}

func ensureDNSAddr(s string) string {
	if strings.Contains(s, "://") {
		return s
	}
	// plain IP or host → udp
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
