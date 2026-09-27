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

	exp := map[string]any{
		"cache_file": map[string]any{
			"enabled": true,
			"path":    filepath.Join(cfg.Paths.RunDir, "cache.db"),
		},
	}
	if cfg.Clash.Enabled {
		clash := map[string]any{
			"external_controller": cfg.Clash.Listen,
		}
		if cfg.Clash.Secret != "" {
			clash["secret"] = cfg.Clash.Secret
		}
		if cfg.Clash.StoreSel {
			clash["store_selected"] = true
		}
		exp["clash_api"] = clash
	}
	out["experimental"] = exp

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
		"tag":      "main-dns",
		"address":  ensureDNSAddr(cfg.DNS.Server),
		"detour":   "main-out",
		"strategy": cfg.DNS.Strategy,
	}
	servers = append(servers, mainDNS)

	for _, es := range cfg.DNS.ExtraServers {
		if es.Tag == "" || es.Address == "" {
			continue
		}
		detour := es.Detour
		if detour == "" {
			detour = "direct-out"
		}
		servers = append(servers, map[string]any{
			"tag":     es.Tag,
			"address": ensureDNSAddr(es.Address),
			"detour":  detour,
		})
	}

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

	// User DNS rules
	for _, dr := range cfg.DNS.Rules {
		if !dr.Enabled || dr.Server == "" {
			continue
		}
		r := map[string]any{"server": dr.Server}
		if len(dr.Domain) > 0 {
			r["domain"] = dr.Domain
		}
		if len(dr.DomainSuffix) > 0 {
			r["domain_suffix"] = dr.DomainSuffix
		}
		if len(dr.DomainKeyword) > 0 {
			r["domain_keyword"] = dr.DomainKeyword
		}
		if dr.RuleSet != "" {
			r["rule_set"] = dr.RuleSet
		}
		rules = append(rules, r)
	}

	dns := map[string]any{
		"servers":  servers,
		"rules":    rules,
		"final":    final,
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

	// Server-side inbounds (homeproxy server)
	for _, srv := range cfg.Servers {
		if !srv.Enabled || srv.Port <= 0 {
			continue
		}
		listen := srv.Listen
		if listen == "" {
			listen = "::"
		}
		tag := "server-" + sanitizeTag(srv.Name)
		if srv.Name == "" {
			tag = fmt.Sprintf("server-%s-%d", srv.Type, srv.Port)
		}
		ib := map[string]any{
			"type":        srv.Type,
			"tag":         tag,
			"listen":      listen,
			"listen_port": srv.Port,
		}
		switch srv.Type {
		case "shadowsocks":
			ib["method"] = srv.Method
			if srv.Method == "" {
				ib["method"] = "aes-128-gcm"
			}
			ib["password"] = srv.Password
		case "mixed", "socks", "http":
			if len(srv.Users) > 0 {
				users := []any{}
				for _, u := range srv.Users {
					users = append(users, map[string]any{
						"username": u.Name,
						"password": u.Password,
					})
				}
				ib["users"] = users
			}
		case "vmess", "vless", "trojan":
			users := []any{}
			for _, u := range srv.Users {
				um := map[string]any{}
				if u.UUID != "" {
					um["uuid"] = u.UUID
				}
				if u.Name != "" {
					um["name"] = u.Name
				}
				if u.Password != "" {
					um["password"] = u.Password
				}
				users = append(users, um)
			}
			if len(users) > 0 {
				ib["users"] = users
			}
			if srv.Password != "" && srv.Type == "trojan" {
				ib["users"] = []any{map[string]any{"name": "user", "password": srv.Password}}
			}
		}
		if srv.TLS != nil && srv.TLS.Enabled {
			tls := map[string]any{"enabled": true}
			if srv.TLS.ServerName != "" {
				tls["server_name"] = srv.TLS.ServerName
			}
			if srv.TLS.CertificatePath != "" {
				tls["certificate_path"] = srv.TLS.CertificatePath
			}
			if srv.TLS.KeyPath != "" {
				tls["key_path"] = srv.TLS.KeyPath
			}
			ib["tls"] = tls
		}
		if srv.Extra != nil {
			for k, v := range srv.Extra {
				ib[k] = v
			}
		}
		inbounds = append(inbounds, ib)
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
	outbounds = append(outbounds, s.buildGroupOutbound(mainTag, cfg.Proxy.MainNode, cfg.Proxy.URLTestNodes)...)

	// main-udp-out (homeproxy main_udp_node)
	udpNode := cfg.Proxy.MainUDP
	if udpNode == "" || udpNode == "same" {
		outbounds = append(outbounds, map[string]any{
			"type":      "selector",
			"tag":       "main-udp-out",
			"outbounds": []string{mainTag},
			"default":   mainTag,
		})
	} else {
		outbounds = append(outbounds, s.buildGroupOutbound("main-udp-out", udpNode, cfg.Proxy.URLTestUDPNodes)...)
	}

	return outbounds, nil
}

// buildGroupOutbound returns urltest or selector outbound for tag.
func (s *SingBox) buildGroupOutbound(tag, mainNode string, urltestNodes []string) []any {
	cfg := s.Cfg
	if mainNode == "urltest" {
		tags := []string{}
		for _, name := range urltestNodes {
			tags = append(tags, nodeTag(name))
		}
		if len(tags) == 0 {
			for _, n := range cfg.Nodes {
				tags = append(tags, nodeTag(n.Name))
			}
		}
		if len(tags) == 0 {
			return []any{map[string]any{"type": "direct", "tag": tag}}
		}
		return []any{map[string]any{
			"type":      "urltest",
			"tag":       tag,
			"outbounds": tags,
			"interval":  fmt.Sprintf("%ds", cfg.Proxy.URLTestInterval),
			"tolerance": cfg.Proxy.URLTestTolerance,
		}}
	}
	if mainNode != "" {
		return []any{map[string]any{
			"type":      "selector",
			"tag":       tag,
			"outbounds": []string{nodeTag(mainNode)},
			"default":   nodeTag(mainNode),
		}}
	}
	if len(cfg.Nodes) > 0 {
		t := nodeTag(cfg.Nodes[0].Name)
		return []any{map[string]any{
			"type":      "selector",
			"tag":       tag,
			"outbounds": []string{t},
			"default":   t,
		}}
	}
	return []any{map[string]any{"type": "direct", "tag": tag}}
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

	// User domain black/white lists
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

	// Custom route rules (always applied when enabled)
	for _, rr := range cfg.Rules {
		if !rr.Enabled {
			continue
		}
		r := map[string]any{}
		ob := rr.Outbound
		if ob == "" {
			ob = "main-out"
		}
		r["outbound"] = ob
		if len(rr.Domain) > 0 {
			r["domain"] = rr.Domain
		}
		if len(rr.DomainSuffix) > 0 {
			r["domain_suffix"] = rr.DomainSuffix
		}
		if len(rr.DomainKeyword) > 0 {
			r["domain_keyword"] = rr.DomainKeyword
		}
		if len(rr.IPCIDR) > 0 {
			r["ip_cidr"] = rr.IPCIDR
		}
		if len(rr.SourceIPCIDR) > 0 {
			r["source_ip_cidr"] = rr.SourceIPCIDR
		}
		if len(rr.Port) > 0 {
			r["port"] = rr.Port
		}
		if rr.Network != "" {
			r["network"] = rr.Network
		}
		if len(rr.Protocol) > 0 {
			r["protocol"] = rr.Protocol
		}
		rules = append(rules, r)
	}

	// UDP → main-udp-out when dedicated UDP node configured
	if cfg.Proxy.MainUDP != "" && cfg.Proxy.MainUDP != "same" {
		rules = append(rules, map[string]any{
			"network":  "udp",
			"outbound": "main-udp-out",
		})
	}

	final := "main-out"

	switch cfg.Mode {
	case config.ModeBypassMainlandChina:
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
		// Prefer local gfw domain list if present (from update-resources)
		gfwPath := filepath.Join(cfg.Paths.DataDir, "resources", "gfw_list.txt")
		if domains := loadDomainFile(gfwPath, 5000); len(domains) > 0 {
			rules = append(rules, map[string]any{
				"domain":   domains,
				"outbound": "main-out",
			})
		}
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
	case "vmess":
		ob["uuid"] = n.UUID
		if n.AlterID > 0 {
			ob["alter_id"] = n.AlterID
		}
		if n.Network != "" {
			ob["network"] = n.Network
		}
	case "vless":
		ob["uuid"] = n.UUID
		if n.Flow != "" {
			ob["flow"] = n.Flow
		}
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
	case "wireguard":
		// fields via Extra: private_key, peer_public_key, local_address, ...
	default:
	}

	// Structured transport → sing-box transport object
	if n.TransportType != "" {
		tr := map[string]any{"type": n.TransportType}
		switch n.TransportType {
		case "ws":
			if n.WSPath != "" {
				tr["path"] = n.WSPath
			}
			if n.WSHost != "" {
				tr["headers"] = map[string]any{"Host": n.WSHost}
			}
		case "grpc":
			if n.GRPCService != "" {
				tr["service_name"] = n.GRPCService
			}
		case "http", "httpupgrade":
			if n.HTTPPath != "" {
				tr["path"] = n.HTTPPath
			}
			if n.HTTPHost != "" {
				tr["host"] = []string{n.HTTPHost}
			}
		}
		ob["transport"] = tr
	}

	if n.TLS != nil && n.TLS.Enabled {
		tls := map[string]any{"enabled": true}
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
		if n.TLS.CertificatePath != "" {
			tls["certificate_path"] = n.TLS.CertificatePath
		}
		if n.TLS.RealityEnabled {
			tls["reality"] = map[string]any{
				"enabled":    true,
				"public_key": n.TLS.RealityPublicKey,
				"short_id":   n.TLS.RealityShortID,
			}
		}
		ob["tls"] = tls
	}

	if n.Transport != nil {
		// merge raw transport map (overrides structured if both set keys)
		if existing, ok := ob["transport"].(map[string]any); ok {
			for k, v := range n.Transport {
				existing[k] = v
			}
			ob["transport"] = existing
		} else {
			ob["transport"] = n.Transport
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
	return "udp://" + s
}

// loadDomainFile reads domain lines (maxN) for GFW-style lists.
func loadDomainFile(path string, maxN int) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
		if maxN > 0 && len(out) >= maxN {
			break
		}
	}
	return out
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
