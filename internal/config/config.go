package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Routing modes aligned with OpenWrt homeproxy.
const (
	ModeGFWList             = "gfwlist"
	ModeBypassMainlandChina = "bypass_mainland_china"
	ModeProxyMainlandChina  = "proxy_mainland_china"
	ModeGlobal              = "global"
	ModeCustom              = "custom"
)

// Proxy modes for transparent interception.
const (
	ProxyTProxy   = "tproxy"
	ProxyRedirect = "redirect"
	ProxyTUN      = "tun"
)

// Config is the top-level YAML configuration.
type Config struct {
	Mode    string         `yaml:"mode"`
	Proxy   ProxyConfig    `yaml:"proxy"`
	DNS     DNSConfig      `yaml:"dns"`
	Nodes   []Node         `yaml:"nodes"`
	Subs    []Subscription `yaml:"subscriptions"`
	Rules   []RouteRule    `yaml:"rules"`
	Servers []ServerInbound `yaml:"servers"` // sing-box server inbounds
	Control ControlConfig  `yaml:"control"`
	DNSMasq DNSMasqConfig  `yaml:"dnsmasq"`
	Clash   ClashConfig    `yaml:"clash"`
	Paths   PathsConfig    `yaml:"paths"`
	Log     LogConfig      `yaml:"log"`
}

// ServerInbound is a local proxy server (homeproxy server side).
type ServerInbound struct {
	Name     string `yaml:"name"`
	Enabled  bool   `yaml:"enabled"`
	Type     string `yaml:"type"` // mixed | socks | http | shadowsocks | vmess | trojan | hysteria2
	Listen   string `yaml:"listen"` // default ::
	Port     int    `yaml:"port"`
	Users    []ServerUser `yaml:"users,omitempty"`
	// shadowsocks
	Method   string `yaml:"method,omitempty"`
	Password string `yaml:"password,omitempty"`
	// TLS optional (certificate_path / key_path on TLS)
	TLS   *TLSConfig     `yaml:"tls,omitempty"`
	Extra map[string]any `yaml:"extra,omitempty"`
}

type ServerUser struct {
	Name     string `yaml:"name,omitempty"`
	Password string `yaml:"password,omitempty"`
	UUID     string `yaml:"uuid,omitempty"`
}

// DNSMasqConfig integrates system dnsmasq with nftset for GFW domains.
type DNSMasqConfig struct {
	Enabled    bool   `yaml:"enabled"`
	// ConfDir fragment path, e.g. /etc/dnsmasq.d/homeproxy-gfw.conf
	ConfPath   string `yaml:"conf_path"`
	// nft table/set names (must match nftables generator)
	Table      string `yaml:"table"` // default inet homeproxy
	SetV4      string `yaml:"set_v4"` // gfw_v4
	SetV6      string `yaml:"set_v6"`
	// Max domains written to conf (gfw list can be large)
	MaxDomains int    `yaml:"max_domains"`
	// Reload command after write (empty = skip), e.g. "systemctl reload dnsmasq"
	ReloadCmd  string `yaml:"reload_cmd"`
}

type ClashConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Listen   string `yaml:"listen"` // 127.0.0.1:9090
	Secret   string `yaml:"secret"`
	StoreSel bool   `yaml:"store_selected"`
}

// RouteRule maps to a sing-box route rule (custom / always-on).
type RouteRule struct {
	Name          string   `yaml:"name,omitempty"`
	Enabled       bool     `yaml:"enabled"`
	Outbound      string   `yaml:"outbound"` // main-out | direct-out | block-out | main-udp-out
	Domain        []string `yaml:"domain,omitempty"`
	DomainSuffix  []string `yaml:"domain_suffix,omitempty"`
	DomainKeyword []string `yaml:"domain_keyword,omitempty"`
	IPCIDR        []string `yaml:"ip_cidr,omitempty"`
	SourceIPCIDR  []string `yaml:"source_ip_cidr,omitempty"`
	Port          []int    `yaml:"port,omitempty"`
	Network       string   `yaml:"network,omitempty"` // tcp | udp
	Protocol      []string `yaml:"protocol,omitempty"`
}

type ProxyConfig struct {
	Mode     string `yaml:"mode"`          // tproxy | redirect | tun
	MainNode string `yaml:"main_node"`     // node name or "urltest"
	MainUDP  string `yaml:"main_udp_node"` // node name | urltest | same | empty=same
	// URLTest
	URLTestNodes     []string `yaml:"urltest_nodes"`
	URLTestUDPNodes  []string `yaml:"urltest_udp_nodes"`
	URLTestInterval  int      `yaml:"urltest_interval"`  // seconds
	URLTestTolerance int      `yaml:"urltest_tolerance"` // ms
	// Ports / marks
	MixedPort    int    `yaml:"mixed_port"`
	TProxyPort   int    `yaml:"tproxy_port"`
	RedirectPort int    `yaml:"redirect_port"`
	TProxyMark   string `yaml:"tproxy_mark"`
	SelfMark     string `yaml:"self_mark"`
	// TUN
	TUNName  string `yaml:"tun_name"`
	TUNAddr4 string `yaml:"tun_addr4"`
	TUNAddr6 string `yaml:"tun_addr6"`
	TUNMTU   int    `yaml:"tun_mtu"`
	IPv6     bool   `yaml:"ipv6"`
}

type DNSConfig struct {
	ListenPort   int    `yaml:"listen_port"`
	Server       string `yaml:"server"`       // remote / proxy DNS (udp:// tcp:// https:// tls:// quic://)
	ChinaServer  string `yaml:"china_server"`
	Strategy     string `yaml:"strategy"`
	FakeIP       bool   `yaml:"fakeip"`
	FakeIPRange4 string `yaml:"fakeip_range4"`
	FakeIPRange6 string `yaml:"fakeip_range6"`
	ExtraServers []DNSServer `yaml:"extra_servers,omitempty"`
	Rules        []DNSRule   `yaml:"rules,omitempty"`
}

type DNSServer struct {
	Tag      string `yaml:"tag"`
	Address  string `yaml:"address"` // supports DoH/DoT/DoQ URLs
	Detour   string `yaml:"detour"`  // main-out | direct-out
	Strategy string `yaml:"strategy,omitempty"`
}

// DNSRule selects which DNS server handles a query.
type DNSRule struct {
	Name          string   `yaml:"name,omitempty"`
	Enabled       bool     `yaml:"enabled"`
	Server        string   `yaml:"server"` // tag of DNS server
	Domain        []string `yaml:"domain,omitempty"`
	DomainSuffix  []string `yaml:"domain_suffix,omitempty"`
	DomainKeyword []string `yaml:"domain_keyword,omitempty"`
	RuleSet       string   `yaml:"rule_set,omitempty"` // e.g. geosite-cn
}

type Node struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"` // shadowsocks, vmess, vless, trojan, hysteria2, tuic, wireguard, ...
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	UUID     string `yaml:"uuid,omitempty"`
	Password string `yaml:"password,omitempty"`
	Method   string `yaml:"method,omitempty"` // ss
	Network  string `yaml:"network,omitempty"` // tcp/udp for some protocols
	Flow     string `yaml:"flow,omitempty"`    // xtls-rprx-vision
	AlterID  int    `yaml:"alter_id,omitempty"`
	// Transport (structured; also merged into Transport map if set)
	TransportType string `yaml:"transport_type,omitempty"` // ws | grpc | http | httpupgrade | ""
	WSPath        string `yaml:"ws_path,omitempty"`
	WSHost        string `yaml:"ws_host,omitempty"`
	GRPCService   string `yaml:"grpc_service,omitempty"`
	HTTPPath      string `yaml:"http_path,omitempty"`
	HTTPHost      string `yaml:"http_host,omitempty"`
	TLS           *TLSConfig      `yaml:"tls,omitempty"`
	Transport     map[string]any  `yaml:"transport,omitempty"`
	Extra         map[string]any  `yaml:"extra,omitempty"`
}

type TLSConfig struct {
	Enabled    bool     `yaml:"enabled"`
	ServerName string   `yaml:"server_name"`
	Insecure   bool     `yaml:"insecure"`
	ALPN       []string `yaml:"alpn,omitempty"`
	UTLS       string   `yaml:"utls,omitempty"` // chrome, firefox, safari, ios, android, edge, 360, qq, random
	// Reality
	RealityEnabled   bool   `yaml:"reality_enabled,omitempty"`
	RealityPublicKey string `yaml:"reality_public_key,omitempty"`
	RealityShortID   string `yaml:"reality_short_id,omitempty"`
	// Certificate files (server side / client verify)
	CertificatePath string `yaml:"certificate_path,omitempty"`
	KeyPath         string `yaml:"key_path,omitempty"`
}

type Subscription struct {
	Name           string `yaml:"name"`
	URL            string `yaml:"url"`
	UpdateInterval string `yaml:"update_interval"` // e.g. 6h
	Enabled        bool   `yaml:"enabled"`
}

// LAN proxy filter modes (aligned with homeproxy).
const (
	LANProxyAll          = "all"           // all LAN clients follow routing mode
	LANProxyExceptListed = "except_listed" // listed = direct, rest = proxy
	LANProxyListedOnly   = "listed_only"   // listed = proxy, rest = direct
)

type ControlConfig struct {
	// Interfaces that receive transparent proxy (LAN side)
	LANInterfaces []string `yaml:"lan_interfaces"`
	// all | except_listed | listed_only
	LANProxyMode string `yaml:"lan_proxy_mode"`
	// LAN ACL
	LANProxyIPv4  []string `yaml:"lan_proxy_ipv4"`
	LANProxyIPv6  []string `yaml:"lan_proxy_ipv6"`
	LANProxyMAC   []string `yaml:"lan_proxy_mac"`
	LANDirectIPv4 []string `yaml:"lan_direct_ipv4"`
	LANDirectIPv6 []string `yaml:"lan_direct_ipv6"`
	LANDirectMAC  []string `yaml:"lan_direct_mac"`
	// Domain lists (applied in sing-box route)
	ProxyDomains  []string `yaml:"proxy_domains"`  // force proxy
	DirectDomains []string `yaml:"direct_domains"` // force direct
	// Gaming mode: these sources always direct (skip transparent proxy) — homeproxy aligned
	LANGamingIPv4 []string `yaml:"lan_gaming_ipv4"`
	LANGamingIPv6 []string `yaml:"lan_gaming_ipv6"`
	LANGamingMAC  []string `yaml:"lan_gaming_mac"`
	// Global proxy devices: always take main-out regardless of mode (via nft force to tproxy + optional)
	LANGlobalProxyIPv4 []string `yaml:"lan_global_proxy_ipv4"`
	LANGlobalProxyIPv6 []string `yaml:"lan_global_proxy_ipv6"`
	LANGlobalProxyMAC  []string `yaml:"lan_global_proxy_mac"`
	// WAN-side destination ACL
	WANDirectIPv4 []string `yaml:"wan_direct_ipv4"`
	WANDirectIPv6 []string `yaml:"wan_direct_ipv6"`
	WANProxyIPv4  []string `yaml:"wan_proxy_ipv4"`
	WANProxyIPv6  []string `yaml:"wan_proxy_ipv6"`
	// Optional port filter (empty = all ports)
	RoutingPorts string `yaml:"routing_ports"`
	// Bypass CN traffic even in custom mode
	BypassCNTraffic bool `yaml:"bypass_cn_traffic"`
}

type PathsConfig struct {
	DataDir       string `yaml:"data_dir"`        // /var/lib/homeproxy
	RunDir        string `yaml:"run_dir"`         // /var/run/homeproxy
	SingBoxBin    string `yaml:"singbox_bin"`     // sing-box
	ChinaIP4URL   string `yaml:"china_ip4_url"`
	ChinaIP6URL   string `yaml:"china_ip6_url"`
	GFWListURL    string `yaml:"gfw_list_url"`
}

type LogConfig struct {
	Level string `yaml:"level"` // trace debug info warn error
}

// Defaults fills empty fields with sensible values.
func (c *Config) Defaults() {
	if c.Mode == "" {
		c.Mode = ModeBypassMainlandChina
	}
	if c.Proxy.Mode == "" {
		c.Proxy.Mode = ProxyTProxy
	}
	if c.Control.LANProxyMode == "" {
		c.Control.LANProxyMode = LANProxyAll
	}
	if c.Proxy.MixedPort == 0 {
		c.Proxy.MixedPort = 5330
	}
	if c.Proxy.TProxyPort == 0 {
		c.Proxy.TProxyPort = 5332
	}
	if c.Proxy.RedirectPort == 0 {
		c.Proxy.RedirectPort = 5331
	}
	if c.Proxy.TProxyMark == "" {
		c.Proxy.TProxyMark = "0x65" // 101
	}
	if c.Proxy.SelfMark == "" {
		c.Proxy.SelfMark = "100"
	}
	if c.Proxy.TUNName == "" {
		c.Proxy.TUNName = "singtun0"
	}
	if c.Proxy.TUNAddr4 == "" {
		c.Proxy.TUNAddr4 = "172.19.0.1/30"
	}
	if c.Proxy.TUNAddr6 == "" {
		c.Proxy.TUNAddr6 = "fdfe:dcba:9876::1/126"
	}
	if c.Proxy.TUNMTU == 0 {
		c.Proxy.TUNMTU = 9000
	}
	if c.Proxy.URLTestInterval == 0 {
		c.Proxy.URLTestInterval = 180
	}
	if c.Proxy.URLTestTolerance == 0 {
		c.Proxy.URLTestTolerance = 50
	}
	if c.DNS.ListenPort == 0 {
		c.DNS.ListenPort = 5333
	}
	if c.DNS.Server == "" {
		c.DNS.Server = "8.8.8.8"
	}
	if c.DNS.ChinaServer == "" {
		c.DNS.ChinaServer = "223.5.5.5"
	}
	if c.DNS.Strategy == "" {
		c.DNS.Strategy = "prefer_ipv4"
	}
	if c.DNS.FakeIPRange4 == "" {
		c.DNS.FakeIPRange4 = "198.18.0.0/15"
	}
	if c.DNS.FakeIPRange6 == "" {
		c.DNS.FakeIPRange6 = "fc00::/18"
	}
	if c.Paths.DataDir == "" {
		c.Paths.DataDir = "/var/lib/homeproxy"
	}
	if c.Paths.RunDir == "" {
		c.Paths.RunDir = "/var/run/homeproxy"
	}
	if c.Paths.SingBoxBin == "" {
		c.Paths.SingBoxBin = "sing-box"
	}
	if c.Paths.ChinaIP4URL == "" {
		c.Paths.ChinaIP4URL = "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"
	}
	if c.Paths.ChinaIP6URL == "" {
		// fallback empty-ish; optional
		c.Paths.ChinaIP6URL = "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt"
	}
	if c.Paths.GFWListURL == "" {
		c.Paths.GFWListURL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
	}
	if c.Log.Level == "" {
		c.Log.Level = "warn"
	}
	if c.DNSMasq.Table == "" {
		c.DNSMasq.Table = "homeproxy"
	}
	if c.DNSMasq.SetV4 == "" {
		c.DNSMasq.SetV4 = "gfw_v4"
	}
	if c.DNSMasq.SetV6 == "" {
		c.DNSMasq.SetV6 = "gfw_v6"
	}
	if c.DNSMasq.ConfPath == "" {
		c.DNSMasq.ConfPath = "/etc/dnsmasq.d/homeproxy-gfw.conf"
	}
	if c.DNSMasq.MaxDomains == 0 {
		c.DNSMasq.MaxDomains = 8000
	}
	if c.Clash.Listen == "" {
		c.Clash.Listen = "127.0.0.1:9090"
	}
}


func (c *Config) Validate() error {
	switch c.Mode {
	case ModeGFWList, ModeBypassMainlandChina, ModeProxyMainlandChina, ModeGlobal, ModeCustom:
	default:
		return fmt.Errorf("invalid mode: %s", c.Mode)
	}
	switch c.Proxy.Mode {
	case ProxyTProxy, ProxyRedirect, ProxyTUN:
	default:
		return fmt.Errorf("invalid proxy.mode: %s", c.Proxy.Mode)
	}
	if c.Proxy.MainNode == "" && len(c.Nodes) == 0 && len(c.Subs) == 0 {
		return fmt.Errorf("proxy.main_node or nodes/subscriptions required")
	}
	names := map[string]struct{}{}
	for _, n := range c.Nodes {
		if n.Name == "" {
			return fmt.Errorf("node name is required")
		}
		if _, ok := names[n.Name]; ok {
			return fmt.Errorf("duplicate node name: %s", n.Name)
		}
		names[n.Name] = struct{}{}
	}
	if c.Proxy.MainNode != "" && c.Proxy.MainNode != "urltest" {
		if _, ok := names[c.Proxy.MainNode]; !ok && len(c.Subs) == 0 {
			// allow missing if subscriptions will populate
			if len(c.Nodes) > 0 {
				return fmt.Errorf("main_node %q not found in nodes", c.Proxy.MainNode)
			}
		}
	}
	return nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) FindNode(name string) *Node {
	for i := range c.Nodes {
		if c.Nodes[i].Name == name {
			return &c.Nodes[i]
		}
	}
	return nil
}

func (c *Config) ModeNeedsChinaIP() bool {
	return c.Mode == ModeBypassMainlandChina ||
		c.Mode == ModeProxyMainlandChina ||
		c.Control.BypassCNTraffic
}

func (c *Config) ModeNeedsGFWList() bool {
	return c.Mode == ModeGFWList
}

// NormalizeMark accepts "101" or "0x65" and returns hex form for nft.
func NormalizeMark(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strings.ToLower(s)
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
		return fmt.Sprintf("0x%x", n)
	}
	return s
}

// Save writes the config as YAML to path.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
