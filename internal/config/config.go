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
	Mode    string          `yaml:"mode"`
	Proxy   ProxyConfig     `yaml:"proxy"`
	DNS     DNSConfig       `yaml:"dns"`
	Nodes   []Node          `yaml:"nodes"`
	Subs    []Subscription  `yaml:"subscriptions"`
	Control ControlConfig   `yaml:"control"`
	Paths   PathsConfig     `yaml:"paths"`
	Log     LogConfig       `yaml:"log"`
}

type ProxyConfig struct {
	Mode     string `yaml:"mode"`
	MainNode string `yaml:"main_node"`
	MainUDP  string `yaml:"main_udp_node"`
	URLTestNodes     []string `yaml:"urltest_nodes"`
	URLTestInterval  int      `yaml:"urltest_interval"`
	URLTestTolerance int      `yaml:"urltest_tolerance"`
	MixedPort    int    `yaml:"mixed_port"`
	TProxyPort   int    `yaml:"tproxy_port"`
	RedirectPort int    `yaml:"redirect_port"`
	TProxyMark   string `yaml:"tproxy_mark"`
	SelfMark     string `yaml:"self_mark"`
	TUNName  string `yaml:"tun_name"`
	TUNAddr4 string `yaml:"tun_addr4"`
	TUNAddr6 string `yaml:"tun_addr6"`
	TUNMTU   int    `yaml:"tun_mtu"`
	IPv6     bool   `yaml:"ipv6"`
}

type DNSConfig struct {
	ListenPort   int    `yaml:"listen_port"`
	Server       string `yaml:"server"`
	ChinaServer  string `yaml:"china_server"`
	Strategy     string `yaml:"strategy"`
	FakeIP       bool   `yaml:"fakeip"`
	FakeIPRange4 string `yaml:"fakeip_range4"`
	FakeIPRange6 string `yaml:"fakeip_range6"`
}

type Node struct {
	Name      string          `yaml:"name"`
	Type      string          `yaml:"type"`
	Server    string          `yaml:"server"`
	Port      int             `yaml:"port"`
	UUID      string          `yaml:"uuid,omitempty"`
	Password  string          `yaml:"password,omitempty"`
	Method    string          `yaml:"method,omitempty"`
	Network   string          `yaml:"network,omitempty"`
	TLS       *TLSConfig      `yaml:"tls,omitempty"`
	Transport map[string]any  `yaml:"transport,omitempty"`
	Extra     map[string]any  `yaml:"extra,omitempty"`
}

type TLSConfig struct {
	Enabled    bool     `yaml:"enabled"`
	ServerName string   `yaml:"server_name"`
	Insecure   bool     `yaml:"insecure"`
	ALPN       []string `yaml:"alpn,omitempty"`
	UTLS       string   `yaml:"utls,omitempty"`
}

type Subscription struct {
	Name           string `yaml:"name"`
	URL            string `yaml:"url"`
	UpdateInterval string `yaml:"update_interval"`
	Enabled        bool   `yaml:"enabled"`
}

const (
	LANProxyAll          = "all"
	LANProxyExceptListed = "except_listed"
	LANProxyListedOnly   = "listed_only"
)

type ControlConfig struct {
	LANInterfaces []string `yaml:"lan_interfaces"`
	LANProxyMode  string   `yaml:"lan_proxy_mode"`
	LANProxyIPv4  []string `yaml:"lan_proxy_ipv4"`
	LANProxyIPv6  []string `yaml:"lan_proxy_ipv6"`
	LANProxyMAC   []string `yaml:"lan_proxy_mac"`
	LANDirectIPv4 []string `yaml:"lan_direct_ipv4"`
	LANDirectIPv6 []string `yaml:"lan_direct_ipv6"`
	LANDirectMAC  []string `yaml:"lan_direct_mac"`
	ProxyDomains  []string `yaml:"proxy_domains"`
	DirectDomains []string `yaml:"direct_domains"`
	WANDirectIPv4 []string `yaml:"wan_direct_ipv4"`
	WANDirectIPv6 []string `yaml:"wan_direct_ipv6"`
	WANProxyIPv4  []string `yaml:"wan_proxy_ipv4"`
	WANProxyIPv6  []string `yaml:"wan_proxy_ipv6"`
	RoutingPorts    string `yaml:"routing_ports"`
	BypassCNTraffic bool   `yaml:"bypass_cn_traffic"`
}

type PathsConfig struct {
	DataDir     string `yaml:"data_dir"`
	RunDir      string `yaml:"run_dir"`
	SingBoxBin  string `yaml:"singbox_bin"`
	ChinaIP4URL string `yaml:"china_ip4_url"`
	ChinaIP6URL string `yaml:"china_ip6_url"`
	GFWListURL  string `yaml:"gfw_list_url"`
}

type LogConfig struct {
	Level string `yaml:"level"`
}

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
		c.Proxy.TProxyMark = "0x65"
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
		c.Paths.ChinaIP6URL = "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt"
	}
	if c.Paths.GFWListURL == "" {
		c.Paths.GFWListURL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
	}
	if c.Log.Level == "" {
		c.Log.Level = "warn"
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
