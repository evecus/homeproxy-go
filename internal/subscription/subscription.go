package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/evecus/homeproxy-go/internal/config"
)

// Fetch downloads a subscription URL and returns parsed nodes.
// Supports: base64 SS/VMess/Trojan share links, plain share links (one per line),
// and Clash-like YAML proxy lists (minimal).
func Fetch(subURL string) ([]config.Node, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest(http.MethodGet, subURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "homeproxy-go/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return Parse(string(body))
}

func Parse(raw string) ([]config.Node, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty subscription body")
	}

	// Try base64 decode
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
		raw = string(decoded)
	} else if decoded, err := base64.URLEncoding.DecodeString(raw); err == nil {
		raw = string(decoded)
	} else {
		// try raw std without padding
		if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
			raw = string(decoded)
		}
	}

	var nodes []config.Node
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		n, err := ParseShareLink(line)
		if err != nil {
			continue // skip unparsable lines
		}
		nodes = append(nodes, *n)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes parsed from subscription")
	}
	return nodes, nil
}

func ParseShareLink(link string) (*config.Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "ss":
		return parseSS(u)
	case "ssr":
		return nil, fmt.Errorf("ssr not supported")
	case "vmess":
		return parseVMess(link)
	case "vless":
		return parseVLESS(u)
	case "trojan":
		return parseTrojan(u)
	case "hysteria2", "hy2":
		return parseHysteria2(u)
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
}

func parseSS(u *url.URL) (*config.Node, error) {
	// ss://base64(method:password)@host:port#name
	// or ss://base64(method:password@host:port)#name
	name, _ := url.QueryUnescape(u.Fragment)
	if name == "" {
		name = u.Host
	}
	var method, password, host string
	var port int

	if u.User != nil {
		// userinfo may be base64
		userinfo := u.User.String()
		if decoded, err := base64.RawStdEncoding.DecodeString(userinfo); err == nil {
			userinfo = string(decoded)
		} else if decoded, err := base64.StdEncoding.DecodeString(userinfo); err == nil {
			userinfo = string(decoded)
		}
		parts := strings.SplitN(userinfo, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid ss userinfo")
		}
		method, password = parts[0], parts[1]
		host = u.Hostname()
		port, _ = strconv.Atoi(u.Port())
	} else {
		// entire body base64
		body := strings.TrimPrefix(u.String(), "ss://")
		if i := strings.Index(body, "#"); i >= 0 {
			body = body[:i]
		}
		decoded, err := base64.RawStdEncoding.DecodeString(body)
		if err != nil {
			decoded, err = base64.StdEncoding.DecodeString(body)
		}
		if err != nil {
			return nil, err
		}
		// method:password@host:port
		s := string(decoded)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return nil, fmt.Errorf("invalid ss link")
		}
		mp := strings.SplitN(s[:at], ":", 2)
		if len(mp) != 2 {
			return nil, fmt.Errorf("invalid ss method:password")
		}
		method, password = mp[0], mp[1]
		hp := s[at+1:]
		h, p, err := splitHostPort(hp)
		if err != nil {
			return nil, err
		}
		host, port = h, p
	}
	if port == 0 {
		return nil, fmt.Errorf("ss missing port")
	}
	return &config.Node{
		Name:     name,
		Type:     "shadowsocks",
		Server:   host,
		Port:     port,
		Method:   method,
		Password: password,
	}, nil
}

func parseVMess(link string) (*config.Node, error) {
	// vmess://base64(json)
	raw := strings.TrimPrefix(link, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(decoded, &m); err != nil {
		return nil, err
	}
	name, _ := m["ps"].(string)
	add, _ := m["add"].(string)
	port := anyToInt(m["port"])
	uuid, _ := m["id"].(string)
	if name == "" {
		name = add
	}
	n := &config.Node{
		Name:   name,
		Type:   "vmess",
		Server: add,
		Port:   port,
		UUID:   uuid,
	}
	if tls, _ := m["tls"].(string); tls == "tls" {
		sni, _ := m["sni"].(string)
		if sni == "" {
			sni, _ = m["host"].(string)
		}
		n.TLS = &config.TLSConfig{Enabled: true, ServerName: sni}
	}
	if net, _ := m["net"].(string); net != "" && net != "tcp" {
		n.Transport = map[string]any{"transport": map[string]any{"type": net}}
	}
	return n, nil
}

func parseVLESS(u *url.URL) (*config.Node, error) {
	name, _ := url.QueryUnescape(u.Fragment)
	if name == "" {
		name = u.Hostname()
	}
	port, _ := strconv.Atoi(u.Port())
	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}
	n := &config.Node{
		Name:   name,
		Type:   "vless",
		Server: u.Hostname(),
		Port:   port,
		UUID:   uuid,
	}
	q := u.Query()
	if q.Get("security") == "tls" || q.Get("security") == "reality" {
		n.TLS = &config.TLSConfig{
			Enabled:    true,
			ServerName: firstNonEmpty(q.Get("sni"), q.Get("host")),
		}
	}
	return n, nil
}

func parseTrojan(u *url.URL) (*config.Node, error) {
	name, _ := url.QueryUnescape(u.Fragment)
	if name == "" {
		name = u.Hostname()
	}
	port, _ := strconv.Atoi(u.Port())
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	n := &config.Node{
		Name:     name,
		Type:     "trojan",
		Server:   u.Hostname(),
		Port:     port,
		Password: password,
		TLS: &config.TLSConfig{
			Enabled:    true,
			ServerName: firstNonEmpty(u.Query().Get("sni"), u.Hostname()),
		},
	}
	return n, nil
}

func parseHysteria2(u *url.URL) (*config.Node, error) {
	name, _ := url.QueryUnescape(u.Fragment)
	if name == "" {
		name = u.Hostname()
	}
	port, _ := strconv.Atoi(u.Port())
	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	n := &config.Node{
		Name:     name,
		Type:     "hysteria2",
		Server:   u.Hostname(),
		Port:     port,
		Password: password,
		TLS: &config.TLSConfig{
			Enabled:    true,
			ServerName: firstNonEmpty(u.Query().Get("sni"), u.Hostname()),
		},
	}
	return n, nil
}

func splitHostPort(s string) (string, int, error) {
	// [ipv6]:port or host:port
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("bad ipv6")
		}
		host := s[1:end]
		rest := s[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return host, 0, nil
		}
		p, err := strconv.Atoi(rest[1:])
		return host, p, err
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, 0, nil
	}
	p, err := strconv.Atoi(s[i+1:])
	return s[:i], p, err
}

func anyToInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// MergeNodes appends subscription nodes into cfg, prefixing names if needed.
func MergeNodes(cfg *config.Config, subName string, nodes []config.Node) {
	existing := map[string]struct{}{}
	for _, n := range cfg.Nodes {
		existing[n.Name] = struct{}{}
	}
	for _, n := range nodes {
		name := n.Name
		if subName != "" {
			name = subName + "/" + name
		}
		base := name
		i := 2
		for {
			if _, ok := existing[name]; !ok {
				break
			}
			name = fmt.Sprintf("%s-%d", base, i)
			i++
		}
		n.Name = name
		existing[name] = struct{}{}
		cfg.Nodes = append(cfg.Nodes, n)
	}
}
