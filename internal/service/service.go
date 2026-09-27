package service

import (
	"fmt"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/evecus/homeproxy-go/internal/cert"
	"github.com/evecus/homeproxy-go/internal/config"
	"github.com/evecus/homeproxy-go/internal/generator"
	"github.com/evecus/homeproxy-go/internal/resources"
	"github.com/evecus/homeproxy-go/internal/subscription"
)

// Manager controls generate / nft / sing-box lifecycle.
type Manager struct {
	mu         sync.Mutex
	ConfigPath string
	Cfg        *config.Config
	cmd        *exec.Cmd
}

func New(configPath string) (*Manager, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	return &Manager{ConfigPath: configPath, Cfg: cfg}, nil
}

func (m *Manager) ReloadConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := config.Load(m.ConfigPath)
	if err != nil {
		return err
	}
	m.Cfg = cfg
	return nil
}

func (m *Manager) SaveConfig(cfg *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := cfg.Save(m.ConfigPath); err != nil {
		return err
	}
	m.Cfg = cfg
	return nil
}

type Status struct {
	Running     bool   `json:"running"`
	PID         int    `json:"pid,omitempty"`
	ConfigPath  string `json:"config_path"`
	Mode        string `json:"mode"`
	ProxyMode   string `json:"proxy_mode"`
	MainNode    string `json:"main_node"`
	MainUDP     string `json:"main_udp_node"`
	Nodes       int    `json:"nodes"`
	Subs        int    `json:"subscriptions"`
	Rules       int    `json:"rules"`
	SingBoxJSON string `json:"singbox_json"`
	NftPath     string `json:"nft_path"`
	ChinaIP4    bool   `json:"china_ip4_ready"`
	ChinaIP6    bool   `json:"china_ip6_ready"`
	GFWList     bool   `json:"gfw_list_ready"`
	Version     string `json:"version,omitempty"`
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	rm := resources.NewManager(m.Cfg)
	st := Status{
		ConfigPath:  m.ConfigPath,
		Mode:        m.Cfg.Mode,
		ProxyMode:   m.Cfg.Proxy.Mode,
		MainNode:    m.Cfg.Proxy.MainNode,
		MainUDP:     m.Cfg.Proxy.MainUDP,
		Nodes:       len(m.Cfg.Nodes),
		Subs:        len(m.Cfg.Subs),
		Rules:       len(m.Cfg.Rules),
		SingBoxJSON: filepath.Join(m.Cfg.Paths.RunDir, "sing-box.json"),
		NftPath:     filepath.Join(m.Cfg.Paths.RunDir, "nftables.nft"),
		Version:     "0.1.0",
	}
	if _, err := os.Stat(rm.Path(resources.FileChinaIP4)); err == nil {
		st.ChinaIP4 = true
	}
	if _, err := os.Stat(rm.Path(resources.FileChinaIP6)); err == nil {
		st.ChinaIP6 = true
	}
	if _, err := os.Stat(rm.Path(resources.FileGFWList)); err == nil {
		st.GFWList = true
	}
	pid := m.readPID()
	if pid > 0 && processAlive(pid) {
		st.Running = true
		st.PID = pid
	} else if m.cmd != nil && m.cmd.Process != nil {
		if processAlive(m.cmd.Process.Pid) {
			st.Running = true
			st.PID = m.cmd.Process.Pid
		}
	}
	return st
}

func (m *Manager) pidFile() string {
	return filepath.Join(m.Cfg.Paths.RunDir, "sing-box.pid")
}

func (m *Manager) readPID() int {
	b, err := os.ReadFile(m.pidFile())
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func (m *Manager) writePID(pid int) error {
	_ = os.MkdirAll(m.Cfg.Paths.RunDir, 0o755)
	return os.WriteFile(m.pidFile(), []byte(strconv.Itoa(pid)+"\n"), 0o644)
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// Generate builds sing-box.json and nftables.nft (does not start proxy).
func (m *Manager) Generate() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generateLocked()
}

func (m *Manager) generateLocked() error {
	cfg := m.Cfg
	// merge subscriptions
	for _, sub := range cfg.Subs {
		if sub.URL == "" {
			continue
		}
		nodes, err := subscription.Fetch(sub.URL)
		if err != nil {
			continue
		}
		subscription.MergeNodes(cfg, sub.Name, nodes)
	}
	if err := os.MkdirAll(cfg.Paths.RunDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.Paths.DataDir, 0o755); err != nil {
		return err
	}
	rm := resources.NewManager(cfg)
	_ = rm.EnsureDir()
	china4, _ := rm.LoadChinaIP4()
	china6, _ := rm.LoadChinaIP6()

	sbPath := filepath.Join(cfg.Paths.RunDir, "sing-box.json")
	if err := generator.NewSingBox(cfg).Write(sbPath); err != nil {
		return fmt.Errorf("sing-box: %w", err)
	}
	nftPath := filepath.Join(cfg.Paths.RunDir, "nftables.nft")
	if err := generator.NewNftables(cfg, china4, china6).Write(nftPath); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	// dnsmasq nftset fragment for GFW
	if cfg.DNSMasq.Enabled {
		path, n, err := generator.NewDNSMasq(cfg).WriteGFWConf()
		if err != nil {
			return fmt.Errorf("dnsmasq: %w", err)
		}
		_ = path
		_ = n
		if cfg.DNSMasq.ReloadCmd != "" {
			_ = exec.Command("sh", "-c", cfg.DNSMasq.ReloadCmd).Run()
		}
	}
	return nil
}

func (m *Manager) ApplyNft() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	nftPath := filepath.Join(m.Cfg.Paths.RunDir, "nftables.nft")
	if _, err := os.Stat(nftPath); err != nil {
		return fmt.Errorf("missing %s — generate first", nftPath)
	}
	cmd := exec.Command("nft", "-f", nftPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %v: %s", err, string(out))
	}
	return nil
}

func (m *Manager) SetupRouting() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.Cfg
	if cfg.Proxy.Mode != config.ProxyTProxy {
		return nil
	}
	mark := config.NormalizeMark(cfg.Proxy.TProxyMark)
	runIP("rule", "del", "fwmark", mark, "lookup", "100")
	runIP("route", "del", "local", "default", "dev", "lo", "table", "100")
	if err := mustIP("rule", "add", "fwmark", mark, "lookup", "100"); err != nil {
		return err
	}
	if err := mustIP("route", "add", "local", "default", "dev", "lo", "table", "100"); err != nil {
		return err
	}
	if cfg.Proxy.IPv6 {
		runIP("-6", "rule", "del", "fwmark", mark, "lookup", "100")
		runIP("-6", "route", "del", "local", "default", "dev", "lo", "table", "100")
		_ = mustIP("-6", "rule", "add", "fwmark", mark, "lookup", "100")
		_ = mustIP("-6", "route", "add", "local", "default", "dev", "lo", "table", "100")
	}
	return nil
}

func (m *Manager) UpdateResources() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return resources.NewManager(m.Cfg).UpdateAll()
}

// Start generates configs, applies nft/routing, starts sing-box.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pid := m.readPID(); pid > 0 && processAlive(pid) {
		return fmt.Errorf("already running (pid %d)", pid)
	}
	if err := m.generateLocked(); err != nil {
		return err
	}
	// unlock-style: call helpers that need lock carefully — we're already locked
	nftPath := filepath.Join(m.Cfg.Paths.RunDir, "nftables.nft")
	if out, err := exec.Command("nft", "-f", nftPath).CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, string(out))
	}
	if m.Cfg.Proxy.Mode == config.ProxyTProxy {
		mark := config.NormalizeMark(m.Cfg.Proxy.TProxyMark)
		runIP("rule", "del", "fwmark", mark, "lookup", "100")
		runIP("route", "del", "local", "default", "dev", "lo", "table", "100")
		_ = mustIP("rule", "add", "fwmark", mark, "lookup", "100")
		_ = mustIP("route", "add", "local", "default", "dev", "lo", "table", "100")
	}

	sbPath := filepath.Join(m.Cfg.Paths.RunDir, "sing-box.json")
	bin := m.Cfg.Paths.SingBoxBin
	cmd := exec.Command(bin, "run", "-c", sbPath)
	logPath := filepath.Join(m.Cfg.Paths.RunDir, "sing-box.log")
	if logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		cmd.Stdout = logf
		cmd.Stderr = logf
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sing-box: %w", err)
	}
	m.cmd = cmd
	_ = m.writePID(cmd.Process.Pid)
	go func() {
		_ = cmd.Wait()
		_ = os.Remove(m.pidFile())
	}()
	time.Sleep(200 * time.Millisecond)
	if !processAlive(cmd.Process.Pid) {
		return fmt.Errorf("sing-box exited immediately")
	}
	return nil
}

// Stop kills sing-box and optionally flushes homeproxy nft table.
func (m *Manager) Stop(flushNft bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []string
	pid := m.readPID()
	if pid <= 0 && m.cmd != nil && m.cmd.Process != nil {
		pid = m.cmd.Process.Pid
	}
	if pid > 0 && processAlive(pid) {
		p, _ := os.FindProcess(pid)
		_ = p.Signal(syscall.SIGTERM)
		time.Sleep(500 * time.Millisecond)
		if processAlive(pid) {
			_ = p.Signal(syscall.SIGKILL)
		}
	}
	_ = os.Remove(m.pidFile())
	m.cmd = nil
	if flushNft {
		if out, err := exec.Command("nft", "delete", "table", "inet", "homeproxy").CombinedOutput(); err != nil {
			// table may not exist
			if !strings.Contains(string(out), "No such file") && !strings.Contains(string(out), "does not exist") {
				errs = append(errs, string(out))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// Restart stops then starts.
func (m *Manager) Restart() error {
	_ = m.Stop(false)
	time.Sleep(300 * time.Millisecond)
	return m.Start()
}

func runIP(args ...string) {
	_ = exec.Command("ip", args...).Run()
}

func mustIP(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %v: %s", args, err, string(out))
	}
	return nil
}

// SetMainNode updates main_node and saves config.
func (m *Manager) SetMainNode(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Cfg.Proxy.MainNode = name
	return m.Cfg.Save(m.ConfigPath)
}

// DeleteNode removes a node by name.
func (m *Manager) DeleteNode(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.Cfg.Nodes[:0]
	for _, n := range m.Cfg.Nodes {
		if n.Name != name {
			out = append(out, n)
		}
	}
	m.Cfg.Nodes = out
	if m.Cfg.Proxy.MainNode == name {
		m.Cfg.Proxy.MainNode = ""
		if len(m.Cfg.Nodes) > 0 {
			m.Cfg.Proxy.MainNode = m.Cfg.Nodes[0].Name
		}
	}
	return m.Cfg.Save(m.ConfigPath)
}

// AddSubscription appends a subscription entry.
func (m *Manager) AddSubscription(sub config.Subscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sub.Name == "" || sub.URL == "" {
		return fmt.Errorf("name and url required")
	}
	for _, s := range m.Cfg.Subs {
		if s.Name == sub.Name {
			return fmt.Errorf("subscription %q already exists", sub.Name)
		}
	}
	if !sub.Enabled {
		sub.Enabled = true
	}
	m.Cfg.Subs = append(m.Cfg.Subs, sub)
	return m.Cfg.Save(m.ConfigPath)
}

// RemoveSubscription deletes subscription by name.
func (m *Manager) RemoveSubscription(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.Cfg.Subs[:0]
	for _, s := range m.Cfg.Subs {
		if s.Name != name {
			out = append(out, s)
		}
	}
	m.Cfg.Subs = out
	return m.Cfg.Save(m.ConfigPath)
}

// UpdateSubscription fetches one or all subscriptions and merges nodes.
// replace=true removes previous nodes with prefix name/
func (m *Manager) UpdateSubscription(name string, replace bool) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, sub := range m.Cfg.Subs {
		if name != "" && sub.Name != name {
			continue
		}
		if sub.URL == "" {
			continue
		}
		nodes, err := subscription.Fetch(sub.URL)
		if err != nil {
			return total, fmt.Errorf("%s: %w", sub.Name, err)
		}
		if replace {
			prefix := sub.Name + "/"
			kept := m.Cfg.Nodes[:0]
			for _, n := range m.Cfg.Nodes {
				if !strings.HasPrefix(n.Name, prefix) {
					kept = append(kept, n)
				}
			}
			m.Cfg.Nodes = kept
		}
		before := len(m.Cfg.Nodes)
		subscription.MergeNodes(m.Cfg, sub.Name, nodes)
		total += len(m.Cfg.Nodes) - before
	}
	if err := m.Cfg.Save(m.ConfigPath); err != nil {
		return total, err
	}
	return total, nil
}


// StartSubScheduler runs background subscription refresh based on UpdateInterval.
// Call once from serve; stops when process exits.
func (m *Manager) StartSubScheduler() {
	go func() {
		for {
			m.mu.Lock()
			subs := append([]config.Subscription(nil), m.Cfg.Subs...)
			m.mu.Unlock()
			minWait := 6 * time.Hour
			for _, sub := range subs {
				if !sub.Enabled || sub.URL == "" {
					continue
				}
				d := parseDurationDefault(sub.UpdateInterval, 6*time.Hour)
				if d < minWait {
					minWait = d
				}
			}
			time.Sleep(minWait)
			m.mu.Lock()
			subs = append([]config.Subscription(nil), m.Cfg.Subs...)
			m.mu.Unlock()
			for _, sub := range subs {
				if !sub.Enabled || sub.URL == "" {
					continue
				}
				_, _ = m.UpdateSubscription(sub.Name, true)
			}
		}
	}()
}

func parseDurationDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// ClashTraffic fetches connection totals from sing-box clash API.
func (m *Manager) ClashTraffic() (map[string]any, error) {
	m.mu.Lock()
	cfg := m.Cfg
	m.mu.Unlock()
	if !cfg.Clash.Enabled {
		return nil, fmt.Errorf("clash api disabled")
	}
	base := "http://" + cfg.Clash.Listen
	req, err := http.NewRequest(http.MethodGet, base+"/connections", nil)
	if err != nil {
		return nil, err
	}
	if cfg.Clash.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Clash.Secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return map[string]any{"raw": string(body)}, nil
	}
	// also proxies
	req2, _ := http.NewRequest(http.MethodGet, base+"/proxies", nil)
	if cfg.Clash.Secret != "" {
		req2.Header.Set("Authorization", "Bearer "+cfg.Clash.Secret)
	}
	if resp2, err := http.DefaultClient.Do(req2); err == nil {
		defer resp2.Body.Close()
		b2, _ := io.ReadAll(resp2.Body)
		var proxies any
		_ = json.Unmarshal(b2, &proxies)
		raw["proxies"] = proxies
	}
	return raw, nil
}


// ProxyDelay tests a proxy via Clash API GET /proxies/{name}/delay
func (m *Manager) ProxyDelay(name string, url string, timeoutMs int) (map[string]any, error) {
	m.mu.Lock()
	cfg := m.Cfg
	m.mu.Unlock()
	if !cfg.Clash.Enabled {
		return nil, fmt.Errorf("clash api disabled — enable clash.enabled")
	}
	if url == "" {
		url = "https://www.gstatic.com/generate_204"
	}
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}
	// Clash uses selector/urltest group names or node display names — we use node tags as outbound tags
	// sing-box clash API exposes outbounds by tag without "node-" sometimes; try both
	base := "http://" + cfg.Clash.Listen
	candidates := []string{name, "node-" + sanitizeProxyName(name)}
	var lastErr error
	for _, n := range candidates {
		u := fmt.Sprintf("%s/proxies/%s/delay?timeout=%d&url=%s", base, pathEscape(n), timeoutMs, pathEscape(url))
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		if cfg.Clash.Secret != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.Clash.Secret)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			lastErr = fmt.Errorf("%s", string(body))
			continue
		}
		out["name"] = n
		return out, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("delay test failed")
}

func sanitizeProxyName(s string) string {
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

func pathEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", "%20"), "/", "%2F")
}

// TailLog returns last lines of sing-box stdout log file if configured, else empty.
func (m *Manager) TailLog(maxLines int) (string, error) {
	m.mu.Lock()
	cfg := m.Cfg
	m.mu.Unlock()
	if maxLines <= 0 {
		maxLines = 200
	}
	logPath := filepath.Join(cfg.Paths.RunDir, "sing-box.log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		return "", fmt.Errorf("no log file at %s (redirect sing-box stdout there for logs)", logPath)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n"), nil
}

// ListProxies returns clash /proxies payload.
func (m *Manager) ListProxies() (map[string]any, error) {
	m.mu.Lock()
	cfg := m.Cfg
	m.mu.Unlock()
	if !cfg.Clash.Enabled {
		return nil, fmt.Errorf("clash api disabled")
	}
	base := "http://" + cfg.Clash.Listen
	req, err := http.NewRequest(http.MethodGet, base+"/proxies", nil)
	if err != nil {
		return nil, err
	}
	if cfg.Clash.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Clash.Secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}


// IssueCertificate runs ACME / self-signed issuance.
func (m *Manager) IssueCertificate() (map[string]string, error) {
	m.mu.Lock()
	cfg := m.Cfg
	m.mu.Unlock()
	certPath, keyPath, err := cert.Issue(cfg)
	if err != nil {
		return nil, err
	}
	return map[string]string{"certificate": certPath, "key": keyPath}, nil
}

// DelayAll tests delay for all nodes (sequential, capped).
func (m *Manager) DelayAll(timeoutMs int) ([]map[string]any, error) {
	m.mu.Lock()
	names := make([]string, 0, len(m.Cfg.Nodes))
	for _, n := range m.Cfg.Nodes {
		names = append(names, n.Name)
	}
	m.mu.Unlock()
	var out []map[string]any
	for _, name := range names {
		d, err := m.ProxyDelay(name, "", timeoutMs)
		if err != nil {
			out = append(out, map[string]any{"name": name, "error": err.Error()})
			continue
		}
		out = append(out, d)
	}
	return out, nil
}
