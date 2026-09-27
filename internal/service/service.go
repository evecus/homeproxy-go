package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/evecus/homeproxy-go/internal/config"
	"github.com/evecus/homeproxy-go/internal/generator"
	"github.com/evecus/homeproxy-go/internal/resources"
	"github.com/evecus/homeproxy-go/internal/subscription"
)

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
	SingBoxJSON string `json:"singbox_json"`
	NftPath     string `json:"nft_path"`
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{
		ConfigPath:  m.ConfigPath,
		Mode:        m.Cfg.Mode,
		ProxyMode:   m.Cfg.Proxy.Mode,
		MainNode:    m.Cfg.Proxy.MainNode,
		SingBoxJSON: filepath.Join(m.Cfg.Paths.RunDir, "sing-box.json"),
		NftPath:     filepath.Join(m.Cfg.Paths.RunDir, "nftables.nft"),
	}
	pid := m.readPID()
	if pid > 0 && processAlive(pid) {
		st.Running = true
		st.PID = pid
	} else if m.cmd != nil && m.cmd.Process != nil && processAlive(m.cmd.Process.Pid) {
		st.Running = true
		st.PID = m.cmd.Process.Pid
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

func (m *Manager) Generate() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generateLocked()
}

func (m *Manager) generateLocked() error {
	cfg := m.Cfg
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
	if err := generator.NewSingBox(cfg).Write(filepath.Join(cfg.Paths.RunDir, "sing-box.json")); err != nil {
		return fmt.Errorf("sing-box: %w", err)
	}
	if err := generator.NewNftables(cfg, china4, china6).Write(filepath.Join(cfg.Paths.RunDir, "nftables.nft")); err != nil {
		return fmt.Errorf("nftables: %w", err)
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
	out, err := exec.Command("nft", "-f", nftPath).CombinedOutput()
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
	return mustIP("route", "add", "local", "default", "dev", "lo", "table", "100")
}

func (m *Manager) UpdateResources() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return resources.NewManager(m.Cfg).UpdateAll()
}

func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pid := m.readPID(); pid > 0 && processAlive(pid) {
		return fmt.Errorf("already running (pid %d)", pid)
	}
	if err := m.generateLocked(); err != nil {
		return err
	}
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
	cmd := exec.Command(m.Cfg.Paths.SingBoxBin, "run", "-c", sbPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
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

func (m *Manager) Stop(flushNft bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
		_, _ = exec.Command("nft", "delete", "table", "inet", "homeproxy").CombinedOutput()
	}
	return nil
}

func (m *Manager) Restart() error {
	_ = m.Stop(false)
	time.Sleep(300 * time.Millisecond)
	return m.Start()
}

func runIP(args ...string) { _ = exec.Command("ip", args...).Run() }

func mustIP(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %v: %s", args, err, string(out))
	}
	return nil
}
