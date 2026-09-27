package resources

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/evecus/homeproxy-go/internal/config"
)

const (
	FileChinaIP4 = "china_ip4.txt"
	FileChinaIP6 = "china_ip6.txt"
	FileGFWList  = "gfw_list.txt"
)

type Manager struct {
	Cfg *config.Config
	Dir string
}

func NewManager(cfg *config.Config) *Manager {
	dir := filepath.Join(cfg.Paths.DataDir, "resources")
	return &Manager{Cfg: cfg, Dir: dir}
}

func (m *Manager) EnsureDir() error {
	return os.MkdirAll(m.Dir, 0o755)
}

func (m *Manager) Path(name string) string {
	return filepath.Join(m.Dir, name)
}

func (m *Manager) UpdateAll() error {
	if err := m.EnsureDir(); err != nil {
		return err
	}
	var errs []string
	if err := m.UpdateChinaIP4(); err != nil {
		errs = append(errs, "china_ip4: "+err.Error())
	}
	if err := m.UpdateChinaIP6(); err != nil {
		errs = append(errs, "china_ip6: "+err.Error())
	}
	if err := m.UpdateGFWList(); err != nil {
		errs = append(errs, "gfw_list: "+err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (m *Manager) UpdateChinaIP4() error {
	return downloadLines(m.Cfg.Paths.ChinaIP4URL, m.Path(FileChinaIP4), isIPv4CIDR)
}

func (m *Manager) UpdateChinaIP6() error {
	if m.Cfg.Paths.ChinaIP6URL == "" {
		return nil
	}
	return downloadLines(m.Cfg.Paths.ChinaIP6URL, m.Path(FileChinaIP6), isIPv6CIDR)
}

func (m *Manager) UpdateGFWList() error {
	body, err := httpGet(m.Cfg.Paths.GFWListURL)
	if err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		decoded = body
	}
	domains := parseGFWList(string(decoded))
	return writeLines(m.Path(FileGFWList), domains)
}

func (m *Manager) LoadChinaIP4() ([]string, error) {
	return readLines(m.Path(FileChinaIP4))
}

func (m *Manager) LoadChinaIP6() ([]string, error) {
	p := m.Path(FileChinaIP6)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return nil, nil
	}
	return readLines(p)
}

func (m *Manager) LoadGFWList() ([]string, error) {
	return readLines(m.Path(FileGFWList))
}

func httpGet(url string) ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
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
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

func downloadLines(url, dest string, filter func(string) bool) error {
	body, err := httpGet(url)
	if err != nil {
		return err
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if filter != nil && !filter(line) {
			continue
		}
		lines = append(lines, line)
	}
	return writeLines(dest, lines)
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

func isIPv4CIDR(s string) bool {
	return strings.Contains(s, ".") && !strings.Contains(s, ":")
}

func isIPv6CIDR(s string) bool {
	return strings.Contains(s, ":")
}

func parseGFWList(content string) []string {
	seen := map[string]struct{}{}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		if strings.HasPrefix(line, "@@") {
			continue
		}
		line = strings.TrimPrefix(line, "||")
		line = strings.TrimPrefix(line, "|")
		line = strings.TrimPrefix(line, ".")
		if i := strings.IndexAny(line, "/^$*"); i >= 0 {
			line = line[:i]
		}
		line = strings.Trim(line, " \t*")
		if line == "" || strings.Contains(line, "*") {
			continue
		}
		if !strings.Contains(line, ".") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out
}
