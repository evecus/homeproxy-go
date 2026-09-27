package resources

import (
	"bufio"
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
	defaultChinaIP4 = "https://raw.githubusercontent.com/fernvenue/chn-cidr-list/master/ipv4.txt"
	defaultChinaIP6 = "https://raw.githubusercontent.com/fernvenue/chn-cidr-list/master/ipv6.txt"
	defaultGFWList  = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
)

// Updater downloads china IP lists and optional GFW list into data_dir.
type Updater struct {
	Cfg *config.Config
}

func New(cfg *config.Config) *Updater {
	return &Updater{Cfg: cfg}
}

func (u *Updater) Update() error {
	dir := u.Cfg.Paths.DataDir
	if dir == "" {
		dir = "/var/lib/homeproxy"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ip4 := u.Cfg.Paths.ChinaIP4URL
	if ip4 == "" {
		ip4 = defaultChinaIP4
	}
	ip6 := u.Cfg.Paths.ChinaIP6URL
	if ip6 == "" {
		ip6 = defaultChinaIP6
	}
	gfw := u.Cfg.Paths.GFWListURL
	if gfw == "" {
		gfw = defaultGFWList
	}

	if err := downloadText(ip4, filepath.Join(dir, "china_ip4.txt")); err != nil {
		return fmt.Errorf("china_ip4: %w", err)
	}
	if err := downloadText(ip6, filepath.Join(dir, "china_ip6.txt")); err != nil {
		return fmt.Errorf("china_ip6: %w", err)
	}
	// GFW list is base64; store raw for optional DNS tooling; not required for nft sets alone
	if err := downloadText(gfw, filepath.Join(dir, "gfwlist.txt")); err != nil {
		// non-fatal
		_ = err
	}
	return nil
}

func downloadText(url, dest string) error {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	_ = f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// LoadChinaIP4 reads CIDR lines from data_dir/china_ip4.txt.
func LoadChinaIP4(dataDir string) ([]string, error) {
	return loadCIDRs(filepath.Join(dataDir, "china_ip4.txt"))
}

// LoadChinaIP6 reads CIDR lines from data_dir/china_ip6.txt.
func LoadChinaIP6(dataDir string) ([]string, error) {
	return loadCIDRs(filepath.Join(dataDir, "china_ip6.txt"))
}

func loadCIDRs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}
