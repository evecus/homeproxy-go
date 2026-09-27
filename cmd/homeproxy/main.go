package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/evecus/homeproxy-go/internal/config"
	"github.com/evecus/homeproxy-go/internal/generator"
	"github.com/evecus/homeproxy-go/internal/resources"
	"github.com/evecus/homeproxy-go/internal/subscription"
)

var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "version", "-v", "--version":
		fmt.Println("homeproxy-go", version)
	case "generate":
		runGenerate(args)
	case "apply-nft":
		runApplyNft(args)
	case "update-resources":
		runUpdateResources(args)
	case "update-subs":
		runUpdateSubs(args)
	case "setup-routing":
		runSetupRouting(args)
	case "check":
		runCheck(args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `homeproxy-go %s — transparent proxy controller (sing-box + nftables)

Usage:
  homeproxy <command> [options]

Commands:
  generate          Generate sing-box.json and nftables.nft from config
  apply-nft         Load generated nftables rules (requires root)
  update-resources  Download China IP lists and GFW list
  update-subs       Fetch subscriptions and print merged node names
  setup-routing     Install ip rule/route for TProxy marks
  check             Validate config file
  version           Print version

Global flags (after command):
  -c, --config path   Config file (default: /etc/homeproxy/config.yaml)

Examples:
  homeproxy update-resources -c ./configs/config.example.yaml
  homeproxy generate -c /etc/homeproxy/config.yaml
  sudo homeproxy apply-nft -c /etc/homeproxy/config.yaml
  sudo homeproxy setup-routing -c /etc/homeproxy/config.yaml
  sing-box run -c /var/run/homeproxy/sing-box.json
`, version)
}

func configPath(fs *flag.FlagSet, args []string) string {
	var path string
	fs.StringVar(&path, "c", "/etc/homeproxy/config.yaml", "config file")
	fs.StringVar(&path, "config", "/etc/homeproxy/config.yaml", "config file")
	_ = fs.Parse(args)
	return path
}

func loadCfg(path string) *config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		fatal("load config: %v", err)
	}
	return cfg
}

func runCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	path := configPath(fs, args)
	cfg := loadCfg(path)
	fmt.Printf("config OK: mode=%s proxy=%s nodes=%d\n", cfg.Mode, cfg.Proxy.Mode, len(cfg.Nodes))
}

func runUpdateResources(args []string) {
	fs := flag.NewFlagSet("update-resources", flag.ExitOnError)
	path := configPath(fs, args)
	cfg := loadCfg(path)
	m := resources.NewManager(cfg)
	fmt.Println("updating resource lists ...")
	if err := m.UpdateAll(); err != nil {
		fatal("%v", err)
	}
	fmt.Printf("done → %s\n", m.Dir)
}

func runUpdateSubs(args []string) {
	fs := flag.NewFlagSet("update-subs", flag.ExitOnError)
	path := configPath(fs, args)
	cfg := loadCfg(path)
	for _, sub := range cfg.Subs {
		if sub.URL == "" {
			continue
		}
		fmt.Printf("fetching %s ...\n", sub.Name)
		nodes, err := subscription.Fetch(sub.URL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  error: %v\n", err)
			continue
		}
		subscription.MergeNodes(cfg, sub.Name, nodes)
		fmt.Printf("  +%d nodes\n", len(nodes))
	}
	for _, n := range cfg.Nodes {
		fmt.Printf("  - %s (%s %s:%d)\n", n.Name, n.Type, n.Server, n.Port)
	}
}

func runGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	path := configPath(fs, args)
	cfg := loadCfg(path)

	for _, sub := range cfg.Subs {
		if sub.URL == "" {
			continue
		}
		nodes, err := subscription.Fetch(sub.URL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "subscription %s: %v (skipped)\n", sub.Name, err)
			continue
		}
		subscription.MergeNodes(cfg, sub.Name, nodes)
	}

	runDir := cfg.Paths.RunDir
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		fatal("mkdir run dir: %v", err)
	}
	if err := os.MkdirAll(cfg.Paths.DataDir, 0o755); err != nil {
		fatal("mkdir data dir: %v", err)
	}

	m := resources.NewManager(cfg)
	_ = m.EnsureDir()
	china4, _ := m.LoadChinaIP4()
	china6, _ := m.LoadChinaIP6()
	if cfg.ModeNeedsChinaIP() && len(china4) == 0 {
		fmt.Fprintln(os.Stderr, "warning: china_ip4.txt empty — run: homeproxy update-resources")
	}

	sbPath := filepath.Join(runDir, "sing-box.json")
	if err := generator.NewSingBox(cfg).Write(sbPath); err != nil {
		fatal("sing-box: %v", err)
	}
	fmt.Println("wrote", sbPath)

	nftPath := filepath.Join(runDir, "nftables.nft")
	if err := generator.NewNftables(cfg, china4, china6).Write(nftPath); err != nil {
		fatal("nftables: %v", err)
	}
	fmt.Println("wrote", nftPath)
}

func runApplyNft(args []string) {
	fs := flag.NewFlagSet("apply-nft", flag.ExitOnError)
	path := configPath(fs, args)
	cfg := loadCfg(path)
	nftPath := filepath.Join(cfg.Paths.RunDir, "nftables.nft")
	if _, err := os.Stat(nftPath); err != nil {
		fatal("missing %s — run generate first", nftPath)
	}
	cmd := exec.Command("nft", "-f", nftPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatal("nft -f: %v", err)
	}
	fmt.Println("nftables applied")
}

func runSetupRouting(args []string) {
	fs := flag.NewFlagSet("setup-routing", flag.ExitOnError)
	path := configPath(fs, args)
	cfg := loadCfg(path)
	if cfg.Proxy.Mode != config.ProxyTProxy {
		fmt.Println("setup-routing is only needed for tproxy mode")
		return
	}
	mark := config.NormalizeMark(cfg.Proxy.TProxyMark)
	runIP("rule", "del", "fwmark", mark, "lookup", "100")
	runIP("route", "del", "local", "default", "dev", "lo", "table", "100")
	mustIP("rule", "add", "fwmark", mark, "lookup", "100")
	mustIP("route", "add", "local", "default", "dev", "lo", "table", "100")
	if cfg.Proxy.IPv6 {
		runIP("-6", "rule", "del", "fwmark", mark, "lookup", "100")
		runIP("-6", "route", "del", "local", "default", "dev", "lo", "table", "100")
		mustIP("-6", "rule", "add", "fwmark", mark, "lookup", "100")
		mustIP("-6", "route", "add", "local", "default", "dev", "lo", "table", "100")
	}
	fmt.Printf("policy routing installed for fwmark %s table 100\n", mark)
}

func runIP(args ...string) {
	cmd := exec.Command("ip", args...)
	_ = cmd.Run()
}

func mustIP(args ...string) {
	cmd := exec.Command("ip", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatal("ip %s: %v", strings.Join(args, " "), err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
