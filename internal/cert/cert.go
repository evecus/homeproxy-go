package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/evecus/homeproxy-go/internal/config"
)

// Issue obtains certificates according to ACME config.
// Returns certPath, keyPath for the first domain.
func Issue(cfg *config.Config) (certPath, keyPath string, err error) {
	acme := cfg.ACME
	if !acme.Enabled {
		return "", "", fmt.Errorf("acme disabled")
	}
	if len(acme.Domains) == 0 {
		return "", "", fmt.Errorf("acme.domains required")
	}
	dir := acme.CertDir
	if dir == "" {
		dir = filepath.Join(cfg.Paths.DataDir, "certs")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	provider := acme.Provider
	if provider == "" {
		provider = "self_signed"
	}
	switch provider {
	case "self_signed":
		return SelfSigned(dir, acme.Domains)
	case "certbot":
		return Certbot(dir, acme)
	case "acme_sh", "acme.sh":
		return AcmeSh(dir, acme)
	default:
		return "", "", fmt.Errorf("unknown acme.provider: %s (self_signed|certbot|acme_sh)", provider)
	}
}

// SelfSigned generates a 1-year ECDSA P-256 cert for domains.
func SelfSigned(dir string, domains []string) (string, string, error) {
	if len(domains) == 0 {
		return "", "", fmt.Errorf("domains required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domains[0], Organization: []string{"homeproxy-go"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     domains,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	certPath := filepath.Join(dir, domains[0]+".crt")
	keyPath := filepath.Join(dir, domains[0]+".key")
	cf, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", "", err
	}
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = cf.Close()
	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		_ = kf.Close()
		return "", "", err
	}
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	_ = kf.Close()
	return certPath, keyPath, nil
}

// Certbot runs: certbot certonly --standalone ...
func Certbot(dir string, acme config.ACMEConfig) (string, string, error) {
	if _, err := exec.LookPath("certbot"); err != nil {
		return "", "", fmt.Errorf("certbot not found in PATH: %w", err)
	}
	args := []string{"certonly", "--non-interactive", "--agree-tos", "--standalone"}
	if acme.Email != "" {
		args = append(args, "-m", acme.Email)
	} else {
		args = append(args, "--register-unsafely-without-email")
	}
	if acme.HTTPPort > 0 && acme.HTTPPort != 80 {
		args = append(args, "--http-01-port", fmt.Sprintf("%d", acme.HTTPPort))
	}
	for _, d := range acme.Domains {
		args = append(args, "-d", d)
	}
	if acme.ExtraArgs != "" {
		args = append(args, strings.Fields(acme.ExtraArgs)...)
	}
	cmd := exec.Command("certbot", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("certbot: %v: %s", err, string(out))
	}
	// live certs under /etc/letsencrypt/live/<domain>/
	d0 := acme.Domains[0]
	live := filepath.Join("/etc/letsencrypt/live", d0)
	certPath := filepath.Join(live, "fullchain.pem")
	keyPath := filepath.Join(live, "privkey.pem")
	if _, err := os.Stat(certPath); err != nil {
		return "", "", fmt.Errorf("certbot finished but %s missing: %s", certPath, string(out))
	}
	// symlink/copy into dir for convenience
	_ = copyFile(certPath, filepath.Join(dir, d0+".crt"))
	_ = copyFile(keyPath, filepath.Join(dir, d0+".key"))
	return certPath, keyPath, nil
}

// AcmeSh runs acme.sh --issue
func AcmeSh(dir string, acme config.ACMEConfig) (string, string, error) {
	bin := "acme.sh"
	if _, err := exec.LookPath(bin); err != nil {
		home := os.Getenv("HOME")
		cand := filepath.Join(home, ".acme.sh", "acme.sh")
		if _, err2 := os.Stat(cand); err2 == nil {
			bin = cand
		} else {
			return "", "", fmt.Errorf("acme.sh not found")
		}
	}
	args := []string{"--issue", "--standalone"}
	if acme.Email != "" {
		args = append(args, "-m", acme.Email)
	}
	for _, d := range acme.Domains {
		args = append(args, "-d", d)
	}
	if acme.ExtraArgs != "" {
		args = append(args, strings.Fields(acme.ExtraArgs)...)
	}
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("acme.sh: %v: %s", err, string(out))
	}
	d0 := acme.Domains[0]
	home := os.Getenv("HOME")
	base := filepath.Join(home, ".acme.sh", d0+"_ecc")
	if _, err := os.Stat(base); err != nil {
		base = filepath.Join(home, ".acme.sh", d0)
	}
	certPath := filepath.Join(base, "fullchain.cer")
	keyPath := filepath.Join(base, d0+".key")
	if _, err := os.Stat(certPath); err != nil {
		return "", "", fmt.Errorf("acme.sh done but cert missing: %s", string(out))
	}
	_ = copyFile(certPath, filepath.Join(dir, d0+".crt"))
	_ = copyFile(keyPath, filepath.Join(dir, d0+".key"))
	return filepath.Join(dir, d0+".crt"), filepath.Join(dir, d0+".key"), nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}
