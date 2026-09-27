package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"

	"github.com/evecus/homeproxy-go/internal/config"
	"github.com/evecus/homeproxy-go/internal/service"
	"gopkg.in/yaml.v3"
)

//go:embed static/*
var staticFS embed.FS

type Server struct {
	Mgr *service.Manager
	Mux *http.ServeMux
}

func New(mgr *service.Manager) *Server {
	s := &Server{Mgr: mgr, Mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	sub, _ := fs.Sub(staticFS, "static")
	s.Mux.Handle("/", http.FileServer(http.FS(sub)))

	s.Mux.HandleFunc("/api/status", s.handleStatus)
	s.Mux.HandleFunc("/api/config", s.handleConfig)
	s.Mux.HandleFunc("/api/config/yaml", s.handleConfigYAML)
	s.Mux.HandleFunc("/api/start", s.handleStart)
	s.Mux.HandleFunc("/api/stop", s.handleStop)
	s.Mux.HandleFunc("/api/restart", s.handleRestart)
	s.Mux.HandleFunc("/api/generate", s.handleGenerate)
	s.Mux.HandleFunc("/api/apply-nft", s.handleApplyNft)
	s.Mux.HandleFunc("/api/update-resources", s.handleUpdateResources)
	s.Mux.HandleFunc("/api/nodes/main", s.handleSetMainNode)
	s.Mux.HandleFunc("/api/nodes/delete", s.handleDeleteNode)
	s.Mux.HandleFunc("/api/subscriptions", s.handleSubscriptions)
	s.Mux.HandleFunc("/api/subscriptions/update", s.handleSubUpdate)
	s.Mux.HandleFunc("/api/traffic", s.handleTraffic)
	s.Mux.HandleFunc("/api/dnsmasq-gfw", s.handleDNSMasqGFW)
	s.Mux.HandleFunc("/api/delay", s.handleDelay)
	s.Mux.HandleFunc("/api/logs", s.handleLogs)
	s.Mux.HandleFunc("/api/proxies", s.handleProxies)
}


func (s *Server) Handler() http.Handler {
	return s.cors(s.Mux)
}

func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.Handler())
}

// Wrap applies optional basic auth around the default handler.
func (s *Server) Wrap(user, pass string) http.Handler {
	h := s.Handler()
	if user == "" {
		return h
	}
	return BasicAuth(user, pass, h)
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.Mgr.Status())
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_ = s.Mgr.ReloadConfig()
		raw, _ := os.ReadFile(s.Mgr.ConfigPath)
		writeJSON(w, http.StatusOK, map[string]any{
			"config": s.Mgr.Cfg,
			"yaml":   string(raw),
		})
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		var cfg config.Config
		if err := json.Unmarshal(body, &cfg); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.Mgr.SaveConfig(&cfg); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "saved"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleConfigYAML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var cfg config.Config
	if err := yaml.Unmarshal([]byte(req.YAML), &cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.Mgr.SaveConfig(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// also write exact yaml text if user wants formatting preserved — SaveConfig re-marshals
	writeJSON(w, http.StatusOK, map[string]string{"ok": "saved"})
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.Mgr.Start(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "started"})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flush := true
	var req struct {
		FlushNft *bool `json:"flush_nft"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.FlushNft != nil {
		flush = *req.FlushNft
	}
	if err := s.Mgr.Stop(flush); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "stopped"})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.Mgr.Restart(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "restarted"})
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.Mgr.Generate(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "generated"})
}

func (s *Server) handleApplyNft(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.Mgr.ApplyNft(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "applied"})
}

func (s *Server) handleUpdateResources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.Mgr.UpdateResources(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "updated"})
}

// Optional basic auth middleware helper for future use.
func BasicAuth(user, pass string, next http.Handler) http.Handler {
	if user == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="homeproxy"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ParseListen(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ":8080"
	}
	if !strings.Contains(addr, ":") {
		return ":" + addr
	}
	return addr
}

func (s *Server) handleSetMainNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("name required"))
		return
	}
	if err := s.Mgr.SetMainNode(req.Name); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "main_node set"})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("name required"))
		return
	}
	if err := s.Mgr.DeleteNode(req.Name); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "deleted"})
}

func (s *Server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var sub config.Subscription
		if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.Mgr.AddSubscription(sub); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "added"})
	case http.MethodDelete:
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("name required"))
			return
		}
		if err := s.Mgr.RemoveSubscription(req.Name); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "removed"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSubUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name    string `json:"name"`
		Replace bool   `json:"replace"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	n, err := s.Mgr.UpdateSubscription(req.Name, req.Replace)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.Mgr.ReloadConfig()
	writeJSON(w, http.StatusOK, map[string]any{"ok": "updated", "nodes_added": n})
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := s.Mgr.ClashTraffic()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func (s *Server) handleDNSMasqGFW(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.Mgr.Generate(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "dnsmasq conf written (via generate)"})
}

func (s *Server) handleDelay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	url := r.URL.Query().Get("url")
	if r.Method == http.MethodPost {
		var req struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Name != "" {
			name = req.Name
		}
		if req.URL != "" {
			url = req.URL
		}
	}
	if name == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("name required"))
		return
	}
	data, err := s.Mgr.ProxyDelay(name, url, 5000)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	text, err := s.Mgr.TailLog(200)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"log": "", "hint": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"log": text})
}

func (s *Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := s.Mgr.ListProxies()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, data)
}
