package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Vigilant-AI-Solutions/dnssecured/pkg/config"
	"github.com/Vigilant-AI-Solutions/dnssecured/pkg/dnssecured"
)

type scanRequest struct {
	TenantID      string   `json:"tenant_id,omitempty"`
	Domain        string   `json:"domain"`
	DKIMSelectors []string `json:"dkim_selectors,omitempty"`
}

func main() {
	cfg, source, err := loadRuntimeConfig()
	if err != nil {
		log.Fatal(err)
	}

	checks, err := dnssecured.ChecksFromNames(cfg.Checks)
	if err != nil {
		log.Fatalf("invalid checks in config: %v", err)
	}
	resolver, err := dnssecured.NewResolverWithConfig(dnssecured.ResolverConfig{
		Mode:          dnssecured.ResolverMode(cfg.ResolverMode),
		Nameservers:   cfg.Nameservers,
		DoTUpstreams:  cfg.DoTUpstreams,
		DoHUpstreams:  cfg.DoHUpstreams,
		TLSServerName: cfg.TLSServerName,
		TLSPins:       cfg.TLSPins,
	})
	if err != nil {
		log.Fatalf("invalid resolver config: %v", err)
	}
	scanner := dnssecured.NewScanner(
		resolver,
		dnssecured.WithTimeout(cfg.Timeout),
		dnssecured.WithMaxConcurrency(cfg.MaxConcurrency),
		dnssecured.WithChecks(checks...),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/scan", func(w http.ResponseWriter, r *http.Request) {
		handleScan(w, r, scanner, cfg.DefaultTenant)
	})
	mux.HandleFunc("POST /v1/analyze", func(w http.ResponseWriter, r *http.Request) {
		handleScan(w, r, scanner, cfg.DefaultTenant)
	})

	handler := http.Handler(mux)
	if cfg.EnableCORS {
		handler = withCORS(handler)
	}
	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("dnssecured listening on %s (config: %s)", cfg.ListenAddress, source)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func loadRuntimeConfig() (config.RuntimeConfig, string, error) {
	envPath := strings.TrimSpace(os.Getenv("DNSSECURED_CONFIG"))
	addrEnv := strings.TrimSpace(os.Getenv("DNSSECURED_ADDR"))
	if envPath != "" {
		cfg, err := config.LoadDNSsecuredfile(envPath)
		if err != nil {
			return config.RuntimeConfig{}, "", fmt.Errorf("failed to load DNSsecured config %q: %w", envPath, err)
		}
		if addrEnv != "" {
			cfg.ListenAddress = addrEnv
		}
		return cfg, envPath, nil
	}

	defaultPath := filepath.Join(".", "DNSsecuredfile")
	cfg := config.DefaultRuntimeConfig()
	if _, err := os.Stat(defaultPath); err == nil {
		fileCfg, err := config.LoadDNSsecuredfile(defaultPath)
		if err != nil {
			return config.RuntimeConfig{}, "", fmt.Errorf("failed to load DNSsecuredfile: %w", err)
		}
		cfg = fileCfg
		if addrEnv != "" {
			cfg.ListenAddress = addrEnv
		}
		return cfg, defaultPath, nil
	}
	if addrEnv != "" {
		cfg.ListenAddress = addrEnv
	}
	return cfg, "defaults", nil
}

func handleScan(w http.ResponseWriter, r *http.Request, scanner *dnssecured.Scanner, defaultTenant string) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	req.Domain = strings.TrimSpace(strings.ToLower(req.Domain))
	if req.Domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = defaultTenant
	}

	report, err := scanner.Scan(r.Context(), dnssecured.ScanRequest{
		TenantID:      tenantID,
		Domain:        req.Domain,
		DKIMSelectors: req.DKIMSelectors,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "scan failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, report)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
