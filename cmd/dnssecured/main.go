package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Vigilant-AI-Solutions/dnssecured/pkg/authoritative"
	"github.com/Vigilant-AI-Solutions/dnssecured/pkg/config"
	"github.com/Vigilant-AI-Solutions/dnssecured/pkg/dnssec"
	"github.com/Vigilant-AI-Solutions/dnssecured/pkg/dnssecured"
	"github.com/Vigilant-AI-Solutions/dnssecured/pkg/steering"
)

type scanRequest struct {
	TenantID      string   `json:"tenant_id,omitempty"`
	Domain        string   `json:"domain"`
	DKIMSelectors []string `json:"dkim_selectors,omitempty"`
}

type dnssecPlanRequest struct {
	Policy dnssec.Policy `json:"policy"`
	State  dnssec.State  `json:"state"`
}

type steeringDecisionRequest struct {
	Policy    steering.Policy     `json:"policy"`
	Endpoints []steering.Endpoint `json:"endpoints"`
}

const version = "0.1.0"

func main() {
	if err := runCLI(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		log.Fatal(err)
	}
}

func runCLI(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return runServer("", "", stdout)
	}
	switch args[0] {
	case "run":
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "", "Path to DNSsecuredfile")
		addr := fs.String("addr", "", "Listen address override")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return runServer(*configPath, *addr, stdout)
	case "validate":
		fs := flag.NewFlagSet("validate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "", "Path to DNSsecuredfile")
		addr := fs.String("addr", "", "Listen address override")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, source, err := loadRuntimeConfig(*configPath, *addr)
		if err != nil {
			return err
		}
		if _, err := buildScanner(cfg); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "Config OK (%s)\n", source)
		return nil
	case "list-checks":
		for _, name := range dnssecured.AvailableCheckNames() {
			_, _ = fmt.Fprintln(stdout, name)
		}
		return nil
	case "version":
		_, _ = fmt.Fprintf(stdout, "dnssecured %s\n", version)
		return nil
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "dnssecured - security-first DNS stack")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  dnssecured run [--config <path>] [--addr <listen>]")
	_, _ = fmt.Fprintln(w, "  dnssecured validate [--config <path>] [--addr <listen>]")
	_, _ = fmt.Fprintln(w, "  dnssecured list-checks")
	_, _ = fmt.Fprintln(w, "  dnssecured version")
	_, _ = fmt.Fprintln(w, "  dnssecured help")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "If no command is provided, dnssecured behaves like: dnssecured run")
}

func runServer(configPath, addrOverride string, stdout io.Writer) error {
	cfg, source, err := loadRuntimeConfig(configPath, addrOverride)
	if err != nil {
		return err
	}

	scanner, err := buildScanner(cfg)
	if err != nil {
		return err
	}

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
	mux.HandleFunc("POST /v1/authoritative/validate", handleAuthoritativeValidation)
	mux.HandleFunc("POST /v1/dnssec/plan", handleDNSSECPlan)
	mux.HandleFunc("POST /v1/steering/decision", handleSteeringDecision)

	handler := http.Handler(mux)
	if cfg.EnableCORS {
		handler = withCORS(handler)
	}
	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	_, _ = fmt.Fprintf(stdout, "dnssecured listening on %s (config: %s)\n", cfg.ListenAddress, source)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func buildScanner(cfg config.RuntimeConfig) (*dnssecured.Scanner, error) {
	checks, err := dnssecured.ChecksFromNames(cfg.Checks)
	if err != nil {
		return nil, fmt.Errorf("invalid checks in config: %w", err)
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
		return nil, fmt.Errorf("invalid resolver config: %w", err)
	}
	return dnssecured.NewScanner(
		resolver,
		dnssecured.WithTimeout(cfg.Timeout),
		dnssecured.WithMaxConcurrency(cfg.MaxConcurrency),
		dnssecured.WithChecks(checks...),
	), nil
}

func loadRuntimeConfig(configPath, addrOverride string) (config.RuntimeConfig, string, error) {
	if strings.TrimSpace(configPath) == "" {
		configPath = strings.TrimSpace(os.Getenv("DNSSECURED_CONFIG"))
	}
	addr := strings.TrimSpace(addrOverride)
	if addr == "" {
		addr = strings.TrimSpace(os.Getenv("DNSSECURED_ADDR"))
	}
	if configPath != "" {
		cfg, err := config.LoadDNSsecuredfile(configPath)
		if err != nil {
			return config.RuntimeConfig{}, "", fmt.Errorf("failed to load DNSsecured config %q: %w", configPath, err)
		}
		if addr != "" {
			cfg.ListenAddress = addr
		}
		return cfg, configPath, nil
	}

	defaultPath := filepath.Join(".", "DNSsecuredfile")
	cfg := config.DefaultRuntimeConfig()
	if _, err := os.Stat(defaultPath); err == nil {
		fileCfg, err := config.LoadDNSsecuredfile(defaultPath)
		if err != nil {
			return config.RuntimeConfig{}, "", fmt.Errorf("failed to load DNSsecuredfile: %w", err)
		}
		cfg = fileCfg
		if addr != "" {
			cfg.ListenAddress = addr
		}
		return cfg, defaultPath, nil
	}
	if addr != "" {
		cfg.ListenAddress = addr
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

func handleAuthoritativeValidation(w http.ResponseWriter, r *http.Request) {
	var req authoritative.Config
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, authoritative.Validate(req))
}

func handleDNSSECPlan(w http.ResponseWriter, r *http.Request) {
	var req dnssecPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	plan, err := dnssec.BuildPlan(req.Policy, req.State)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to build dnssec plan: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func handleSteeringDecision(w http.ResponseWriter, r *http.Request) {
	var req steeringDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	decision, err := steering.Select(req.Policy, req.Endpoints)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to compute steering decision: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, decision)
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
