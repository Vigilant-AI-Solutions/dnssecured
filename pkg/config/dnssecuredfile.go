package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type RuntimeConfig struct {
	ListenAddress  string
	EnableCORS     bool
	DefaultTenant  string
	Timeout        time.Duration
	MaxConcurrency int
	Checks         []string
	Nameservers    []string
	ResolverMode   string
	DoTUpstreams   []string
	DoHUpstreams   []string
	TLSServerName  string
	TLSPins        []string
}

func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		ListenAddress:  ":8080",
		EnableCORS:     true,
		DefaultTenant:  "public",
		Timeout:        10 * time.Second,
		MaxConcurrency: 4,
		ResolverMode:   "system",
	}
}

func ParseDNSsecuredfile(content string) (RuntimeConfig, error) {
	cfg := DefaultRuntimeConfig()
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if trimmed == "{" || trimmed == "}" || strings.HasSuffix(trimmed, "{") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		args := fields[1:]
		switch key {
		case "listen":
			if len(args) != 1 {
				return RuntimeConfig{}, fmt.Errorf("line %d: listen expects 1 value", lineNo)
			}
			cfg.ListenAddress = args[0]
		case "cors":
			if len(args) != 1 {
				return RuntimeConfig{}, fmt.Errorf("line %d: cors expects true or false", lineNo)
			}
			v, err := strconv.ParseBool(args[0])
			if err != nil {
				return RuntimeConfig{}, fmt.Errorf("line %d: invalid cors value %q", lineNo, args[0])
			}
			cfg.EnableCORS = v
		case "default_tenant":
			if len(args) != 1 {
				return RuntimeConfig{}, fmt.Errorf("line %d: default_tenant expects 1 value", lineNo)
			}
			cfg.DefaultTenant = args[0]
		case "timeout":
			if len(args) != 1 {
				return RuntimeConfig{}, fmt.Errorf("line %d: timeout expects 1 duration", lineNo)
			}
			d, err := time.ParseDuration(args[0])
			if err != nil {
				return RuntimeConfig{}, fmt.Errorf("line %d: invalid timeout %q", lineNo, args[0])
			}
			cfg.Timeout = d
		case "max_concurrency":
			if len(args) != 1 {
				return RuntimeConfig{}, fmt.Errorf("line %d: max_concurrency expects 1 integer", lineNo)
			}
			n, err := strconv.Atoi(args[0])
			if err != nil || n <= 0 {
				return RuntimeConfig{}, fmt.Errorf("line %d: invalid max_concurrency %q", lineNo, args[0])
			}
			cfg.MaxConcurrency = n
		case "checks":
			if len(args) == 0 {
				return RuntimeConfig{}, fmt.Errorf("line %d: checks expects one or more check names", lineNo)
			}
			cfg.Checks = append([]string(nil), args...)
		case "nameservers":
			if len(args) == 0 {
				return RuntimeConfig{}, fmt.Errorf("line %d: nameservers expects one or more values", lineNo)
			}
			cfg.Nameservers = append([]string(nil), args...)
		case "resolver_mode":
			if len(args) != 1 {
				return RuntimeConfig{}, fmt.Errorf("line %d: resolver_mode expects 1 value", lineNo)
			}
			mode := strings.ToLower(strings.TrimSpace(args[0]))
			switch mode {
			case "system", "udp", "dot", "doh":
				cfg.ResolverMode = mode
			default:
				return RuntimeConfig{}, fmt.Errorf("line %d: resolver_mode must be one of system|udp|dot|doh", lineNo)
			}
		case "dot_upstreams":
			if len(args) == 0 {
				return RuntimeConfig{}, fmt.Errorf("line %d: dot_upstreams expects one or more values", lineNo)
			}
			cfg.DoTUpstreams = append([]string(nil), args...)
		case "doh_upstreams":
			if len(args) == 0 {
				return RuntimeConfig{}, fmt.Errorf("line %d: doh_upstreams expects one or more values", lineNo)
			}
			cfg.DoHUpstreams = append([]string(nil), args...)
		case "tls_server_name":
			if len(args) != 1 {
				return RuntimeConfig{}, fmt.Errorf("line %d: tls_server_name expects 1 value", lineNo)
			}
			cfg.TLSServerName = args[0]
		case "tls_pins":
			if len(args) == 0 {
				return RuntimeConfig{}, fmt.Errorf("line %d: tls_pins expects one or more values", lineNo)
			}
			cfg.TLSPins = append([]string(nil), args...)
		default:
			return RuntimeConfig{}, fmt.Errorf("line %d: unknown directive %q", lineNo, key)
		}
	}
	return cfg, nil
}

func LoadDNSsecuredfile(path string) (RuntimeConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return RuntimeConfig{}, err
	}
	return ParseDNSsecuredfile(string(raw))
}
