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
}

func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		ListenAddress:  ":8080",
		EnableCORS:     true,
		DefaultTenant:  "public",
		Timeout:        10 * time.Second,
		MaxConcurrency: 4,
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
