package config

import "testing"

func TestParseDNSsecuredfile(t *testing.T) {
	cfg, err := ParseDNSsecuredfile(`
# DNSsecuredfile
listen :9443
cors false
default_tenant acme
timeout 7s
max_concurrency 6
checks ns_redundancy tls_certificate dmarc
nameservers 1.1.1.1 8.8.8.8:53
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.ListenAddress != ":9443" {
		t.Fatalf("listen=%q", cfg.ListenAddress)
	}
	if cfg.EnableCORS {
		t.Fatalf("cors should be false")
	}
	if cfg.DefaultTenant != "acme" {
		t.Fatalf("default_tenant=%q", cfg.DefaultTenant)
	}
	if cfg.Timeout.String() != "7s" {
		t.Fatalf("timeout=%s", cfg.Timeout)
	}
	if cfg.MaxConcurrency != 6 {
		t.Fatalf("max_concurrency=%d", cfg.MaxConcurrency)
	}
	if len(cfg.Checks) != 3 {
		t.Fatalf("checks=%v", cfg.Checks)
	}
	if len(cfg.Nameservers) != 2 {
		t.Fatalf("nameservers=%v", cfg.Nameservers)
	}
}

func TestParseDNSsecuredfileRejectsUnknownDirective(t *testing.T) {
	_, err := ParseDNSsecuredfile("banana true")
	if err == nil {
		t.Fatal("expected error")
	}
}
