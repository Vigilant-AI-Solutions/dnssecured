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
resolver_mode dot
dot_upstreams 1.1.1.1 8.8.8.8:853
tls_server_name cloudflare-dns.com
tls_pins sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
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
	if cfg.ResolverMode != "dot" {
		t.Fatalf("resolver_mode=%q", cfg.ResolverMode)
	}
	if len(cfg.DoTUpstreams) != 2 {
		t.Fatalf("dot_upstreams=%v", cfg.DoTUpstreams)
	}
	if cfg.TLSServerName != "cloudflare-dns.com" {
		t.Fatalf("tls_server_name=%q", cfg.TLSServerName)
	}
	if len(cfg.TLSPins) != 1 {
		t.Fatalf("tls_pins=%v", cfg.TLSPins)
	}
}

func TestParseDNSsecuredfileRejectsUnknownDirective(t *testing.T) {
	_, err := ParseDNSsecuredfile("banana true")
	if err == nil {
		t.Fatal("expected error")
	}
}
