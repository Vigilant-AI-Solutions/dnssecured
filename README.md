# DNSsecured Tech Stack

DNSsecured is a reusable, library-first DNS security stack in Go for building hardened email and domain security platforms.

## Core stack architecture

- **Security engine**: pluggable check pipeline with bounded concurrent execution
- **Resolver abstraction**: replaceable DNS resolver layer (`net.Resolver` default)
- **Policy checks**: NS redundancy, DNSSEC validation, DANE/TLSA posture, TLS certificate posture, SPF, DKIM selector health, DMARC, MTA-STS, TLS-RPT, BIMI
- **Scoring model**: posture score + normalized findings for downstream automation
- **Service runtime**: lightweight HTTP façade for integration and demos

## Why this is reusable

- Runs as both an **embedded library** and a **standalone service**
- Supports custom checks through `WithChecks(...)`
- Supports performance tuning via `WithTimeout(...)` and `WithMaxConcurrency(...)`
- Keeps proprietary intelligence outside this repo while exposing production-grade infrastructure primitives

## Recent hardening upgrades

- **NS1-style resilience**: added authoritative nameserver redundancy analysis (`ns_redundancy`) to flag weak DNS fault tolerance.
- **ZeroSSL-aligned SSL control**: added HTTPS certificate posture validation (`tls_certificate`) for expiry and modern TLS enforcement to support automated renewal operations.

## CLI (Caddy-style commands)

```bash
dnssecured run --config ./DNSsecuredfile
dnssecured validate --config ./DNSsecuredfile
dnssecured list-checks
dnssecured version
```

If no command is provided, `dnssecured` defaults to `run`.

## Quick start (service mode)

```bash
go run ./cmd/dnssecured run --config ./DNSsecuredfile
```

Optional environment variable:

- `DNSSECURED_ADDR` (default `:8080`)
- `DNSSECURED_CONFIG` (path to custom `DNSsecuredfile`)

## DNSsecuredfile (Caddy-style custom config)

Create `DNSsecuredfile` in the app root (or set `DNSSECURED_CONFIG`):

```txt
listen :8080
cors true
default_tenant public
timeout 10s
max_concurrency 4
checks ns_redundancy dnssec_validation dane_tlsa tls_certificate spf dkim_selector_health dmarc mta_sts tls_rpt bimi
nameservers 1.1.1.1 1.0.0.1 8.8.8.8:53
resolver_mode dot
dot_upstreams 1.1.1.1 1.0.0.1
tls_server_name cloudflare-dns.com
# tls_pins sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
```

Supported directives:

- `listen` — HTTP listen address
- `cors` — enable/disable CORS middleware
- `default_tenant` — tenant used when request omits `tenant_id`
- `timeout` — per-check timeout duration
- `max_concurrency` — maximum concurrent checks
- `checks` — enabled checks in execution order
- `nameservers` — custom DNS resolver targets used for lookups
- `resolver_mode` — `system`, `udp`, `dot`, or `doh`
- `dot_upstreams` — DNS-over-TLS upstreams (`host` or `host:port`)
- `doh_upstreams` — DNS-over-HTTPS upstream URLs (`https://.../dns-query`)
- `tls_server_name` — optional TLS SNI/hostname override for `dot`/`doh`
- `tls_pins` — optional SHA-256 certificate pins (`sha256/<base64>`) for `dot`/`doh`

## HTTP API

- `GET /healthz`
- `POST /v1/scan` (compatibility)
- `POST /v1/analyze` (preferred)
- `POST /v1/authoritative/validate` (authoritative nameserver hardening posture)
- `POST /v1/dnssec/plan` (DNSSEC rollover/automation planning)
- `POST /v1/steering/decision` (health + latency aware traffic-steering decision)

Request body:

```json
{
  "tenant_id": "public",
  "domain": "example.com",
  "dkim_selectors": ["s1", "default"]
}
```

## Library embedding

```go
resolver := dnssecured.NewNetResolver()
scanner := dnssecured.NewScanner(
    resolver,
    dnssecured.WithTimeout(8*time.Second),
    dnssecured.WithMaxConcurrency(6),
)

result, err := scanner.Scan(ctx, dnssecured.ScanRequest{
    TenantID: "public",
    Domain:   "example.com",
})
```

## Project layout

- `pkg/dnssecured/` core engine, resolver abstraction, checks, and types
- `pkg/authoritative/` authoritative DNS security posture validator
- `pkg/dnssec/` DNSSEC rollover planning engine
- `pkg/steering/` traffic-steering policy engine
- `cmd/dnssecured/` standalone runtime for API usage
- `site/` static project website (`index.html`, `docs.html`, `styles.css`)

## Static project site

The repository includes a static site inspired by infrastructure-first product docs:

- `site/index.html` - value proposition and stack overview
- `site/docs.html` - quick docs, API summary, and deployment snippet
- `site/assets/` - DNSsecured logo, favicon, and Resolvora sponsorship logo

Host it with any static server (Caddy, nginx, GitHub Pages, or object storage CDN).
