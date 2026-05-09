package dnssecured

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupCNAME(ctx context.Context, name string) (string, error)
}

type NetResolver struct {
	Resolver *net.Resolver
}

type ResolverMode string

const (
	ResolverModeSystem ResolverMode = "system"
	ResolverModeUDP    ResolverMode = "udp"
	ResolverModeDoT    ResolverMode = "dot"
	ResolverModeDoH    ResolverMode = "doh"
)

type ResolverConfig struct {
	Mode          ResolverMode
	Nameservers   []string
	DoTUpstreams  []string
	DoHUpstreams  []string
	TLSServerName string
	TLSPins       []string
}

func NewNetResolver() *NetResolver {
	return &NetResolver{Resolver: net.DefaultResolver}
}

func NewNetResolverWithNameservers(nameservers []string) *NetResolver {
	normalized := make([]string, 0, len(nameservers))
	for _, ns := range nameservers {
		ns = normalizeNameserver(ns)
		if ns != "" {
			normalized = append(normalized, ns)
		}
	}
	if len(normalized) == 0 {
		return NewNetResolver()
	}
	var next atomic.Uint64
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			i := next.Add(1)
			target := normalized[(i-1)%uint64(len(normalized))]
			dialNetwork := network
			if !strings.HasPrefix(dialNetwork, "udp") && !strings.HasPrefix(dialNetwork, "tcp") {
				dialNetwork = "udp"
			}
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, dialNetwork, target)
		},
	}
	return &NetResolver{Resolver: resolver}
}

func NewResolverWithConfig(cfg ResolverConfig) (Resolver, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = ResolverModeSystem
	}
	switch mode {
	case ResolverModeSystem:
		return NewNetResolver(), nil
	case ResolverModeUDP:
		if len(cfg.Nameservers) == 0 {
			return nil, fmt.Errorf("resolver mode udp requires nameservers")
		}
		return NewNetResolverWithNameservers(cfg.Nameservers), nil
	case ResolverModeDoT:
		if len(cfg.DoTUpstreams) == 0 {
			return nil, fmt.Errorf("resolver mode dot requires dot upstreams")
		}
		return newAdvancedResolver(mode, cfg)
	case ResolverModeDoH:
		if len(cfg.DoHUpstreams) == 0 {
			return nil, fmt.Errorf("resolver mode doh requires doh upstreams")
		}
		return newAdvancedResolver(mode, cfg)
	default:
		return nil, fmt.Errorf("unsupported resolver mode %q", mode)
	}
}

func normalizeNameserver(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		return value
	}
	if strings.Count(value, ":") >= 2 && !strings.HasPrefix(value, "[") {
		return "[" + value + "]:53"
	}
	return net.JoinHostPort(value, "53")
}

type advancedResolver struct {
	mode          ResolverMode
	dotUpstreams  []string
	dohUpstreams  []string
	tlsServerName string
	tlsPins       [][]byte
	next          atomic.Uint64
}

func newAdvancedResolver(mode ResolverMode, cfg ResolverConfig) (*advancedResolver, error) {
	resolver := &advancedResolver{
		mode:          mode,
		tlsServerName: strings.TrimSpace(cfg.TLSServerName),
	}
	switch mode {
	case ResolverModeDoT:
		resolver.dotUpstreams = normalizeUpstreams(cfg.DoTUpstreams, "853")
		if len(resolver.dotUpstreams) == 0 {
			return nil, fmt.Errorf("no valid dot upstreams configured")
		}
	case ResolverModeDoH:
		resolver.dohUpstreams = normalizeDoHUpstreams(cfg.DoHUpstreams)
		if len(resolver.dohUpstreams) == 0 {
			return nil, fmt.Errorf("no valid doh upstreams configured")
		}
	}
	var err error
	resolver.tlsPins, err = parseTLSPins(cfg.TLSPins)
	if err != nil {
		return nil, err
	}
	return resolver, nil
}

func normalizeUpstreams(values []string, defaultPort string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(value); err == nil {
			out = append(out, value)
			continue
		}
		if strings.Count(value, ":") >= 2 && !strings.HasPrefix(value, "[") {
			out = append(out, "["+value+"]:"+defaultPort)
			continue
		}
		out = append(out, net.JoinHostPort(value, defaultPort))
	}
	return out
}

func normalizeDoHUpstreams(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
			continue
		}
		out = append(out, parsed.String())
	}
	return out
}

func parseTLSPins(values []string) ([][]byte, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([][]byte, 0, len(values))
	for _, value := range values {
		v := strings.TrimSpace(value)
		if strings.HasPrefix(strings.ToLower(v), "sha256/") {
			v = v[len("sha256/"):]
		}
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid tls pin %q: %w", value, err)
		}
		if len(raw) != sha256.Size {
			return nil, fmt.Errorf("invalid tls pin %q: expected %d-byte sha256", value, sha256.Size)
		}
		out = append(out, raw)
	}
	return out, nil
}

func buildTLSConfig(serverName string, pins [][]byte) *tls.Config {
	serverName = strings.TrimSpace(serverName)
	if len(pins) == 0 {
		return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("tls peer certificate missing")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].Raw)
			for _, pin := range pins {
				if bytes.Equal(pin, sum[:]) {
					return nil
				}
			}
			return fmt.Errorf("tls certificate pin mismatch")
		},
	}
}

func (r *advancedResolver) nextTarget(upstreams []string) string {
	i := r.next.Add(1)
	return upstreams[(i-1)%uint64(len(upstreams))]
}

func (r *advancedResolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true

	switch r.mode {
	case ResolverModeDoT:
		target := r.nextTarget(r.dotUpstreams)
		host, _, _ := net.SplitHostPort(target)
		serverName := r.tlsServerName
		if serverName == "" {
			serverName = host
		}
		client := &dns.Client{
			Net:       "tcp-tls",
			Timeout:   7 * time.Second,
			TLSConfig: buildTLSConfig(serverName, r.tlsPins),
		}
		resp, _, err := client.ExchangeContext(ctx, msg, target)
		if err != nil {
			return nil, err
		}
		return resp, nil
	case ResolverModeDoH:
		target := r.nextTarget(r.dohUpstreams)
		parsed, _ := url.Parse(target)
		serverName := r.tlsServerName
		if serverName == "" && parsed != nil {
			serverName = parsed.Hostname()
		}
		client := &dns.Client{
			Net:       "https",
			Timeout:   7 * time.Second,
			TLSConfig: buildTLSConfig(serverName, r.tlsPins),
		}
		resp, _, err := client.ExchangeContext(ctx, msg, target)
		if err != nil {
			return nil, err
		}
		return resp, nil
	default:
		return nil, fmt.Errorf("unsupported resolver mode %q", r.mode)
	}
}

func toNotFound(name string) error {
	return &net.DNSError{
		Err:        "no such host",
		Name:       name,
		Server:     "",
		IsNotFound: true,
	}
}

func (r *advancedResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	resp, err := r.query(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, toNotFound(name)
	}
	out := make([]string, 0)
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(txt.Txt, ""))
		}
	}
	if len(out) == 0 {
		return nil, toNotFound(name)
	}
	return out, nil
}

func (r *advancedResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	resp, err := r.query(ctx, name, dns.TypeMX)
	if err != nil {
		return nil, err
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, toNotFound(name)
	}
	out := make([]*net.MX, 0)
	for _, rr := range resp.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			out = append(out, &net.MX{
				Host: strings.TrimSuffix(mx.Mx, "."),
				Pref: mx.Preference,
			})
		}
	}
	if len(out) == 0 {
		return nil, toNotFound(name)
	}
	return out, nil
}

func (r *advancedResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	resp, err := r.query(ctx, name, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, toNotFound(name)
	}
	out := make([]*net.NS, 0)
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			out = append(out, &net.NS{
				Host: strings.TrimSuffix(ns.Ns, "."),
			})
		}
	}
	if len(out) == 0 {
		return nil, toNotFound(name)
	}
	return out, nil
}

func (r *advancedResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	resp, err := r.query(ctx, name, dns.TypeCNAME)
	if err != nil {
		return "", err
	}
	if resp.Rcode == dns.RcodeNameError {
		return "", toNotFound(name)
	}
	for _, rr := range resp.Answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			return strings.TrimSuffix(cn.Target, "."), nil
		}
	}
	return "", toNotFound(name)
}

func (r *NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.Resolver.LookupTXT(ctx, name)
}

func (r *NetResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return r.Resolver.LookupMX(ctx, name)
}

func (r *NetResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	return r.Resolver.LookupNS(ctx, name)
}

func (r *NetResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	return r.Resolver.LookupCNAME(ctx, name)
}
