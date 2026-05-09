package dnssecured

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"time"
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
