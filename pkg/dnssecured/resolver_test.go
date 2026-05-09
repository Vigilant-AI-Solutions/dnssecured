package dnssecured

import "testing"

func TestNewResolverWithConfigDoT(t *testing.T) {
	resolver, err := NewResolverWithConfig(ResolverConfig{
		Mode:         ResolverModeDoT,
		DoTUpstreams: []string{"1.1.1.1", "8.8.8.8:853"},
		TLSPins:      []string{"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	})
	if err != nil {
		t.Fatalf("NewResolverWithConfig: %v", err)
	}
	if resolver == nil {
		t.Fatal("resolver is nil")
	}
}

func TestNewResolverWithConfigRejectsBadPin(t *testing.T) {
	_, err := NewResolverWithConfig(ResolverConfig{
		Mode:         ResolverModeDoT,
		DoTUpstreams: []string{"1.1.1.1"},
		TLSPins:      []string{"not-base64"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewResolverWithConfigRequiresDohUpstream(t *testing.T) {
	_, err := NewResolverWithConfig(ResolverConfig{
		Mode: ResolverModeDoH,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}
