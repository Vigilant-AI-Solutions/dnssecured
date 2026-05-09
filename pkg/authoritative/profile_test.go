package authoritative

import "testing"

func TestValidateStrongProfile(t *testing.T) {
	report := Validate(Config{
		Nameservers:      []string{"ns1.provider-a.net", "ns2.provider-a.net", "ns1.provider-b.net", "ns2.provider-b.net"},
		HiddenPrimary:    true,
		TSIGRequired:     true,
		XFRACL:           []string{"198.51.100.20/32"},
		DNSCookies:       true,
		RRLEnabled:       true,
		MinimalResponses: true,
	})
	if report.PostureScore < 90 {
		t.Fatalf("score=%.2f", report.PostureScore)
	}
}

func TestValidateWeakProfile(t *testing.T) {
	report := Validate(Config{
		Nameservers: []string{"ns1.example.com"},
	})
	if report.PostureScore >= 70 {
		t.Fatalf("score=%.2f", report.PostureScore)
	}
}
