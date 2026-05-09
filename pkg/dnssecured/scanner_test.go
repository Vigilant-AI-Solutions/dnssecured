package dnssecured

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

type fakeResolver struct {
	txt map[string][]string
	ns  map[string][]*net.NS
	err map[string]error
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if err, ok := f.err[name]; ok {
		return nil, err
	}
	if records, ok := f.txt[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name}
}

func (f fakeResolver) LookupMX(_ context.Context, _ string) ([]*net.MX, error) {
	return nil, errors.New("not used")
}

func (f fakeResolver) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	if records, ok := f.ns[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name}
}

func (f fakeResolver) LookupCNAME(_ context.Context, _ string) (string, error) {
	return "", errors.New("not used")
}

func useTestTLSProbe(t *testing.T, result tlsProbeResult, err error) {
	t.Helper()
	previous := probeTLSCertificate
	probeTLSCertificate = func(_ context.Context, _ string) (tlsProbeResult, error) {
		return result, err
	}
	t.Cleanup(func() {
		probeTLSCertificate = previous
	})
}

func TestScannerHealthyDomain(t *testing.T) {
	useTestTLSProbe(t, tlsProbeResult{
		Version:  tls.VersionTLS13,
		NotAfter: time.Now().UTC().Add(90 * 24 * time.Hour),
		Issuer:   "CN=ZeroSSL",
	}, nil)

	domain := "example.com"
	resolver := fakeResolver{
		txt: map[string][]string{
			domain:                    {"v=spf1 include:spf.example.net -all"},
			"s1._domainkey." + domain: {"v=DKIM1; k=rsa; p=abc"},
			"_dmarc." + domain:        {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
			"_mta-sts." + domain:      {"v=STSv1; id=2026010101"},
			"_smtp._tls." + domain:    {"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"},
			"default._bimi." + domain: {"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"},
		},
		ns: map[string][]*net.NS{
			domain: {
				{Host: "ns1.example.net."},
				{Host: "ns2.example.net."},
				{Host: "ns3.example.net."},
				{Host: "ns4.example.net."},
			},
		},
	}

	scanner := NewScanner(resolver)
	report, err := scanner.Scan(context.Background(), ScanRequest{
		TenantID:      "t1",
		Domain:        domain,
		DKIMSelectors: []string{"s1"},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if report.Summary.Failed != 0 || report.Summary.Errored != 0 {
		t.Fatalf("unexpected summary: %+v", report.Summary)
	}
	if report.PostureScore < 95 {
		t.Fatalf("score = %.2f, want >=95", report.PostureScore)
	}
}

func TestScannerBIMIWarnWhenMissingLogo(t *testing.T) {
	useTestTLSProbe(t, tlsProbeResult{
		Version:  tls.VersionTLS13,
		NotAfter: time.Now().UTC().Add(90 * 24 * time.Hour),
		Issuer:   "CN=ZeroSSL",
	}, nil)

	domain := "example.com"
	resolver := fakeResolver{
		txt: map[string][]string{
			domain:                    {"v=spf1 include:spf.example.net -all"},
			"s1._domainkey." + domain: {"v=DKIM1; k=rsa; p=abc"},
			"_dmarc." + domain:        {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
			"_mta-sts." + domain:      {"v=STSv1; id=2026010101"},
			"_smtp._tls." + domain:    {"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"},
			"default._bimi." + domain: {"v=BIMI1; a=https://example.com/vmc.pem"},
		},
		ns: map[string][]*net.NS{
			domain: {
				{Host: "ns1.example.net."},
				{Host: "ns2.example.net."},
				{Host: "ns3.example.net."},
				{Host: "ns4.example.net."},
			},
		},
	}
	scanner := NewScanner(resolver)
	report, err := scanner.Scan(context.Background(), ScanRequest{
		TenantID:      "t1",
		Domain:        domain,
		DKIMSelectors: []string{"s1"},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var bimi Finding
	found := false
	for _, finding := range report.Findings {
		if finding.Check == "bimi" {
			bimi = finding
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected bimi finding")
	}
	if bimi.Status != StatusWarn {
		t.Fatalf("bimi status = %s, want warn", bimi.Status)
	}
}

func TestScannerMissingRecords(t *testing.T) {
	useTestTLSProbe(t, tlsProbeResult{
		Version:  tls.VersionTLS13,
		NotAfter: time.Now().UTC().Add(90 * 24 * time.Hour),
		Issuer:   "CN=ZeroSSL",
	}, nil)

	domain := "example.com"
	resolver := fakeResolver{
		txt: map[string][]string{
			domain: {"v=spf1 include:spf.example.net ~all"},
		},
		ns: map[string][]*net.NS{
			domain: {
				{Host: "ns1.example.net."},
				{Host: "ns2.example.net."},
			},
		},
	}

	scanner := NewScanner(resolver)
	report, err := scanner.Scan(context.Background(), ScanRequest{
		TenantID: "t1",
		Domain:   domain,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if report.Summary.Failed == 0 {
		t.Fatalf("expected failures, got %+v", report.Summary)
	}
	if report.PostureScore >= 80 {
		t.Fatalf("score = %.2f, want <80", report.PostureScore)
	}
}

func TestScannerTLSWarnWhenExpiringSoon(t *testing.T) {
	useTestTLSProbe(t, tlsProbeResult{
		Version:  tls.VersionTLS13,
		NotAfter: time.Now().UTC().Add(10 * 24 * time.Hour),
		Issuer:   "CN=ZeroSSL",
	}, nil)

	domain := "example.com"
	resolver := fakeResolver{
		txt: map[string][]string{
			domain:                    {"v=spf1 include:spf.example.net -all"},
			"s1._domainkey." + domain: {"v=DKIM1; k=rsa; p=abc"},
			"_dmarc." + domain:        {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
			"_mta-sts." + domain:      {"v=STSv1; id=2026010101"},
			"_smtp._tls." + domain:    {"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"},
			"default._bimi." + domain: {"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"},
		},
		ns: map[string][]*net.NS{
			domain: {
				{Host: "ns1.example.net."},
				{Host: "ns2.example.net."},
				{Host: "ns3.example.net."},
				{Host: "ns4.example.net."},
			},
		},
	}
	scanner := NewScanner(resolver)
	report, err := scanner.Scan(context.Background(), ScanRequest{
		TenantID:      "t1",
		Domain:        domain,
		DKIMSelectors: []string{"s1"},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var tlsFinding Finding
	found := false
	for _, finding := range report.Findings {
		if finding.Check == "tls_certificate" {
			tlsFinding = finding
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected tls_certificate finding")
	}
	if tlsFinding.Status != StatusWarn {
		t.Fatalf("tls_certificate status = %s, want warn", tlsFinding.Status)
	}
}

type passOnlyCheck struct{}

func (passOnlyCheck) Name() string { return "custom_pass" }

func (passOnlyCheck) Run(_ context.Context, _ CheckInput) Finding {
	return Finding{
		Check:    "custom_pass",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "Custom check passed",
		Summary:  "custom pipeline ran",
	}
}

func TestScannerWithCustomChecks(t *testing.T) {
	scanner := NewScanner(fakeResolver{}, WithChecks(passOnlyCheck{}), WithTimeout(2*time.Second), WithMaxConcurrency(1))
	report, err := scanner.Scan(context.Background(), ScanRequest{
		TenantID: "t1",
		Domain:   "example.com",
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(report.Findings))
	}
	if report.Findings[0].Check != "custom_pass" {
		t.Fatalf("unexpected check: %+v", report.Findings[0])
	}
}

func TestChecksFromNamesRejectsUnknown(t *testing.T) {
	_, err := ChecksFromNames([]string{"unknown_check"})
	if err == nil {
		t.Fatal("expected error for unknown check")
	}
}
