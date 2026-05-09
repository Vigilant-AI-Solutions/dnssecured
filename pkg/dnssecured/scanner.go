package dnssecured

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Scanner struct {
	Resolver       Resolver
	Timeout        time.Duration
	MaxConcurrency int
	checks         []Check
}

type ScannerOption func(*Scanner)

func NewScanner(resolver Resolver, opts ...ScannerOption) *Scanner {
	s := &Scanner{
		Resolver: resolver,
		Timeout:  10 * time.Second,
		// Bounded parallelism keeps scans fast while avoiding resolver overload.
		MaxConcurrency: 4,
		checks:         defaultChecks(),
	}
	for _, opt := range opts {
		opt(s)
	}
	if len(s.checks) == 0 {
		s.checks = defaultChecks()
	}
	if s.MaxConcurrency <= 0 {
		s.MaxConcurrency = 1
	}
	return s
}

func defaultChecks() []Check {
	return []Check{
		nsRedundancyCheck{},
		tlsCertificateCheck{},
		spfCheck{},
		dkimCheck{},
		dmarcCheck{},
		mtaSTSCheck{},
		tlsRPTCheck{},
		bimiCheck{},
	}
}

func AvailableCheckNames() []string {
	return []string{
		"ns_redundancy",
		"tls_certificate",
		"spf",
		"dkim_selector_health",
		"dmarc",
		"mta_sts",
		"tls_rpt",
		"bimi",
	}
}

func ChecksFromNames(names []string) ([]Check, error) {
	if len(names) == 0 {
		return defaultChecks(), nil
	}
	out := make([]Check, 0, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(strings.ToLower(raw))
		switch name {
		case "ns_redundancy":
			out = append(out, nsRedundancyCheck{})
		case "tls_certificate":
			out = append(out, tlsCertificateCheck{})
		case "spf":
			out = append(out, spfCheck{})
		case "dkim_selector_health":
			out = append(out, dkimCheck{})
		case "dmarc":
			out = append(out, dmarcCheck{})
		case "mta_sts":
			out = append(out, mtaSTSCheck{})
		case "tls_rpt":
			out = append(out, tlsRPTCheck{})
		case "bimi":
			out = append(out, bimiCheck{})
		default:
			return nil, fmt.Errorf("unknown check %q", raw)
		}
	}
	return out, nil
}

func WithChecks(checks ...Check) ScannerOption {
	normalized := append([]Check(nil), checks...)
	return func(s *Scanner) {
		s.checks = normalized
	}
}

func WithTimeout(timeout time.Duration) ScannerOption {
	return func(s *Scanner) {
		s.Timeout = timeout
	}
}

func WithMaxConcurrency(n int) ScannerOption {
	return func(s *Scanner) {
		s.MaxConcurrency = n
	}
}

func (s *Scanner) Scan(ctx context.Context, req ScanRequest) (Report, error) {
	domain := normalizeDomain(req.Domain)
	if domain == "" {
		return Report{}, fmt.Errorf("domain is required")
	}
	selectors := normalizeSelectors(req.DKIMSelectors)
	if s.Resolver == nil {
		return Report{}, fmt.Errorf("dns resolver not configured")
	}

	start := time.Now().UTC()
	report := Report{
		ID:            uuid.NewString(),
		TenantID:      strings.TrimSpace(req.TenantID),
		Domain:        domain,
		DKIMSelectors: selectors,
		StartedAt:     start,
	}

	input := CheckInput{
		Domain:        domain,
		DKIMSelectors: selectors,
		Resolver:      s.Resolver,
	}
	report.Findings = s.runChecks(ctx, input)

	report.PostureScore = scoreFindings(report.Findings)
	report.Summary = summarize(report.Findings)
	report.CompletedAt = time.Now().UTC()
	return report, nil
}

func (s *Scanner) runChecks(ctx context.Context, input CheckInput) []Finding {
	if len(s.checks) == 0 {
		return nil
	}
	type workItem struct {
		index int
		check Check
	}
	workers := s.MaxConcurrency
	if workers > len(s.checks) {
		workers = len(s.checks)
	}
	if workers <= 0 {
		workers = 1
	}

	work := make(chan workItem)
	out := make([]Finding, len(s.checks))
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range work {
				checkCtx := ctx
				if s.Timeout > 0 {
					var cancel context.CancelFunc
					checkCtx, cancel = context.WithTimeout(ctx, s.Timeout)
					out[item.index] = item.check.Run(checkCtx, input)
					cancel()
					continue
				}
				out[item.index] = item.check.Run(checkCtx, input)
			}
		}()
	}
	for i, check := range s.checks {
		work <- workItem{index: i, check: check}
	}
	close(work)
	wg.Wait()
	return out
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func normalizeSelectors(selectors []string) []string {
	out := make([]string, 0, len(selectors)+2)
	add := func(v string) {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "" || slices.Contains(out, v) {
			return
		}
		out = append(out, v)
	}
	for _, selector := range selectors {
		add(selector)
	}
	if len(out) == 0 {
		add("s1")
		add("default")
	}
	return out
}

func summarize(findings []Finding) Summary {
	var s Summary
	for _, finding := range findings {
		switch finding.Status {
		case StatusPass:
			s.Passed++
		case StatusWarn:
			s.Warned++
		case StatusFail:
			s.Failed++
		case StatusError:
			s.Errored++
		}
	}
	return s
}

func scoreFindings(findings []Finding) float64 {
	score := 100.0
	for _, finding := range findings {
		var penalty float64
		switch finding.Status {
		case StatusFail:
			switch finding.Severity {
			case SeverityHigh:
				penalty = 25
			case SeverityMedium:
				penalty = 15
			default:
				penalty = 8
			}
		case StatusWarn:
			switch finding.Severity {
			case SeverityHigh:
				penalty = 12
			case SeverityMedium:
				penalty = 8
			default:
				penalty = 4
			}
		case StatusError:
			penalty = 10
		}
		score -= penalty
	}
	if score < 0 {
		score = 0
	}
	return score
}
