package authoritative

import "strings"

type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
)

type Issue struct {
	Check          string   `json:"check"`
	Status         Status   `json:"status"`
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Summary        string   `json:"summary"`
	Recommendation string   `json:"recommendation,omitempty"`
}

type Config struct {
	Nameservers      []string `json:"nameservers"`
	HiddenPrimary    bool     `json:"hidden_primary"`
	TSIGRequired     bool     `json:"tsig_required"`
	XFRACL           []string `json:"xfr_acl,omitempty"`
	DNSCookies       bool     `json:"dns_cookies"`
	RRLEnabled       bool     `json:"rrl_enabled"`
	MinimalResponses bool     `json:"minimal_responses"`
}

type Report struct {
	PostureScore float64 `json:"posture_score"`
	Issues       []Issue `json:"issues"`
}

func Validate(cfg Config) Report {
	issues := []Issue{
		checkNSRedundancy(cfg),
		checkProviderDiversity(cfg),
		checkHiddenPrimary(cfg),
		checkTSIG(cfg),
		checkXFRACL(cfg),
		checkDNSCookies(cfg),
		checkRRL(cfg),
		checkMinimalResponses(cfg),
	}
	return Report{
		PostureScore: score(issues),
		Issues:       issues,
	}
}

func checkNSRedundancy(cfg Config) Issue {
	count := len(cfg.Nameservers)
	if count < 2 {
		return Issue{
			Check:          "ns_count",
			Status:         StatusFail,
			Severity:       SeverityHigh,
			Title:          "Insufficient nameserver redundancy",
			Summary:        "At least two authoritative nameservers are required.",
			Recommendation: "Run multiple authoritative nameservers in separate regions/failure domains.",
		}
	}
	if count < 4 {
		return Issue{
			Check:          "ns_count",
			Status:         StatusWarn,
			Severity:       SeverityLow,
			Title:          "Nameserver redundancy can be improved",
			Summary:        "Two nameservers are present; four or more is recommended for high-availability deployments.",
			Recommendation: "Add additional anycast/distributed nameservers for resilience.",
		}
	}
	return Issue{
		Check:    "ns_count",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "Nameserver redundancy healthy",
		Summary:  "Nameserver count meets high-availability baseline.",
	}
}

func checkProviderDiversity(cfg Config) Issue {
	parents := map[string]struct{}{}
	for _, ns := range cfg.Nameservers {
		parent := parentZone(ns)
		if parent != "" {
			parents[parent] = struct{}{}
		}
	}
	if len(parents) < 2 {
		return Issue{
			Check:          "ns_diversity",
			Status:         StatusWarn,
			Severity:       SeverityMedium,
			Title:          "Nameserver provider diversity appears low",
			Summary:        "Nameservers look concentrated under a single parent zone/provider.",
			Recommendation: "Use multiple independent DNS providers or separate authoritative infrastructures.",
		}
	}
	return Issue{
		Check:    "ns_diversity",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "Nameserver diversity healthy",
		Summary:  "Nameservers appear distributed across multiple parent zones.",
	}
}

func checkHiddenPrimary(cfg Config) Issue {
	if !cfg.HiddenPrimary {
		return Issue{
			Check:          "hidden_primary",
			Status:         StatusWarn,
			Severity:       SeverityMedium,
			Title:          "Hidden primary not enabled",
			Summary:        "Directly exposed primaries increase attack and operational risk.",
			Recommendation: "Use hidden primary with controlled AXFR/IXFR to public secondaries.",
		}
	}
	return Issue{
		Check:    "hidden_primary",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "Hidden primary enabled",
		Summary:  "Primary exposure is reduced.",
	}
}

func checkTSIG(cfg Config) Issue {
	if !cfg.TSIGRequired {
		return Issue{
			Check:          "tsig",
			Status:         StatusFail,
			Severity:       SeverityHigh,
			Title:          "TSIG not required for zone transfer/update paths",
			Summary:        "Unsigned transfer/update channels can be abused.",
			Recommendation: "Require TSIG for AXFR/IXFR and dynamic update operations.",
		}
	}
	return Issue{
		Check:    "tsig",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "TSIG requirement enabled",
		Summary:  "Transfer/update channel authentication is enabled.",
	}
}

func checkXFRACL(cfg Config) Issue {
	if len(cfg.XFRACL) == 0 {
		return Issue{
			Check:          "xfr_acl",
			Status:         StatusFail,
			Severity:       SeverityHigh,
			Title:          "Zone transfer ACL missing",
			Summary:        "Unrestricted transfers can leak authoritative zone data.",
			Recommendation: "Restrict zone transfers to approved secondaries only.",
		}
	}
	return Issue{
		Check:    "xfr_acl",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "Zone transfer ACL configured",
		Summary:  "Transfer scope is explicitly restricted.",
	}
}

func checkDNSCookies(cfg Config) Issue {
	if !cfg.DNSCookies {
		return Issue{
			Check:          "dns_cookies",
			Status:         StatusWarn,
			Severity:       SeverityMedium,
			Title:          "DNS Cookies not enabled",
			Summary:        "Cookies improve spoofing resistance and reflection abuse protection.",
			Recommendation: "Enable DNS Cookies on authoritative infrastructure.",
		}
	}
	return Issue{
		Check:    "dns_cookies",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "DNS Cookies enabled",
		Summary:  "Spoofing resistance controls are active.",
	}
}

func checkRRL(cfg Config) Issue {
	if !cfg.RRLEnabled {
		return Issue{
			Check:          "rrl",
			Status:         StatusWarn,
			Severity:       SeverityMedium,
			Title:          "Response rate limiting disabled",
			Summary:        "RRL helps mitigate reflection/amplification abuse during attacks.",
			Recommendation: "Enable response rate limiting with tuned thresholds.",
		}
	}
	return Issue{
		Check:    "rrl",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "Response rate limiting enabled",
		Summary:  "Abuse-throttling controls are active.",
	}
}

func checkMinimalResponses(cfg Config) Issue {
	if !cfg.MinimalResponses {
		return Issue{
			Check:          "minimal_responses",
			Status:         StatusWarn,
			Severity:       SeverityLow,
			Title:          "Minimal responses disabled",
			Summary:        "Large responses increase amplification potential.",
			Recommendation: "Enable minimal response mode to reduce unnecessary payload size.",
		}
	}
	return Issue{
		Check:    "minimal_responses",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "Minimal responses enabled",
		Summary:  "Amplification surface is reduced.",
	}
}

func score(issues []Issue) float64 {
	score := 100.0
	for _, issue := range issues {
		penalty := 0.0
		switch issue.Status {
		case StatusFail:
			switch issue.Severity {
			case SeverityHigh:
				penalty = 20
			case SeverityMedium:
				penalty = 12
			default:
				penalty = 8
			}
		case StatusWarn:
			switch issue.Severity {
			case SeverityHigh:
				penalty = 10
			case SeverityMedium:
				penalty = 6
			default:
				penalty = 3
			}
		}
		score -= penalty
	}
	if score < 0 {
		return 0
	}
	return score
}

func parentZone(host string) string {
	host = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(host), "."))
	if host == "" {
		return ""
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
