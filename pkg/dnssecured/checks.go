package dnssecured

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type spfCheck struct{}

func (spfCheck) Name() string { return "spf" }

func (spfCheck) Run(ctx context.Context, input CheckInput) Finding {
	txt, err := input.Resolver.LookupTXT(ctx, input.Domain)
	if err != nil {
		return Finding{
			Check:    "spf",
			Status:   StatusError,
			Severity: SeverityMedium,
			Title:    "SPF lookup failed",
			Summary:  err.Error(),
		}
	}
	spfRecords := findTXTWithPrefix(txt, "v=spf1")
	if len(spfRecords) == 0 {
		return Finding{
			Check:    "spf",
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "SPF record missing",
			Summary:  "No SPF TXT record found at the root domain.",
			Remediation: []string{
				"Publish a TXT record at the domain root beginning with v=spf1.",
				"Authorize only your approved sending infrastructure.",
			},
		}
	}
	if len(spfRecords) > 1 {
		return Finding{
			Check:    "spf",
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "Multiple SPF records found",
			Summary:  "Exactly one SPF record should exist for a domain.",
			Evidence: spfRecords,
			Remediation: []string{
				"Consolidate SPF into a single TXT record.",
			},
		}
	}
	record := strings.ToLower(strings.TrimSpace(spfRecords[0]))
	if strings.Contains(record, "-all") {
		return Finding{
			Check:    "spf",
			Status:   StatusPass,
			Severity: SeverityLow,
			Title:    "SPF record present",
			Summary:  "SPF uses hard fail (-all).",
			Evidence: []string{spfRecords[0]},
		}
	}
	if strings.Contains(record, "~all") {
		return Finding{
			Check:    "spf",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "SPF uses soft fail",
			Summary:  "Soft fail (~all) provides weaker spoofing protection than -all.",
			Evidence: []string{spfRecords[0]},
			Remediation: []string{
				"Move toward -all after validating authorized senders.",
			},
		}
	}
	return Finding{
		Check:    "spf",
		Status:   StatusWarn,
		Severity: SeverityLow,
		Title:    "SPF terminal policy should be explicit",
		Summary:  "SPF record does not end with -all or ~all.",
		Evidence: []string{spfRecords[0]},
	}
}

type dkimCheck struct{}

func (dkimCheck) Name() string { return "dkim_selector_health" }

func (dkimCheck) Run(ctx context.Context, input CheckInput) Finding {
	missing := make([]string, 0)
	found := make([]string, 0)
	malformed := make([]string, 0)
	for _, selector := range input.DKIMSelectors {
		host := fmt.Sprintf("%s._domainkey.%s", selector, input.Domain)
		txt, err := input.Resolver.LookupTXT(ctx, host)
		if err != nil {
			var dnsErr *net.DNSError
			notFound := errors.As(err, &dnsErr) && dnsErr != nil && (dnsErr.IsNotFound || strings.Contains(strings.ToLower(dnsErr.Err), "no such host"))
			if !notFound && !strings.Contains(strings.ToLower(err.Error()), "no such host") && !strings.Contains(strings.ToLower(err.Error()), "nxdomain") && !strings.Contains(strings.ToLower(err.Error()), "does not exist") {
				return Finding{
					Check:    "dkim_selector_health",
					Status:   StatusError,
					Severity: SeverityMedium,
					Title:    "DKIM lookup failed",
					Summary:  err.Error(),
				}
			}
			missing = append(missing, selector)
			continue
		}
		match := findTXTWithPrefix(txt, "v=dkim1")
		if len(match) == 0 {
			malformed = append(malformed, selector)
			continue
		}
		valid := false
		for _, rec := range match {
			if strings.Contains(strings.ToLower(rec), "p=") {
				valid = true
				found = append(found, selector)
				break
			}
		}
		if !valid {
			malformed = append(malformed, selector)
		}
	}
	if len(found) == 0 {
		return Finding{
			Check:    "dkim_selector_health",
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "No healthy DKIM selectors found",
			Summary:  "None of the checked selectors resolved to a valid DKIM key.",
			Evidence: []string{fmt.Sprintf("checked selectors: %s", strings.Join(input.DKIMSelectors, ", "))},
			Remediation: []string{
				"Publish a TXT record at <selector>._domainkey.<domain> with v=DKIM1 and p=.",
			},
		}
	}
	if len(missing) > 0 || len(malformed) > 0 {
		evidence := []string{}
		if len(missing) > 0 {
			evidence = append(evidence, "missing selectors: "+strings.Join(missing, ", "))
		}
		if len(malformed) > 0 {
			evidence = append(evidence, "malformed selectors: "+strings.Join(malformed, ", "))
		}
		return Finding{
			Check:    "dkim_selector_health",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "Some DKIM selectors are unhealthy",
			Summary:  "At least one selector was missing or malformed.",
			Evidence: evidence,
			Remediation: []string{
				"Ensure all active selectors have valid TXT records containing v=DKIM1 and p=.",
			},
		}
	}
	return Finding{
		Check:    "dkim_selector_health",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "DKIM selectors are healthy",
		Summary:  "Checked selectors resolved to valid DKIM records.",
		Evidence: []string{fmt.Sprintf("healthy selectors: %s", strings.Join(found, ", "))},
	}
}

type dmarcCheck struct{}

func (dmarcCheck) Name() string { return "dmarc" }

func (dmarcCheck) Run(ctx context.Context, input CheckInput) Finding {
	host := "_dmarc." + input.Domain
	txt, err := input.Resolver.LookupTXT(ctx, host)
	if err != nil {
		return Finding{
			Check:    "dmarc",
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "DMARC record missing",
			Summary:  "No DMARC TXT record found.",
			Remediation: []string{
				"Publish TXT at _dmarc.<domain> with v=DMARC1 and a policy.",
			},
		}
	}
	records := findTXTWithPrefix(txt, "v=dmarc1")
	if len(records) == 0 {
		return Finding{
			Check:    "dmarc",
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "DMARC record malformed",
			Summary:  "TXT record exists but is missing v=DMARC1.",
		}
	}
	record := strings.ToLower(records[0])
	policy := findTagValue(record, "p")
	rua := findTagValue(record, "rua")
	if policy == "none" {
		return Finding{
			Check:    "dmarc",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "DMARC policy is monitor-only",
			Summary:  "DMARC policy p=none does not enforce spoofing protection.",
			Evidence: []string{records[0]},
			Remediation: []string{
				"Progress to p=quarantine or p=reject after monitoring.",
			},
		}
	}
	if policy == "quarantine" || policy == "reject" {
		status := StatusPass
		severity := SeverityLow
		title := "DMARC policy enforced"
		summary := "DMARC policy is enforcing."
		if rua == "" {
			status = StatusWarn
			severity = SeverityLow
			title = "DMARC policy enforced without reporting"
			summary = "DMARC policy is enforcing, but rua is not configured."
		}
		return Finding{
			Check:    "dmarc",
			Status:   status,
			Severity: severity,
			Title:    title,
			Summary:  summary,
			Evidence: []string{records[0]},
			Remediation: []string{
				"Add rua=mailto:... to receive aggregate reports.",
			},
		}
	}
	return Finding{
		Check:    "dmarc",
		Status:   StatusWarn,
		Severity: SeverityMedium,
		Title:    "DMARC policy unrecognized",
		Summary:  "DMARC policy tag p= is missing or invalid.",
		Evidence: []string{records[0]},
	}
}

type nsRedundancyCheck struct{}

func (nsRedundancyCheck) Name() string { return "ns_redundancy" }

func (nsRedundancyCheck) Run(ctx context.Context, input CheckInput) Finding {
	records, err := input.Resolver.LookupNS(ctx, input.Domain)
	if err != nil {
		return Finding{
			Check:    "ns_redundancy",
			Status:   StatusError,
			Severity: SeverityMedium,
			Title:    "NS lookup failed",
			Summary:  err.Error(),
		}
	}
	if len(records) < 2 {
		return Finding{
			Check:    "ns_redundancy",
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "Insufficient authoritative nameservers",
			Summary:  "At least two nameservers are required for resilient DNS.",
			Remediation: []string{
				"Configure at least two authoritative nameservers in separate failure domains.",
			},
		}
	}
	hosts := make([]string, 0, len(records))
	for _, record := range records {
		hosts = append(hosts, strings.TrimSuffix(strings.ToLower(record.Host), "."))
	}
	if len(records) < 4 {
		return Finding{
			Check:    "ns_redundancy",
			Status:   StatusWarn,
			Severity: SeverityLow,
			Title:    "Nameserver redundancy can be improved",
			Summary:  "Two nameservers are present; four or more improves global resilience for high-traffic systems.",
			Evidence: hosts,
			Remediation: []string{
				"Consider adding additional nameservers and network diversity for stronger availability.",
			},
		}
	}
	return Finding{
		Check:    "ns_redundancy",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "Nameserver redundancy is healthy",
		Summary:  "Domain has strong nameserver redundancy.",
		Evidence: hosts,
	}
}

type dnssecValidationCheck struct{}

func (dnssecValidationCheck) Name() string { return "dnssec_validation" }

func (dnssecValidationCheck) Run(ctx context.Context, input CheckInput) Finding {
	ds, err := input.Resolver.LookupDS(ctx, input.Domain)
	if err != nil {
		if dnsNotFound(err) {
			return Finding{
				Check:    "dnssec_validation",
				Status:   StatusFail,
				Severity: SeverityHigh,
				Title:    "DNSSEC DS record missing",
				Summary:  "No DS records found at delegation; chain of trust is not established.",
				Remediation: []string{
					"Publish DS records at the parent zone and verify delegation signer state.",
				},
			}
		}
		return Finding{
			Check:    "dnssec_validation",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "DNSSEC DS lookup unavailable",
			Summary:  err.Error(),
			Remediation: []string{
				"Use resolver_mode udp/dot/doh with configured upstreams for DNSSEC checks.",
			},
		}
	}
	if len(ds) == 0 {
		return Finding{
			Check:    "dnssec_validation",
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "DNSSEC DS record missing",
			Summary:  "No DS records found at delegation; chain of trust is not established.",
			Remediation: []string{
				"Publish DS records at the parent zone and verify delegation signer state.",
			},
		}
	}

	dnskeys, err := input.Resolver.LookupDNSKEY(ctx, input.Domain)
	if err != nil {
		if dnsNotFound(err) {
			return Finding{
				Check:    "dnssec_validation",
				Status:   StatusFail,
				Severity: SeverityHigh,
				Title:    "DNSKEY records missing",
				Summary:  "No DNSKEY records found for signed domain.",
			}
		}
		return Finding{
			Check:    "dnssec_validation",
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "DNSKEY lookup failed",
			Summary:  err.Error(),
			Remediation: []string{
				"Ensure signed DNSKEY RRset is published and reachable from your resolvers.",
			},
		}
	}
	if len(dnskeys) == 0 {
		return Finding{
			Check:    "dnssec_validation",
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "DNSKEY records missing",
			Summary:  "No DNSKEY records found for signed domain.",
		}
	}

	var ksk, zsk int
	for _, key := range dnskeys {
		switch key.Flags {
		case 257:
			ksk++
		case 256:
			zsk++
		}
	}
	evidence := []string{
		fmt.Sprintf("ds_records=%d", len(ds)),
		fmt.Sprintf("dnskey_records=%d", len(dnskeys)),
		fmt.Sprintf("ksk=%d", ksk),
		fmt.Sprintf("zsk=%d", zsk),
	}
	if ksk == 0 || zsk == 0 {
		return Finding{
			Check:    "dnssec_validation",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "DNSSEC key role split not clear",
			Summary:  "DNSKEY records found, but expected KSK/ZSK roles are incomplete.",
			Evidence: evidence,
			Remediation: []string{
				"Maintain clear KSK (257) and ZSK (256) key roles for operational rollover safety.",
			},
		}
	}
	return Finding{
		Check:    "dnssec_validation",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "DNSSEC chain components present",
		Summary:  "DS and DNSKEY records are present with KSK/ZSK roles.",
		Evidence: evidence,
	}
}

type daneCheck struct{}

func (daneCheck) Name() string { return "dane_tlsa" }

func (daneCheck) Run(ctx context.Context, input CheckInput) Finding {
	mx, err := input.Resolver.LookupMX(ctx, input.Domain)
	if err != nil {
		return Finding{
			Check:    "dane_tlsa",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "MX lookup failed",
			Summary:  err.Error(),
			Remediation: []string{
				"Ensure MX records resolve before enforcing DANE for SMTP endpoints.",
			},
		}
	}
	if len(mx) == 0 {
		return Finding{
			Check:    "dane_tlsa",
			Status:   StatusWarn,
			Severity: SeverityLow,
			Title:    "No MX records found",
			Summary:  "DANE for SMTP could not be evaluated without MX hosts.",
		}
	}

	tlsaFound := 0
	validTLSA := 0
	evidence := make([]string, 0)
	for _, record := range mx {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record.Host)), ".")
		if host == "" {
			continue
		}
		name := "_25._tcp." + host
		tlsaRecords, lookupErr := input.Resolver.LookupTLSA(ctx, name)
		if lookupErr != nil {
			if !dnsNotFound(lookupErr) {
				return Finding{
					Check:    "dane_tlsa",
					Status:   StatusWarn,
					Severity: SeverityMedium,
					Title:    "TLSA lookup failed",
					Summary:  lookupErr.Error(),
				}
			}
			continue
		}
		if len(tlsaRecords) == 0 {
			continue
		}
		tlsaFound += len(tlsaRecords)
		for _, rec := range tlsaRecords {
			if rec.Usage <= 3 && rec.Selector <= 1 && rec.MatchingType <= 2 && strings.TrimSpace(rec.Certificate) != "" {
				validTLSA++
			}
		}
		evidence = append(evidence, fmt.Sprintf("%s tlsa=%d", host, len(tlsaRecords)))
	}

	if tlsaFound == 0 {
		return Finding{
			Check:    "dane_tlsa",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "DANE TLSA records missing",
			Summary:  "No TLSA records found for MX endpoints.",
			Remediation: []string{
				"Publish TLSA records on _25._tcp.<mx-host> and align with SMTP certificates.",
			},
		}
	}
	if validTLSA == 0 {
		return Finding{
			Check:    "dane_tlsa",
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "DANE TLSA records malformed",
			Summary:  "TLSA records exist but no valid usage/selector/matching values were detected.",
			Evidence: evidence,
		}
	}
	return Finding{
		Check:    "dane_tlsa",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "DANE TLSA records present",
		Summary:  "TLSA records found for MX endpoints with valid structure.",
		Evidence: append(evidence, fmt.Sprintf("valid_tlsa=%d", validTLSA)),
	}
}

type tlsCertificateCheck struct{}

func (tlsCertificateCheck) Name() string { return "tls_certificate" }

type tlsProbeResult struct {
	Version  uint16
	NotAfter time.Time
	Issuer   string
}

var probeTLSCertificate = func(ctx context.Context, domain string) (tlsProbeResult, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(domain, "443"), &tls.Config{
		ServerName: domain,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return tlsProbeResult{}, err
	}
	defer conn.Close()
	select {
	case <-ctx.Done():
		return tlsProbeResult{}, ctx.Err()
	default:
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return tlsProbeResult{}, fmt.Errorf("no peer certificate presented")
	}
	return tlsProbeResult{
		Version:  state.Version,
		NotAfter: state.PeerCertificates[0].NotAfter.UTC(),
		Issuer:   state.PeerCertificates[0].Issuer.String(),
	}, nil
}

func (tlsCertificateCheck) Run(ctx context.Context, input CheckInput) Finding {
	probe, err := probeTLSCertificate(ctx, input.Domain)
	if err != nil {
		return Finding{
			Check:    "tls_certificate",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "TLS endpoint validation failed",
			Summary:  err.Error(),
			Remediation: []string{
				"Ensure HTTPS is reachable on port 443 and certificate chain is valid.",
			},
		}
	}
	now := time.Now().UTC()
	if probe.NotAfter.Before(now) {
		return Finding{
			Check:    "tls_certificate",
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "TLS certificate expired",
			Summary:  "HTTPS certificate is expired.",
			Evidence: []string{fmt.Sprintf("issuer=%s expires=%s", probe.Issuer, probe.NotAfter.Format(time.RFC3339))},
			Remediation: []string{
				"Renew certificate immediately using ACME automation (for example ZeroSSL ACME).",
			},
		}
	}
	if probe.NotAfter.Sub(now) < 21*24*time.Hour {
		return Finding{
			Check:    "tls_certificate",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "TLS certificate expires soon",
			Summary:  "Certificate has less than 21 days remaining.",
			Evidence: []string{fmt.Sprintf("issuer=%s expires=%s", probe.Issuer, probe.NotAfter.Format(time.RFC3339))},
			Remediation: []string{
				"Enable automated certificate rotation and renewal monitoring.",
			},
		}
	}
	if probe.Version < tls.VersionTLS12 {
		return Finding{
			Check:    "tls_certificate",
			Status:   StatusFail,
			Severity: SeverityHigh,
			Title:    "Insecure TLS protocol negotiated",
			Summary:  "Endpoint supports protocol lower than TLS 1.2.",
			Remediation: []string{
				"Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
			},
		}
	}
	if probe.Version == tls.VersionTLS12 {
		return Finding{
			Check:    "tls_certificate",
			Status:   StatusWarn,
			Severity: SeverityLow,
			Title:    "TLS 1.2 in use",
			Summary:  "TLS is secure; consider prioritizing TLS 1.3 where available.",
			Evidence: []string{fmt.Sprintf("issuer=%s expires=%s", probe.Issuer, probe.NotAfter.Format(time.RFC3339))},
		}
	}
	return Finding{
		Check:    "tls_certificate",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "TLS certificate posture healthy",
		Summary:  "Endpoint is reachable with modern TLS and healthy certificate lifetime.",
		Evidence: []string{fmt.Sprintf("issuer=%s expires=%s", probe.Issuer, probe.NotAfter.Format(time.RFC3339))},
	}
}

type mtaSTSCheck struct{}

func (mtaSTSCheck) Name() string { return "mta_sts" }

func (mtaSTSCheck) Run(ctx context.Context, input CheckInput) Finding {
	host := "_mta-sts." + input.Domain
	txt, err := input.Resolver.LookupTXT(ctx, host)
	if err != nil {
		return Finding{
			Check:    "mta_sts",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "MTA-STS TXT record missing",
			Summary:  "No MTA-STS TXT record found.",
			Remediation: []string{
				"Publish TXT at _mta-sts.<domain> with v=STSv1; id=<version>.",
				"Host an HTTPS policy file at mta-sts.<domain>/.well-known/mta-sts.txt.",
			},
		}
	}
	records := findTXTWithPrefix(txt, "v=stsv1")
	if len(records) == 0 {
		return Finding{
			Check:    "mta_sts",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "MTA-STS TXT malformed",
			Summary:  "TXT record exists but does not contain v=STSv1.",
		}
	}
	return Finding{
		Check:    "mta_sts",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "MTA-STS TXT present",
		Summary:  "MTA-STS TXT record is present.",
		Evidence: []string{records[0]},
	}
}

type tlsRPTCheck struct{}

func (tlsRPTCheck) Name() string { return "tls_rpt" }

func (tlsRPTCheck) Run(ctx context.Context, input CheckInput) Finding {
	host := "_smtp._tls." + input.Domain
	txt, err := input.Resolver.LookupTXT(ctx, host)
	if err != nil {
		return Finding{
			Check:    "tls_rpt",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "TLS-RPT TXT record missing",
			Summary:  "No TLS-RPT TXT record found.",
			Remediation: []string{
				"Publish TXT at _smtp._tls.<domain> with v=TLSRPTv1; rua=mailto:... .",
			},
		}
	}
	records := findTXTWithPrefix(txt, "v=tlsrptv1")
	if len(records) == 0 {
		return Finding{
			Check:    "tls_rpt",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "TLS-RPT TXT malformed",
			Summary:  "TXT record exists but does not contain v=TLSRPTv1.",
		}
	}
	record := strings.ToLower(records[0])
	if findTagValue(record, "rua") == "" {
		return Finding{
			Check:    "tls_rpt",
			Status:   StatusWarn,
			Severity: SeverityLow,
			Title:    "TLS-RPT missing rua",
			Summary:  "TLS-RPT record is present but no reporting address is configured.",
			Evidence: []string{records[0]},
			Remediation: []string{
				"Add rua=mailto:tlsrpt@<domain> to receive reports.",
			},
		}
	}
	return Finding{
		Check:    "tls_rpt",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "TLS-RPT record present",
		Summary:  "TLS-RPT record is present with reporting configured.",
		Evidence: []string{records[0]},
	}
}

type bimiCheck struct{}

func (bimiCheck) Name() string { return "bimi" }

func (bimiCheck) Run(ctx context.Context, input CheckInput) Finding {
	host := "default._bimi." + input.Domain
	txt, err := input.Resolver.LookupTXT(ctx, host)
	if err != nil {
		return Finding{
			Check:    "bimi",
			Status:   StatusWarn,
			Severity: SeverityLow,
			Title:    "BIMI not configured",
			Summary:  "No BIMI TXT record found at default._bimi.<domain>.",
			Remediation: []string{
				"Publish TXT at default._bimi.<domain> with v=BIMI1; l=https://.../logo.svg.",
				"Optionally add a=https://... to reference a VMC/CMC certificate.",
			},
		}
	}

	records := findTXTWithPrefix(txt, "v=bimi1")
	if len(records) == 0 {
		return Finding{
			Check:    "bimi",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "BIMI TXT malformed",
			Summary:  "TXT record exists but does not contain v=BIMI1.",
			Evidence: txt,
		}
	}

	record := strings.ToLower(records[0])
	logo := findTagValue(record, "l")
	cert := findTagValue(record, "a")
	if logo == "" {
		return Finding{
			Check:    "bimi",
			Status:   StatusWarn,
			Severity: SeverityMedium,
			Title:    "BIMI logo location missing",
			Summary:  "BIMI record is present but l= is missing.",
			Evidence: []string{records[0]},
			Remediation: []string{
				"Set l=https://.../logo.svg in the BIMI record.",
			},
		}
	}
	if cert == "" {
		return Finding{
			Check:    "bimi",
			Status:   StatusWarn,
			Severity: SeverityLow,
			Title:    "BIMI configured without certificate reference",
			Summary:  "BIMI l= is present. Add a= for stronger mailbox-provider compatibility.",
			Evidence: []string{records[0]},
			Remediation: []string{
				"Add a=https://... to reference a VMC/CMC certificate when available.",
			},
		}
	}
	return Finding{
		Check:    "bimi",
		Status:   StatusPass,
		Severity: SeverityLow,
		Title:    "BIMI record present",
		Summary:  "BIMI is configured with logo and certificate reference.",
		Evidence: []string{records[0]},
	}
}

func findTXTWithPrefix(records []string, prefix string) []string {
	out := make([]string, 0)
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), strings.ToLower(prefix)) {
			out = append(out, strings.TrimSpace(record))
		}
	}
	return out
}

func findTagValue(record, tag string) string {
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, tag+"=") {
			return strings.TrimSpace(strings.TrimPrefix(part, tag+"="))
		}
	}
	return ""
}

func dnsNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr != nil && (dnsErr.IsNotFound || strings.Contains(strings.ToLower(dnsErr.Err), "no such host")) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such host") || strings.Contains(msg, "nxdomain") || strings.Contains(msg, "does not exist")
}
