package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunCLIVersion(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	if err := runCLI([]string{"version"}, &out, &errOut); err != nil {
		t.Fatalf("runCLI: %v", err)
	}
	if !strings.Contains(out.String(), "dnssecured") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestRunCLIListChecks(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	if err := runCLI([]string{"list-checks"}, &out, &errOut); err != nil {
		t.Fatalf("runCLI: %v", err)
	}
	if !strings.Contains(out.String(), "dnssec_validation") {
		t.Fatalf("missing expected check list output: %q", out.String())
	}
}
