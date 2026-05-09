package dnssecured

import (
	"context"
	"errors"
	"time"
)

type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

type Status string

const (
	StatusPass  Status = "pass"
	StatusWarn  Status = "warn"
	StatusFail  Status = "fail"
	StatusError Status = "error"
)

type Finding struct {
	Check       string   `json:"check"`
	Status      Status   `json:"status"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Summary     string   `json:"summary"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation []string `json:"remediation,omitempty"`
}

type Summary struct {
	Passed  int `json:"passed"`
	Warned  int `json:"warned"`
	Failed  int `json:"failed"`
	Errored int `json:"errored"`
}

type Report struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Domain        string    `json:"domain"`
	DKIMSelectors []string  `json:"dkim_selectors"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	PostureScore  float64   `json:"posture_score"`
	Findings      []Finding `json:"findings"`
	Summary       Summary   `json:"summary"`
}

type ScanRequest struct {
	TenantID      string
	Domain        string
	DKIMSelectors []string
}

type CheckInput struct {
	Domain        string
	DKIMSelectors []string
	Resolver      Resolver
}

type Check interface {
	Name() string
	Run(ctx context.Context, input CheckInput) Finding
}

var ErrReportNotFound = errors.New("dnssecured report not found")

type ReportStore interface {
	Save(ctx context.Context, report Report) error
	Get(ctx context.Context, tenantID, reportID string) (Report, error)
}
