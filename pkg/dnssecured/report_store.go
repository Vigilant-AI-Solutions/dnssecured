package dnssecured

import (
	"context"
	"sync"
)

type MemoryReportStore struct {
	mu      sync.RWMutex
	reports map[string]map[string]Report
}

func NewMemoryReportStore() *MemoryReportStore {
	return &MemoryReportStore{
		reports: make(map[string]map[string]Report),
	}
}

func (m *MemoryReportStore) Save(_ context.Context, report Report) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.reports[report.TenantID]; !ok {
		m.reports[report.TenantID] = make(map[string]Report)
	}
	m.reports[report.TenantID][report.ID] = report
	return nil
}

func (m *MemoryReportStore) Get(_ context.Context, tenantID, reportID string) (Report, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	reports, ok := m.reports[tenantID]
	if !ok {
		return Report{}, ErrReportNotFound
	}
	report, ok := reports[reportID]
	if !ok {
		return Report{}, ErrReportNotFound
	}
	return report, nil
}
