package dnssec

import (
	"testing"
	"time"
)

func TestBuildPlan(t *testing.T) {
	now := time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC)
	plan, err := BuildPlan(Policy{
		KSKRotationDays:    180,
		ZSKRotationDays:    30,
		DSPropagationHours: 48,
	}, State{
		Now:             now,
		LastKSKRotation: now.Add(-10 * 24 * time.Hour),
		LastZSKRotation: now.Add(-5 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if !plan.NextKSKRotateAt.After(now) || !plan.NextZSKRotateAt.After(now) {
		t.Fatalf("invalid plan dates: %+v", plan)
	}
}

func TestBuildPlanOverdue(t *testing.T) {
	now := time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC)
	_, err := BuildPlan(Policy{KSKRotationDays: 30}, State{
		Now:             now,
		LastKSKRotation: now.Add(-60 * 24 * time.Hour),
		LastZSKRotation: now,
	})
	if err == nil {
		t.Fatal("expected overdue error")
	}
}
