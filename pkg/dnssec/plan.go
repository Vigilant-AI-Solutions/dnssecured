package dnssec

import (
	"fmt"
	"time"
)

type Policy struct {
	KSKRotationDays    int `json:"ksk_rotation_days"`
	ZSKRotationDays    int `json:"zsk_rotation_days"`
	DSPropagationHours int `json:"ds_propagation_hours"`
}

type State struct {
	Now             time.Time `json:"now"`
	LastKSKRotation time.Time `json:"last_ksk_rotation"`
	LastZSKRotation time.Time `json:"last_zsk_rotation"`
}

type Plan struct {
	GeneratedAt      time.Time `json:"generated_at"`
	NextKSKRotateAt  time.Time `json:"next_ksk_rotate_at"`
	PublishDSBy      time.Time `json:"publish_ds_by"`
	ActivateDSAt     time.Time `json:"activate_ds_at"`
	NextZSKRotateAt  time.Time `json:"next_zsk_rotate_at"`
	RecommendedSteps []string  `json:"recommended_steps"`
}

func BuildPlan(policy Policy, state State) (Plan, error) {
	if policy.KSKRotationDays <= 0 {
		policy.KSKRotationDays = 180
	}
	if policy.ZSKRotationDays <= 0 {
		policy.ZSKRotationDays = 45
	}
	if policy.DSPropagationHours <= 0 {
		policy.DSPropagationHours = 48
	}
	now := state.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	lastKSK := state.LastKSKRotation.UTC()
	if lastKSK.IsZero() {
		lastKSK = now
	}
	lastZSK := state.LastZSKRotation.UTC()
	if lastZSK.IsZero() {
		lastZSK = now
	}

	nextKSK := lastKSK.Add(time.Duration(policy.KSKRotationDays) * 24 * time.Hour)
	nextZSK := lastZSK.Add(time.Duration(policy.ZSKRotationDays) * 24 * time.Hour)
	if nextKSK.Before(now) {
		return Plan{}, fmt.Errorf("ksk rotation is overdue")
	}
	if nextZSK.Before(now) {
		return Plan{}, fmt.Errorf("zsk rotation is overdue")
	}
	publishDSBy := nextKSK.Add(-time.Duration(policy.DSPropagationHours) * time.Hour)

	return Plan{
		GeneratedAt:     now,
		NextKSKRotateAt: nextKSK,
		PublishDSBy:     publishDSBy,
		ActivateDSAt:    nextKSK,
		NextZSKRotateAt: nextZSK,
		RecommendedSteps: []string{
			"Pre-publish new KSK before DS update window.",
			"Publish CDS/CDNSKEY and confirm parent DS update before KSK activation.",
			"Use RFC-compliant double-signing window during KSK rollover.",
			"Rotate ZSK on schedule with overlap to preserve validation continuity.",
		},
	}, nil
}
