package steering

import (
	"fmt"
	"math"
	"slices"
	"strings"
)

type Policy struct {
	Mode       string `json:"mode"`
	RegionBias string `json:"region_bias,omitempty"`
}

type Endpoint struct {
	ID        string  `json:"id"`
	Region    string  `json:"region,omitempty"`
	Weight    int     `json:"weight"`
	Healthy   bool    `json:"healthy"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Capacity  float64 `json:"capacity,omitempty"`
}

type Decision struct {
	EndpointID string   `json:"endpoint_id"`
	Reason     string   `json:"reason"`
	Candidates []string `json:"candidates"`
}

func Select(policy Policy, endpoints []Endpoint) (Decision, error) {
	mode := strings.ToLower(strings.TrimSpace(policy.Mode))
	if mode == "" {
		mode = "latency"
	}
	healthy := make([]Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep.Healthy {
			healthy = append(healthy, normalizeEndpoint(ep))
		}
	}
	if len(healthy) == 0 {
		return Decision{}, fmt.Errorf("no healthy endpoints available")
	}

	switch mode {
	case "latency":
		return chooseByLatency(policy, healthy), nil
	case "weighted":
		return chooseByWeightedScore(policy, healthy), nil
	case "failover":
		return chooseByFailover(healthy), nil
	default:
		return Decision{}, fmt.Errorf("unsupported policy mode %q", policy.Mode)
	}
}

func normalizeEndpoint(ep Endpoint) Endpoint {
	if ep.Weight <= 0 {
		ep.Weight = 1
	}
	if ep.Capacity <= 0 {
		ep.Capacity = 1
	}
	if ep.LatencyMS <= 0 {
		ep.LatencyMS = 100
	}
	return ep
}

func chooseByLatency(policy Policy, endpoints []Endpoint) Decision {
	region := strings.ToLower(strings.TrimSpace(policy.RegionBias))
	candidates := append([]Endpoint(nil), endpoints...)
	if region != "" {
		local := make([]Endpoint, 0, len(endpoints))
		for _, ep := range endpoints {
			if strings.ToLower(strings.TrimSpace(ep.Region)) == region {
				local = append(local, ep)
			}
		}
		if len(local) > 0 {
			candidates = local
		}
	}
	best := candidates[0]
	for _, ep := range candidates[1:] {
		if ep.LatencyMS < best.LatencyMS {
			best = ep
		}
	}
	return Decision{
		EndpointID: best.ID,
		Reason:     "selected lowest-latency healthy endpoint",
		Candidates: endpointIDs(candidates),
	}
}

func chooseByWeightedScore(policy Policy, endpoints []Endpoint) Decision {
	best := endpoints[0]
	bestScore := -1.0
	for _, ep := range endpoints {
		latencyFactor := 1 / math.Max(ep.LatencyMS, 1)
		regionBoost := 1.0
		if strings.EqualFold(strings.TrimSpace(ep.Region), strings.TrimSpace(policy.RegionBias)) && strings.TrimSpace(policy.RegionBias) != "" {
			regionBoost = 1.2
		}
		score := float64(ep.Weight) * ep.Capacity * latencyFactor * regionBoost
		if score > bestScore {
			best = ep
			bestScore = score
		}
	}
	return Decision{
		EndpointID: best.ID,
		Reason:     "selected highest weighted performance score",
		Candidates: endpointIDs(endpoints),
	}
}

func chooseByFailover(endpoints []Endpoint) Decision {
	ordered := append([]Endpoint(nil), endpoints...)
	slices.SortStableFunc(ordered, func(a, b Endpoint) int {
		if a.Weight == b.Weight {
			return strings.Compare(a.ID, b.ID)
		}
		if a.Weight > b.Weight {
			return -1
		}
		return 1
	})
	return Decision{
		EndpointID: ordered[0].ID,
		Reason:     "selected highest-priority healthy failover endpoint",
		Candidates: endpointIDs(ordered),
	}
}

func endpointIDs(endpoints []Endpoint) []string {
	out := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		out = append(out, ep.ID)
	}
	return out
}
