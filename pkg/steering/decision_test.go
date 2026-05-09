package steering

import "testing"

func TestSelectLatency(t *testing.T) {
	decision, err := Select(Policy{Mode: "latency"}, []Endpoint{
		{ID: "a", Healthy: true, LatencyMS: 120},
		{ID: "b", Healthy: true, LatencyMS: 40},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if decision.EndpointID != "b" {
		t.Fatalf("endpoint=%s", decision.EndpointID)
	}
}

func TestSelectWeightedWithRegionBias(t *testing.T) {
	decision, err := Select(Policy{Mode: "weighted", RegionBias: "us-east"}, []Endpoint{
		{ID: "a", Healthy: true, Weight: 10, Capacity: 1, LatencyMS: 80, Region: "us-west"},
		{ID: "b", Healthy: true, Weight: 8, Capacity: 1, LatencyMS: 20, Region: "us-east"},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if decision.EndpointID != "b" {
		t.Fatalf("endpoint=%s", decision.EndpointID)
	}
}

func TestSelectFailover(t *testing.T) {
	decision, err := Select(Policy{Mode: "failover"}, []Endpoint{
		{ID: "a", Healthy: true, Weight: 1},
		{ID: "b", Healthy: true, Weight: 100},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if decision.EndpointID != "b" {
		t.Fatalf("endpoint=%s", decision.EndpointID)
	}
}
