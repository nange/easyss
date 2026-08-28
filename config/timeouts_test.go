package config

import (
	"testing"
	"time"
)

// TestDefaultStreamIdleTimeoutDerived guards the single-source-of-truth
// constraint: the fallback default must always equal the formula evaluated
// at the default base timeout, never a second magic number.
func TestDefaultStreamIdleTimeoutDerived(t *testing.T) {
	want := StreamIdleTimeout(time.Duration(DefaultTimeout) * time.Second)
	if DefaultStreamIdleTimeout != want {
		t.Errorf("DefaultStreamIdleTimeout = %v, want StreamIdleTimeout(DefaultTimeout) = %v", DefaultStreamIdleTimeout, want)
	}
	if DefaultStreamIdleTimeout <= 0 {
		t.Fatalf("DefaultStreamIdleTimeout must be positive, got %v", DefaultStreamIdleTimeout)
	}
}

func TestStreamIdleTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"默认值 30s", 30 * time.Second, 300 * time.Second},
		{"0s", 0, 0},
		{"小值 5s", 5 * time.Second, 50 * time.Second},
		{"大值 120s", 120 * time.Second, 20 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StreamIdleTimeout(tt.timeout); got != tt.want {
				t.Errorf("StreamIdleTimeout(%v) = %v, want %v", tt.timeout, got, tt.want)
			}
		})
	}
}

func TestUDPIdleTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"默认值 30s", 30 * time.Second, 60 * time.Second},
		{"0s", 0, 0},
		{"小值 5s", 5 * time.Second, 10 * time.Second},
		{"大值 120s", 120 * time.Second, 4 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UDPIdleTimeout(tt.timeout); got != tt.want {
				t.Errorf("UDPIdleTimeout(%v) = %v, want %v", tt.timeout, got, tt.want)
			}
		})
	}
}

func TestDialTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"默认值 30s", 30 * time.Second, 10 * time.Second},
		{"最小值保底：0s", 0, 3 * time.Second},
		{"最小值保底：9s", 9 * time.Second, 3 * time.Second},
		{"正常值：15s", 15 * time.Second, 5 * time.Second},
		{"正常值：45s", 45 * time.Second, 15 * time.Second},
		{"最大值封顶：60s", 60 * time.Second, 15 * time.Second},
		{"最大值封顶：120s", 120 * time.Second, 15 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DialTimeout(tt.timeout); got != tt.want {
				t.Errorf("DialTimeout(%v) = %v, want %v", tt.timeout, got, tt.want)
			}
		})
	}
}
