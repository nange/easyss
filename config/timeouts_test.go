package config

import (
	"testing"
	"time"
)

// TestDefaultStreamIdleTimeoutDerived 守护单一事实来源约束：回退默认值必须始终等于
// 在默认基础超时下求得的公式结果，绝不允许出现第二个魔法数字。
func TestDefaultStreamIdleTimeoutDerived(t *testing.T) {
	want := StreamIdleTimeout(time.Duration(DefaultTimeout) * time.Second)
	if DefaultStreamIdleTimeout != want {
		t.Errorf("DefaultStreamIdleTimeout = %v, want StreamIdleTimeout(DefaultTimeout) = %v", DefaultStreamIdleTimeout, want)
	}
	if DefaultStreamIdleTimeout <= 0 {
		t.Fatalf("DefaultStreamIdleTimeout must be positive, got %v", DefaultStreamIdleTimeout)
	}
}

// TestDefaultUDPIdleTimeoutDerived 为 UDP 回退值守护同样的约束：它必须等于
// UDPIdleTimeout(DefaultTimeout)，使回退值永不偏离正常路径所使用的派生值。
func TestDefaultUDPIdleTimeoutDerived(t *testing.T) {
	want := UDPIdleTimeout(time.Duration(DefaultTimeout) * time.Second)
	if DefaultUDPIdleTimeout != want {
		t.Errorf("DefaultUDPIdleTimeout = %v, want UDPIdleTimeout(DefaultTimeout) = %v", DefaultUDPIdleTimeout, want)
	}
	if DefaultUDPIdleTimeout <= 0 {
		t.Fatalf("DefaultUDPIdleTimeout must be positive, got %v", DefaultUDPIdleTimeout)
	}
}

// TestDefaultDialTimeoutDerived 为拨号回退值守护同样的约束：它必须等于
// DialTimeout(DefaultTimeout)。
func TestDefaultDialTimeoutDerived(t *testing.T) {
	want := DialTimeout(time.Duration(DefaultTimeout) * time.Second)
	if DefaultDialTimeout != want {
		t.Errorf("DefaultDialTimeout = %v, want DialTimeout(DefaultTimeout) = %v", DefaultDialTimeout, want)
	}
	if DefaultDialTimeout <= 0 {
		t.Fatalf("DefaultDialTimeout must be positive, got %v", DefaultDialTimeout)
	}
}

func TestStreamIdleTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"默认值 30s", 30 * time.Second, 120 * time.Second},
		{"0s", 0, 0},
		{"小值 5s", 5 * time.Second, 20 * time.Second},
		{"大值 120s", 120 * time.Second, 8 * time.Minute},
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
