package config

import (
	"testing"
	"time"
)

// TestTimeoutsNormalizeFillsDefaults 守护单一事实来源：零值字段必须由
// Timeouts.Normalize 按默认基础超时算一次，不允许出现第二个魔法数字。
func TestTimeoutsNormalizeFillsDefaults(t *testing.T) {
	want := NewTimeouts(time.Duration(DefaultTimeout) * time.Second)
	if got := (Timeouts{}).Normalize(); got != want {
		t.Errorf("Timeouts{}.Normalize() = %#v, want %#v", got, want)
	}
	for name, d := range map[string]time.Duration{
		"Base":         want.Base,
		"Dial":         want.Dial,
		"StreamIdle":   want.StreamIdle,
		"UDPIdle":      want.UDPIdle,
		"DNSResp":      want.DNSResp,
		"ConnLifetime": want.ConnLifetime,
	} {
		if d <= 0 {
			t.Errorf("%s must be positive, got %v", name, d)
		}
	}
}

// TestTimeoutsNormalizeKeepsExplicitValues 固定"只填零值"的语义：调用方显式设置
// 的字段必须原样保留，否则嵌入式调用方与测试就无法只钉住自己关心的那一项。
func TestTimeoutsNormalizeKeepsExplicitValues(t *testing.T) {
	in := Timeouts{
		Base:         5 * time.Second,
		Dial:         2 * time.Second,
		StreamIdle:   3 * time.Second,
		UDPIdle:      4 * time.Second,
		DNSResp:      200 * time.Millisecond,
		ConnLifetime: 6 * time.Second,
	}
	if got := in.Normalize(); got != in {
		t.Errorf("Normalize() = %#v, want the explicit values untouched", got)
	}
}

// TestTimeoutsNormalizePartial 覆盖只设置部分字段的情形：已设置的保留，其余按
// Base 重新派生（而不是退回默认基础超时）。
func TestTimeoutsNormalizePartial(t *testing.T) {
	got := (Timeouts{Base: 5 * time.Second}).Normalize()
	if got.Dial != DialTimeout(5*time.Second) {
		t.Errorf("Dial = %v, want %v", got.Dial, DialTimeout(5*time.Second))
	}
	if got.StreamIdle != StreamIdleTimeout(5*time.Second) {
		t.Errorf("StreamIdle = %v, want %v", got.StreamIdle, StreamIdleTimeout(5*time.Second))
	}
	if got.UDPIdle != UDPIdleTimeout(5*time.Second) {
		t.Errorf("UDPIdle = %v, want %v", got.UDPIdle, UDPIdleTimeout(5*time.Second))
	}
	if got.DNSResp != 5*time.Second/3 {
		t.Errorf("DNSResp = %v, want %v", got.DNSResp, 5*time.Second/3)
	}
	if got.ConnLifetime != ConnLifetime(5*time.Second) {
		t.Errorf("ConnLifetime = %v, want %v", got.ConnLifetime, ConnLifetime(5*time.Second))
	}
}

// TestTimeoutsNormalizeDoesNotClamp 固定归一化的边界：它只填零值，**不**钳制
// 调用方显式给出的基础超时。区间钳制发生在配置层（NormalizeTimeout，用户输入的
// timeout 秒数），测试与嵌入式调用方因此仍可以用远小于 MinTimeout 的值构建集合。
func TestTimeoutsNormalizeDoesNotClamp(t *testing.T) {
	for _, base := range []time.Duration{time.Second, time.Hour} {
		if got := (Timeouts{Base: base}).Normalize().Base; got != base {
			t.Errorf("Normalize() with explicit Base = %v changed it to %v", base, got)
		}
	}
}

func TestNormalizeTimeout(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{"未配置（0）", 0, DefaultTimeout},
		{"负值", -5, DefaultTimeout},
		{"低于下限", 1, MinTimeout},
		{"下限", MinTimeout, MinTimeout},
		{"默认值", DefaultTimeout, DefaultTimeout},
		{"上限", MaxTimeout, MaxTimeout},
		{"高于上限", 3600, MaxTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeTimeout(tt.in); got != tt.want {
				t.Errorf("NormalizeTimeout(%d) = %d, want %d", tt.in, got, tt.want)
			}
			want := time.Duration(tt.want) * time.Second
			if got := TimeoutDuration(tt.in); got != want {
				t.Errorf("TimeoutDuration(%d) = %v, want %v", tt.in, got, want)
			}
		})
	}
}

// TestTimeoutBounds 守护区间自身的合法性：默认值必须落在 [MinTimeout, MaxTimeout]
// 内，否则"未配置"与"越界"两条归一化路径会互相矛盾。
func TestTimeoutBounds(t *testing.T) {
	if MinTimeout <= 0 {
		t.Fatalf("MinTimeout must be positive, got %d", MinTimeout)
	}
	if MaxTimeout < MinTimeout {
		t.Fatalf("MaxTimeout = %d must not be below MinTimeout = %d", MaxTimeout, MinTimeout)
	}
	if DefaultTimeout < MinTimeout || DefaultTimeout > MaxTimeout {
		t.Fatalf("DefaultTimeout = %d must lie in [%d, %d]", DefaultTimeout, MinTimeout, MaxTimeout)
	}
}

func TestStreamIdleTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"默认值 30s", 30 * time.Second, 240 * time.Second},
		{"0s", 0, 0},
		{"小值 5s", 5 * time.Second, 40 * time.Second},
		{"大值 120s", 120 * time.Second, 16 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StreamIdleTimeout(tt.timeout); got != tt.want {
				t.Errorf("StreamIdleTimeout(%v) = %v, want %v", tt.timeout, got, tt.want)
			}
		})
	}
}

func TestConnLifetime(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"默认值 30s", 30 * time.Second, 6 * time.Minute},
		{"0s", 0, 0},
		{"小值 5s", 5 * time.Second, time.Minute},
		{"大值 120s", 120 * time.Second, 24 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConnLifetime(tt.timeout); got != tt.want {
				t.Errorf("ConnLifetime(%v) = %v, want %v", tt.timeout, got, tt.want)
			}
		})
	}
}

// TestConnLifetimeExceedsStreamIdle 守护两条公式的次序关系：轮换生命周期（12 倍）
// 必须长于流空闲（8 倍），使一条流不会因为所在连接被安排轮换而提前结束。
func TestConnLifetimeExceedsStreamIdle(t *testing.T) {
	for _, base := range []time.Duration{time.Second, 5 * time.Second, 30 * time.Second, 2 * time.Minute} {
		if ConnLifetime(base) <= StreamIdleTimeout(base) {
			t.Errorf("ConnLifetime(%v) = %v must exceed StreamIdleTimeout(%v) = %v",
				base, ConnLifetime(base), base, StreamIdleTimeout(base))
		}
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
