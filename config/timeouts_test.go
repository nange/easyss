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

// TestDefaultConnLifetimeDerived 为连接轮换生命周期的回退值守护同样的约束：
// 它必须等于 ConnLifetime(DefaultTimeout)，使回退值永不偏离正常路径所使用的派生值。
func TestDefaultConnLifetimeDerived(t *testing.T) {
	want := ConnLifetime(time.Duration(DefaultTimeout) * time.Second)
	if DefaultConnLifetime != want {
		t.Errorf("DefaultConnLifetime = %v, want ConnLifetime(DefaultTimeout) = %v", DefaultConnLifetime, want)
	}
	if DefaultConnLifetime <= 0 {
		t.Fatalf("DefaultConnLifetime must be positive, got %v", DefaultConnLifetime)
	}
}

// TestNormalizeTimeout 固定基础超时的归一化：非正值取默认值，越界值钳制到
// [MinTimeout, MaxTimeout]（它派生出全部空闲/拨号/轮换超时，因此不能随意设置）。
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
