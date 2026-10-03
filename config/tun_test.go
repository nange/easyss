package config

import "testing"

// TestNormalizeTunMTU 固定 MTU 归一化的唯一入口：非正值表示"未配置"（取默认值），
// 越界值取最近的边界。客户端配置、client/tun.New 与提权 helper 都依赖它，
// 因此任何一处放松都会让设备 MTU 与 netstack MTU 出现无提示的偏离。
func TestNormalizeTunMTU(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"未配置", 0, DefaultTunMTU},
		{"负值视为未配置", -1, DefaultTunMTU},
		{"默认值原样保留", DefaultTunMTU, DefaultTunMTU},
		{"区间内原样保留", 8500, 8500},
		{"下界", MinTunMTU, MinTunMTU},
		{"低于下界取最近边界", 100, MinTunMTU},
		{"上界", MaxTunMTU, MaxTunMTU},
		{"高于上界取最近边界", 1 << 20, MaxTunMTU},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeTunMTU(tc.in); got != tc.want {
				t.Errorf("NormalizeTunMTU(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestNormalizeTunMTUIsIdempotent 守护"已归一化的值再次归一化不变"。
// client/tun.New 与 helper 都会对同一个值各归一化一次，若这里不是幂等的，
// 两次归一化就会得到不同的设备 MTU 与 netstack MTU。
func TestNormalizeTunMTUIsIdempotent(t *testing.T) {
	for _, in := range []int{-1, 0, 576, MinTunMTU, 1500, 8500, MaxTunMTU, 1 << 20} {
		once := NormalizeTunMTU(in)
		if twice := NormalizeTunMTU(once); twice != once {
			t.Errorf("NormalizeTunMTU(NormalizeTunMTU(%d)) = %d, want %d", in, twice, once)
		}
	}
}

// TestTunMTUBoundsAreConsistent 约束默认值落在合法区间内：默认值越界时
// NormalizeTunMTU(0) 会被钳制，"未配置"与"默认值"将不再等价。
func TestTunMTUBoundsAreConsistent(t *testing.T) {
	if DefaultTunMTU < MinTunMTU || DefaultTunMTU > MaxTunMTU {
		t.Fatalf("DefaultTunMTU = %d, want within [%d, %d]", DefaultTunMTU, MinTunMTU, MaxTunMTU)
	}
	if MinTunMTU < 1280 {
		t.Errorf("MinTunMTU = %d, want >= 1280 (the IPv6 minimum link MTU)", MinTunMTU)
	}
}
