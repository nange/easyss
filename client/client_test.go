package client

import (
	"testing"
)

func TestChooseSlotCount(t *testing.T) {
	t.Run("min<=0 使用默认值3", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			n := chooseSlotCount(0, 8)
			if n < 3 || n > 8 {
				t.Errorf("chooseSlotCount(0, 8) = %d, want [3, 8]", n)
			}
		}
	})

	t.Run("max<min 自动纠正", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			n := chooseSlotCount(10, 5)
			if n != 10 {
				t.Errorf("chooseSlotCount(10, 5) = %d, want 10", n)
			}
		}
	})

	t.Run("单值范围返回该值", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			n := chooseSlotCount(8, 8)
			if n != 8 {
				t.Errorf("chooseSlotCount(8, 8) = %d, want 8", n)
			}
		}
	})

	t.Run("范围分布验证", func(t *testing.T) {
		minVal, maxVal := 8, 16
		seenMin, seenMax := false, false
		for i := 0; i < 200; i++ {
			n := chooseSlotCount(minVal, maxVal)
			if n < minVal || n > maxVal {
				t.Errorf("chooseSlotCount = %d out of range [%d, %d]", n, minVal, maxVal)
			}
			if n == minVal {
				seenMin = true
			}
			if n == maxVal {
				seenMax = true
			}
		}
		if !seenMin {
			t.Error("never got min value (unlikely)")
		}
		if !seenMax {
			t.Error("never got max value (unlikely)")
		}
	})

	t.Run("负 min 值", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			n := chooseSlotCount(-5, 8)
			if n < 3 || n > 8 {
				t.Errorf("chooseSlotCount(-5, 8) = %d, want [3, 8]", n)
			}
		}
	})
}
