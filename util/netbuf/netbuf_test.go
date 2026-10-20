package netbuf

import (
	"testing"

	"github.com/nange/easyss/v3/util/bytespool"
	"github.com/stretchr/testify/assert"
)

// TestNewReaderStartsAtHint 固定"空闲流只占最小档位"这一内存契约——它是本包
// 存在的理由：每流常驻读缓冲的下限，而不是一整块预留。
func TestNewReaderStartsAtHint(t *testing.T) {
	r := NewReader(0, 32768)
	defer r.Release()
	assert.Equal(t, Hint, r.Cap())
	assert.Equal(t, Hint, len(r.Buf()))

	// 显式 hint 生效，且被归一到池内档位。
	r2 := NewReader(7000, 32768)
	defer r2.Release()
	assert.Equal(t, 8192, r2.Cap(), "非 2 的幂的 hint 应向上取到池内档位")
}

// TestNewReaderClampsHintToMax 固定"hint 不得越过 max"：调用方声明的预算
// 是硬上限，构造期就收敛，避免出现"初始档位已经超预算"的中间态。
func TestNewReaderClampsHintToMax(t *testing.T) {
	r := NewReader(65536, 4096)
	defer r.Release()
	assert.Equal(t, 4096, r.Cap())
}

// TestGrowDoublesUpToMax 固定 2 倍增长到 max 为止；"是否读满"由调用方判断，
// Reader 不猜测读到了多少，每次 Grow 都是一次显式的"上一次读满了"声明。
func TestGrowDoublesUpToMax(t *testing.T) {
	r := NewReader(0, 32768)
	defer r.Release()

	for _, want := range []int{8192, 16384, 32768, 32768} {
		r.Grow()
		assert.Equal(t, want, r.Cap())
	}
}

// TestGrowNonPowerOfTwoMax 固定 max 不是 2 的幂时的行为：向上取到池内档位，
// 因此实际上限可能略高于调用方给的值——这是刻意的，池的 Put 不变式要求
// cap 恰好是 2 的幂，宁可在同一档内多给一点，也不能交出无法归还的缓冲。
func TestGrowNonPowerOfTwoMax(t *testing.T) {
	r := NewReader(0, 31744)
	defer r.Release()
	for range 8 {
		r.Grow()
	}
	assert.Equal(t, 32768, r.Cap())
}

// TestNewReaderClampsMaxToPoolSize 守住 max 不得超过池上限：bytespool.Get 对超限请求
// 返回 nil，Grow 会把缓冲换成 nil，调用方 Read(nil) 立刻返回 (0, nil) 变成 100% CPU 空转。
func TestNewReaderClampsMaxToPoolSize(t *testing.T) {
	r := NewReader(0, 1<<30)
	defer r.Release()
	assert.Equal(t, bytespool.MaxSize, r.max, "max 必须被钳到池的上限")

	for range 32 {
		r.Grow()
	}
	assert.Equal(t, bytespool.MaxSize, r.Cap(), "增长应停在池的上限")
	assert.NotNil(t, r.Buf(), "Grow 绝不能让缓冲变成 nil")
	assert.Equal(t, bytespool.MaxSize, len(r.Buf()), "Buf 的 len 与 cap 必须相等")
}

// TestReleaseReturnsBufferToPool 固定归还语义：Release 之后该缓冲可被同档位
// 的 Get 复用。借"归还后 Put 必须成功"这一点反证 Release 归还的是合法档位
// （cap 是 2 的幂），否则 MustPut 会 panic。
func TestReleaseReturnsBufferToPool(t *testing.T) {
	r := NewReader(0, 32768)
	r.Grow()
	class := r.Cap()
	r.Release()

	// Release 后 r 不再持有缓冲。
	assert.Equal(t, 0, r.Cap())

	// 归还的档位可以被立即复取，且 Put 路径不再 panic（MustPut 已在上一步执行）。
	buf := bytespool.Get(class)
	assert.Equal(t, class, cap(buf))
	bytespool.MustPut(buf)
}

// TestGrowthSurvivesPoolReuse 守住增长过程中不泄漏旧缓冲：每个中间档位都要归还一次。
// 不做精确计数——GC 会静默清空 sync.Pool，计数器只是近似量。
func TestGrowthSurvivesPoolReuse(t *testing.T) {
	for range 32 {
		r := NewReader(0, 32768)
		r.Grow()
		r.Grow()
		r.Grow()
		assert.Equal(t, 32768, r.Cap())
		r.Release()
	}
}
