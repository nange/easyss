package protocol

import (
	"math/bits"
	"testing"
)

// TestRecordSizesStayInOnePoolClass 固定"记录层的三块缓冲落在同一个池档位"这条
// 不变量的三个方向。它是 MaxPoolClass → MaxRecordPlaintext → MaxUDPDataSize 这条
// 推导链的唯一守卫：三者一旦被单独调大，本进程就会为十几字节的溢出在**每条记录**
// 上多申请一块大一倍的缓冲（bytespool 的档位是 2 的幂），而那种回归在功能测试里
// 完全看不出来——记录照样发得出去。
//
// 三个方向分别是：
//
//  1. 上界：一条满记录（明文上限 + 3 字节长度前缀 + AEAD 标签）必须落在档位内；
//  2. 下界：最大的合法 UDP 数据报帧必须能完整落进一条记录，否则它会被整形器的
//     单帧校验判成超限，把整条 UDP 流打断；
//  3. 紧致：UDP 载荷上限必须**由池档位与两个结构开销反推**，而不是向下取整到某个
//     看起来整齐的数——多留 22 字节余量就会让密文缓冲跳到下一档。
func TestRecordSizesStayInOnePoolClass(t *testing.T) {
	// 档位本身必须是池的合法档位（2 的幂），否则 bytespool.MustPut 会因
	// "cap 不是 2 的幂"而 panic，而这条不变量的其余部分都建立在它之上。
	if MaxPoolClass <= 0 || MaxPoolClass&(MaxPoolClass-1) != 0 {
		t.Fatalf("MaxPoolClass = %d 不是 2 的幂，不是 bytespool 的合法档位", MaxPoolClass)
	}
	if got := bits.Len32(uint32(MaxPoolClass)) - 1; 1<<got != MaxPoolClass {
		t.Fatalf("MaxPoolClass = %d 无法表示为单个档位", MaxPoolClass)
	}

	// 方向 1：满记录的线上长度仍落在档位内。
	if got := MaxRecordPlaintext + MaxCipherLenSize + MaxTagOverhead; got > MaxPoolClass {
		t.Fatalf("满记录线上长度 %d 越过池档位 %d（明文上限 %d）",
			got, MaxPoolClass, MaxRecordPlaintext)
	}

	// 方向 2：最大数据报帧放得进一条记录。
	if got := MaxUDPDataSize + FrameHeaderSize; got > MaxRecordPlaintext {
		t.Fatalf("最大数据报帧 %d 超过记录明文上限 %d，会被单帧校验判成超限",
			got, MaxRecordPlaintext)
	}

	// 方向 3：反过来也要紧致。上面两条只约束了上界与下界之间的区间，而区间内的
	// 任何取值都能通过——但只有紧贴档位的取值能让密文缓冲也停在那一档。
	if got := MaxUDPDataSize + FrameHeaderSize + MaxCipherLenSize + MaxTagOverhead; got != MaxPoolClass {
		t.Fatalf("UDP 载荷上限没有贴紧池档位：满记录线上长度 %d，档位 %d（差 %d 字节）",
			got, MaxPoolClass, MaxPoolClass-got)
	}

	// 三个上限必须由档位导出，而不是各自写死的字面量：改动其中任何一个都必须
	// 同步改动 MaxPoolClass，否则上面的紧致断言会失败。
	if MaxRecordPlaintext != MaxPoolClass-MaxCipherLenSize-MaxTagOverhead {
		t.Fatalf("MaxRecordPlaintext = %d 不是由档位反推的值 %d",
			MaxRecordPlaintext, MaxPoolClass-MaxCipherLenSize-MaxTagOverhead)
	}
	if MaxUDPDataSize != MaxRecordPlaintext-FrameHeaderSize {
		t.Fatalf("MaxUDPDataSize = %d 不是由记录上限反推的值 %d",
			MaxUDPDataSize, MaxRecordPlaintext-FrameHeaderSize)
	}

	// 读侧必须比写侧宽松得多：它要能解码旧对端用更大档位写出的记录。这条不对称
	// 是刻意的，不能因为"统一上限"而被抹平。
	if MaxPlainRecordSize <= MaxRecordPlaintext {
		t.Fatalf("线上格式上限 %d 不大于写入上限 %d，旧对端的记录将无法解码",
			MaxPlainRecordSize, MaxRecordPlaintext)
	}
}
