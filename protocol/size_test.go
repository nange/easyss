package protocol

import (
	"math/bits"
	"testing"
)

// TestRecordSizesStayInTheirPoolClasses 固定两条**互不推导**的尺寸链：
//
//	数据报链路：UDPPoolClassSize(16KB) → MaxUDPDataSize(16,362)
//	记录链路：  MaxReadRecordPlaintext(64KB) → MaxWriteRecordPlaintext(65,517)
//
// 二者不能合并成一条：TCP 读缓冲由 netbuf 按 2 的幂取档（客户端 16,384、
// 服务端 32,768），一次读满会原样交给 PushData，单帧最大 32,771 字节；记录
// 上限一旦跟着 UDP 缩到 16KB，这些帧会直接被单帧校验拒绝。反过来，UDP 读缓冲
// 必须停在 16KB 档，所以数据报上限只能由档位反推，不能跟着记录上限放大。
func TestRecordSizesStayInTheirPoolClasses(t *testing.T) {
	// UDPPoolClassSize 本身必须是池的合法档位（2 的幂），否则 bytespool.MustPut
	// 会因 "cap 不是 2 的幂" 而 panic，数据报链路的其余部分都建立在它之上。
	if UDPPoolClassSize <= 0 || UDPPoolClassSize&(UDPPoolClassSize-1) != 0 {
		t.Fatalf("UDPPoolClassSize = %d 不是 2 的幂，不是 bytespool 的合法档位", UDPPoolClassSize)
	}
	if got := bits.Len32(uint32(UDPPoolClassSize)) - 1; 1<<got != UDPPoolClassSize {
		t.Fatalf("UDPPoolClassSize = %d 无法表示为单个档位", UDPPoolClassSize)
	}

	// 数据报链路：P + 帧头 + 长度前缀 + 标签 = 16KB，且 P 由档位反推。
	if got := MaxUDPDataSize + FrameHeaderSize + MaxCipherLenSize + MaxTagOverhead; got != UDPPoolClassSize {
		t.Fatalf("UDP 载荷上限没有贴紧池档位：满记录线上长度 %d，档位 %d（差 %d 字节）",
			got, UDPPoolClassSize, UDPPoolClassSize-got)
	}
	if MaxUDPDataSize != UDPPoolClassSize-MaxCipherLenSize-MaxTagOverhead-FrameHeaderSize {
		t.Fatalf("MaxUDPDataSize = %d 不是由数据报档位反推的值 %d",
			MaxUDPDataSize, UDPPoolClassSize-MaxCipherLenSize-MaxTagOverhead-FrameHeaderSize)
	}

	// 记录链路：明文上限 + 长度前缀 + 标签 = 64KB，且由线上格式上限反推。
	if got := MaxWriteRecordPlaintext + MaxCipherLenSize + MaxTagOverhead; got != MaxReadRecordPlaintext {
		t.Fatalf("记录明文上限没有贴紧 64KB 档位：满记录线上长度 %d，上限 %d（差 %d 字节）",
			got, MaxReadRecordPlaintext, MaxReadRecordPlaintext-got)
	}
	if MaxWriteRecordPlaintext != MaxReadRecordPlaintext-MaxCipherLenSize-MaxTagOverhead {
		t.Fatalf("MaxWriteRecordPlaintext = %d 不是由解码侧上限反推的值 %d",
			MaxWriteRecordPlaintext, MaxReadRecordPlaintext-MaxCipherLenSize-MaxTagOverhead)
	}

	// 最大的数据报帧必须能落进一条记录。现在两者之间有大量余量，但这条关系仍要
	// 显式守住：两条链路一旦被单独调大，这里会第一个失败。
	if got := MaxUDPDataSize + FrameHeaderSize; got > MaxWriteRecordPlaintext {
		t.Fatalf("最大数据报帧 %d 超过记录明文上限 %d，会被单帧校验判成超限",
			got, MaxWriteRecordPlaintext)
	}

	// 读侧必须比写侧宽松：它要能解码旧对端用更大档位写出的记录。这条不对称
	// 是刻意的，不能因为"统一上限"而被抹平。
	if MaxReadRecordPlaintext <= MaxWriteRecordPlaintext {
		t.Fatalf("解码侧上限 %d 不大于写入上限 %d，旧对端的记录将无法解码",
			MaxReadRecordPlaintext, MaxWriteRecordPlaintext)
	}
}
