package protocol

import "testing"

// TestRecordSizesStayInTheirPoolClasses 固定两条互不推导的尺寸链：数据报上限由 UDPPoolClassSize(16KB)
// 反推，记录上限由 MaxReadRecordPlaintext(64KB) 反推。合并会让 TCP 侧 32,771 字节的单帧被单帧校验拒绝，
// 而 UDP 读缓冲必须停在 16KB，它的上限只能由档位反推。
func TestRecordSizesStayInTheirPoolClasses(t *testing.T) {
	// 必须是 2 的幂：否则 bytespool.MustPut 会因 "cap 不是 2 的幂" 而 panic。
	if UDPPoolClassSize <= 0 || UDPPoolClassSize&(UDPPoolClassSize-1) != 0 {
		t.Fatalf("UDPPoolClassSize = %d 不是 2 的幂，不是 bytespool 的合法档位", UDPPoolClassSize)
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

	// 最大的数据报帧必须能落进一条记录：两条链路被单独调大时这里会第一个失败。
	if got := MaxUDPDataSize + FrameHeaderSize; got > MaxWriteRecordPlaintext {
		t.Fatalf("最大数据报帧 %d 超过记录明文上限 %d，会被单帧校验判成超限",
			got, MaxWriteRecordPlaintext)
	}

	// 读侧刻意比写侧宽松：它要能解码旧对端用更大档位写出的记录。
	if MaxReadRecordPlaintext <= MaxWriteRecordPlaintext {
		t.Fatalf("解码侧上限 %d 不大于写入上限 %d，旧对端的记录将无法解码",
			MaxReadRecordPlaintext, MaxWriteRecordPlaintext)
	}
}
