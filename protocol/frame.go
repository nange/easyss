package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/nange/easyss/v3/config"
)

type FrameType uint8

const (
	FrameDATA      FrameType = 0x0
	FrameDATAGRAM  FrameType = 0x1
	FrameFIN       FrameType = 0x2
	FrameRST       FrameType = 0x3
	FramePADDING   FrameType = 0x4
	FrameCOVER     FrameType = 0x5
	FrameHANDSHAKE FrameType = 0x6
)

const (
	FrameHeaderSize = 3
)

const (
	Version3 = 3
)

type Proto uint8

const (
	ProtoTCP  Proto = 1
	ProtoUDP  Proto = 2
	ProtoICMP Proto = 3
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	default:
		return "unknown"
	}
}

type Method uint8

const (
	MethodAES256GCM        Method = 1
	MethodChaCha20Poly1305 Method = 2
)

func MethodFromString(s string) Method {
	switch s {
	case "aes-256-gcm":
		return MethodAES256GCM
	case "chacha20-poly1305":
		return MethodChaCha20Poly1305
	default:
		return 0
	}
}

func (m Method) String() string {
	switch m {
	case MethodAES256GCM:
		return "aes-256-gcm"
	case MethodChaCha20Poly1305:
		return "chacha20-poly1305"
	default:
		return "unknown"
	}
}

const (
	// UDPPoolClassSize 是 **UDP 数据报链路**承诺使用的 bytespool 档位大小，也是
	// MaxUDPDataSize 的唯一来源。取 16KB 的理由是"够用"与"每条会话的常驻内存"：
	// UDP 数据报的常见上限是局域网巨型帧(9216)与本项目自己宣告的 DNS EDNS0
	// 上限(8192，见 client/dns 与 client/proxy/dns.go)；更大的数据报（NFS over
	// UDP 之类）不值得让每条会话各钉一块 64KB 读缓冲（客户端 128 条并发交换
	// 即 8MB）。
	//
	// 它**不是整个记录层的上限**：TCP 字节流记录的写入上限是 MaxWriteRecordPlaintext
	// (65,517)，仍会用到池的 64KB 档——读缓冲由 netbuf 按 2 的幂取档（客户端
	// 16,384、服务端 32,768），单帧最大 32,771 字节。把记录上限压到 16KB 会让
	// 这些读缓冲在单帧校验处直接报错，见 shaper.(*batchShaper).appendFrameLocked。
	//
	// 它是导出的，因为数据报链路的不变量要能被跨包断言：crypto 与 protocol 的
	// 测试都对着它检查，而不是各自写死 16KB。
	UDPPoolClassSize = 16 * 1024

	// MaxReadRecordPlaintext 是**解码侧**接受的明文上限（线上格式的长度前缀能
	// 表达 16MB，这里按 64KB 收口），同时是写入侧上限的出处：
	// MaxWriteRecordPlaintext = MaxReadRecordPlaintext - MaxCipherLenSize -
	// MaxTagOverhead，正好把一条满记录填进池的 64KB 档。留它不变是为了继续接受
	// 旧对端发来的大记录（见 crypto.MaxCipherRecordSize 的推导）。
	MaxReadRecordPlaintext = 64 * 1024

	MaxCipherLenSize = 3

	// MaxTagOverhead 是本项目两种 AEAD（AES-256-GCM 与 ChaCha20-Poly1305）
	// 认证标签的上界。记录层要它才能算出"明文上限"与"池档位"之间的正确关系：
	// 一条记录的线上长度是 MaxCipherLenSize + 明文 + 标签，而 bytespool 的
	// 档位必须容纳这三者之和，否则密文缓冲会向上跳一档——为十几字节的溢出
	// 付一倍的池保留与瞬时分配。
	//
	// 它是常量而不是运行时从 Encryptor.Overhead() 读取，因为 protocol 是记录
	// 格式的定义方，不应该依赖 crypto 包；两个 AEAD 的标签都是 16 字节，
	// 若将来引入更长的标签，这里必须同步上调。这条耦合由 crypto 包的
	// TestAEADOverheadMatchesProtocolCeiling 守住（两种 AEAD 都断言
	// Overhead() <= MaxTagOverhead）。
	MaxTagOverhead = 16

	// MaxWriteRecordPlaintext 是一条记录里明文的**写入上限**，由解码侧上限减去
	// 长度前缀与 AEAD 标签反推：65,517 + 3 + 16 = 64KB，正好用满池的该档位。
	//
	// 它是**加密侧与整形侧共用的同一个上限**，两侧必须一致：
	//   - crypto.RecordWriter 用它做写入校验（超过即报错）；
	//   - shaper 用它做单帧校验、预冲刷边界与填充预算（否则它能攒出 WriteRecord
	//     拒绝的明文，把一条正常的流打断）。
	//
	// 它**不是最大合法单帧**：TCP 的 DATA 帧由 netbuf 读缓冲决定（客户端
	// 16,384、服务端 32,768，见 config.TCPStreamBufferSize /
	// ServerTCPStreamBufferSize），最大 32,771 字节，必须远小于它；UDP 数据报帧
	// 则另有更紧的 MaxUDPDataSize。读侧不受它约束：MaxCipherRecordSize 仍按解码
	// 侧上限推导，以便解码旧对端发来的、明文到 64KB 的记录。
	MaxWriteRecordPlaintext = MaxReadRecordPlaintext - MaxCipherLenSize - MaxTagOverhead // 65,517

	// MaxUDPDataSize 是单个 UDP 数据报的载荷上限，也是 UDP 读缓冲的容量。它由
	// **数据报链路的池档位**反推，而不是由记录上限反推：这条链路上一共有三块
	// 池缓冲会按数据报长度申请内存（P 为载荷长度）——
	//
	//	1) socket 读缓冲   bytespool.Get(P)                        = P
	//	2) 整形器明文缓冲  protocol.AppendFrame(DATAGRAM, payload)  = P + 3（帧头）
	//	3) 记录密文缓冲    crypto.RecordWriter.WriteRecord          = P + 3 + 16
	//	                                                              （前缀 + 明文 + 标签）
	//
	// 三者必须落在同一档位内，(3) 是其中最紧的一条（它比 (2) 多一个 3 字节的
	// cipher_len 前缀）：P + 19 <= 16KB。取 16,362 正是这个解——比"看起来更整齐"
	// 的档位值小 22 字节，却决定了这条链路上**每一块缓冲**都停在 16KB 档；多这
	// 22 字节就会让密文缓冲跳到 32KB 档，而每条记录都要现场分配一块它。
	// 注意 (3) 是"记录里只有这一条数据报"时的请求量：多条数据报仍可能被批进
	// 同一条记录，此时密文缓冲按整条记录申请（最大到 64KB 档），但那是批处理的
	// 瞬时开销，不影响本常量控制的每会话读缓冲。
	// 由 TestRecordSizesStayInTheirPoolClasses 守住这条不变量。
	//
	// 它**不是协议上限**：帧长是 uint16，解码侧仍接受旧对端发来的最大 65,535
	// 字节的帧。不要拿它去限制解码，否则旧客户端的大数据报会被直接拒掉。
	//
	// 顺带的影响是 server/nextproxy 的 maxUDPDatagram(= 本值 + 22) 正好等于
	// 档位大小，池请求零浪费。
	//
	// 历史取值是 65,507（IPv4 下 UDP 载荷的算术上限 = 65,535 - 20 - 8）。它对
	// 应的是"单个 IP 报文理论上能有多大"，而真实 UDP 数据报绝大多数在 MTU 以内，
	// 本项目自己宣告的 DNS EDNS0 也只有 8192；为 64KB 让每条 UDP 会话各钉一块
	// 64KB 读缓冲（客户端 128 条并发交换即 8MB），不划算。
	MaxUDPDataSize = UDPPoolClassSize - MaxCipherLenSize - MaxTagOverhead - FrameHeaderSize // 16,362

	// MinRecordBufferSize 是每条流的明文缓冲区初始大小。缓冲按需增长（见
	// shaper.(*batchShaper).ensureCapacity），因此空闲流与只传少量数据的流
	// 终生只占这么多，只有真正的大流量流才会长到 MaxWriteRecordPlaintext。
	//
	// 它是"流"这个维度的内存下限，而服务端的内存占用 ≈ 峰值并发流数 ×
	// 每流缓冲区大小：常驻连接、心跳流、探测流在数量上往往占绝大多数，
	// 把它们从一整块记录缓冲区（64KB）降到 4KB 是这次收敛里收益最大的一项
	// （实测：600 条空闲流从约 38MB 降到约 2.4MB）。
	//
	// 它刻意不改变 MaxReadRecordPlaintext：线上格式的最大尺寸参与旧对端的解码能力，
	// 调小它会让更新的版本无法解码老版本客户端发出的记录。因此这次只收敛
	// "每条流预留多少"，不动"线上格式能表达多大"。
	MinRecordBufferSize = 4 * 1024
)

type Handshake struct {
	Version uint8
	Proto   Proto
	Method  Method
	Target  string
}

func (h Handshake) Encode() []byte {
	targetLen := len(h.Target)
	buf := make([]byte, 3+targetLen)
	buf[0] = h.Version
	buf[1] = byte(h.Proto)
	buf[2] = byte(h.Method)
	copy(buf[3:], h.Target)
	return buf
}

func DecodeHandshake(data []byte) (Handshake, error) {
	if len(data) < 3 {
		return Handshake{}, errors.New("protocol: handshake too short")
	}
	h := Handshake{
		Version: data[0],
		Proto:   Proto(data[1]),
		Method:  Method(data[2]),
		Target:  string(data[3:]),
	}
	if h.Version != Version3 {
		return Handshake{}, fmt.Errorf("protocol: unsupported version %d", h.Version)
	}
	return h, nil
}

func (h Handshake) MatchesEndpoint(endpoint string) bool {
	switch h.Proto {
	case ProtoTCP:
		return endpoint == config.EndpointTCP
	case ProtoUDP:
		return endpoint == config.EndpointUDP
	case ProtoICMP:
		return endpoint == config.EndpointICMP
	default:
		return false
	}
}

type Frame struct {
	Type    FrameType
	Length  uint16
	Payload []byte
}

func (f Frame) EncodedLen() int {
	return FrameHeaderSize + int(f.Length)
}

// DecodeFrame 从 data 头部解码一个帧。它是记录层的非流式对应物：解密的
// CryptoRecord 在内存中切分，因此不涉及 io.Reader。返回帧、其占用的字节数
// 以及错误。帧的 payload 别名自 data，其生命周期由调用方负责。
func DecodeFrame(data []byte) (Frame, int, error) {
	if len(data) < FrameHeaderSize {
		return Frame{}, 0, io.ErrUnexpectedEOF
	}
	ftype := FrameType(data[0])
	length := int(binary.BigEndian.Uint16(data[1:3]))
	encoded := FrameHeaderSize + length
	if encoded > len(data) {
		return Frame{}, 0, io.ErrUnexpectedEOF
	}

	f := Frame{Type: ftype, Length: uint16(length)}
	if length > 0 {
		f.Payload = data[FrameHeaderSize:encoded]
	}
	return f, encoded, nil
}

// NewFrame 构建给定类型的帧，并复制 payload，使调用方可以复用其缓冲区
// （shaper 交出的是 bytespool 缓冲区）。Length 始终由 payload 推导，
// 因此线上的头部永远不可能与随后写入的字节不一致。
func NewFrame(typ FrameType, payload []byte) Frame {
	return NewFrameWithPayload(typ, append([]byte(nil), payload...))
}

// NewFrameWithPayload 包装现有 payload 缓冲区而不复制，供持有池化缓冲区
// （cover 流量）的调用方使用：必须原样交给 shaper，以便归还池中。
func NewFrameWithPayload(typ FrameType, payload []byte) Frame {
	checkPayloadLen(payload)
	return Frame{
		Type:    typ,
		Length:  uint16(len(payload)),
		Payload: payload,
	}
}

// NewZeroFrame 构建给定类型的帧，payload 为 length 字节的零值缓冲区，
// 供随后再填充缓冲区的调用方使用（padding）。
func NewZeroFrame(typ FrameType, length uint16) Frame {
	return Frame{
		Type:    typ,
		Length:  length,
		Payload: make([]byte, length),
	}
}

func NewFrameDATA(data []byte) Frame {
	return NewFrame(FrameDATA, data)
}

func NewFrameDATAGRAM(data []byte) Frame {
	return NewFrame(FrameDATAGRAM, data)
}

func NewFrameFIN() Frame {
	return Frame{Type: FrameFIN}
}

func NewFrameRST() Frame {
	return Frame{Type: FrameRST}
}

func NewFramePADDING(length uint16) Frame {
	return NewZeroFrame(FramePADDING, length)
}

func NewFrameHANDSHAKE(h Handshake) Frame {
	return NewFrame(FrameHANDSHAKE, h.Encode())
}

func checkPayloadLen(payload []byte) {
	if len(payload) > math.MaxUint16 {
		panic(fmt.Sprintf("protocol: frame payload too large: %d", len(payload)))
	}
}

// AppendFrame 把单个帧（头部 + payload）追加到 buf，不重置已有内容。
// 这是唯一的帧编码路径：头部由 len(f.Payload) 推导而非 f.Length，
// 因此两个字段不一致的 Frame（例如刚从线上解码出来的）永远不会产生
// 损坏的记录。
func AppendFrame(buf []byte, f Frame) []byte {
	var header [FrameHeaderSize]byte
	header[0] = byte(f.Type)
	binary.BigEndian.PutUint16(header[1:3], uint16(len(f.Payload)))
	buf = append(buf, header[:]...)
	return append(buf, f.Payload...)
}

// EncodeFrames 把一组帧编码进单个新缓冲区。
func EncodeFrames(frames []Frame) []byte {
	total := 0
	for _, f := range frames {
		total += FrameHeaderSize + len(f.Payload)
	}
	buf := make([]byte, 0, total)
	for _, f := range frames {
		buf = AppendFrame(buf, f)
	}
	return buf
}
