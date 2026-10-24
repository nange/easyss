package http2

import (
	"net"
	"net/http"
)

// slotWithPool 返回一个池已就绪、但没有池工厂的槽位：判死路径只清空连接身份
// （那一代的 conn CAS），不会动池——没有工厂时 advanceGeneration 直接返回，既不
// 重建也不清空（生产槽位由 newSlot 装上工厂，见 transportSlot.advanceGeneration）。仅测试
// 使用——裸构造的槽位在生命周期/调度测试里只需要一个池占位。
func slotWithPool(t *http.Transport) *transportSlot {
	s := &transportSlot{}
	s.gen.Store(&slotTransport{slot: s, tr: t})
	return s
}

// slotWithGenFactory 返回一个带池工厂的槽位：判死与连接回收能真的换上新一代
// （生产槽位由 newSlot 装上工厂，见 transportSlot.advanceGeneration）。工厂建出的
// 池是空的，因此测试必须自己用 attachConn 装上连接身份。
func slotWithGenFactory() *transportSlot {
	s := &transportSlot{}
	s.newGen = func() *slotTransport { return &slotTransport{slot: s, tr: &http.Transport{}} }
	s.gen.Store(s.newGen())
	return s
}

// attachConn 给槽位当前一代装上一个可控的连接身份——测试无法真的拨号，只能
// 直接构造身份（生产路径由 DialTLSContext 写入，见 buildTransport）。
func attachConn(s *transportSlot, c net.Conn) *slotConn {
	sc := &slotConn{c: c}
	s.generation().conn.Store(sc)
	return sc
}

// probeSlotWithPool 返回一个"这一代有连接身份"的池已就绪槽位：探测在这一代没有连接时
// 拒绝白拨一条新连接（见 slotProber.probe），测试用占位身份满足它，真实连接由 net/http
// 拨出。"无连接不拨号"由 probe_test 用 slotWithPool 直接覆盖。
func probeSlotWithPool(t *http.Transport) *transportSlot {
	s := slotWithPool(t)
	attachConn(s, &countingConn{})
	return s
}
