package http2

import (
	"net"
	"net/http"
)

// slotWithPool 返回一个池已就绪、但没有池工厂的槽位：判死路径只清空连接身份
// （那一代的 conn CAS），不会动池——没有工厂时 replacePool 直接返回，既不重建也
// 不清空（生产槽位由 newSlot 装上工厂，见 transportSlot.replacePool）。仅测试
// 使用——裸构造的槽位在生命周期/调度测试里只需要一个池占位。
func slotWithPool(t *http.Transport) *transportSlot {
	s := &transportSlot{}
	s.gen.Store(&slotTransport{tr: t})
	return s
}

// slotWithGenFactory 返回一个带池工厂的槽位：判死路径能真的换上新一代
// （生产槽位由 newSlot 装上工厂，见 transportSlot.replacePool）。工厂建出的
// 池是空的，因此测试必须自己用 attachConn 装上连接身份。
func slotWithGenFactory() *transportSlot {
	s := &transportSlot{}
	s.newGen = func() *slotTransport { return &slotTransport{tr: &http.Transport{}} }
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
