package http2

import "net/http"

// slotWithPool 返回一个池已就绪、但没有池工厂的槽位：判死路径只清空连接引用
// （s.conn 的 CAS），不会动池——没有工厂时 replacePool 直接返回，既不重建也不
// 清空（生产槽位由 newSlot 装上工厂，见 transportSlot.replacePool）。仅测试
// 使用——裸构造的槽位在生命周期/调度测试里只需要一个池占位。
func slotWithPool(t *http.Transport) *transportSlot {
	s := &transportSlot{}
	s.pool.Store(t)
	return s
}
