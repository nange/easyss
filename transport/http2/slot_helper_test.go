package http2

import "net/http"

// slotWithPool 返回一个池已就绪、但没有池工厂的槽位：判死路径只会清空池引用，
// 不会重建（生产槽位由 newSlot 装上工厂，见 transportSlot.replacePool）。
// 仅测试使用——裸构造的槽位在生命周期/调度测试里只需要一个可替换的池占位。
func slotWithPool(t *http.Transport) *transportSlot {
	s := &transportSlot{}
	s.pool.Store(t)
	return s
}
