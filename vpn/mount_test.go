package vpn

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubFallback 记录伪装页被调用的次数，替代真实的伪装页面。
type stubFallback struct{ calls int }

func (s *stubFallback) Serve(w http.ResponseWriter, r *http.Request) {
	s.calls++
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("fake site"))
}

// stubDERP 记录 DERP 处理器被调用的次数。
type stubDERP struct{ calls int }

func (s *stubDERP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.calls++
	w.WriteHeader(http.StatusSwitchingProtocols)
}

// TestDERPMountRouting 固定 /derp 的路由契约。核心是伪装面：**不带 DERP Upgrade
// 头的 /derp 必须回伪装页面**，因为 derpserver.Handler 对这类请求会返回带
// "DERP requires connection upgrade" 的 426 —— 那是一个一眼可辨的指纹。
func TestDERPMountRouting(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		upgrade  string
		wantDERP bool
		why      string
	}{
		{
			name:     "普通 GET /derp 走伪装页",
			path:     "/derp",
			wantDERP: false,
			why:      "无 Upgrade 头时 derpserver 会回 426 纯文本，暴露中继的存在",
		},
		{
			name:     "Upgrade: derp 走中继",
			path:     "/derp",
			upgrade:  "derp",
			wantDERP: true,
			why:      "真实 DERP 客户端的握手请求",
		},
		{
			name:     "Upgrade 大小写不敏感",
			path:     "/derp",
			upgrade:  "DERP",
			wantDERP: true,
			why:      "HTTP 头值的大小写由客户端决定，derpserver 自己也做了 ToLower",
		},
		{
			name:     "Upgrade: websocket 走中继",
			path:     "/derp",
			upgrade:  "websocket",
			wantDERP: true,
			why:      "Tailscale 的备用传输使用同一路径",
		},
		{
			name:     "别的 Upgrade 走伪装页",
			path:     "/derp",
			upgrade:  "h2c",
			wantDERP: false,
			why:      "只有 DERP 协议族认账，避免把任意可疑请求都送进中继",
		},
		{
			name:     "netcheck 探测走中继",
			path:     "/derp/probe",
			wantDERP: true,
			why:      "探测端点返回体不含 DERP 字样；挡住它会让带 netcheck 的客户端把中继判为不可用",
		},
		{
			name:     "延迟探测走中继",
			path:     "/derp/latency-check",
			wantDERP: true,
			why:      "同上",
		},
		{
			name:     "/derp 子树下的未知路径走伪装页",
			path:     "/derp/anything",
			wantDERP: false,
			why:      "真实 DERP 服务端只有三个路径，多出来的路径只会暴露实现细节",
		},
		{
			name:     "名字相近的路径走伪装页",
			path:     "/derpfoo",
			wantDERP: false,
			why:      "前缀匹配必须落在路径分隔符边界上",
		},
		{
			name:     "根路径走伪装页",
			path:     "/",
			wantDERP: false,
			why:      "既有伪装面不变",
		},
		{
			name:     "代理端点由 mux 单独注册，不经过这里",
			path:     "/v3/tcp",
			wantDERP: false,
			why:      "这里只守住兜底处理器的语义",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fallback := &stubFallback{}
			derp := &stubDERP{}
			h := NewDERPMount(derp, fallback)

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.upgrade != "" {
				req.Header.Set("Upgrade", tc.upgrade)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if tc.wantDERP {
				if derp.calls != 1 {
					t.Errorf("DERP handler calls = %d, want 1 (%s)", derp.calls, tc.why)
				}
				if fallback.calls != 0 {
					t.Errorf("fallback calls = %d, want 0 (%s)", fallback.calls, tc.why)
				}
				return
			}
			if fallback.calls != 1 {
				t.Errorf("fallback calls = %d, want 1 (%s)", fallback.calls, tc.why)
			}
			if derp.calls != 0 {
				t.Errorf("DERP handler calls = %d, want 0 (%s)", derp.calls, tc.why)
			}
			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want the fallback page's %d", rec.Code, http.StatusNotFound)
			}
		})
	}
}

// TestDERPMountNeverLeaksDERPAttributes 守护伪装面：无论请求长什么样，非 DERP
// 流量都不应该看到 426 或任何来自 derpserver 的响应。
func TestDERPMountNeverLeaksDERPAttributes(t *testing.T) {
	fallback := &stubFallback{}
	// 真实的 derpserver.Handler 会对无 Upgrade 的 /derp 回 426。
	real := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "DERP requires connection upgrade", http.StatusUpgradeRequired)
	})
	h := NewDERPMount(real, fallback)

	for _, path := range []string{"/derp", "/derp/unknown"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code == http.StatusUpgradeRequired {
			t.Errorf("GET %s returned 426, which reveals a DERP relay", path)
		}
		if body := rec.Body.String(); body != "fake site" {
			t.Errorf("GET %s body = %q, want the fallback page", path, body)
		}
	}
}
