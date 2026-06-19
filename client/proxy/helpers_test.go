package proxy

import (
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/miekg/dns"
)

func TestIsLocalConnClosedError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"net.ErrClosed", net.ErrClosed, true},
		{"io.ErrClosedPipe", io.ErrClosedPipe, true},
		{"use of closed network connection", errors.New("use of closed network connection"), true},
		{"Use Of Closed Network Connection", errors.New("Use Of Closed Network Connection"), true}, // 大小写不敏感
		{"connection reset by peer", errors.New("connection reset by peer"), true},
		{"forcibly closed by the remote host", errors.New("forcibly closed by the remote host"), true},
		{"software caused connection abort", errors.New("software caused connection abort"), true},
		{"connection was aborted", errors.New("connection was aborted"), true},
		{"broken pipe", errors.New("broken pipe"), true},
		{"normal error", errors.New("some other error"), false},
		{"io.EOF", io.EOF, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLocalConnClosedError(tt.err)
			if got != tt.want {
				t.Errorf("isLocalConnClosedError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestParseBasicAuth(t *testing.T) {
	tests := []struct {
		name     string
		auth     string
		wantUser string
		wantPass string
		wantOK   bool
	}{
		{"有效认证", "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")), "user", "pass", true},
		{"仅用户名", "Basic " + base64.StdEncoding.EncodeToString([]byte("user:")), "user", "", true},
		{"含冒号的密码", "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass:extra")), "user", "pass:extra", true},
		{"空认证头", "", "", "", false},
		{"无 Basic 前缀", "Bearer token", "", "", false},
		{"前缀过短", "Bas", "", "", false},
		{"无效 Base64", "Basic invalid!!base64", "", "", false},
		{"大小写不敏感前缀", "basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")), "user", "pass", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, pass, ok := parseBasicAuth(tt.auth)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if user != tt.wantUser {
				t.Errorf("user = %q, want %q", user, tt.wantUser)
			}
			if pass != tt.wantPass {
				t.Errorf("pass = %q, want %q", pass, tt.wantPass)
			}
		})
	}
}

func TestConnectTarget(t *testing.T) {
	tests := []struct {
		name    string
		urlHost string
		reqHost string
		want    string
	}{
		{"URL.Host 有端口", "example.com:443", "", "example.com:443"},
		{"URL.Host 无端口", "example.com", "", "example.com:443"},
		{"使用 r.Host", "", "example.com:8080", "example.com:8080"},
		{"r.Host 无端口", "", "example.com", "example.com:443"},
		{"IPv4", "1.2.3.4", "", "1.2.3.4:443"},
		{"带端口的 URL", "example.com:8443", "", "example.com:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{
				URL:  &url.URL{Host: tt.urlHost},
				Host: tt.reqHost,
			}
			got := connectTarget(r)
			if got != tt.want {
				t.Errorf("connectTarget() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsDNSRequest(t *testing.T) {
	makeMsg := func(qtype uint16, isResponse bool) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", qtype)
		msg.Response = isResponse
		return msg
	}

	tests := []struct {
		name string
		msg  *dns.Msg
		want bool
	}{
		{"A 查询", makeMsg(dns.TypeA, false), true},
		{"AAAA 查询", makeMsg(dns.TypeAAAA, false), true},
		{"MX 查询", makeMsg(dns.TypeMX, false), false},
		{"A 响应", makeMsg(dns.TypeA, true), false},
		{"AAAA 响应", makeMsg(dns.TypeAAAA, true), false},
		{"无 Question", &dns.Msg{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDNSRequest(tt.msg)
			if got != tt.want {
				t.Errorf("isDNSRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDNSResponse(t *testing.T) {
	makeMsg := func(isResponse bool) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		msg.Response = isResponse
		return msg
	}

	tests := []struct {
		name string
		msg  *dns.Msg
		want bool
	}{
		{"Response=true", makeMsg(true), true},
		{"Response=false", makeMsg(false), false},
		{"无 Question", &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDNSResponse(tt.msg)
			if got != tt.want {
				t.Errorf("isDNSResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ParseAddress 委托给 socks5.ParseAddress，此处仅验证代理不 panic
func TestParseAddress(t *testing.T) {
	_, _, _, _ = ParseAddress("example.com:80")
	// 纯 delegate 调用，只验证不 panic
}
