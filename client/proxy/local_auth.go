package proxy

import (
	"errors"
	"io"
	"net"

	thingssocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

// AuthEnabled 报告本地代理是否启用用户名/密码鉴权：两个字段必须同时非空。SOCKS5 入口据此
// 选 Authenticator，runner 的 bind_all 暴露告警用它判断"无鉴权"，两处共用避免判定漂移。
func AuthEnabled(username, password string) bool {
	return username != "" && password != ""
}

// 鉴权只作用于非回环来源：本机自用路径（系统代理、托盘 /stats、TUN）拿不到凭据，
// 让它们也过认证会把本地功能一起弄坏。控制端点的回环闸门用的是同一个判据。
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

var errRemoteNoAuthRejected = errors.New("socks5: no-auth is only accepted from loopback")

// loopbackNoAuthAuthenticator 只对回环来源接受 no-auth 方法。服务端按 authMethods 的
// 顺序挑选客户端也声明的方法，因此鉴权开启时它必须排在 UserPass 之后（见 socks5AuthMethods）：
// 排在前面会让同时声明两种方法的远程客户端落到 no-auth 分支。
type loopbackNoAuthAuthenticator struct{}

func (loopbackNoAuthAuthenticator) GetCode() uint8 { return statute.MethodNoAuth }

func (loopbackNoAuthAuthenticator) Authenticate(_ io.Reader, w io.Writer, userAddr string) (*thingssocks5.AuthContext, error) {
	if !isLoopbackAddr(userAddr) {
		// 与库在"没有可用方法"时的应答一致：客户端看到的是协议错误而不是 EOF。
		_, _ = w.Write([]byte{statute.VersionSocks5, statute.MethodNoAcceptable})
		return nil, errRemoteNoAuthRejected
	}
	if _, err := w.Write([]byte{statute.VersionSocks5, statute.MethodNoAuth}); err != nil {
		return nil, err
	}
	return &thingssocks5.AuthContext{Method: statute.MethodNoAuth, Payload: map[string]string{}}, nil
}

// socks5AuthMethods 的切片顺序是协议契约（库按服务端顺序选方法，见 loopbackNoAuthAuthenticator）。
func socks5AuthMethods(username, password string) []thingssocks5.Authenticator {
	if !AuthEnabled(username, password) {
		return []thingssocks5.Authenticator{thingssocks5.NoAuthAuthenticator{}}
	}
	return []thingssocks5.Authenticator{
		thingssocks5.UserPassAuthenticator{
			Credentials: socksCredentials{user: username, password: password},
		},
		loopbackNoAuthAuthenticator{},
	}
}
