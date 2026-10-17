package config

import (
	"fmt"
	"net/netip"

	"github.com/nange/easyss/v3/util"
)

// UsesManualCertificate 报告本次部署的证书来自 server.cert_path/server.key_path。
//
// 它是"证书从哪来"的唯一判定入口：initTLS 与启动日志都读它，而不是各自判断两个
// 字段是否非空——那种重复判断正是"只配了一个路径"的半配置能逃过校验、最终却在
// 运行期静默忽略该文件的原因（见 validateTLS）。
func (fc *FileConfig) UsesManualCertificate() bool {
	return fc.Server.CertPath != "" && fc.Server.KeyPath != ""
}

// ACMESubjectIsIP 报告自动申请证书的标识符是 IP 字面量（而不是域名）。
//
// 它只回答"形态"这一件事：该地址能否被公网 CA 签发由 validateTLS 在配置加载
// 阶段把关，所以这里不做公网性判断——绕过 LoadConfig 的调用方（测试、嵌入式）
// 手搓一份私有地址的配置时，仍然应该拿到"IP 模式"的行为（显式请求短生命周期
// profile、打 IP 模式的启动日志），随后由 certmagic 的预检明确拒绝。
//
// 手工证书模式下恒为 false：那时标识符不参与取证，IP 与否没有运行期含义。
func (fc *FileConfig) ACMESubjectIsIP() bool {
	if fc.UsesManualCertificate() {
		return false
	}
	addr, ok := parseIPLiteral(fc.Server.Host)
	return ok && addr.Is4()
}

// validateTLS 固定"证书从哪来"这一启动期契约，由 LoadConfig 调用，使这些错误在
// 进程启动时（而不是第一次 ACME 申请、更不是运行期）以明确的配置错误暴露。
//
// 判定顺序：
//
//  1. cert_path/key_path 恰好只配了一个 → 配置错误。两个都配才是手工证书模式
//     （tls.LoadX509KeyPair 需要两份文件），只配一个时旧行为是**静默忽略**它、
//     转而向 Let's Encrypt 申请——运维以为自己用的是自己的证书，实际不是。
//  2. 两个都配 → 手工证书模式：host 不参与取证（它只进日志），因此不做约束。
//  3. 都没配 → ACME 模式：host 必填；若写的是 IP 字面量，只接受**公网 IPv4**。
//
// 为什么 IP-only 只接受公网 IPv4：
//
//   - 公网性：Let's Encrypt 的 IP 地址证书（RFC 8738、2026-01 GA）在验证时会连接
//     该地址的 443 端口，并拒绝私有/保留/环回/链路本地/CGNAT 等不可公网验证的
//     地址，因此这类地址写进来必然申请失败。这里的判据是 util.IsLANIP，它**故意
//     比 certmagic 的 SubjectQualifiesForPublicCert 更严**（后者不含 CGNAT、
//     TEST-NET、240/4 等段，只靠 CA 侧兜底）：与其让运维等一轮 ACME 往返才看到
//     拒绝，不如在配置加载阶段就说清楚出路（公网 IP，或自签证书 + 客户端 ca_path）。
//     不要为了"和 certmagic 对齐"而放宽这里。
//   - IPv4：客户端用 `https://<host>:<port>` 与 `<host>:<port>` 拼服务端
//     地址，IPv6 字面量（以及 IPv4-mapped 的 ::ffff:a.b.c.d、带方括号的写法）
//     在这两处都无法表达，net.Dial 会以 "too many colons" 失败——那是运行期才
//     暴露的症状，而且看起来与证书无关。
//
// IP-only 模式的运行期前提（README 有面向运维的说明）：Let's Encrypt 对 IP 标识符
// 只能用 tls-alpn-01（dns-01 被 RFC 8738 禁止），所以公网 443 必须可达；IP 证书
// 只能是短生命周期证书（约 160 小时），续期同样要重新验证。
func (fc *FileConfig) validateTLS() error {
	srvCfg := fc.Server

	certSet := srvCfg.CertPath != ""
	keySet := srvCfg.KeyPath != ""
	switch {
	case certSet != keySet:
		return fmt.Errorf("server.cert_path and server.key_path must be set together (cert_path=%q, key_path=%q)",
			srvCfg.CertPath, srvCfg.KeyPath)
	case certSet:
		return nil
	}

	if srvCfg.Host == "" {
		return fmt.Errorf("server.host is required unless server.cert_path and server.key_path are both set")
	}

	addr, isIP := parseIPLiteral(srvCfg.Host)
	if !isIP {
		if isBracketedIPLiteral(srvCfg.Host) {
			return errNotPlainIPv4Literal(srvCfg.Host)
		}
		// 域名：公网性与可解析性由 certmagic/ACME 侧判断。
		return nil
	}
	if !addr.Is4() {
		return errNotPlainIPv4Literal(srvCfg.Host)
	}
	if util.IsLANIP(srvCfg.Host) {
		return fmt.Errorf("server.host %q is a private or reserved address, for which Let's Encrypt cannot issue "+
			"a certificate (it validates by connecting to the address on port 443 and refuses non-public addresses); "+
			"use the server's public IPv4 address, or set server.cert_path/server.key_path and hand clients "+
			"the matching server.ca_path", srvCfg.Host)
	}
	return nil
}

func errNotPlainIPv4Literal(host string) error {
	return fmt.Errorf("server.host %q is an IP literal, but only a plain IPv4 literal is supported: "+
		"the client builds https://<address>:<port> from this value, which cannot express an IPv6 or "+
		"IPv4-mapped address (write 1.2.3.4, not [1.2.3.4] or ::ffff:1.2.3.4)", host)
}

// parseIPLiteral 解析规范写法的 IP 字面量。netip.ParseAddr 本身就不接受方括号、
// 前导零与结尾空白，因此"能解析"等价于"是逐字可用的字面量"。
func parseIPLiteral(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// isBracketedIPLiteral 报告 s 是不是带方括号的 IP 字面量（[1.2.3.4]、[2001:db8::1]）。
// 它只用于把这类写法从"域名"里挑出来给出明确报错：否则它们会一路走到 ACME，
// 最后以"subject '[1.2.3.4]' does not qualify for a public certificate"这种
// 看不出问题在哪的报错结束。
func isBracketedIPLiteral(s string) bool {
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return false
	}
	_, ok := parseIPLiteral(s[1 : len(s)-1])
	return ok
}
