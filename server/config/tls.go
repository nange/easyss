package config

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/nange/easyss/v3/util"
)

// UsesManualCertificate 是"证书从哪来"的唯一判定入口，initTLS 与启动日志都读它。
func (fc *FileConfig) UsesManualCertificate() bool {
	return fc.Server.CertPath != "" && fc.Server.KeyPath != ""
}

// ACMESubjectIsIP 只回答"形态"这一件事，公网性由 validateTLS 把关；手工证书模式下恒为 false。
func (fc *FileConfig) ACMESubjectIsIP() bool {
	if fc.UsesManualCertificate() {
		return false
	}
	addr, ok := parseIPLiteral(fc.Server.Host)
	return ok && addr.Is4()
}

// validateTLS 在进程启动时以明确的配置错误暴露问题。公网性判据是 util.IsLANIP，故意比
// certmagic 的 SubjectQualifiesForPublicCert 更严，不要为"对齐"放宽。只接受 IPv4：客户端用
// https://<host>:<port> 拼服务端地址，IPv6 字面量在那里会以 "too many colons" 失败。
func (fc *FileConfig) validateTLS() error {
	srvCfg := fc.Server

	// host 里出现冒号只可能是把端口写了进来；带方括号的字面量不是客户端能拼出的形态。
	if srvCfg.Host != "" {
		if _, isIP := parseIPLiteral(srvCfg.Host); !isIP {
			if isBracketedIPLiteral(srvCfg.Host) {
				return errNotPlainIPv4Literal(srvCfg.Host)
			}
			if strings.Contains(srvCfg.Host, ":") {
				return fmt.Errorf("server.host %q must not include a port; use server.port for the listen port", srvCfg.Host)
			}
		}
	}

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
		// 域名：公网性与可解析性由 certmagic/ACME 侧判断，形态已在前面校验过。
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

// parseIPLiteral 依赖 netip.ParseAddr 不接受方括号、前导零与结尾空白，"能解析"因此等价于
// "是逐字可用的字面量"。
func parseIPLiteral(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// isBracketedIPLiteral 把这类写法从"域名"里挑出来明确报错：否则它们会一路走到 ACME，
// 以看不出问题在哪的 "does not qualify for a public certificate" 结束。
func isBracketedIPLiteral(s string) bool {
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return false
	}
	_, ok := parseIPLiteral(s[1 : len(s)-1])
	return ok
}
