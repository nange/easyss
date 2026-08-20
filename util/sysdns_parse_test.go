package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDNSServersFromIPConfigEnglish(t *testing.T) {
	output := `Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : example.com
   IPv4 Address. . . . . . . . . . . : 192.168.1.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter VPN:

   Connection-specific DNS Suffix  . :
   DNS Servers . . . . . . . . . . . : 10.8.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
`
	assert.Equal(t, []string{"192.168.1.1", "8.8.8.8", "10.8.0.1"}, parseDNSServersFromIPConfig(output))
}

func TestParseDNSServersFromIPConfigChineseUTF8(t *testing.T) {
	output := `Windows IP 配置

以太网适配器 以太网:

   连接特定的 DNS 后缀 . . . . . . . : example.com
   IPv4 地址 . . . . . . . . . . . . : 192.168.1.100
   子网掩码  . . . . . . . . . . . . : 255.255.255.0
   默认网关. . . . . . . . . . . . . : 192.168.1.1
   DNS 服务器  . . . . . . . . . . . : 192.168.1.1
                                       8.8.8.8
   通过 TCP/IP 的 NetBIOS . . . . . : 已启用
`
	assert.Equal(t, []string{"192.168.1.1", "8.8.8.8"}, parseDNSServersFromIPConfig(output))
}

func TestParseDNSServersFromIPConfigChineseGBK(t *testing.T) {
	// "DNS 服务器" encoded in gbk(cp936)
	label := "DNS " + "\xB7\xFE\xCE\xF1\xC6\xF7"
	output := "Windows IP Configuration\r\n" +
		"\r\n" +
		"Ethernet adapter Ethernet:\r\n" +
		"   " + label + "  . . . . . . . . . . . : 192.168.1.1\r\n" +
		"                                       8.8.8.8\r\n" +
		"   NetBIOS over Tcpip. . . . . . . . : Enabled\r\n"
	assert.Equal(t, []string{"192.168.1.1", "8.8.8.8"}, parseDNSServersFromIPConfig(output))
}

func TestParseDNSServersFromIPConfigDedupe(t *testing.T) {
	output := `DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       192.168.1.1
                                       8.8.8.8

Ethernet adapter VPN:
   DNS Servers . . . . . . . . . . . : 8.8.8.8
`
	assert.Equal(t, []string{"192.168.1.1", "8.8.8.8"}, parseDNSServersFromIPConfig(output))
}

func TestParseDNSServersFromIPConfigNoDNS(t *testing.T) {
	output := `Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : example.com
   IPv4 Address. . . . . . . . . . . : 192.168.1.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
`
	assert.Empty(t, parseDNSServersFromIPConfig(output))
}

func TestParseDNSServersFromIPConfigEmpty(t *testing.T) {
	assert.Empty(t, parseDNSServersFromIPConfig(""))
	assert.Empty(t, parseDNSServersFromIPConfig("\r\n\r\n"))
}
