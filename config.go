package easyss

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/nange/easyss/v2/util"
)

var Methods = map[string]struct{}{
	"aes-256-gcm":       {},
	"chacha20-poly1305": {},
}

var ProxyRules = map[string]struct{}{
	"auto":       {},
	"auto_block": {},
	"proxy":      {},
	"direct":     {},
}

const (
	OutboundProtoNative = "native"
	OutboundProtoHTTP   = "http"
	OutboundProtoHTTPS  = "https"
)

type ServerConfig struct {
	Server                 string `json:"server"`
	ServerPort             int    `json:"server_port"`
	Password               string `json:"password"`
	Timeout                int    `json:"timeout"`
	LogLevel               string `json:"log_level"`
	LogFilePath            string `json:"log_file_path"`
	DisableUTLS            bool   `json:"disable_utls"`
	DisableTLS             bool   `json:"disable_tls"`
	CertPath               string `json:"cert_path"`
	KeyPath                string `json:"key_path"`
	EnableHTTPInbound      bool   `json:"enable_http_inbound"`
	HTTPInboundPort        int    `json:"http_inbound_port"`
	NextProxyURL           string `json:"next_proxy_url"`
	NextProxyDomainsFile   string `json:"next_proxy_domains_file"`
	NextProxyIPsFile       string `json:"next_proxy_ips_file"`
	EnableNextProxyUDP     bool   `json:"enable_next_proxy_udp"`
	EnableNextProxyALLHost bool   `json:"enable_next_proxy_all_host"`
	// the below fields only be used for easyss client
	CAPath           string `json:"ca_path,omitempty"`
	Default          bool   `json:"default,omitempty"`
	OutboundProto    string `json:"outbound_proto,omitempty"`
	CMDBeforeStartup string `json:"cmd_before_startup,omitempty"`
	CMDInterval      string `json:"cmd_interval,omitempty"`
	CMDIntervalTime  int    `json:"cmd_interval_time,omitempty"`
}

type Config struct {
	ServerList        []ServerConfig `json:"server_list,omitempty"`
	Server            string         `json:"server"`
	ServerPort        int            `json:"server_port"`
	LocalPort         int            `json:"local_port"`
	HTTPPort          int            `json:"http_port"`
	Password          string         `json:"password"`
	Method            string         `json:"method"` // encryption method
	LogLevel          string         `json:"log_level"`
	LogFilePath       string         `json:"log_file_path"`
	Timeout           int            `json:"timeout"`
	AuthUsername      string         `json:"auth_username"`
	AuthPassword      string         `json:"auth_password"`
	BindALL           bool           `json:"bind_all"`
	DisableUTLS       bool           `json:"disable_utls"`
	DisableSysProxy   bool           `json:"disable_sys_proxy"`
	DisableIPV6       bool           `json:"disable_ipv6"`
	DisableTLS        bool           `json:"disable_tls"`
	EnableForwardDNS  bool           `json:"enable_forward_dns"`
	EnableTun2socks   bool           `json:"enable_tun2socks"`
	TunConfig         *TunConfig     `json:"tun_config"`
	DirectIPsFile     string         `json:"direct_ips_file"`
	DirectDomainsFile string         `json:"direct_domains_file"`
	ProxyRule         string         `json:"proxy_rule"`
	CAPath            string         `json:"ca_path"`
	OutboundProto     string         `json:"outbound_proto"`
	CMDBeforeStartup  string         `json:"cmd_before_startup"`
	CMDInterval       string         `json:"cmd_interval"`
	CMDIntervalTime   int            `json:"cmd_interval_time"`
	ConfigFile        string         `json:"-"`
}

type TunConfig struct {
	TunDevice string `json:"tun_device"`
	TunIP     string `json:"tun_ip"`
	TunGW     string `json:"tun_gw"`
	TunMask   string `json:"tun_mask"`
}

func (tc *TunConfig) IPSub() string {
	if tc == nil {
		return ""
	}
	items := strings.Split(tc.TunMask, ".")
	if len(items) != 4 {
		return ""
	}

	m0, _ := strconv.ParseUint(items[0], 10, 8)
	m1, _ := strconv.ParseUint(items[1], 10, 8)
	m2, _ := strconv.ParseUint(items[2], 10, 8)
	m3, _ := strconv.ParseUint(items[3], 10, 8)
	ipNet := net.IPNet{
		IP:   net.ParseIP(tc.TunIP),
		Mask: net.IPv4Mask(byte(m0), byte(m1), byte(m2), byte(m3)),
	}

	return ipNet.String()
}

func (c *Config) Validate() error {
	if len(c.ServerList) == 0 && (c.Server == "" || c.ServerPort == 0 || c.Password == "" || c.Method == "") {
		return errors.New("server address, server port, password, method should not empty")
	}
	if len(c.ServerList) > 0 {
		for _, s := range c.ServerList {
			if s.Server == "" || s.ServerPort == 0 || s.Password == "" {
				return errors.New("server address, server port and password should not empty in server list")
			}
		}
	}
	if c.Method != "" {
		if _, ok := Methods[c.Method]; !ok {
			return fmt.Errorf("unsupported method:%s, supported methods:[aes-256-gcm, chacha20-poly1305]", c.Method)
		}
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("unsupported log-level:%s, supported log-levels:[debug, info, warn, error]", c.LogLevel)
	}
	if c.ProxyRule != "" {
		if _, ok := ProxyRules[c.ProxyRule]; !ok {
			return fmt.Errorf("unsupported proxy rule:%s, supported rules:[auto, auto_block, proxy, direct]", c.ProxyRule)
		}
	}
	if c.OutboundProto != OutboundProtoNative && c.OutboundProto != OutboundProtoHTTP &&
		c.OutboundProto != OutboundProtoHTTPS {
		return fmt.Errorf("outbound proto must be one of [%s, %s, %s]",
			OutboundProtoNative, OutboundProtoHTTP, OutboundProtoHTTPS)
	}
	if c.TunConfig == nil {
		return fmt.Errorf("tun config should not be empty")
	}
	if c.TunConfig.TunDevice == "" || c.TunConfig.TunIP == "" || c.TunConfig.TunGW == "" || c.TunConfig.TunMask == "" {
		return fmt.Errorf("any of tun config field should not be empty")
	}

	return nil
}

func getLogFilePath(path string) string {
	if path != "" {
		if filepath.IsAbs(path) {
			return path
		}
		dir := util.CurrentDir()
		return filepath.Join(dir, path)
	}
	return ""
}

func (c *Config) GetLogFilePath() string {
	return getLogFilePath(c.LogFilePath)
}

func (c *Config) Clone() *Config {
	b, _ := json.Marshal(c)
	cc := new(Config)
	_ = json.Unmarshal(b, cc)
	return cc
}

func ParseConfig[T any](path string) (config *T, err error) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return
	}

	config = new(T)
	err = json.Unmarshal(data, config)

	return
}

func OverrideConfig[T any](dst, src *T) {
	newVal := reflect.ValueOf(src).Elem()
	oldVal := reflect.ValueOf(dst).Elem()

	for i := 0; i < newVal.NumField(); i++ {
		srcField := newVal.Field(i)
		dstField := oldVal.Field(i)

		switch srcField.Kind() {
		case reflect.String:
			s := srcField.String()
			if s != "" {
				dstField.SetString(s)
			}
		case reflect.Int:
			i := srcField.Int()
			if i != 0 {
				dstField.SetInt(i)
			}
		case reflect.Bool:
			b := srcField.Bool()
			if b {
				dstField.SetBool(b)
			}
		}
	}

}

func (c *Config) SetDefaultValue() {
	// if server is empty, try to use the first item in server list instead
	if c.Server == "" && len(c.ServerList) > 0 {
		sc := c.DefaultServerConfigFrom(c.ServerList)
		c.OverrideFrom(sc)
	}

	if c.LocalPort == 0 {
		c.LocalPort = 2080
	}
	if c.HTTPPort == 0 {
		c.HTTPPort = c.LocalPort + 1000
	}
	if c.Method == "" {
		c.Method = "aes-256-gcm"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Timeout <= 0 || c.Timeout > 60 {
		c.Timeout = 30
	}
	if c.DirectIPsFile == "" {
		c.DirectIPsFile = "direct_ips.txt"
	}
	if c.DirectDomainsFile == "" {
		c.DirectDomainsFile = "direct_domains.txt"
	}
	if c.ProxyRule == "" {
		c.ProxyRule = "auto"
	}
	if c.OutboundProto == "" {
		c.OutboundProto = OutboundProtoNative
	}
	if c.CMDIntervalTime == 0 {
		c.CMDIntervalTime = 600
	}
	if c.TunConfig == nil {
		c.TunConfig = &TunConfig{}
		switch runtime.GOOS {
		case "darwin":
			c.TunConfig.TunDevice = "utun9"
		default:
			c.TunConfig.TunDevice = "tun-easyss"
		}
		c.TunConfig.TunIP = "198.18.0.1"
		c.TunConfig.TunGW = "198.18.0.1"
		c.TunConfig.TunMask = "255.255.0.0"
	}
	if c.TunConfig.TunIP == "" && c.TunConfig.TunGW != "" {
		c.TunConfig.TunIP = c.TunConfig.TunGW
	}
	if c.TunConfig.TunMask == "" {
		c.TunConfig.TunMask = "255.255.0.0"
	}
}

func (c *Config) OverrideFrom(sc *ServerConfig) {
	if sc != nil {
		c.Server = sc.Server
		c.ServerPort = sc.ServerPort
		c.Password = sc.Password
		if sc.Timeout != 0 {
			c.Timeout = sc.Timeout
		}
		if sc.DisableUTLS {
			c.DisableUTLS = sc.DisableUTLS
		}
		c.DisableTLS = sc.DisableTLS
		c.CAPath = sc.CAPath
		c.OutboundProto = sc.OutboundProto
		c.CMDInterval = sc.CMDInterval
		c.CMDBeforeStartup = sc.CMDBeforeStartup
		c.CMDIntervalTime = sc.CMDIntervalTime
	}
}

func (c *Config) DefaultServerConfigFrom(list []ServerConfig) *ServerConfig {
	if len(list) == 0 {
		return nil
	}
	if len(list) == 1 {
		return &list[0]
	}
	for _, v := range list {
		if v.Default {
			return &v
		}
	}

	return &list[0]
}

func (c *ServerConfig) SetDefaultValue() {
	if c.Timeout <= 0 || c.Timeout > 60 {
		c.Timeout = 30
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.OutboundProto == "" {
		c.OutboundProto = OutboundProtoNative
	}
	if c.CMDIntervalTime == 0 {
		c.CMDIntervalTime = 600
	}
	if c.HTTPInboundPort == 0 {
		c.HTTPInboundPort = c.ServerPort + 1000
	}
	if c.NextProxyDomainsFile == "" {
		c.NextProxyDomainsFile = "next_proxy_domains.txt"
	}
	if c.NextProxyIPsFile == "" {
		c.NextProxyIPsFile = "next_proxy_ips.txt"
	}
}

func (c *ServerConfig) Validate() error {
	if !c.DisableTLS && (c.KeyPath == "" || c.CertPath == "") {
		if c.Server == "" {
			return errors.New("server address should not empty")
		}
	}
	if c.ServerPort == 0 {
		return errors.New("server port should not empty")
	}
	if c.Password == "" {
		return errors.New("password should not empty")
	}
	if c.OutboundProto != OutboundProtoNative && c.OutboundProto != OutboundProtoHTTP &&
		c.OutboundProto != OutboundProtoHTTPS {
		return fmt.Errorf("outbound proto must be one of [%s, %s, %s]",
			OutboundProtoNative, OutboundProtoHTTP, OutboundProtoHTTPS)
	}
	if c.EnableHTTPInbound && c.HTTPInboundPort == 0 {
		return errors.New("http inbound port should not empty")
	}
	if c.NextProxyURL != "" {
		if u, err := url.Parse(c.NextProxyURL); err != nil {
			return fmt.Errorf("next proxy url %s is invalid", c.NextProxyURL)
		} else {
			if u.Scheme != "socks5" { // only support 'socks5' for now
				return fmt.Errorf("%s next proxy scheme is unsupported", u.Scheme)
			}
		}
	}

	return nil
}

func (c *ServerConfig) GetLogFilePath() string {
	return getLogFilePath(c.LogFilePath)
}

func ExampleJSONConfig() string {
	example := Config{
		Server:     "example.com",
		ServerPort: 9999,
		LocalPort:  2080,
		Password:   "your-pass",
		Method:     "aes-256-gcm",
		Timeout:    30,
		BindALL:    false,
	}

	b, _ := json.MarshalIndent(example, "", "    ")
	return string(b)
}

func ExampleServerJSONConfig() string {
	example := ServerConfig{
		Server:            "example.com",
		ServerPort:        9999,
		Password:          "your-pass",
		Timeout:           30,
		DisableUTLS:       false,
		CertPath:          "",
		KeyPath:           "",
		EnableHTTPInbound: true,
	}

	b, _ := json.MarshalIndent(example, "", "    ")
	return string(b)
}
