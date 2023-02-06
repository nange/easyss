package easyss

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/pkg/errors"
)

var Methods = map[string]struct{}{
	"aes-256-gcm":       {},
	"chacha20-poly1305": {},
}

var ProxyRules = map[string]struct{}{
	"auto":   {},
	"proxy":  {},
	"direct": {},
}

type ServerConfig struct {
	Server      string `json:"server"`
	ServerPort  int    `json:"server_port"`
	Password    string `json:"password"`
	Timeout     int    `json:"timeout"`
	DisableUTLS bool   `json:"disable_utls"`
	CertPath    string `json:"cert_path"`
	KeyPath     string `json:"key_path"`
	CAPath      string `json:"ca_path"`
}

type Config struct {
	ServerList        []ServerConfig `json:"server_list,omitempty"`
	Server            string         `json:"server"`
	ServerPort        int            `json:"server_port"`
	LocalPort         int            `json:"local_port"`
	HTTPPort          int            `json:"http_port"`
	Password          string         `json:"password"`
	Method            string         `json:"method"` // encryption method
	Timeout           int            `json:"timeout"`
	BindALL           bool           `json:"bind_all"`
	DisableUTLS       bool           `json:"disable_utls"`
	EnableForwardDNS  bool           `json:"enable_forward_dns"`
	EnableTun2socks   bool           `json:"enable_tun2socks"`
	DirectIPsFile     string         `json:"direct_ips_file"`
	DirectDomainsFile string         `json:"direct_domains_file"`
	ProxyRule         string         `json:"proxy_rule"`
	CAPath            string         `json:"ca_path"`
	ConfigFile        string         `json:"-"`
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
	if c.ProxyRule != "" {
		if _, ok := ProxyRules[c.ProxyRule]; !ok {
			return fmt.Errorf("unsupported proxy rule:%s, supported rules:[auto, proxy, direct]", c.ProxyRule)
		}
	}

	return nil
}

func (c *Config) Clone() *Config {
	b, _ := json.Marshal(c)
	cc := new(Config)
	_ = json.Unmarshal(b, cc)
	return cc
}

func ParseConfig[T any](path string) (config *T, err error) {
	file, err := os.Open(path) // For read access.
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	config = new(T)
	if err = json.Unmarshal(data, config); err != nil {
		err = errors.WithStack(err)
		return nil, err
	}

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
		c.Server = c.ServerList[0].Server
		c.ServerPort = c.ServerList[0].ServerPort
		c.Password = c.ServerList[0].Password
		c.DisableUTLS = c.ServerList[0].DisableUTLS
		c.CAPath = c.ServerList[0].CAPath
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
	if c.Timeout <= 0 || c.Timeout > 60 {
		c.Timeout = 60
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
}

func (c *ServerConfig) SetDefaultValue() {
	if c.Timeout <= 0 || c.Timeout > 60 {
		c.Timeout = 60
	}
}

func (c *ServerConfig) Validate() error {
	if c.Server == "" || c.ServerPort == 0 || c.Password == "" {
		return errors.New("server address, server port and password should not empty")
	}
	return nil
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
		Server:      "example.com",
		ServerPort:  9999,
		Password:    "your-pass",
		Timeout:     30,
		DisableUTLS: false,
		CertPath:    "",
		KeyPath:     "",
	}

	b, _ := json.MarshalIndent(example, "", "    ")
	return string(b)
}
