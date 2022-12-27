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

type Config struct {
	Server            string `json:"server"`
	ServerPort        int    `json:"server_port"`
	LocalPort         int    `json:"local_port"`
	Password          string `json:"password"`
	Method            string `json:"method"` // encryption method
	Timeout           int    `json:"timeout"`
	BindALL           bool   `json:"bind_all"`
	DisableUTLS       bool   `json:"disable_utls"`
	EnableForwardDNS  bool   `json:"enable_forward_dns"`
	EnableTun2socks   bool   `json:"enable_tun2socks"`
	DirectIPsFile     string `json:"direct_ips_file"`
	DirectDomainsFile string `json:"direct_domains_file"`
	ProxyRule         string `json:"proxy_rule"`
	ConfigFile        string `json:"-"`
}

func (c *Config) ClientValidate() error {
	if c.Server == "" || c.ServerPort == 0 || c.Password == "" {
		errors.New("server address, server port and password should not empty")
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

func (c *Config) ServerValidate() error {
	if c.Server == "" || c.ServerPort == 0 || c.Password == "" {
		errors.New("server address, server port and password should not empty")
	}
	return nil
}

func ParseConfig(path string) (config *Config, err error) {
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

	config = &Config{}
	if err = json.Unmarshal(data, config); err != nil {
		err = errors.WithStack(err)
		return nil, err
	}

	return
}

func OverrideConfig(dst, src *Config) {
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

	if dst.LocalPort == 0 {
		dst.LocalPort = 2080
	}
	if dst.Method == "" {
		dst.Method = "aes-256-gcm"
	}
	if dst.Timeout <= 0 || dst.Timeout > 60 {
		dst.Timeout = 60
	}
	if dst.DirectIPsFile == "" {
		dst.DirectIPsFile = "direct_ips.txt"
	}
	if dst.DirectDomainsFile == "" {
		dst.DirectDomainsFile = "direct_domains.txt"
	}
	if dst.ProxyRule == "" {
		dst.ProxyRule = "auto"
	}
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
