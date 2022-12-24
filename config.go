package easyss

import (
	"encoding/json"
	"io"
	"os"
	"reflect"

	"github.com/pkg/errors"
)

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
	Tun2socksModel    string `json:"tun2socks_model"`
	DirectIPsFile     string `json:"direct_ips_file"`
	DirectDomainsFile string `json:"direct_domains_file"`
	ProxyIPsFile      string `json:"proxy_ips_file"`
	ProxyDomainsFile  string `json:"proxy_domains_file"`
	ConfigFile        string `json:"-"`
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

// TODO: rename old, ne to dst, src and rename UpdateConfig to OverrideConfig
func UpdateConfig(old, ne *Config) {
	newVal := reflect.ValueOf(ne).Elem()
	oldVal := reflect.ValueOf(old).Elem()

	for i := 0; i < newVal.NumField(); i++ {
		newField := newVal.Field(i)
		oldField := oldVal.Field(i)

		switch newField.Kind() {
		case reflect.String:
			s := newField.String()
			if s != "" {
				oldField.SetString(s)
			}
		case reflect.Int:
			i := newField.Int()
			if i != 0 {
				oldField.SetInt(i)
			}
		case reflect.Bool:
			b := newField.Bool()
			if b {
				oldField.SetBool(b)
			}
		}
	}

	if old.LocalPort == 0 {
		old.LocalPort = 2080
	}
	if old.Method == "" {
		old.Method = "aes-256-gcm"
	}
	if old.Timeout <= 0 || old.Timeout > 60 {
		old.Timeout = 60
	}
	if old.DirectIPsFile == "" {
		old.DirectIPsFile = "direct_ips.txt"
	}
	if old.DirectDomainsFile == "" {
		old.DirectDomainsFile = "direct_domains.txt"
	}
	if old.ProxyIPsFile == "" {
		old.ProxyIPsFile = "proxy_ips.txt"
	}
	if old.ProxyDomainsFile == "" {
		old.ProxyDomainsFile = "proxy_domains.txt"
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
