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
	if dst.Tun2socksModel == "" {
		dst.Tun2socksModel = "off"
	}
	if dst.DirectIPsFile == "" {
		dst.DirectIPsFile = "direct_ips.txt"
	}
	if dst.DirectDomainsFile == "" {
		dst.DirectDomainsFile = "direct_domains.txt"
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
