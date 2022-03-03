package easyss

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"reflect"

	"github.com/pkg/errors"
)

type Config struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	LocalPort  int    `json:"local_port"`
	Password   string `json:"password"`
	Method     string `json:"method"` // encryption method
	Timeout    int    `json:"timeout"`
	BindALL    bool   `json:"bind_all"`
}

func ParseConfig(path string) (config *Config, err error) {
	file, err := os.Open(path) // For read access.
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
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

	if old.Method == "" {
		old.Method = "aes-256-gcm"
	}
	if old.Timeout <= 0 || old.Timeout > 600 {
		old.Timeout = 600
	}
}
