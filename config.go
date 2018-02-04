package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"reflect"
	"time"

	"github.com/pkg/errors"
)

const (
	LOG_MAX_AGE       = 48 * time.Hour
	LOG_ROTATION_TIME = 24 * time.Hour
)

type PACStatus int

const (
	PACON PACStatus = iota + 1
	PACOFF
	PACONGLOBAL
	PACOFFGLOBAL
)

type Config struct {
	Server      string `json:"server"`
	ServerPort  int    `json:"server_port"`
	LocalPort   int    `json:"local_port"`
	Password    string `json:"password"`
	Method      string `json:"method"` // encryption method
	Timeout     int    `json:"timeout"`
	EnableQuic  bool   `json:"quic"`
	ServerModel bool   `json:"server_model"`
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
