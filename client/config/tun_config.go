package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// TunConfig 是 local.tun_config 的形状，加载期校验与运行时读取共用它：各定义一份会让
// 键名拼错通过校验，再在消费点静默退回默认设备名。
type TunConfig struct {
	Device string `json:"device"`
}

// ParseTunConfig 按消费形状解析 tun_config。未知键、类型不匹配与尾随数据都报错，
// 否则 {"devce":...} 这类拼写错误会一路溜到运行时。
func ParseTunConfig(raw json.RawMessage) (TunConfig, error) {
	var cfg TunConfig
	if len(raw) == 0 {
		return cfg, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return TunConfig{}, fmt.Errorf("tun_config: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return TunConfig{}, fmt.Errorf("tun_config: trailing data after the object")
	}
	return cfg, nil
}
