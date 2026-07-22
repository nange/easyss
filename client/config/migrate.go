package config

import (
	"encoding/json"
	"os"

	sharedconfig "github.com/nange/easyss/v3/config"
)

func MigrateV2Config(s sharedconfig.SimpleConfig) (*ClientConfig, error) {
	return BuildSimpleConfig(&s)
}

func MigrateV2ToV3(v2Path, v3Path string) error {
	data, err := os.ReadFile(v2Path)
	if err != nil {
		return err
	}

	var s sharedconfig.SimpleConfig
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	v3, err := BuildSimpleConfig(&s)
	if err != nil {
		return err
	}

	v3JSON, err := json.MarshalIndent(v3, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(v3Path, v3JSON, 0644)
}
