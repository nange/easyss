package easyss

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_ClientValidate(t *testing.T) {
	c := &Config{
		Server:     "your-domain.com",
		ServerPort: 9999,
		LocalPort:  2080,
		Password:   "test-pass",
		Method:     "aes-256-gcm",
	}
	c.SetDefaultValue()
	assert.Nil(t, c.Validate())

	c.Method = "invalid-method"
	assert.NotNil(t, c.Validate())

	c.Method = "aes-256-gcm"
	c.Server = ""
	assert.NotNil(t, c.Validate())

	c.Server = "your-domain.com"
	c.ServerPort = 0
	assert.NotNil(t, c.Validate())

	c.ServerPort = 9999
	c.Password = ""
	assert.NotNil(t, c.Validate())
}

func TestConfig_ServerValidate(t *testing.T) {
	c := &ServerConfig{
		Server:     "your-domain.com",
		ServerPort: 9999,
		Password:   "you-pass",
	}
	c.SetDefaultValue()
	assert.Nil(t, c.Validate())

	c.Server = ""
	assert.NotNil(t, c.Validate())

	c.Server = "your-domain.com"
	c.Password = ""
	assert.NotNil(t, c.Validate())

	c.Password = "your-pass"
	c.ServerPort = 0
	assert.NotNil(t, c.Validate())

	c.Server = ""
	c.ServerPort = 9999
	assert.NotNil(t, c.Validate())

	c.DisableTLS = true
	assert.Nil(t, c.Validate())

	c.DisableTLS = false
	c.CertPath = "/test.pem"
	c.KeyPath = "key.pem"
	assert.Nil(t, c.Validate())
}

func TestConfig_Clone(t *testing.T) {
	c := &Config{
		Server:     "your-domain.com",
		Password:   "your-pass",
		ServerPort: 9999,
	}
	cloned := c.Clone()
	assert.Equal(t, "your-domain.com", cloned.Server)

	c.Server = "xx-domain.com"
	assert.Equal(t, "your-domain.com", cloned.Server)
}

func TestOverrideConfig(t *testing.T) {
	dst := &Config{
		Server:     "your-domain.com",
		Password:   "your-pass",
		ServerPort: 9999,
	}
	src := &Config{
		Server:     "xx-domain.com",
		Password:   "",
		ServerPort: 0,
	}
	OverrideConfig(dst, src)

	assert.Equal(t, "xx-domain.com", dst.Server)
	assert.Equal(t, 9999, dst.ServerPort)
	assert.Equal(t, "your-pass", dst.Password)
}
