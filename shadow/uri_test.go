package shadow

import (
	"shadowsocks/config"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseURI(t *testing.T) {
	assert := assert.New(t)
	uri := []struct {
		name, cipher, password, address, port, value string
	}{
		{"BlankURI", "AES-256-GCM", "Shadowsocks!Go", ":8488", "8488", ""},
		{"StringURI", "AES-256-GCM", "Shadowsocks!Go", "invalidURI:8488", "8488", "invalidURI"},
		{"PortURI", "AES-256-GCM", "Shadowsocks!Go", "google.com:3000", "3000", "google.com:3000"},
		{"UsernameURI", "yuqlee", "Shadowsocks!Go", "google.com:3000", "3000", "yuqlee@google.com:3000"},
		{"PasswordURI", "AES-256-GCM", "iamyuqlee", "google.com:3000", "3000", "AES-256-GCM:iamyuqlee@google.com:3000"},
		{"CipherPasswordURI", "yuqlee", "iamyuqlee", "google.com:3000", "3000", "yuqlee:iamyuqlee@google.com:3000"},
	}

	for _, u := range uri {
		t.Run(u.name, func(t *testing.T) {
			setting := config.Setting
			err := ParseURI(u.value)
			assert.Nil(err)
			assert.Equal(u.address, setting.Address)
			assert.Equal(u.cipher, setting.Cipher)
			assert.Equal(u.password, setting.Password)
			assert.Equal(u.port, setting.Port)
		})
	}
}
