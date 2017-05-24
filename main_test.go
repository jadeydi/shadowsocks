package main

import (
	"os"
	"shadowsocks/config"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFlags(t *testing.T) {
	assert := assert.New(t)
	setting := config.Setting
	assert.False(setting.Help)
	assert.False(setting.Quiet)
	assert.False(setting.Server)
	assert.Equal(":8488", setting.Address)
	assert.Equal("", setting.Client)

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"cmd", "-h", "-q", "-s", "-a=ss://user:password@:8288", "-c=ss://user:password@127.0.0.1:8288"}
	parseFlags()

	assert.True(setting.Help)
	assert.True(setting.Quiet)
	assert.True(setting.Server)
	assert.Equal("ss://user:password@:8288", setting.Address)
	assert.Equal("ss://user:password@127.0.0.1:8288", setting.Client)
}
