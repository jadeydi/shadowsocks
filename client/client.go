package client

import (
	"log"
	"shadowsocks/config"
	"shadowsocks/shadow"
)

type ClientImpl struct{}

// Start client application
func (c *ClientImpl) Start() {
	setting := config.Setting
	if err := shadow.ParseURI(setting.Client); err != nil {
		log.Panicln(err)
	}
	go c.ListenSock(setting.Socks, setting.Address)
}
