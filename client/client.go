package client

import (
	"log"
	"shadowsocks/config"
	"shadowsocks/security"
	"shadowsocks/shadow"
)

type ClientImpl struct{}

// Parse the custom settings from uri, update the settings, e.g.: cipher, address, port, and build cipher and start the client application.
func (c *ClientImpl) Start() {
	setting := config.Setting
	if err := shadow.ParseURI(setting.Client); err != nil {
		log.Panicln(err)
	}
	cipher := security.Choice(setting.Cipher, setting.Password)
	go c.ListenSock(setting.Socks, setting.Address, cipher)
}
