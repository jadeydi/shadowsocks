package client

import (
	"log"
	"shadowsocks/config"
	"shadowsocks/shadow"
	"shadowsocks/socks"
)

type ClientImpl struct{}

// Start client application
func (c *ClientImpl) Start() {
	setting := config.Setting
	if err := shadow.ParseURI(setting.Client); err != nil {
		log.Panicln(err)
	}
	ciph := socks.ChoiceCipher(setting.Cipher, setting.Password)
	go c.ListenSock(setting.Socks, setting.Address, ciph)
}
