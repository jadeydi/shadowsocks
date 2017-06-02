package server

import (
	"log"
	"shadowsocks/config"
	"shadowsocks/shadow"
	"shadowsocks/socks"
)

type ServerImpl struct{}

// Start server application
func (s *ServerImpl) Start() {
	setting := config.Setting
	if err := shadow.ParseURI(setting.Address); err != nil {
		log.Panicln(err)
	}
	ciph := socks.ChoiceCipher(setting.Cipher, setting.Password)
	go s.ListenTCP(setting.Address, ciph)
}
