package server

import (
	"log"
	"shadowsocks/config"
	"shadowsocks/shadow"
)

type ServerImpl struct{}

// Parse server address, choice cipher, and start server application
func (s *ServerImpl) Start() {
	setting := config.Setting
	if err := shadow.ParseURI(setting.Address); err != nil {
		log.Panicln(err)
	}
	ciph := shadow.ChoiceCipher(setting.Cipher, setting.Password)
	go s.ListenTCP(setting.Address, ciph)
}
