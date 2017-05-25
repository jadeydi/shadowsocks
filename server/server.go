package server

import (
	"log"
	"shadowsocks/config"
	"shadowsocks/shadow"
)

type ServerImpl struct{}

// Start server application
func (s *ServerImpl) Start() {

	setting := config.Setting
	if err := shadow.ParseURI(setting.Address); err != nil {
		log.Panicln(err)
	}
	go s.ListenTCP(setting.Address)
}
