package server

import (
	"log"
	"net"

	"shadowsocks/shadow"
)

// Start to listen TCP on address
func (s *ServerImpl) ListenTCP(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Panicln("failed to listen TCP on %s: %v", addr, err)
	}
	defer l.Close()
	log.Printf("listening TCP on %s\n", addr)

	for {
		c, err := l.Accept()
		if err != nil {
			shadow.Println("failed to accept: %v", err)
			continue
		}

		// Use goroutine and parameter here, so the loop returns to accepting, and multiple connections may be served concurrently.
		// Why not closure? https://stackoverflow.com/questions/30183669/passing-parameters-to-function-closure
		go func(c net.Conn) {
			defer c.Close()
			c.(*net.TCPConn).SetKeepAlive(true)

			a, err := shadow.ReadAddr(c)
			if err != nil {
				shadow.Println("failed to get target address ", err)
				return
			}
			log.Println(string(a))

			c.Write([]byte(shadow.UnmarshalAddr(a)))
		}(c)
	}
}
