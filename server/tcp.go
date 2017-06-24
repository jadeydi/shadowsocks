package server

import (
	"fmt"
	"log"
	"net"
	"shadowsocks/security"
	"shadowsocks/shadow"
)

// ListenTCP is implemention of shadowsocks tcp data exchange in server side. Cointains:
//  `1. read and dial to the remote server address.
//   2. exchange data by relay.
func (s *ServerImpl) ListenTCP(addr string, cipher security.SocksCipher) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Panicln(fmt.Sprintf("failed to listen TCP on %s: %v", addr, err))
	}
	defer l.Close()
	log.Printf("listening TCP on %s\n", addr)

	for {
		c, err := l.Accept()
		if err != nil {
			shadow.Printf("failed to accept: %v", err)
			continue
		}

		// Use goroutine and parameter here, so the loop returns to accepting, and multiple connections may be served concurrently.
		// Why not closure? https://stackoverflow.com/questions/30183669/passing-parameters-to-function-closure
		go func(c net.Conn) {
			defer c.Close()
			c.(*net.TCPConn).SetKeepAlive(true)
			c = cipher.NewStream(c)

			rAddr, err := shadow.ReadAddr(c)
			if err != nil {
				shadow.Printf("failed to get target address: %v", err)
				return
			}
			rc, err := net.Dial("tcp", rAddr.String())
			if err != nil {
				shadow.Printf("failed to connection address: %v", err)
				return
			}
			defer rc.Close()
			rc.(*net.TCPConn).SetKeepAlive(true)
			shadow.Printf("server proxy %s <-> %s", c.RemoteAddr(), rAddr)
			if _, _, err = shadow.Relay(c, rc); err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				shadow.Printf("relay error: %v", err)
			}
		}(c)
	}
}
