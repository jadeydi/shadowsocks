package client

import (
	"fmt"
	"net"
	"shadowsocks/shadow"
)

// ListenSock build a SOCKS connection to server
func (c *ClientImpl) ListenSock(port, serverAddr string, ciph shadow.SocksCipher) {
	shadow.Printf("SOCKS proxy %s <-> %s", port, serverAddr)
	f := func(c net.Conn) (shadow.Address, error) {
		return shadow.Handshake(c)
	}
	c.listenTCP(port, serverAddr, ciph, f)
}

// listenTCP implement a tcp tunnel from local to server, which build a tcp listener on local port, and dial to remote server.
// It exchange the data between client and server, contains write encrypt data to server, and decrypt data from server.
func (c *ClientImpl) listenTCP(port, serverAddr string, ciph shadow.SocksCipher, dstAddr func(net.Conn) (shadow.Address, error)) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		shadow.Printf("failed to listen on %s: %v", port, err)
		return
	}

	for {
		c, err := l.Accept()
		if err != nil {
			shadow.Printf("failed to accept: %s", err)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			c.(*net.TCPConn).SetKeepAlive(true)

			addr, err := dstAddr(c)
			if err != nil {
				shadow.Printf("failed to get target address: %v", err)
				return
			}

			rc, err := net.Dial("tcp", serverAddr)
			if err != nil {
				shadow.Printf("failed to connect to server address %v: %v", serverAddr, err)
				return
			}
			defer rc.Close()
			rc.(*net.TCPConn).SetKeepAlive(true)
			rc = ciph.NewStream(rc)

			if _, err = rc.Write(addr); err != nil {
				shadow.Printf("failed to send target address %s : %v", addr, err)
				return
			}

			shadow.Printf("proxy %s <-> %s <-> %s", c.RemoteAddr(), serverAddr, addr)
			if _, _, err = shadow.Relay(rc, c); err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				shadow.Printf("relay error: %v", err)
			}
		}(c)
	}
}
