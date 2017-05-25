package client

import (
	"fmt"
	"net"
	"shadowsocks/shadow"
	"shadowsocks/socks"
)

// ListenSock build a tcp connection refer to SOCKS5
func (c *ClientImpl) ListenSock(port, serverAddr string) {
	shadow.Printf("SOCKS proxy %s <-> %s", port, serverAddr)
	f := func(c net.Conn) (socks.Address, error) {
		return socks.Handshake(c)
	}
	c.listenTCP(port, serverAddr, f)
}

// listenTCP implement a tcp tunnel from local to server
// dstAddr is the distant server address. e.g. google.com:443 in SOCKS5 addressing format
func (c *ClientImpl) listenTCP(port, serverAddr string, dstAddr func(net.Conn) (socks.Address, error)) {
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

			if _, err = rc.Write(addr); err != nil {
				shadow.Printf("failed to send target address %s : %v", addr, err)
				return
			}

			shadow.Printf("proxy %s <-> %s <-> %s", c.RemoteAddr(), serverAddr, addr)
			if _, _, err = socks.Relay(rc, c); err != nil {
				shadow.Printf("relay error: %v", err)
			}
		}(c)
	}
}
