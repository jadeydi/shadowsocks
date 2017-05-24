package server

import (
	"io"
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
			shadow.Printf("failed to accept: %v", err)
			continue
		}

		// Use goroutine and parameter here, so the loop returns to accepting, and multiple connections may be served concurrently.
		// Why not closure? https://stackoverflow.com/questions/30183669/passing-parameters-to-function-closure
		go func(c net.Conn) {
			defer c.Close()
			c.(*net.TCPConn).SetKeepAlive(true)

			rAddr, err := shadow.ReadAddr(c)
			if err != nil {
				shadow.Printf("failed to get target address: %v", err)
				return
			}
			rc, err := net.Dial("tcp", shadow.UnmarshalAddr(rAddr))
			if err != nil {
				shadow.Printf("failed to connection address: %v", err)
				return
			}
			defer rc.Close()
			rc.(*net.TCPConn).SetKeepAlive(true)
			shadow.Printf("proxy %s <-> %s", c.RemoteAddr(), rAddr)
			if _, _, err = relay(c, rc); err != nil {
				shadow.Printf("relay error: %v", err)
			}
		}(c)
	}
}

// relay as its name, it's the bridge of server and target server,
// send the request to target, get the response and send to client
func relay(src, tgt net.Conn) (int64, int64, error) {
	read, cerr := make(chan int64), make(chan error)

	go func() {
		data, err := io.Copy(tgt, src)
		read <- data
		cerr <- err
	}()

	// TODO maybe we should break the net.Conn
	// detail: https://www.reddit.com/r/golang/comments/3m54cf/netconn_setdeadline_confusion/
	written, err := io.Copy(src, tgt)
	if err == nil {
		err = <-cerr
	}
	return <-read, written, err
}
