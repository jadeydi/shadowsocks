package shadow

import (
	"io"
	"net"
	"time"
)

const (
	MaxReqLen = 1 + 1 + 1 + MaxAddrLen

	CMDConnect = 0x01
	CMDBind    = 0x02
	CMDUDP     = 0x03
)

// Handshake is the implementation of socks request and reply
// 1. client request: VER, NMETHODS, METHODS
// 2. server relay: VER, METHOD
// 3. client request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
// 4. server relay: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
// more detail: https://tools.ietf.org/html/rfc1928#section-4
func Handshake(rw io.ReadWriter) ([]byte, error) {
	buf := make([]byte, MaxReqLen)
	if _, err := rw.Read(buf); err != nil {
		return nil, err
	}
	if _, err := rw.Write([]byte{5, 0}); err != nil {
		return nil, err
	}
	n, err := rw.Read(buf)
	if err != nil {
		return nil, err
	}

	buf = buf[:n]
	if buf[1] != CMDConnect {
		return nil, CommandNotSupportedError
	}

	if _, err := rw.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	return buf[3:], nil
}

// relay as its name, it's the bridge of server and target server,
// send the request to target, get the response and send to client
func Relay(src, tgt net.Conn) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		// src.WriteTo(tgt) or tgt.ReadFrom(src)
		n, err := io.Copy(tgt, src)
		tgt.SetDeadline(time.Now())
		src.SetDeadline(time.Now())
		ch <- res{n, err}
	}()

	// should break the net.Conn
	// more detail: https://www.reddit.com/r/golang/comments/3m54cf/netconn_setdeadline_confusion/
	// tgt.WriteTo(src) or src.ReadFrom(tgt)
	n, err := io.Copy(src, tgt)
	tgt.SetDeadline(time.Now())
	src.SetDeadline(time.Now())
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}
