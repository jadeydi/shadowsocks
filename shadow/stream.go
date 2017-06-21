package shadow

import (
	"net"
	"shadowsocks/stream"
)

type StreamCipher struct {
	Key    []byte
	IVSize int
}

var StreamCiphers = map[string]struct {
	KeySize, IVSize int
}{
	"AES-128-CTR": {16, 16},
	"AES-256-CTR": {32, 16},
}

func (sc *StreamCipher) NewStream(conn net.Conn) net.Conn {
	return &stream.Stream{
		Conn:   conn,
		IVSize: sc.IVSize,
		Key:    sc.Key,
	}
}
