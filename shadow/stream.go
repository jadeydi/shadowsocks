package shadow

import (
	"net"
	"shadowsocks/stream"
)

// MetaCipher implements SocksCipher interface.
type StreamCipher struct {
	Key    []byte
	IVSize int
}

// StreamCiphers contains all of stream ciphers, includes KeySize and IVSize.
var StreamCiphers = map[string]struct {
	KeySize, IVSize int
}{
	"AES-128-CTR": {16, 16},
	"AES-256-CTR": {32, 16},
}

// NewStream covert a net.Conn to an custom net.Conn, which decrypt data from io.Reader and encrypt data write to io.Writer
func (sc *StreamCipher) NewStream(conn net.Conn) net.Conn {
	return &stream.Stream{
		Conn:   conn,
		IVSize: sc.IVSize,
		Key:    sc.Key,
	}
}
