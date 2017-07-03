package security

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
	"shadowsocks/stream"
)

// MetaCipher implements SocksCipher interface.
type StreamCipher struct {
	Key                  []byte
	IVSize               int
	Encrypter, Decrypter func(key, iv []byte) (cipher.Stream, error)
}

// StreamCiphers contains all of stream ciphers, includes KeySize and IVSize.
var StreamCiphers = map[string]struct {
	KeySize, IVSize      int
	Encrypter, Decrypter func(key, iv []byte) (cipher.Stream, error)
}{
	"AES-128-CFB": {16, 16, CFBEncrypter, CFBDecrypter},
	"AES-192-CFB": {24, 16, CFBEncrypter, CFBDecrypter},
	"AES-256-CFB": {32, 16, CFBEncrypter, CFBDecrypter},
	"AES-128-CTR": {16, 16, CTRBuilder, CTRBuilder},
	"AES-192-CTR": {24, 16, CTRBuilder, CTRBuilder},
	"AES-256-CTR": {32, 16, CTRBuilder, CTRBuilder},
}

// NewStream covert a net.Conn to an custom net.Conn, which decrypt data from io.Reader and encrypt data write to io.Writer
func (sc *StreamCipher) NewStream(conn net.Conn) net.Conn {
	return &stream.Stream{
		Conn:      conn,
		IVSize:    sc.IVSize,
		Key:       sc.Key,
		Encrypter: sc.Encrypter,
		Decrypter: sc.Decrypter,
	}
}

func (sc *StreamCipher) NewPacket(conn net.PacketConn) net.PacketConn {
	return &stream.Packet{
		PacketConn: conn,
		IVSize:     sc.IVSize,
		Key:        sc.Key,
		Payload:    make([]byte, 64*1024),
		Encrypter:  sc.Encrypter,
		Decrypter:  sc.Decrypter,
	}
}

// CFB mode
func CFBEncrypter(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	return stream, nil
}

func CFBDecrypter(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBDecrypter(block, iv)
	return stream, nil
}

// CTR mode
func CTRBuilder(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	return stream, nil
}
