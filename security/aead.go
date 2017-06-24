// aead is the implemention of AEAD Ciphers of shadowsocks
// see more details: https://shadowsocks.org/en/spec/AEAD-Ciphers.html
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
	"shadowsocks/aead"

	"golang.org/x/crypto/chacha20poly1305"
)

// MetaCipher contains Key, SaltSize, and implements SocksCipher interface.
type MetaCipher struct {
	Key         []byte
	SaltSize    int
	AEADBuilder func(key []byte) (cipher.AEAD, error)
}

// AEADCiphers contains the informations of AEAD ciphers, e.g.: KeySize, SaltSize, method to build cipher.AEAD.
var AEADCiphers = map[string]struct {
	KeySize     int
	SaltSize    int
	AEADBuilder func(key []byte) (cipher.AEAD, error)
}{
	"AES-128-GCM":            {16, 16, AESGCM},
	"AES-192-GCM":            {24, 24, AESGCM},
	"AES-256-GCM":            {32, 32, AESGCM},
	"CHACHA20-IETF-POLY1305": {32, 32, Chacha20Poly1305},
}

func AESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func Chacha20Poly1305(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// NewStream covert a net.Conn to an custom net.Conn, which decrypt data from io.Reader and encrypt data write to io.Writer
func (mc *MetaCipher) NewStream(conn net.Conn) net.Conn {
	return &aead.Stream{
		Key:         mc.Key,
		SaltSize:    mc.SaltSize,
		Conn:        conn,
		AEADBuilder: mc.AEADBuilder,
	}
}
