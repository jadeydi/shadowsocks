package security

import (
	"crypto/md5"
	"log"
	"net"
	"strings"
)

type SocksCipher interface {
	NewStream(conn net.Conn) net.Conn
	NewPacket(conn net.PacketConn) net.PacketConn
}

// TODO password can't blank
// name is setting.Cipher p is used to generate cipher key
func Choice(name, password string) SocksCipher {
	if c, ok := AEADCiphers[strings.ToUpper(name)]; ok {
		return &MetaCipher{
			Key:         cipherKey(password, c.KeySize),
			SaltSize:    c.SaltSize,
			AEADBuilder: c.AEADBuilder,
		}
	}

	if c, ok := StreamCiphers[strings.ToUpper(name)]; ok {
		return &StreamCipher{
			Key:       cipherKey(password, c.KeySize),
			IVSize:    c.IVSize,
			Encrypter: c.Encrypter,
			Decrypter: c.Decrypter,
		}
	}
	log.Panicln("Cipher is not valid")
	return nil
}

// cipherKey is used to encrypt password to suitable key,
// which is different between ciphers, at least 12 bits and no more than 32 bits.
func cipherKey(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
