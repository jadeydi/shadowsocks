package socks

import (
	"crypto/cipher"
	"crypto/md5"
	"log"
	"strings"
)

// SocksCipher is a interface, which is used by defferent ciphers
type SocksCipher interface {
	KeySize() int
	Builder(salt []byte) (cipher.AEAD, error)
}

// TODO password can't blank
// name is setting.Cipher p is used to generate cipher key
func ChoiceCipher(name, password string) SocksCipher {
	mc, ok := AEADCiphers[strings.ToUpper(name)]
	if !ok {
		log.Panicln("Cipher is not valid")
	}
	return &MetaCipher{
		Key:         cipherKey(password, mc.KeySize),
		AEADBuilder: mc.AEADBuilder,
	}
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
