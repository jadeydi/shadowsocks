// aead is the implemention of AEAD Ciphers of shadowsocks
// see more details: https://shadowsocks.org/en/spec/AEAD-Ciphers.html
package socks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"io"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// salt size is equal key size
var AEADCiphers = map[string]struct {
	KeySize     int
	AEADBuilder func(key []byte) (cipher.AEAD, error)
}{
	"AES-128-GCM":            {16, AESGCM},
	"AES-192-GCM":            {24, AESGCM},
	"AES-256-GCM":            {32, AESGCM},
	"CHACHA20-IETF-POLY1305": {32, Chacha20Poly1305},
}

// TODO should handle error
// hkdfSHA1 is a function that takes a secret key, a non-secret salt, an info string, and produces a subkey that is cryptographically strong even if the input secret key is weak.
func hkdfSHA1(key, salt, subkey []byte) {
	info := []byte("ss-subkey")
	r := hkdf.New(sha1.New, key, salt, info)
	if _, err := io.ReadFull(r, subkey); err != nil {
		log.Panicln(err)
	}
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

type MetaCipher struct {
	Key         []byte
	AEADBuilder func(key []byte) (cipher.AEAD, error)
}

func (mc *MetaCipher) KeySize() int {
	return len(mc.Key)
}

func (mc *MetaCipher) Builder(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, mc.KeySize())
	hkdfSHA1(mc.Key, salt, subkey)
	return mc.AEADBuilder(subkey)
}
