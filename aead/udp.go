package aead

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
	"shadowsocks/shadow"
	"sync"
)

var _zerononce [32]byte // read-only.

type Packet struct {
	sync.Mutex
	net.PacketConn

	Salt        []byte
	SaltSize    int
	Payload     []byte
	AEADBuilder func(salt []byte) (cipher.AEAD, error)
}

// ReadFrom implements encrypt data from udp.
func (p *Packet) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = p.PacketConn.ReadFrom(b)
	if err != nil {
		return
	}
	b = b[:n]
	if len(b) < p.SaltSize {
		err = shadow.ShortPacketError
		return
	}
	gcm, err := p.AEADBuilder(b[:p.SaltSize])
	if err != nil {
		return
	}
	if len(b) < p.SaltSize+gcm.Overhead() {
		err = shadow.ShortPacketError
		return
	}
	b, err = gcm.Open(b[:0], _zerononce[:gcm.NonceSize()], b[p.SaltSize:], nil)
	if err != nil {
		return
	}
	n = len(b)
	return
}

// WriteTo implements encrypt data from udp.
func (p *Packet) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	p.Lock()
	defer p.Unlock()
	n = len(b)
	salt := p.Payload[:p.SaltSize]
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return
	}
	gcm, err := p.AEADBuilder(salt)
	if err != nil {
		return
	}
	if len(p.Payload) < p.SaltSize+n+gcm.Overhead() {
		err = io.ErrShortBuffer
		return
	}
	ciphertext := gcm.Seal(p.Payload[p.SaltSize:p.SaltSize], _zerononce[:gcm.NonceSize()], b, nil)
	_, err = p.PacketConn.WriteTo(p.Payload[:p.SaltSize+len(ciphertext)], addr)
	return
}
