package stream

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
	"shadowsocks/shadow"
	"sync"
)

type Packet struct {
	sync.Mutex
	net.PacketConn

	Key, Payload         []byte
	IVSize               int
	Encrypter, Decrypter func(key, iv []byte) (cipher.Stream, error)
}

// ReadFrom implements encrypt data from udp.
func (p *Packet) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = p.PacketConn.ReadFrom(b)
	if err != nil {
		return
	}
	b = b[:n]
	if len(b) < p.IVSize {
		err = shadow.ShortPacketError
		return
	}
	iv := b[:p.IVSize]
	gcm, err := p.Decrypter(p.Key, iv)
	if err != nil {
		return
	}
	gcm.XORKeyStream(b, b[p.IVSize:])
	b = b[:n-p.IVSize]
	n = len(b)
	return
}

// WriteTo implements encrypt data from udp.
func (p *Packet) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	p.Lock()
	defer p.Unlock()
	n = len(b)
	iv := p.Payload[:p.IVSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}
	gcm, err := p.Encrypter(p.Key, iv)
	if err != nil {
		return
	}
	gcm.XORKeyStream(p.Payload[p.IVSize:], b)
	buf := p.Payload[:p.IVSize+n]
	_, err = p.PacketConn.WriteTo(buf, addr)
	return
}
