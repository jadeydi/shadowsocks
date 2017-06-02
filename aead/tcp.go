package aead

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
	"shadowsocks/socks"
)

const payloadLimit = 0x3FFF // 16*1024 - 1

type Stream struct {
	Salt, Nonce, Remain []byte

	net.Conn
	socks.SocksCipher
	cipher.AEAD
}

// NewStream return a new *aead.Stream, which contains encryption methods,
// encrypt and decrypt tcp data
func NewStream(conn net.Conn, c socks.SocksCipher) *Stream {
	return &Stream{Conn: conn, SocksCipher: c}
}

// Read implement TCP method. Which read the source data from TCP net.Conn,
// and return b after decrypt
// more details: https://golang.org/pkg/io/#Reader
func (s *Stream) Read(b []byte) (n int, err error) {
	if err = s.inlet(); err != nil {
		return
	}
	if len(s.Remain) > 0 {
		n = copy(b, s.Remain)
		s.Remain = s.Remain[n:]
		return n, nil
	}
	if _, err = s.decrypt(); err != nil {
		return
	}
	n = copy(b, s.Remain)
	s.Remain = s.Remain[n:]
	return
}

// ReadFrom read all data from io.Reader encrypt underline stream data,
// and return the data size.
// Which is used by io.Copy, do not return io.EOF.
// https://golang.org/pkg/io/#Copy
func (s *Stream) ReadFrom(r io.Reader) (n int64, err error) {
	if err = s.outlet(); err != nil {
		return
	}
	n, err = s.encrypt(r)
	return
}

// Write len(p) bytes to the underlying data stream.
// p will be cute into slices, each slice is less than 0x3FFF.
// https://golang.org/pkg/io/#Writer
func (s *Stream) Write(p []byte) (int, error) {
	var l int64
	l, err := s.ReadFrom(bytes.NewBuffer(p))
	if int(l) != len(p) {
		return int(l), io.ErrShortWrite
	}
	return int(l), err
}

// WriteTo implement method, which used by io.Copy.
// With encrypt the underlying stream data.
// https://golang.org/pkg/io/#Copy
func (s *Stream) WriteTo(w io.Writer) (n int64, err error) {
	if err = s.inlet(); err != nil {
		return
	}
	var l int
	for len(s.Remain) > 0 {
		l, err = w.Write(s.Remain)
		n += int64(l)
		if err != nil {
			return
		}
	}
	for {
		l, err = s.decrypt()
		n += int64(l)
		if err == io.EOF {
			err = nil
			break
		} else if err != nil {
			return
		}
		l, err = w.Write(s.Remain)
		if err != nil {
			return
		} else if l != len(s.Remain) {
			err = io.ErrShortWrite
			return
		}
	}
	return
}

func (s *Stream) decrypt() (int, error) {
	buf := make([]byte, 2+s.Overhead())
	if _, err := io.ReadFull(s.Conn, buf); err != nil {
		return 0, err
	}
	if _, err := s.Open(buf[:0], s.Nonce, buf, nil); err != nil {
		return 0, err
	}
	s.incrNonce()

	size := (int(buf[0])<<8 + int(buf[1])) & payloadLimit
	buf = make([]byte, size+s.Overhead())
	if _, err := io.ReadFull(s.Conn, buf); err != nil {
		return 0, err
	}
	if _, err := s.Open(buf[:0], s.Nonce, buf, nil); err != nil {
		return 0, err
	}
	s.incrNonce()
	s.Remain = buf
	return size, nil
}

func (s *Stream) encrypt(r io.Reader) (n int64, err error) {
	for {
		payload := make([]byte, 2+s.Overhead()+payloadLimit+s.Overhead())
		buf := payload[2+s.Overhead() : 2+s.Overhead()+payloadLimit]
		var l int
		l, err = r.Read(buf)
		n += int64(l)
		if err == io.EOF {
			err = nil
			break
		} else if err != nil {
			return
		}
		buf = buf[:l]
		payload = payload[:2+s.Overhead()+l+s.Overhead()]
		payload[0], payload[1] = byte(l>>8), byte(l)
		s.Seal(payload[:0], s.Nonce, payload[:2], nil)
		s.incrNonce()

		s.Seal(buf[:0], s.Nonce, buf, nil)
		s.incrNonce()
		if _, err = s.Conn.Write(payload); err != nil {
			return
		}
	}
	return
}

func (s *Stream) inlet() error {
	if len(s.Salt) == 0 {
		return s.inject(s.Conn)
	}
	return nil
}

func (s *Stream) outlet() error {
	if len(s.Salt) == 0 {
		if err := s.inject(rand.Reader); err != nil {
			return err
		}
		if n, err := s.Conn.Write(s.Salt); err != nil {
			return err
		} else if n != len(s.Salt) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (s *Stream) inject(r io.Reader) error {
	s.Salt = make([]byte, s.KeySize())
	_, err := io.ReadFull(r, s.Salt)
	if err != nil {
		return err
	}
	s.AEAD, err = s.Builder(s.Salt)
	if err != nil {
		return err
	}
	s.Nonce = make([]byte, s.NonceSize())
	return nil
}

func (s *Stream) incrNonce() {
	for i := range s.Nonce {
		s.Nonce[i]++
		if s.Nonce[i] != 0 {
			return
		}
	}
}
