// Copyright 2017 jadeydi. All rights reserved.

package aead

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"net"

	"golang.org/x/crypto/hkdf"
)

const payloadLimit = 0x3FFF // size 16*1024 - 1

// This is the AEAD Ciphers implementation for tcp.
// Stream implement Read and Write methods of net.Conn, ReadFrom and WriteTo methods of io.Copy.
// Decrypt data for Read and WriteTo, and encrypt for Write and ReadFrom.
type Stream struct {
	Key, Nonce, Remain []byte
	Payload            []byte
	Salt               []byte
	SaltSize           int

	net.Conn
	cipher.AEAD
	AEADBuilder func(salt []byte) (cipher.AEAD, error)
}

// Read read encrypted data from net.Conn, return it after decrypt.
// more details: https://golang.org/pkg/io/#Reader
func (s *Stream) Read(b []byte) (n int, err error) {
	if err = s.inlet(); err != nil {
		return
	}
	if len(s.Remain) > 0 {
		n = copy(b, s.Remain)
		s.Remain = s.Remain[n:]
		b = b[:n]
		return n, nil
	}
	if _, err = s.decrypt(); err != nil {
		return
	}
	n = copy(b, s.Remain)
	b = b[:n]
	s.Remain = s.Remain[n:]
	return
}

// ReadFrom read all data from io.Reader, and encrypt the underline stream data, and write to net.Conn, Which is used by io.Copy, and do not return io.EOF.
// More detail: https://golang.org/pkg/io/#Copy
func (s *Stream) ReadFrom(r io.Reader) (n int64, err error) {
	if err = s.outlet(); err != nil {
		return
	}
	n, err = s.encrypt(r)
	return
}

// Write implement a method, which write encrypted p to net.Conn. p will be cute into slices, each slice is less than 0x3FFF.
// About slice size: https://shadowsocks.org/en/spec/AEAD-Ciphers.html
// About io.Write: https://golang.org/pkg/io/#Writer
func (s *Stream) Write(p []byte) (int, error) {
	var l int64
	l, err := s.ReadFrom(bytes.NewBuffer(p))
	if int(l) != len(p) {
		return int(l), io.ErrShortWrite
	}
	return int(l), err
}

// WriteTo implement method, which is read data from net.Conn, decrypt the data and write it to io.Writer. It is used by io.Copy.
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
	buf := s.Payload[:2+s.Overhead()]
	if _, err := io.ReadFull(s.Conn, buf); err != nil {
		return 0, err
	}
	if _, err := s.Open(buf[:0], s.Nonce, buf, nil); err != nil {
		return 0, err
	}
	s.incrNonce()

	size := (int(buf[0])<<8 + int(buf[1])) & payloadLimit
	// TODO := reassign VS make
	buf = s.Payload[:size+s.Overhead()]
	if _, err := io.ReadFull(s.Conn, buf); err != nil {
		return 0, err
	}
	if _, err := s.Open(buf[:0], s.Nonce, buf, nil); err != nil {
		return 0, err
	}
	s.incrNonce()
	s.Remain = buf[:size]
	return size, nil
}

func (s *Stream) encrypt(r io.Reader) (n int64, err error) {
	for {
		buf := s.Payload[2+s.Overhead() : 2+s.Overhead()+payloadLimit]
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
		payload := s.Payload[:2+s.Overhead()+l+s.Overhead()]
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
		var err error
		if err = s.inject(rand.Reader); err != nil {
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
	s.Salt = make([]byte, s.SaltSize)
	var err error
	if _, err = io.ReadFull(r, s.Salt); err != nil {
		return err
	}
	if s.AEAD, err = s.Builder(s.Salt); err != nil {
		return err
	}
	s.Nonce = make([]byte, s.NonceSize())
	s.Payload = make([]byte, 2+s.Overhead()+payloadLimit+s.Overhead())
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

// Builder is used to create cipher.AEAD, which is used to encrypt and decrypt data.
func (s *Stream) Builder(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, len(s.Key))
	if err := s.hkdfSHA1(s.Key, salt, subkey); err != nil {
		return nil, err
	}
	return s.AEADBuilder(subkey)
}

// hkdfSHA1 is method that takes a secret key, a non-secret salt, an info string, and produces a subkey that is cryptographically strong even if the input secret key is weak.
func (s *Stream) hkdfSHA1(key, salt, subkey []byte) error {
	info := []byte("ss-subkey")
	r := hkdf.New(sha1.New, key, salt, info)
	if _, err := io.ReadFull(r, subkey); err != nil {
		return err
	}
	return nil
}
