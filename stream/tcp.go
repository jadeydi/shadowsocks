package stream

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
)

const bufSize = 32 * 1024

type Stream struct {
	Key, IV []byte
	IVSize  int

	net.Conn
	cipher.Stream
}

func (s *Stream) Read(b []byte) (n int, err error) {
	if err = s.inlet(); err != nil {
		return
	}
	n, err = s.Conn.Read(b)
	b = b[:n]
	s.XORKeyStream(b, b)
	return
}

func (s *Stream) ReadFrom(r io.Reader) (n int64, err error) {
	if err = s.outlet(); err != nil {
		return
	}
	for {
		buf := make([]byte, bufSize)
		var l int
		l, err = r.Read(buf)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return
		}
		if l > 0 {
			s.XORKeyStream(buf[:l], buf[:l])
			l, err = s.Conn.Write(buf[:l])
			n += int64(l)
			if err != nil {
				return
			}
		}
	}
	return
}

func (s *Stream) Write(p []byte) (int, error) {
	var l int64
	l, err := s.ReadFrom(bytes.NewBuffer(p))
	if int(l) != len(p) {
		return int(l), io.ErrShortWrite
	}
	return int(l), err
}

func (s *Stream) WriteTo(w io.Writer) (n int64, err error) {
	for {
		buf := make([]byte, bufSize)
		var l int
		l, err = s.Read(buf)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return
		}
		if l > 0 {
			l, err = s.Conn.Write(buf[:l])
			n += int64(l)
			if err != nil {
				return
			}
		}
	}
}

func (s *Stream) inlet() error {
	if len(s.IV) == 0 {
		s.IV = make([]byte, s.IVSize)
		_, err := io.ReadFull(s.Conn, s.IV)
		if err != nil {
			return err
		}
		s.Stream, err = s.Decrypter(s.IV)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Stream) outlet() error {
	if len(s.IV) == 0 {
		s.IV = make([]byte, s.IVSize)
		_, err := io.ReadFull(rand.Reader, s.IV)
		if err != nil {
			return err
		}
		s.Conn.Write(s.IV)
		s.Stream, err = s.Encrypter(s.IV)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Stream) Encrypter(iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(s.Key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	return stream, nil
}

func (s *Stream) Decrypter(iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(s.Key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBDecrypter(block, iv)
	return stream, nil
}
