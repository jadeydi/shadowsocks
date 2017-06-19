package shadow

import (
	"errors"
	"io"
	"net"
	"strconv"
)

const (
	IPv4     = 0x01
	IPv6     = 0x04
	VLDomain = 0x03 // Variable Length Domain

	MaxAddrLen = 1 + 1 + 255 + 2
)

type Address []byte

func (a Address) String() string {
	return UnmarshalAddr(a)
}

// Addresses follow the SOCKS5 address format.
// doc: https://tools.ietf.org/html/rfc1928#section-5

// MarshalAddr convert a string (e.g. google.com:https) to a SOCK5 format address
func MarshalAddr(in string) ([]byte, error) {
	var addr []byte
	host, port, err := net.SplitHostPort(in)
	if err != nil {
		return addr, err
	}

	if ip := net.ParseIP(host); ip != nil {
		l, t := net.IPv6len, IPv6
		if v := ip.To4(); v != nil {
			l, t, ip = net.IPv4len, IPv4, v
		}
		addr = make([]byte, 1+l+2)
		addr[0] = byte(t)
		copy(addr[1:], ip) // copy is more effective than append
	} else {
		if len(host) > 255 {
			return addr, errors.New("Domain length is larger than 255")
		}
		addr = make([]byte, 1+1+len(host)+2)
		addr[0] = VLDomain
		addr[1] = byte(len(host))
		copy(addr[2:], host)
	}

	p, err := strconv.ParseUint(port, 10, 16)
	addr[len(addr)-2], addr[len(addr)-1] = byte(p>>8), byte(p)
	return addr, nil
}

// UnmarshalAddr implements the decoding. Convert a SOCKS5 address to string
// address type IPv4, IPv6, Variable Length Domain
func UnmarshalAddr(in []byte) string {
	var (
		host, port string
		pl         int // port left length
	)
	switch in[0] {
	case VLDomain:
		pl = 2 + int(in[1])
		host = string(in[2:pl])
	case IPv4:
		pl = 1 + net.IPv4len
		host = net.IP(in[1:pl]).String()
	case IPv6:
		pl = 1 + net.IPv6len
		host = net.IP(in[1:pl]).String()
	}
	port = strconv.Itoa((int(in[pl]) << 8) | int(in[pl+1]))
	return net.JoinHostPort(host, port)
}

// ReadAddr implements get address from tcp connection reader.
func ReadAddr(r io.Reader) (Address, error) {
	b := make([]byte, MaxAddrLen)
	// Read the type of the address
	_, err := io.ReadFull(r, b[:1])
	if err != nil {
		return nil, err
	}

	switch b[0] {
	case VLDomain:
		// Read the domain address length
		_, err = io.ReadFull(r, b[1:2])
		if err != nil {
			return nil, err
		}
		_, err = io.ReadFull(r, b[2:2+b[1]+2])
		return b[:2+b[1]+2], err
	case IPv4:
		_, err = io.ReadFull(r, b[1:1+net.IPv4len+2])
		return b[:1+net.IPv4len+2], err
	case IPv6:
		_, err = io.ReadFull(r, b[1:1+net.IPv6len+2])
		return b[:1+net.IPv6len+2], err
	}

	return nil, AddressNotSupportedError
}
