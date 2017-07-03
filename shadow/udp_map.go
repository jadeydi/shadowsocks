package shadow

import (
	"net"
	"sync"
	"time"
)

const UDPBufSize = 64 * 1024

type UDPGonnMap struct {
	sync.RWMutex
	collection map[string]net.PacketConn
	timeout    time.Duration
}

func NewUDPConnMap(timeout time.Duration) *UDPGonnMap {
	return &UDPGonnMap{
		collection: make(map[string]net.PacketConn),
		timeout:    timeout,
	}
}

func (m *UDPGonnMap) Get(key string) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.collection[key]
}

func (m *UDPGonnMap) Set(key string, c net.PacketConn) {
	m.Lock()
	defer m.Unlock()
	m.collection[key] = c
}

func (m *UDPGonnMap) Del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()
	if pc, ok := m.collection[key]; ok {
		delete(m.collection, key)
		return pc
	}
	return nil
}

func (m *UDPGonnMap) Add(src, tgt net.PacketConn, addr net.Addr, withSrc bool) {
	m.Set(addr.String(), tgt)

	go func() {
		udpCopy(src, tgt, addr, m.timeout, withSrc)
		if pc := m.Del(addr.String()); pc != nil {
			pc.Close()
		}
	}()
}

func udpCopy(src, tgt net.PacketConn, addr net.Addr, timeout time.Duration, withSrc bool) error {
	buf := make([]byte, UDPBufSize)

	for {
		tgt.SetReadDeadline(time.Now().Add(timeout))
		n, raddr, err := tgt.ReadFrom(buf)
		if err != nil {
			return err
		}
		srcAddr, err := MarshalAddr(raddr.String())
		if err != nil {
			return err
		}
		if withSrc {
			copy(buf[len(srcAddr):], buf[:n])
			copy(buf, srcAddr)
			if _, err = src.WriteTo(buf[:len(srcAddr)+n], addr); err != nil {
				return err
			}
		} else {
			if _, err = src.WriteTo(buf[len(srcAddr):n], addr); err != nil {
				return err
			}
		}
	}
	return nil
}
