package server

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"shadowsocks/config"
	"shadowsocks/security"
	"shadowsocks/shadow"
)

const udpBufSize = 64 * 1024

func (s *ServerImpl) ListenUDP(addr string, cipher security.SocksCipher) {
	setting := config.Setting
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Panicln(fmt.Sprintf("failed to listen UDP on %s: %v", addr, err))
	}
	defer c.Close()
	shadow.Printf("listening UDP on %s\n", addr)
	c = cipher.NewPacket(c)

	buf := make([]byte, udpBufSize)
	udpMap := newUDPConnMap(setting.UDPTimeout)
	for {
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			shadow.Printf("UDP remote read error: %v", err)
			continue
		}
		tgtAddr, err := shadow.ReadAddrFromBytes(buf[:n])
		tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
		if err != nil {
			shadow.Printf("failed to resolve target UDP address: %v", err)
			continue
		}
		if err != nil {
			shadow.Printf("UDP remote read error: %v", err)
			continue
		} else if tgtAddr == nil {
			shadow.Printf("failed to get target address from packet: %q", buf[:n])
		}
		payload := buf[len(tgtAddr):n]

		pc := udpMap.Get(addr.String())
		if pc == nil {
			pc, err = net.ListenPacket("udp", "")
			if err != nil {
				shadow.Printf("UDP remote listen error: %v", err)
				continue
			}
			udpMap.Add(c, pc, addr)
		}
		_, err = pc.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
	}
}

type udpConnMap struct {
	sync.RWMutex
	collection map[string]net.PacketConn
	timeout    time.Duration
}

func newUDPConnMap(timeout time.Duration) *udpConnMap {
	return &udpConnMap{
		collection: make(map[string]net.PacketConn),
		timeout:    timeout,
	}
}

func (m *udpConnMap) Get(key string) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.collection[key]
}

func (m *udpConnMap) Set(key string, c net.PacketConn) {
	m.Lock()
	defer m.Unlock()
	m.collection[key] = c
}

func (m *udpConnMap) Del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()
	if pc, ok := m.collection[key]; ok {
		delete(m.collection, key)
		return pc
	}
	return nil
}

func (m *udpConnMap) Add(src, tgt net.PacketConn, addr net.Addr) {
	m.Set(addr.String(), tgt)

	go func() {
		udpCopy(src, tgt, addr, m.timeout)
		if pc := m.Del(addr.String()); pc != nil {
			pc.Close()
		}
	}()
}

func udpCopy(src, tgt net.PacketConn, addr net.Addr, timeout time.Duration) error {
	buf := make([]byte, udpBufSize)

	for {
		tgt.SetReadDeadline(time.Now().Add(timeout))
		n, raddr, err := tgt.ReadFrom(buf)
		if err != nil {
			return err
		}
		srcAddr, err := shadow.MarshalAddr(raddr.String())
		if err != nil {
			return err
		}
		copy(buf[len(srcAddr):], buf[:n])
		copy(buf, srcAddr)
		if _, err = src.WriteTo(buf[:len(srcAddr)+n], addr); err != nil {
			return err
		}
	}
	return nil
}
