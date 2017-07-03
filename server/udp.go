package server

import (
	"fmt"
	"log"
	"net"

	"shadowsocks/config"
	"shadowsocks/security"
	"shadowsocks/shadow"
)

func (s *ServerImpl) ListenUDP(addr string, cipher security.SocksCipher) {
	setting := config.Setting
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Panicln(fmt.Sprintf("failed to listen UDP on %s: %v", addr, err))
	}
	defer c.Close()
	shadow.Printf("listening UDP on %s\n", addr)
	c = cipher.NewPacket(c)

	buf := make([]byte, shadow.UDPBufSize)
	udpMap := shadow.NewUDPConnMap(setting.UDPTimeout)
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
			udpMap.Add(c, pc, addr, true)
		}
		_, err = pc.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
	}
}
