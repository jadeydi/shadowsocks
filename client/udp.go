package client

import (
	"log"
	"net"
	"shadowsocks/config"
	"shadowsocks/security"
	"shadowsocks/shadow"
)

func (c *ClientImpl) ListenUDP(local, server, remote string, cipher security.SocksCipher) {
	setting := config.Setting
	saddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		log.Panicln("UDP server address error: %v, server address: %s", err, server)
		return
	}

	raddr, err := shadow.MarshalAddr(remote)
	if err != nil {
		log.Panicln("UDP target address error: %v", err)
		return
	}

	conn, err := net.ListenPacket("udp", local)
	if err != nil {
		log.Panicln("UDP local listen error: %v, locale address %s", err, local)
		return
	}
	defer conn.Close()

	udpMap := shadow.NewUDPConnMap(setting.UDPTimeout)
	buf := make([]byte, shadow.UDPBufSize)
	copy(buf, raddr)
	shadow.Printf("UDP tunnel %s <-> %s <-> %s\n", local, server, remote)
	for {
		n, laddr, err := conn.ReadFrom(buf[len(raddr):])
		if err != nil {
			shadow.Printf("UDP local read error: %v\n", err)
			continue
		}

		pc := udpMap.Get(laddr.String())
		if pc == nil {
			pc, err = net.ListenPacket("udp", "")
			if err != nil {
				shadow.Printf("UDP remote listen error: %v", err)
				continue
			}
			pc = cipher.NewPacket(pc)
			udpMap.Add(conn, pc, laddr, false)
		}
		_, err = pc.WriteTo(buf[:len(raddr)+n], saddr)
		if err != nil {
			shadow.Printf("UDP local write error: %v\n", err)
			continue
		}
	}
}
