package server

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"shadowsocks/config"
	"shadowsocks/security"
	"shadowsocks/shadow"
)

func TestListenServerUDP(t *testing.T) {
	go cloudUDP()

	testAddr := []struct {
		name, address string
	}{
		{"AEAD128", "AES-128-GCM:Shadowsocks!Go@google.com:8708"},
		{"AEAD192", "AES-192-GCM:Shadowsocks!Go@google.com:8718"},
		{"AEAD256", "AES-256-GCM:Shadowsocks!Go@google.com:8728"},
		{"AEADCHACHA20", "CHACHA20-IETF-POLY1305:Shadowsocks!Go@google.com:8738"},
		{"Stream128CTR", "AES-128-CTR:Shadowsocks!Go@google.com:8518"},
		{"Stream192CTR", "AES-192-CTR:Shadowsocks!Go@google.com:8528"},
		{"Stream256CTR", "AES-256-CTR:Shadowsocks!Go@google.com:8538"},
		{"Stream128CFB", "AES-128-CFB:Shadowsocks!Go@google.com:8548"},
		{"Stream192CFB", "AES-192-CFB:Shadowsocks!Go@google.com:8558"},
		{"Stream256CFB", "AES-256-CFB:Shadowsocks!Go@google.com:8568"},
	}

	for _, a := range testAddr {
		t.Run(a.name, func(t *testing.T) {
			testServerUDP(t, a.address)
		})
	}
}

func testServerUDP(t *testing.T, addr string) {
	buf := make([]byte, udpBufSize)
	assert := assert.New(t)

	shadow.ParseURI(addr)
	setting := config.Setting
	ciph := security.Choice(setting.Cipher, setting.Password)
	s := &ServerImpl{}
	go s.ListenUDP(fmt.Sprintf(":%s", setting.Port), ciph)

	b, _ := shadow.MarshalAddr("127.0.0.1:3000")
	n := copy(buf, b)
	tn := copy(buf[n:], []byte(txt))

	laddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%s", setting.Port))
	l, _ := net.ListenPacket("udp", ":3222")
	defer l.Close()
	l = ciph.NewPacket(l)
	l.WriteTo(buf[:n+tn], laddr)
	n, _, _ = l.ReadFrom(buf)
	raddr, _ := shadow.ReadAddrFromBytes(buf[:n])
	assert.Equal(strings.ToUpper(txt), string(buf[len(raddr):n]))
	time.Sleep(time.Second * 2)
}

func cloudUDP() {
	buf := make([]byte, udpBufSize)
	l, _ := net.ListenPacket("udp", ":3000")
	defer l.Close()

	for {
		n, addr, _ := l.ReadFrom(buf)
		l.WriteTo([]byte(strings.ToUpper(string(buf[:n]))), addr)
	}
}
