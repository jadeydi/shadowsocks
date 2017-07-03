package client

import (
	"fmt"
	"net"
	"shadowsocks/config"
	"shadowsocks/security"
	"shadowsocks/server"
	"shadowsocks/shadow"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestListenClientUDP(t *testing.T) {
	go cloudUDP()
	testAddr := []struct {
		name, address, port string
	}{
		{"AEAD128", "AES-128-GCM:Shadowsocks!Go@google.com:8708", "10089"},
		{"AEAD192", "AES-192-GCM:Shadowsocks!Go@google.com:8718", "10189"},
		{"AEAD256", "AES-256-GCM:Shadowsocks!Go@google.com:8728", "10289"},
		{"AEADCHACHA20", "CHACHA20-IETF-POLY1305:Shadowsocks!Go@google.com:8738", "10389"},
		{"Stream128CTR", "AES-128-CTR:Shadowsocks!Go@google.com:8518", "10489"},
		{"Stream192CTR", "AES-192-CTR:Shadowsocks!Go@google.com:8528", "10589"},
		{"Stream256CTR", "AES-256-CTR:Shadowsocks!Go@google.com:8538", "10689"},
		{"Stream128CFB", "AES-128-CFB:Shadowsocks!Go@google.com:8548", "10789"},
		{"Stream192CFB", "AES-192-CFB:Shadowsocks!Go@google.com:8558", "10889"},
		{"Stream256CFB", "AES-256-CFB:Shadowsocks!Go@google.com:8568", "10989"},
	}

	for _, a := range testAddr {
		t.Run(a.name, func(t *testing.T) {
			testClientUDP(t, a.address, a.port)
		})
	}
}

func testClientUDP(t *testing.T, addr, port string) {
	buf := make([]byte, shadow.UDPBufSize)
	assert := assert.New(t)
	shadow.ParseURI(addr)
	setting := config.Setting

	ciph := security.Choice(setting.Cipher, setting.Password)
	c, s := &ClientImpl{}, &server.ServerImpl{}
	go s.ListenUDP(fmt.Sprintf("127.0.0.1:%s", setting.Port), ciph)
	go c.ListenUDP(fmt.Sprintf(":%s", port), fmt.Sprintf("127.0.0.1:%s", setting.Port), "127.0.0.1:3000", ciph)
	time.Sleep(time.Second)

	conn, _ := net.ListenPacket("udp", ":3222")
	defer conn.Close()

	laddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%s", port))
	n := copy(buf, []byte(txt))
	conn.WriteTo(buf[:n], laddr)
	n, _, _ = conn.ReadFrom(buf)
	assert.Equal(strings.ToUpper(txt), string(buf[:n]))
	time.Sleep(2 * time.Second)
}

func cloudUDP() {
	buf := make([]byte, shadow.UDPBufSize)
	l, _ := net.ListenPacket("udp", ":3000")
	defer l.Close()

	for {
		n, addr, _ := l.ReadFrom(buf)
		l.WriteTo([]byte(strings.ToUpper(string(buf[:n]))), addr)
	}
}
