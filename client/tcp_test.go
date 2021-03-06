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

var txt string = "Hello ShadowSocks"

func TestListenClientTCP(t *testing.T) {
	go cloud()
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
			testClientTCP(t, a.address, a.port)
		})
	}
}

func testClientTCP(t *testing.T, addr, port string) {
	assert := assert.New(t)
	shadow.ParseURI(addr)
	setting := config.Setting
	ciph := security.Choice(setting.Cipher, setting.Password)
	c, s := &ClientImpl{}, &server.ServerImpl{}
	go s.ListenTCP(fmt.Sprintf("127.0.0.1:%s", setting.Port), ciph)
	go c.ListenSock(port, fmt.Sprintf("127.0.0.1:%s", setting.Port), ciph)
	time.Sleep(time.Second)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", port))
	assert.Nil(err)
	defer conn.Close()

	// Handshake
	buf := make([]byte, shadow.MaxReqLen)
	conn.Write([]byte{5, 1, 0})
	conn.Read(buf)
	b := []byte{5, 1, 0}
	b1, _ := shadow.MarshalAddr("127.0.0.1:3000")
	b = append(b, b1...)
	conn.Write(b)
	conn.Read(buf)
	assert.Equal(byte(0x5), buf[0])
	assert.Equal(byte(0x1), buf[3])
	buf = make([]byte, len(txt))
	conn.Read(buf)
	assert.Equal("HELLO SHADOWSOCKS", string(buf))
}

// mock distance server
func cloud() {
	l, _ := net.Listen("tcp", fmt.Sprintf("127.0.0.1:3000"))
	defer l.Close()
	for {
		c, _ := l.Accept()
		defer c.Close()
		c.(*net.TCPConn).SetKeepAlive(true)
		c.Write([]byte(strings.ToUpper(txt)))
	}
}
