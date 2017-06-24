package server

import (
	"fmt"
	"net"
	"shadowsocks/config"
	"shadowsocks/security"
	"shadowsocks/shadow"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var txt string = "Hello ShadowSocks"

func TestListenServerTCP(t *testing.T) {
	go cloud()
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
			testServer(t, a.address)
		})
	}
}

func testServer(t *testing.T, addr string) {
	assert := assert.New(t)
	shadow.ParseURI(addr)
	setting := config.Setting

	ciph := security.Choice(setting.Cipher, setting.Password)
	s := &ServerImpl{}
	go s.ListenTCP(fmt.Sprintf("127.0.0.1:%s", setting.Port), ciph)
	time.Sleep(time.Second)

	ciph2 := security.Choice(setting.Cipher, setting.Password)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", setting.Port))
	assert.Nil(err)
	conn = ciph2.NewStream(conn)
	defer conn.Close()

	b, _ := shadow.MarshalAddr("127.0.0.1:3000")
	n, err := conn.Write(b)
	assert.Nil(err)
	assert.Equal(n, len(b))
	buf := make([]byte, len(txt))
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
