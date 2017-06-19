package server

import (
	"fmt"
	"net"
	"shadowsocks/config"
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
		{"AEAD", "AES-256-GCM:Shadowsocks!Go@google.com:8488"},
		{"Stream", "AES-128-CTR:Shadowsocks!Go@google.com:8588"},
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

	ciph := shadow.ChoiceCipher(setting.Cipher, setting.Password)
	s := &ServerImpl{}
	go s.ListenTCP(fmt.Sprintf("127.0.0.1:%s", setting.Port), ciph)
	time.Sleep(time.Second)

	ciph2 := shadow.ChoiceCipher(setting.Cipher, setting.Password)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", setting.Port))
	assert.Nil(err)
	conn = ciph2.NewStream(conn)
	defer conn.Close()

	b, _ := shadow.MarshalAddr("127.0.0.1:3000")
	conn.Write(b)
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
