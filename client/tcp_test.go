package client

import (
	"fmt"
	"net"
	"shadowsocks/config"
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
		{"AEAD", "AES-256-GCM:Shadowsocks!Go@google.com:8488", "10089"},
		{"Stream", "AES-128-CTR:Shadowsocks!Go@google.com:8588", "10099"},
	}

	for _, a := range testAddr {
		t.Run(a.name, func(t *testing.T) {
			testClient(t, a.address, a.port)
		})
	}
}

func testClient(t *testing.T, addr, port string) {
	assert := assert.New(t)
	shadow.ParseURI(addr)
	setting := config.Setting
	ciph := shadow.ChoiceCipher(setting.Cipher, setting.Password)
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
