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

func TestListenTCP(t *testing.T) {
	assert := assert.New(t)
	setting := config.Setting
	ciph := shadow.ChoiceCipher(setting.Cipher, setting.Password)
	ciph2 := shadow.ChoiceCipher(setting.Cipher, setting.Password)
	c, s := &ClientImpl{}, &server.ServerImpl{}
	go cloud()
	go s.ListenTCP("127.0.0.1:8488", ciph)
	go c.ListenSock("10089", "127.0.0.1:8488", ciph2)
	time.Sleep(time.Second)

	conn, err := net.Dial("tcp", "127.0.0.1:10089")
	assert.Nil(err)
	defer conn.Close()

	// Handshake
	buf := make([]byte, shadow.MaxReqLen)
	conn.Write([]byte{5, 1, 0})
	conn.Read(buf)
	b := []byte{5, 1, 0}
	b1, _ := shadow.MarshalAddr("127.0.0.1:3000")
	//b1, _ := shadow.MarshalAddr("zhihu.com:443")
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
