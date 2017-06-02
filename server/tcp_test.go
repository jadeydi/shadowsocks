package server

import (
	"fmt"
	"net"
	"shadowsocks/aead"
	"shadowsocks/config"
	"shadowsocks/socks"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var txt string = "Hello ShadowSocks"

func TestListenTCP(t *testing.T) {
	assert := assert.New(t)

	setting := config.Setting
	ciph := socks.ChoiceCipher(setting.Cipher, setting.Password)
	s := &ServerImpl{}
	go cloud()
	go s.ListenTCP("127.0.0.1:8488", ciph)
	time.Sleep(time.Second)

	ciph2 := socks.ChoiceCipher(setting.Cipher, setting.Password)
	conn, err := net.Dial("tcp", "127.0.0.1:8488")
	assert.Nil(err)
	conn = aead.NewStream(conn, ciph2)
	defer conn.Close()

	b, _ := socks.MarshalAddr("127.0.0.1:3000")
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
