package server

import (
	"bytes"
	"net"
	"shadowsocks/shadow"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO expired
func TestListenTCP(t *testing.T) {
	assert := assert.New(t)
	conn, err := net.Dial("tcp", "127.0.0.1:8488")
	assert.Nil(err)
	defer conn.Close()

	b, _ := shadow.MarshalAddr("google.com:443")
	conn.Write(b)
	buf := new(bytes.Buffer)
	buf.ReadFrom(conn)
	assert.Equal("google.com:443", buf.String())
}
