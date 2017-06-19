package shadow

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdress(t *testing.T) {
	t.Run("InvalidAddr", testFailAddress)
	t.Run("ValidAddr", testRightAddress)
}

func testFailAddress(t *testing.T) {
	assert := assert.New(t)

	address := []struct {
		name, value string
	}{
		{"BlackAddr", ""},
		{"InvalidAddr", "invalid_addr"},
		{"IpAddr", "127.0.0.1"},
		{"LongAddr", strings.Repeat("0123456789", 30)},
	}
	for _, addr := range address {
		t.Run(addr.name, func(t *testing.T) {
			_, err := MarshalAddr(addr.value)
			assert.NotNil(err)
		})
	}
}

func testRightAddress(t *testing.T) {
	assert := assert.New(t)

	address := []struct {
		name, value string
	}{
		{"IpPort80", "127.0.0.1:80"},
		{"IpPort443", "127.0.0.1:443"},
		{"DomainPort80", "google.com:80"},
		{"DomainPort443", "google.com:443"},
	}
	for _, addr := range address {
		t.Run(addr.name, func(t *testing.T) {
			b, err := MarshalAddr(addr.value)
			assert.Nil(err)
			assert.Equal(addr.value, Address(b).String())
		})
	}
}
