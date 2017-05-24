package shadow

import (
	"fmt"
	"net/url"
	"shadowsocks/config"
	"strings"
)

// parseURI is used to abstract password address from ss URI.
// Generic URI form: scheme:[//[user[:password]@]host[:port]][/path][?query][#fragment]
func ParseURI(uri string) error {
	if !strings.HasPrefix(uri, "ss://") {
		uri = fmt.Sprintf("ss://%s", uri)
	}

	u, err := url.Parse(uri)
	if err != nil {
		return err
	}

	setting := config.Setting
	if u.Port() != "" {
		setting.Port = u.Port()
	}
	if u.User != nil {
		if n := u.User.Username(); n != "" {
			setting.Cipher = n
		}
		if p, _ := u.User.Password(); p != "" {
			setting.Password = p
		}
	}

	setting.Address = fmt.Sprintf("%s:%s", u.Hostname(), setting.Port)
	return nil
}
