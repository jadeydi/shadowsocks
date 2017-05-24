package shadow

import (
	"log"

	"shadowsocks/config"
)

func Println(v ...interface{}) {
	if !config.Setting.Quiet {
		log.Println(v...)
	}
}
