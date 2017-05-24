package shadow

import (
	"log"
	"shadowsocks/config"
)

// Println is the switch of log
// User -q to quite the log output
func Printf(format string, v ...interface{}) {
	if !config.Setting.Quiet {
		log.Printf(format, v...)
	}
}
