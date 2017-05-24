package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"shadowsocks/config"
	"shadowsocks/server"
)

func main() {
	parseFlags()

	setting := config.Setting
	if setting.Help || (!setting.Server && setting.Client == "") {
		flag.Usage()
		return
	}
	if setting.Server {
		s := &server.ServerImpl{}
		s.Start()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT)
	<-sigCh
}

func parseFlags() {
	setting := config.Setting

	// system flags
	flag.BoolVar(&setting.Help, "h", false, "show this help messages")
	flag.BoolVar(&setting.Quiet, "q", false, "suppress log output")

	// server application flags
	flag.BoolVar(&setting.Server, "s", false, "(server-only) start server")
	flag.StringVar(&setting.Address, "a", ":8488", "(server-only) default :8488 address should be listened by server")

	// client application flags
	flag.StringVar(&setting.Client, "c", "", "(client-only) address should be dial by client")
	flag.Parse()
}
