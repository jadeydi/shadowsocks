package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"shadowsocks/client"
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

	if setting.Client != "" {
		c := &client.ClientImpl{}
		c.Start()
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
	flag.BoolVar(&setting.Server, "S", false, "(server-only) start server")
	flag.StringVar(&setting.Address, "a", ":8488", "(server-only) default :8488 address should be listened by server")

	// client application flags
	flag.StringVar(&setting.Client, "C", "", "(client-only) server address should be connected by client")
	flag.StringVar(&setting.Socks, "s", "1080", "(client-only) the port is listened by incoming SOCKS5 connection, default: 1080")
	flag.Parse()
}
