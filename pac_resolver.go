package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/jackwakefield/gopac"
)

var ppac *gopac.Parser

func init() {
	ppac = new(gopac.Parser)
	if err := ppac.Parse("./PAC"); err != nil {
		panic(err)
	}
}

func DialViaProxyPAC(addr string) (c net.Conn, err error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	fmt.Println(addr)

	fmt.Println(host)

	// find the proxy entry for host check.immun.es
	entry, err := ppac.FindProxy(addr, host)
	fmt.Println(entry)
	if err != nil {
		return nil, err
	}

	if entry == "DIRECT" {
		return DialDirect(addr)
	} else {
		arr := strings.Split(entry, " ")
		verb, proxy_url := arr[0], arr[1]

		if verb == "PROXY" {
			return DialConnect(addr, proxy_url)
		}
		return nil, nil
	}

}
