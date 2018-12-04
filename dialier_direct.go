package main

import (
	"net"
)

func DialDirect(u string) (c net.Conn, err error) {
	return net.Dial("tcp", u)
}
