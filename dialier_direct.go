package main

import (
	"net"
)

func DialDirect(u string, conn net.Conn) (c net.Conn, err error) {
	return net.Dial("tcp", u)
}
