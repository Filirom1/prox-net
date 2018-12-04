package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	vhost "github.com/inconshreveable/go-vhost"
)

func Listen() {
	listener, err := net.Listen("tcp", "127.0.0.1:1234")
	if err != nil {
		log.Fatalf("Failed to setup listener: %v", err)
	}
	log.Println("Listen")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("ERROR: failed to accept listener: %v", err)
		}
		go forward(conn)
	}
}

func forward(conn net.Conn) {
	dst, err := GetOriginalDST(conn)
	if err != nil {
		log.Printf("No Original Destination found for %v", conn)
	}
	dstIp := dst.IP.String()
	dstPort := strconv.Itoa(dst.Port)

	var u string
	if strings.Contains(dstIp, ":") {
		u = "[" + dstIp + "]:" + dstPort
	} else {
		u = dstIp + ":" + dstPort
	}

	var newConn net.Conn
	var proto string
	vhostConn, err := vhost.HTTP(conn)
	newConn = vhostConn
	if err != nil {
		vhostConnTLS, err := vhost.TLS(vhostConn)
		newConn = vhostConnTLS
		if err != nil {
			proto = "?"
		} else {
			proto = "https " + vhostConnTLS.Host()
		}
	} else {
		proto = "http " + vhostConn.Host()
	}
	fmt.Println(dstIp + " " + dstPort + " " + proto)

	client, err := DialViaProxyPAC(u)
	if err != nil {
		log.Fatalf("Dial failed: %v", err)
	}
	go func() {
		defer client.Close()
		defer newConn.Close()
		io.Copy(client, newConn)
	}()
	go func() {
		defer client.Close()
		defer newConn.Close()
		io.Copy(newConn, client)
	}()
}

func main() {
	StartNAT()
	defer EndNAT()
	Listen()
}
