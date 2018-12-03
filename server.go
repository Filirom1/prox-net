package main

import (
	"log"
	"net"
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

func main() {
	StartNAT()
	defer EndNAT()
	Listen()
}
