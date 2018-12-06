package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
)

func init() {
	dns.HandleFunc(".", handleRequest)
	go func() {
		srv := &dns.Server{Addr: "127.0.0.1:53", Net: "udp"}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to set udp listener %s\n", err.Error())
		}
	}()
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	ttl := 1
	domain := r.Question[0].Name

	t := time.Now()
	ip, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	fmt.Printf("%d-%02d-%02d_%02d:%02d:%02d\t%s\t%s\n", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), ip, domain)
	// TODO: log to file

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	rr1 := new(dns.A)
	rr1.Hdr = dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)}
	rr2 := new(dns.AAAA)
	rr2.Hdr = dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: uint32(ttl)}
	rr1.A = net.ParseIP("127.0.0.1")
	rr2.AAAA = net.ParseIP("::1")
	m.Answer = []dns.RR{rr1, rr2}
	w.WriteMsg(m)
}
