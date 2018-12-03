package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"syscall"
	"unsafe"
  "strings"
	"github.com/hashicorp/golang-lru"
	"github.com/williamfhe/godivert"
	"golang.org/x/sys/windows"
  "github.com/inconshreveable/go-vhost"
)

const (
	tcpTableOwnerPidConnections = 5
)

var clientServerMap *lru.Cache
var tcpConnections map[Addr]int
var getExtendedTcpTablePtr uintptr
var winDivertReq godivert.WinDivertHandle
var winDivertResp godivert.WinDivertHandle

type Conn struct {
	local       *Addr
	remote      *Addr
	divert_addr *godivert.WinDivertAddress
}

type Addr struct {
	ip   string
	port uint16
}

func getNetTable(fn uintptr, order bool, family int, class int) ([]byte, error) {
	var sorted uintptr
	if order {
		sorted = 1
	}
	for size, ptr, addr := uint32(8), []byte(nil), uintptr(0); ; {
		err, _, _ := syscall.Syscall6(fn, 5, addr, uintptr(unsafe.Pointer(&size)), sorted, uintptr(family), uintptr(class), 0)
		if err == 0 {
			return ptr, nil
		} else if err == uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
			ptr = make([]byte, size)
			addr = uintptr(unsafe.Pointer(&ptr[0]))
		} else {
			return nil, fmt.Errorf("getNetTable failed: %v", err)
		}
	}
}

func refreshTcpConnectionTable() {
	tcpConnections = make(map[Addr]int)
	refreshTcp4ConnectionTable()
	refreshTcp6ConnectionTable()
}

func refreshTcp4ConnectionTable() {
	res, err := getNetTable(getExtendedTcpTablePtr, false, windows.AF_INET, tcpTableOwnerPidConnections)
	if err == nil {
		if res != nil && len(res) >= 4 {
			count := *(*uint32)(unsafe.Pointer(&res[0]))
			const structLen = 24
			for n, pos := uint32(0), 4; n < count && pos+structLen <= len(res); n, pos = n+1, pos+structLen {
				state := *(*uint32)(unsafe.Pointer(&res[pos]))
				if state < 1 || state > 12 {
					panic(state)
				}
				laddr := net.IPv4(res[pos+4], res[pos+5], res[pos+6], res[pos+7]).String()
				lport := binary.BigEndian.Uint16(res[pos+8 : pos+10])
				//raddr := net.IPv4(res[pos+12], res[pos+13], res[pos+14], res[pos+15]).String()
				//rport := binary.BigEndian.Uint16(res[pos+16 : pos+18])
				pid := *(*uint32)(unsafe.Pointer(&res[pos+20]))
				//fmt.Printf("%5d = %d %s:%d %s:%d pid:%d\n", n, state, laddr, lport, raddr, rport, pid)
				local := Addr{
					ip:   laddr,
					port: lport,
				}
				tcpConnections[local] = int(pid)
			}
		} else {
			panic("nil result!\n")
		}
	} else {
		panic(err)
	}
}

func refreshTcp6ConnectionTable() {
	res, err := getNetTable(getExtendedTcpTablePtr, false, windows.AF_INET6, tcpTableOwnerPidConnections)
	if err == nil {
		if res != nil && len(res) >= 4 {
			count := *(*uint32)(unsafe.Pointer(&res[0]))
			const structLen = 56
			for n, pos := uint32(0), 4; n < count && pos+structLen <= len(res); n, pos = n+1, pos+structLen {
				laddr := net.IP(res[pos : pos+16]).String()
				//lscopeid := *(*uint32)(unsafe.Pointer(&res[pos+16]))
				lport := binary.BigEndian.Uint16(res[pos+20 : pos+22])
				//raddr := net.IP(res[pos+24: pos+40]).String()
				//rscopeid := *(*uint32)(unsafe.Pointer(&res[pos+40]))
				//rport := binary.BigEndian.Uint16(res[pos+44 : pos+46])
				state := *(*uint32)(unsafe.Pointer(&res[pos+48]))
				if state < 1 || state > 12 {
					panic(state)
				}
				pid := *(*uint32)(unsafe.Pointer(&res[pos+52]))
				//fmt.Printf("%5d = %d %s:%d %x %s:%d %x pid:%d\n", n, state, laddr, lport, lscopeid, raddr, rport, rscopeid, pid)
				//socket := &Socket{
				//	lip:   laddr,
				//	lport: lport,
				//	rip:   raddr,
				//	rport: rport,
				//}
				local := Addr{
					ip:   laddr,
					port: lport,
				}
				tcpConnections[local] = int(pid)
			}
		} else {
			panic("nil result!\n")
		}
	} else {
		panic(err)
	}
}

func redirectRequest(winDivert *godivert.WinDivertHandle, packetChan <-chan *godivert.Packet) {
	pid := os.Getpid()
	for packet := range packetChan {
		dstPort, err := packet.DstPort()
		if err != nil {
			log.Printf("Should not happen, no dst port: %v", err)
			continue
		}
		srcPort, err := packet.SrcPort()
		if err != nil {
			log.Printf("Should not happen, no src port: %v", err)
			continue
		}
		conn := &Conn{
			local: &Addr{
				ip:   packet.SrcIP().String(),
				port: srcPort,
			},
			remote: &Addr{
				ip:   packet.DstIP().String(),
				port: dstPort,
			},
			divert_addr: packet.Addr,
		}

		conn_pid, ok := tcpConnections[*conn.local]
		if !ok {
			refreshTcpConnectionTable()
			conn_pid = tcpConnections[*conn.local]
		}

		if conn_pid == pid {
			packet.Send(winDivert)
			continue
		}

		clientServerMap.Add(srcPort, *conn)
		packet.SetDstPort(1234)
		packet.SetDstIP(net.IPv4(127, 0, 0, 1))
		packet.SetSrcIP(net.IPv4(127, 0, 0, 1))

		packet.Send(winDivert)
	}
}

func redirectResponse(winDivert *godivert.WinDivertHandle, packetChan <-chan *godivert.Packet) {

  for packet := range packetChan {

		dstPort, err := packet.DstPort()
    if err != nil {
			log.Printf("Should not happen, no dst port: %v", err)
			continue
		}

		value, ok := clientServerMap.Get(dstPort)
		if !ok {
			log.Printf("Warning: Previously unseen connection")
			continue
		}

		conn, ok := value.(Conn)
		if !ok {
			log.Printf("Should not happen, %v not a Con", conn)
		}

		packet.SetSrcPort(conn.remote.port)
		packet.SetSrcIP(net.ParseIP(conn.remote.ip))
		packet.SetDstPort(conn.local.port)
		packet.SetDstIP(net.ParseIP(conn.local.ip))
		packet.Addr = conn.divert_addr

		packet.Send(winDivert)
	}
}

func GetOriginalDST(c net.Conn) (*net.TCPAddr, error) {
	h, p, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return nil, err
	}

	lport, err := strconv.Atoi(p)
	if err != nil {
		return nil, err
	}
	value, ok := clientServerMap.Get(uint16(lport))
	if !ok {
		return nil, fmt.Errorf("No destination found for %v %v", h, p)
	}

	conn, ok := value.(Conn)
	if !ok {
		return nil, fmt.Errorf("Should not happen, %v not a Con", conn)
	}

	addr := &net.TCPAddr{
		IP:   net.ParseIP(conn.remote.ip),
		Port: int(conn.remote.port),
	}

	return addr, nil
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

	client, err := DialViaProxyPAC(u, newConn)
  if err != nil {
    log.Fatalf("Dial failed: %v", err)
  }
  go func() {
    defer client.Close()
    defer conn.Close()
    io.Copy(client, conn)
  }()
  go func() {
    defer client.Close()
    defer conn.Close()
    io.Copy(conn, client)
  }()
}

func StartNAT() {
  moduleHandle, err := windows.LoadLibrary("iphlpapi.dll")
	if err != nil {
		panic(err)
	}

	getExtendedTcpTablePtr, err = windows.GetProcAddress(moduleHandle, "GetExtendedTcpTable")
	if err != nil {
		panic(err)
	}

	clientServerMap, _ = lru.New(65536)

	winDivertReq, err := godivert.NewWinDivertHandle("outbound and !loopback and tcp.DstPort != 1234 and tcp.DstPort < 49152")
	if err != nil {
		panic(err)
	}
	packetChanReq, err := winDivertReq.Packets()
	if err != nil {
		panic(err)
	}
	go redirectRequest(winDivertReq, packetChanReq)

	winDivertResp, err := godivert.NewWinDivertHandle("outbound and tcp.SrcPort == 1234")
	if err != nil {
		panic(err)
	}
	packetChanResp, err := winDivertResp.Packets()
	if err != nil {
		panic(err)
	}

	go redirectResponse(winDivertResp, packetChanResp)
  Listen()
}

func EndNAT(){
  defer winDivertReq.Close()
  defer winDivertResp.Close()
}
