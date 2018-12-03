// This file provides a dialer type of "http://" scheme for
// golang.org/x/net/proxy package.
//
// The dialer type will be automatically registered by init().
//
// The dialer requests an upstream HTTP proxy to create a TCP tunnel
// by CONNECT method.

package transocks

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

func DialConnect(network, addr string, proxy string) (c net.Conn, err error) {
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
	}
	c, err = net.Dial("tcp", proxy)
	if err != nil {
		return
	}
	req.Write(c)

	// Read response until "\r\n\r\n".
	// bufio cannot be used as the connected server may not be
	// a HTTP(S) server.
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 0, 4096)
	b := make([]byte, 1)
	state := 0
	for {
		_, e := c.Read(b)
		if e != nil {
			c.Close()
			return nil, errors.New("reset proxy connection")
		}
		buf = append(buf, b[0])
		switch state {
		case 0:
			if b[0] == byte('\r') {
				state++
			}
			continue
		case 1:
			if b[0] == byte('\n') {
				state++
			} else {
				state = 0
			}
			continue
		case 2:
			if b[0] == byte('\r') {
				state++
			} else {
				state = 0
			}
			continue
		case 3:
			if b[0] == byte('\n') {
				goto PARSE
			} else {
				state = 0
			}
		}
	}

PARSE:
	var zero time.Time
	c.SetReadDeadline(zero)
	resp, e := http.ReadResponse(bufio.NewReader(bytes.NewBuffer(buf)), req)
	if e != nil {
		c.Close()
		return nil, e
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		c.Close()
		return nil, fmt.Errorf("proxy returns %s", resp.Status)
	}

	return c, nil
}
