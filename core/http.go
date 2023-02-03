package core

import (
	"golang.org/x/net/proxy"
	"io"
	"log"
	"net"
	"net/http"
)

// The MIT License (MIT)
//
// Copyright (c) 2016 Ian Denhardt <ian@zenhack.net>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

var (
	socks5proxy proxy.Dialer
	client      *http.Client
)

func newClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Dial: func(net, addr string) (net.Conn, error) {
				return socks5proxy.Dial(net, addr)
			},
		},
	}
}

func ServeHttp() {
	var err error

	socks5proxy, err = proxy.SOCKS5("tcp", SocksBind, nil, proxy.Direct)
	if err != nil {
		panic(err)
	}

	client = newClient()

	handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "CONNECT" {
			serverConn, err := socks5proxy.Dial("tcp", req.Host)
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(err.Error() + "\n"))
				return
			}

			hijacker, ok := w.(http.Hijacker)
			if !ok {
				serverConn.Close()
				w.WriteHeader(500)
				w.Write([]byte("Failed cast to Hijacker\n"))
				return
			}

			w.WriteHeader(200)

			_, bio, err := hijacker.Hijack()
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(err.Error() + "\n"))
				serverConn.Close()
				return
			}

			go io.Copy(serverConn, bio)
			go io.Copy(bio, serverConn)
		} else {
			// Server-Only field; we get an error fi we pass this to `client.Do`.
			req.RequestURI = ""

			resp, err := client.Do(req)
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(err.Error() + "\n"))
				return
			}

			hdr := w.Header()
			for k, v := range resp.Header {
				hdr[k] = v
			}

			w.WriteHeader(resp.StatusCode)

			io.Copy(w, resp.Body)
		}
	})

	log.Fatal(http.ListenAndServe(HttpBind, handlerFunc))
}
