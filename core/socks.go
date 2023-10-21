package core

import (
	"github.com/things-go/go-socks5"
	"log"
	"os"
)

func ServeSocks5(bindAddr string, dialer Dialer, dnsResolve *DnsResolve) {

	var authMethods []socks5.Authenticator
	if SocksUser != "" && SocksPasswd != "" {
		authMethods = append(authMethods, socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{SocksUser: SocksPasswd},
		})
	} else {
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}

	server := socks5.NewServer(
		socks5.WithAuthMethods(authMethods),
		socks5.WithResolver(dnsResolve),
		socks5.WithDial(dialer.DialIpAndPort),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "", log.LstdFlags))),
	)

	log.Printf("SOCKS5 server listening on " + bindAddr)

	if SocksUser != "" && SocksPasswd != "" {
		log.Printf("\u001B[31mNeither traffic nor credentials are encrypted in the SOCKS5 protocol!\u001B[0m")
		log.Printf("\u001B[31mDO NOT deploy it to the public network. All consequences and responsibilities have nothing to do with the developer.\u001B[0m")
	}

	if err := server.ListenAndServe("tcp", bindAddr); err != nil {
		panic("SOCKS5 listen failed: " + err.Error())
	}
}
