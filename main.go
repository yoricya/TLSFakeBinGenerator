package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

type fileConn struct {
	file *os.File
}

func (c *fileConn) Read(b []byte) (n int, err error) {
	return 0, io.EOF
}

func (c *fileConn) Write(b []byte) (n int, err error) {
	return c.file.Write(b)
}

func (c *fileConn) Close() error {
	return c.file.Close()
}

func (c *fileConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *fileConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

func (c *fileConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *fileConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *fileConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Use: tls_gen <Domain Name>")
		return
	}

	f, err := os.Create("tls_clienthello_" + os.Args[1] + ".bin")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	tlsConfig := &tls.Config{
		ServerName:         os.Args[1],
		InsecureSkipVerify: true,

		// Версии TLS (Chrome обычно поддерживает 1.2-1.3)
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,

		// Шифры в порядке приоритета Chrome
		CipherSuites: []uint16{
			// TLS 1.3 (Go автоматически добавляет эти шифры)
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,

			// TLS 1.2
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},

		// Кривые для ECDHE (X25519 в приоритете)
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},

		// ALPN-протоколы (h2 для HTTP/2)
		NextProtos: []string{"h2", "http/1.1"},
	}

	fmt.Println("Used ServerName: " + tlsConfig.ServerName)

	conn := &fileConn{file: f}
	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	err = tlsConn.Handshake()
	tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + os.Args[1] + "\r\n\r\n"))

	fmt.Println("TLS writed to tls_clienthello_" + os.Args[1] + ".bin")
}
