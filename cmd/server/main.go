package main

import (
	"fmt"
	"net"
	"os"

	"github.com/payamb/dns-server/pkg/dns"
)

const (
	serverPort    = 5300
	serverAddress = "127.0.0.1"
)

func main() {
	// file, err := os.Open("root.zone")
	// if err != nil {
	// 	fmt.Printf("Error openning root.zone file %v", err)
	// }

	// records, _ := dns.ParseRootZoneFile(file)
	// fmt.Printf("%+v\n", records)

	addr := &net.UDPAddr{
		Port: serverPort,
		IP:   net.ParseIP(serverAddress),
	}

	conn, err := net.ListenUDP("udp", addr)

	if err != nil {
		fmt.Printf("Can not start server on %s, error: %v\n", addr.String(), err)
		os.Exit(1)
	}

	defer conn.Close()

	fmt.Printf("DNS server listening on UDP port %d\n", serverPort)

	buff := make([]byte, 512)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buff)

		if err != nil {
			fmt.Printf("Failed to read DNS packet: %v\n", err)
			continue
		}

		fmt.Printf("Received DNS packet from %s with %d bytes\n", remoteAddr, n)
		// fmt.Println(hex.EncodeToString(buff[:n]))
		DNSMessageParser := dns.NewDNSMessageParser()
		message, err := DNSMessageParser.Parse(buff)

		if err != nil {
			fmt.Printf("Failed to parse DNS packet: %v\n", err)
			continue
		}

		fmt.Printf("DNS Packet Content: %+v\n", message)
	}
}
