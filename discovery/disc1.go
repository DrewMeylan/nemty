package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func ping(address string, timeout time.Duration) bool {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("Error creating listener: %v\n", err)
		return false
	}
	defer c.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff, // unique id
			Seq:  1,
			Data: []byte("HELLO-PING"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		fmt.Printf("Error marshaling ICMP message: %v\n", err)
		return false
	}

	target := &net.IPAddr{IP: net.ParseIP(address)}
	if _, err := c.WriteTo(msgBytes, target); err != nil {
		fmt.Printf("Error sending ICMP message: %v\n", err)
		return false
	}

	reply := make([]byte, 1500)
	c.SetReadDeadline(time.Now().Add(timeout))
	n, peer, err := c.ReadFrom(reply)
	if err != nil {
		return false
	}

	parsedMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:n])
	if err != nil {
		fmt.Printf("Error parsing ICMP reply: %v\n", err)
		return false
	}

	// Ensure the reply comes from the target
	if peer.(*net.IPAddr).IP.String() == address && parsedMsg.Type == ipv4.ICMPTypeEchoReply {
		fmt.Printf("Host %s is reachable (reply from %s)\n", address, peer)
		return true
	}

	return false
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ping_scanner.go <subnet>")
		os.Exit(1)
	}

	subnet := os.Args[1]
	fmt.Printf("Scanning subnet: %s\n", subnet)
	sem := make(chan struct{}, 20)
	for i := 1; i <= 254; i++ {
		ip := fmt.Sprintf("%s.%d", subnet, i)
		sem <- struct{}{}
		go func(ip string) {
			defer func() { <-sem }()
			if ping(ip, 5*time.Second) {
				fmt.Printf("%s is alive\n", ip)
			}
		}(ip)
		time.Sleep(50 * time.Millisecond)
	}

	time.Sleep(10 * time.Second) // Give goroutines time to finish
}
