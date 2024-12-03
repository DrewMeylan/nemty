package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// HostInfo stores comprehensive host discovery information
type HostInfo struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	IsAlive   bool   `json:"is_alive"`
	OpenPorts []int  `json:"open_ports,omitempty"`
}

// NetworkScanner manages network discovery operations
type NetworkScanner struct {
	BaseIP     string
	SubnetMask int
	Timeout    time.Duration
}

// NewNetworkScanner creates a new network scanner
func NewNetworkScanner(baseIP string, subnetMask int) *NetworkScanner {
	return &NetworkScanner{
		BaseIP:     baseIP,
		SubnetMask: subnetMask,
		Timeout:    1 * time.Second,
	}
}

// isHostAvailable checks host availability via ICMP ping
func (ns *NetworkScanner) isHostAvailable(ip string) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("PING"),
		},
	}

	wb, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	_, err = conn.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		return false
	}

	rb := make([]byte, 1500)
	err = conn.SetReadDeadline(time.Now().Add(ns.Timeout))
	if err != nil {
		return false
	}

	n, _, err := conn.ReadFrom(rb)
	if err != nil {
		return false
	}

	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
	return err == nil && rm.Type == ipv4.ICMPTypeEchoReply
}

// comprehensivePortScan checks a wider range of ports
func (ns *NetworkScanner) comprehensivePortScan(ip string) []int {
	ports := []int{
		// Common service ports
		22,   // SSH
		80,   // HTTP
		443,  // HTTPS
		21,   // FTP
		25,   // SMTP
		53,   // DNS
		88,   // Kerberos
		110,  // POP3
		143,  // IMAP
		389,  // LDAP
		3306, // MySQL
		3389, // RDP
		5900, // VNC
		8080, // HTTP Proxy
		445,  // SMB
	}

	var openPorts []int
	var wg sync.WaitGroup
	portChan := make(chan int, len(ports))

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, ns.Timeout)
			if err == nil {
				portChan <- p
				conn.Close()
			}
		}(port)
	}

	go func() {
		wg.Wait()
		close(portChan)
	}()

	for port := range portChan {
		openPorts = append(openPorts, port)
	}

	return openPorts
}

// DiscoverHosts finds active hosts on the network
func (ns *NetworkScanner) DiscoverHosts() []HostInfo {
	var hosts []HostInfo
	var mu sync.Mutex
	var wg sync.WaitGroup
	hostChan := make(chan HostInfo, 255)

	ipRange := ns.generateIPRange()

	for _, ip := range ipRange {
		wg.Add(1)
		go func(currentIP string) {
			defer wg.Done()

			// Only check if host is alive via ping
			if !ns.isHostAvailable(currentIP) {
				return
			}

			host := HostInfo{
				IP:      currentIP,
				IsAlive: true,
			}

			// Hostname resolution
			names, err := net.LookupAddr(currentIP)
			if err == nil && len(names) > 0 {
				host.Hostname = names[0]
			}

			// Perform port scan only for alive hosts
			host.OpenPorts = ns.comprehensivePortScan(currentIP)

			// Send host info only if it's alive (ping successful)
			hostChan <- host
		}(ip)
	}

	go func() {
		wg.Wait()
		close(hostChan)
	}()

	for host := range hostChan {
		mu.Lock()
		hosts = append(hosts, host)
		mu.Unlock()
	}

	return hosts
}

// generateIPRange creates a list of IP addresses to scan
func (ns *NetworkScanner) generateIPRange() []string {
	var ips []string
	base := ns.BaseIP
	for i := 1; i < 255; i++ {
		ips = append(ips, fmt.Sprintf("%s.%d", base, i))
	}
	return ips
}

// SaveHostsToJSON writes discovered hosts to a JSON file
func SaveHostsToJSON(hosts []HostInfo, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(hosts)
}

func main() {
	// Requires root/admin privileges
	if os.Getuid() != 0 {
		log.Fatal("This program requires root/administrator privileges to run")
	}

	scanner := NewNetworkScanner("192.168.1", 24)

	fmt.Println("Scanning network... This may take a few moments.")

	discoveredHosts := scanner.DiscoverHosts()

	outputFile := "network_discovery.json"

	err := SaveHostsToJSON(discoveredHosts, outputFile)
	if err != nil {
		log.Fatalf("Failed to save discovery results: %v", err)
	}

	fmt.Printf("Network scan complete. %d hosts discovered. Results saved to %s\n", len(discoveredHosts), outputFile)
}
