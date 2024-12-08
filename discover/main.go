package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ------------------------------------- CONSTANTS -----------------------------------------------------
const pingWorkers = 100

var seqNum uint32

// -------------------------------------- STRUCT DEFS --------------------------------------------------
// HostInfo stores comprehensive host discovery information
type HostInfo struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	IsAlive   bool   `json:"is_alive"`
	OpenPorts []int  `json:"open_ports,omitempty"`
}

// NetScanner manages network discovery operations
type NetScanner struct {
	cidr    string
	Timeout time.Duration
}

// reply binds target ip with boolean for host discovery
type reply struct {
	Host net.IP
	Did  bool
}

// --------------------------------------- Network Scanner ---------------------------------------------

// NewNetScanner creates a new network scanner
func NewNetScanner(cidr string) *NetScanner {
	return &NetScanner{
		cidr:    cidr,
		Timeout: 1 * time.Second,
	}
}

func (ns *NetScanner) EnumerateHosts(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)

	if err != nil {
		return nil, err
	}
	fmt.Println("Network: " + ipNet.String())

	if ip.To4() == nil {
		return nil, fmt.Errorf("You must enter a valid IPv4 address")
	}

	var ips []net.IP
	for currentIP := ip.Mask(ipNet.Mask); ipNet.Contains(currentIP); NextIP(&currentIP) {
		ipCopy := make(net.IP, len(currentIP))
		copy(ipCopy, currentIP)
		ips = append(ips, ipCopy)
	}

	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

// Inputs: CIDR address range | INVOKES EnumerateHosts & worker | Outputs: Array of Active hosts in that address space
func (ns *NetScanner) PingSweep(cidr string) ([]HostInfo, error) {
	ips, err := ns.EnumerateHosts(cidr)
	if err != nil {
		return nil, err
	}

	hosts := make(chan net.IP, len(ips))
	results := make(chan HostInfo)
	var wg sync.WaitGroup

	for i := 0; i < pingWorkers && i < len(ips); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range hosts {
				isAlive, _ := PingIP(&ip)
				if isAlive {
					hostInfo := HostInfo{
						IP:        ip.String(),
						IsAlive:   true,
						Hostname:  GetHostname(ip),
						OpenPorts: PortScan(ip, ns.Timeout),
					}
					results <- hostInfo
				}
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			hosts <- ip
		}
		close(hosts)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var discoveredHosts []HostInfo
	for hostInfo := range results {
		discoveredHosts = append(discoveredHosts, hostInfo)
	}

	return discoveredHosts, nil
}
func NextIP(ip *net.IP) {
	for j := len(*ip) - 1; j >= 0; j-- {
		(*ip)[j]++
		if (*ip)[j] > 0 {
			break
		}
	}
}

// --------------------------------------- Helpers ----------------------------------------
func GetHostname(ip net.IP) string {
	names, err := net.LookupAddr(ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}
func PortScan(ip net.IP, timeout time.Duration) []int {
	tcp_ports := []int{22, 80, 88, 389, 443, 21, 25, 53, 3306, 3389} // Add more ports as needed
	//udp_ports := []int{53, 67, 69, 88, 123, 161, 514}
	openPorts := []int{}

	for _, port := range tcp_ports {
		address := fmt.Sprintf("%s:%d", ip.String(), port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}
	//	for _, port := range udp_ports {
	//		address := fmt.Sprintf("%s:%d", ip.String(), port)
	//		conn, err := net.DialTimeout("udp", address, timeout)
	//		if err == nil {
	//			openPorts = append(openPorts, port)
	//			conn.Close()
	//		}
	//	}
	return openPorts
}

func worker(hosts chan net.IP, res chan reply) {
	for host := range hosts {
		did, err := PingIP(&host)
		if err != nil {
			fmt.Println(err)
			res <- reply{
				Host: host,
				Did:  false,
			}
			continue
		}
		res <- reply{
			Host: host,
			Did:  did,
		}
	}
}
func PingIP(dstIp *net.IP) (bool, error) {
	id := uint16(rand.Intn(65535))
	seq := uint16(atomic.AddUint32(&seqNum, 1) % 65536)
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0),
		Id:       id,
		Seq:      seq,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, icmp); err != nil {
		fmt.Println("Couldn't serialize layer")
		return false, fmt.Errorf("couldn't serialize layer: %w", err)
	}

	// Listen for ICMP packets
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Println("Couldn't listen")
		return false, fmt.Errorf("couldn't listen: %w", err)
	}
	defer conn.Close()

	// Send ICMP echo request
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: *dstIp}); err != nil {
		fmt.Println("Write error")
		return false, fmt.Errorf("write error: %w", err)
	}

	// Set read timeout
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		fmt.Println("Set deadline error")
		return false, fmt.Errorf("set deadline error: %w", err)
	}
	// next step is to get host response (if it responds)
	for {
		b := make([]byte, 2048)

		if n, _, err := conn.ReadFrom(b); err != nil {
			// timeout (no response from host)
			return false, nil
		} else {
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeICMPv4, gopacket.Default)
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmpResponse := icmpLayer.(*layers.ICMPv4)
				if icmpResponse.Id == id && icmpResponse.Seq == seq {
					// Received expected ICMP response
					return true, nil
				}
			}
		}
	}
}
func SaveHostsToJSON(hosts []HostInfo, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	jsonData, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return err
	}

	_, err = file.Write(jsonData)
	return err
}

func main() {
	if os.Getuid() != 0 {
		log.Fatal("This program requires root/administrator privileges to run")
	}

	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <CIDR address space>\nExample: %s 192.168.1.0/24", os.Args[0], os.Args[0])
	}

	cidr := os.Args[1]

	// Validate the CIDR
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("Invalid CIDR address space provided: %v", err)
	}

	scanner := NewNetScanner(cidr)

	fmt.Printf("Scanning network %s... This may take a few moments.\n", cidr)

	discoveredHosts, err := scanner.PingSweep(scanner.cidr)
	if err != nil {
		log.Fatalf("Failed to perform network scan: %v", err)
	}

	outputFile := "network_discovery.json"
	err = SaveHostsToJSON(discoveredHosts, outputFile)
	if err != nil {
		log.Fatalf("Failed to save discovery results: %v", err)
	}

	fmt.Printf("Network scan complete. %d hosts discovered. Results saved to %s\n", len(discoveredHosts), outputFile)
}
