package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// -------------------------------------- STRUCT DEFS --------------------------------------------------
// HostInfo stores comprehensive host discovery information
type HostInfo struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	IsAlive   bool   `json:"is_alive"`
	OpenPorts []int  `json:"open_ports,omitempty"`
	SysType   string `json:"OS,omitempty"`
}
// NetScanner manages network discovery operations
type NetScanner struct {
	cidr       string
	Timeout    time.Duration
}
// reply binds target ip with boolean for host discovery
type reply struct {
	Host net.IP
	Did  bool
}

type scan struct {
	Port		layers.TCPPort,
	State		state // open(0), close(1), filtered
}

//------------------------------------- FUNC DEFS -----------------------------------------------------
// NewNetScanner creates a new network scanner
func NewNetScanner(cidr string) *NetScanner {
	return &NetScanner{
		cidr:		cidr
		Timeout:    1 * time.Second,
	}
}
// Might need to move to a helpers folder? Or can struct instance call self.EnumerateHosts?
// Inputs: CIDR Address Range || Outputs: An array of all IP addresses in the address space
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
		return ips[1: len(ips)-1], nil
	}
	return ips, nil
}
// Similar to Enumerate hosts - may need to move to helpers else self.worker?
// Inputs: host channel (from EnumerateHosts) and res channel || No output, writes to res channel in PingSweep
func worker(hosts chan net.IP, res chan reply) {
	for host := range hosts {
		did, err := PingIP(&host)
		if err != nil {
			fmt.Println(err)
			res <- reply{
				Host: host,
				Did: false,
			}
			continue
		}
		res <- reply{
			Host: host,
			Did: did,
		}
	}
}
// Inputs: CIDR address range | INVOKES EnumerateHosts & worker | Outputs: Array of Active hosts in that address space
func (ns *NetScanner) PingSweep(cidr string) ([]net.IP, error){
	ips, err := helpers.EnumberHosts(cidr) // Modify?
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	liveHosts := []net.IP
	nHosts := len(ips)
	hosts := make(chan net.IP)
	res := make(chan reply) //MUST DEFINE REPLY STRUCT

	// spawn workers
	if nHosts > pingWorkers { //pingWorkers undefined
		for i := 0; i = < pingWorkers; i++ { // ping worker defines upperbound of number of workers
			go worker(hosts, res)
		}
	} else {
		for i := 0; i < nHosts; i++ {
			go worker(hosts, res)
		}
	}
	// Does this need to go before the spawn workers block?
	go func() {
		for _, ip := range ips {
			hosts <- ip //load hosts channel with ips to be consumed
		}

		close(hosts)
	}()

	noRep := 0
	for i := 0; i < nHosts; i++ {
		rep := <-res
		if rep.Did {
			liveHosts = append(liveHosts, rep.Host)
			//fmt.Printf("%sEcho reply from %s\n %s", helpers.Green, rep.Host, helpers.Reset) // Helpers.Green, Reset??
		} else {
			noRep++
		}
	}
	close(res)

	return liveHosts
}
// Helper?
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
// comprehensivePortScan checks a wider range of ports
func (ns *NetScanner) TcpScan(ip string) []int {
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
