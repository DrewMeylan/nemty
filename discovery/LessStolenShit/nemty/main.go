package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/DrewMeylan/nemty/disocvery/LessStolenShit/disc"
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
	cidr    string
	Timeout time.Duration
}

// reply binds target ip with boolean for host discovery
type reply struct {
	Host net.IP
	Did  bool
}

// -- Main --
func main() {
	// Requires root/admin privileges
	if os.Getuid() != 0 {
		log.Fatal("This program requires root/administrator privileges to run")
	}

	scanner := disc.NewNetScanner("192.168.1", 24)

	fmt.Println("Scanning network... This may take a few moments.")

	discoveredHosts := scanner.DiscoverHosts()

	outputFile := "network_discovery.json"

	err := SaveHostsToJSON(discoveredHosts, outputFile)
	if err != nil {
		log.Fatalf("Failed to save discovery results: %v", err)
	}

	fmt.Printf("Network scan complete. %d hosts discovered. Results saved to %s\n", len(discoveredHosts), outputFile)
}
