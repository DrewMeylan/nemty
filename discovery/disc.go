package sweep

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/murrrda/goSweep/pkg/helpers"
)

var seqNum uint32

type reply struct {
	Host      net.IP `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	Alive     bool   `json:"is_alive"`
	OpenPorts []int  `json:"open_ports,omitempty"`
	SysType   string `json:"systype,omitempty"`
}

const pingWorkers = 100

func PingSweep(subnetFlag string) {
	ips, err := helpers.GetHosts(subnetFlag)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	nHosts := len(ips)

	hosts := make(chan net.IP)
	res := make(chan reply)

	// spawn workers
	if nHosts > pingWorkers {
		for i := 0; i < pingWorkers; i++ {
			go worker(hosts, res)
		}
	} else {
		for i := 0; i < nHosts; i++ {
			go worker(hosts, res)
		}
	}

	// populate chan with ip addresses that will workers consume
	go func() {
		for _, ip := range ips {
			hosts <- ip
		}
		close(hosts)
	}()

	noRep := 0

	for i := 0; i < nHosts; i++ {
		rep := <-res
		if rep.Alive {
			fmt.Printf("%sEcho reply from %s\n%s", helpers.Green, rep.Host, helpers.Reset)
		} else {
			noRep++
		}
	}
	close(res)


func worker(hosts chan net.IP, res chan reply) {
	for host := range hosts {
		Alive, err := PingIP(&host)
		if err != nil {
			fmt.Println(err)
			res <- reply{
				Host:  host,
				Alive: false,
			}
			continue
		}
		res <- reply{
			Host:  host,
			Alive: Alive,
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

func main() {
	// Requires root/admin privileges
	if os.Getuid() != 0 {
		log.Fatal("This program requires root/administrator privileges to run")
	}

	scanner := NewNetworkScanner("192.168.50", 24)

	fmt.Println("Scanning network... This may take a few moments.")

	discoveredHosts := scanner.DiscoverHosts()

	outputFile := "network_discovery.json"

	err := SaveHostsToJSON(discoveredHosts, outputFile)
	if err != nil {
		log.Fatalf("Failed to save discovery results: %v", err)
	}

	fmt.Printf("Network scan complete. %d hosts discovered. Results saved to %s\n", len(discoveredHosts), outputFile)
}
