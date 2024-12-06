package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---------------------------------------- STRUCT DEF -----------------------------------------------
// Device represents a network device in the topology
type Device struct {
	IP        string     `json:"ip"`
	Hostname  string     `json:"hostname"`
	Neighbors []Neighbor `json:"neighbors"`
}

// Neighbor represents a connected device
type Neighbor struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	LocalIf   string `json:"local_if"`
	RemoteIf  string `json:"remote_if"`
	LinkSpeed string `json:"link_speed"`
	LinkType  string `json:"link_type"`
	VLANs     []int  `json:"vlans"`
}

// Credential holds login information for network devices
type Credential struct {
	Username string
	Password string
}

// TopologyCrawler manages the network discovery process
type TopologyCrawler struct {
	Credentials   []Credential
	Topology      map[string]*Device
	DiscoveredIPs map[string]bool
	MaxWorkers    int
	mu            sync.RWMutex
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	NetBoxClient  *NetBoxClient
}

// Manages API calls to netbox
type NetBoxClient struct {
	APIURL    string
	AuthToken string
}

// --------------------------------------- FUNCTION DEFS ----------------------------------------------
// ----------------- NETBOX CLIENT FUNCS
// NewNetBoxClient initializes a new NetBox client
func NewNetBoxClient(apiURL, authToken string) *NetBoxClient {
	return &NetBoxClient{
		APIURL:    apiURL,
		AuthToken: authToken,
	}
}

// AddDevice adds a device to NetBox
func (nb *NetBoxClient) AddDevice(device *Device) error {
	url := fmt.Sprintf("%s/api/dcim/devices/", nb.APIURL)
	payload := map[string]interface{}{
		"name":        device.Hostname,
		"device_type": "Switch",       // Change as needed
		"site":        "Default Site", // Adjust based on your NetBox configuration
		"primary_ip":  device.IP,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Token "+nb.AuthToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("NetBox API error: %s", body)
	}

	return nil
}

// AddLink adds a link between two devices in NetBox
func (nb *NetBoxClient) AddLink(localIf, remoteIf, localDevice, remoteDevice string) error {
	url := fmt.Sprintf("%s/api/dcim/interfaces/", nb.APIURL)

	// Logic for adding a link will depend on NetBox's interface representation
	// Implementing it would require querying NetBox for interface IDs

	log.Printf("Adding link: %s (%s) -> %s (%s)\n", localDevice, localIf, remoteDevice, remoteIf)
	return nil // Placeholder
}

// ---------------- TOPOLOGY CRAWLER FUNCS
// Creates new instance of TopologyCrawler
func NewTopologyCrawler(maxWorkers int, credentials []Credential) *TopologyCrawler {
	ctx, cancel := context.WithCancel(context.Background())
	return &TopologyCrawler{
		Credentials:   credentials,
		Topology:      make(map[string]*Device),
		DiscoveredIPs: make(map[string]bool),
		MaxWorkers:    maxWorkers,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Crawl starts the network discovery process
func (tc *TopologyCrawler) Crawl(seedIP string) error {
	defer tc.cancel()

	// Semaphore to limit concurrent workers
	workerSemaphore := make(chan struct{}, tc.MaxWorkers)

	// Start the crawl
	tc.queueIP(seedIP)
	tc.wg.Add(1)

	go tc.worker(workerSemaphore)

	tc.wg.Wait()
	return nil
}

// queueIP adds an IP to the discovery queue if it hasn't been discovered
func (tc *TopologyCrawler) queueIP(ip string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if !tc.DiscoveredIPs[ip] {
		tc.DiscoveredIPs[ip] = true
		tc.wg.Add(1)
		go func(ip string) {
			defer tc.wg.Done()
			tc.discoverDevice(ip)
		}(ip)
	}
}

// Updated discoverDevice function to integrate with NetBox
func (tc *TopologyCrawler) discoverDevice(ip string) (*Device, error) {
	for _, cred := range tc.Credentials {
		device, err := tc.connectAndDiscover(ip, cred)
		if err == nil {
			// Push to NetBox
			if err := tc.NetBoxClient.AddDevice(device); err != nil {
				log.Printf("Failed to add device %s to NetBox: %v", ip, err)
			}
			// Push links to NetBox
			for _, neighbor := range device.Neighbors {
				err := tc.NetBoxClient.AddLink(neighbor.LocalIf, neighbor.RemoteIf, device.Hostname, neighbor.Hostname)
				if err != nil {
					log.Printf("Failed to add link for device %s: %v", device.Hostname, err)
				}
			}
			return device, nil
		}
	}
	return nil, fmt.Errorf("could not connect to device %s", ip)
}

// connectAndDiscover establishes an SSH connection to retrieve device information
func (tc *TopologyCrawler) connectAndDiscover(ip string) (*Device, error) {
	for _, cred := range tc.Credentials {
		device, err := tc.sshDiscover(ip, cred)
		if err == nil {
			return device, nil
		}
	}
	return nil, fmt.Errorf("failed to connect to %s with available credentials", ip)
}

// sshDiscover uses SSH to retrieve device details and neighbors
func (tc *TopologyCrawler) sshDiscover(ip string, cred Credential) (*Device, error) {
	config := &ssh.ClientConfig{
		User: cred.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(cred.Password),
		},
		Timeout:         10 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Use secure host key verification in production
	}

	client, err := ssh.Dial("tcp", ip+":22", config)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	// Execute CDP/LLDP command (Cisco example)
	output, err := session.CombinedOutput("show cdp neighbors detail")
	if err != nil {
		return nil, err
	}

	return parseCDPOutput(ip, string(output))
}

// SaveTopology saves the discovered topology as a JSON file
func (tc *TopologyCrawler) SaveTopology(filename string) error {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	data, err := json.MarshalIndent(tc.Topology, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// parseCDPOutput converts raw CDP output to structured device info
func parseCDPOutput(sourceIP, output string) (*Device, error) {
	// Mock implementation - replace with actual parsing logic
	return &Device{
		IP:       sourceIP,
		Hostname: "Example Device",
		Neighbors: []Neighbor{
			{
				IP:        "192.168.1.2",
				Hostname:  "Neighbor Device",
				LocalIf:   "Gig0/1",
				RemoteIf:  "Gig0/2",
				LinkSpeed: "1Gbps",
				LinkType:  "Trunk",
				VLANs:     []int{10, 20},
			},
		},
	}, nil
}

// ------------------------------------ MAIN
func main() {
	credentials := []Credential{
		{Username: "admin", Password: "password1"},
		{Username: "network", Password: "password2"},
	}

	netBoxClient := NewNetBoxClient("http://your-netbox-url", "your-netbox-token")
	crawler := NewTopologyCrawler(5, credentials)
	crawler.NetBoxClient = netBoxClient

	err := crawler.Crawl("192.168.1.1")
	if err != nil {
		log.Fatalf("Crawl failed: %v", err)
	}

	err = crawler.SaveTopology("network_topology.json")
	if err != nil {
		log.Fatalf("Failed to save topology: %v", err)
	}

	fmt.Println("Network topology discovery complete with NetBox integration")
}
