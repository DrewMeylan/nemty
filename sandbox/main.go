package main

// test running a command and capturing output
import (
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHConfig holds the credentials and configuration for SSH
type SSHConfig struct {
	Username string
	Password string
	Host     string
	Port     int
	Command  string
}

// RunCommand executes an SSH command on a remote device and returns the output
func RunCommand(config SSHConfig) (string, error) {
	// Set up SSH client configuration
	sshConfig := &ssh.ClientConfig{
		User: config.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(config.Password),
		},
		Timeout:         5 * time.Second,             // Connection timeout
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // WARNING: Not secure for production
	}

	// Connect to the SSH server
	address := fmt.Sprintf("%s:%d", config.Host, config.Port)
	client, err := ssh.Dial("tcp", address, sshConfig)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s: %v", address, err)
	}
	defer client.Close()

	// Create a session to run the command
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Run the command and capture output
	output, err := session.CombinedOutput(config.Command)
	if err != nil {
		return "", fmt.Errorf("failed to run command: %v", err)
	}

	return string(output), nil
}

func main() {
	// Define the SSH configuration
	config := SSHConfig{
		Username: "admin",
		Password: "password",
		Host:     "192.168.1.1",
		Port:     22,
		Command:  "show lldp neighbors", // Replace with the desired command
	}

	// Execute the command
	output, err := RunCommand(config)
	if err != nil {
		log.Fatalf("Error executing SSH command: %v", err)
	}

	// Print the command output
	fmt.Println("Command Output:")
	fmt.Println(output)
}
