package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

const (
	MTU         = 1500
	TUN_DEVICE  = "tun0"
	CLIENT_IP   = "10.8.0.2"
	SERVER_IP   = "10.8.0.1"
)

type VPNClient struct {
	serverAddr string
	encryption bool
	key        []byte
	tunFile    *os.File
	conn       net.Conn
	enabled    bool
	originalGW string
}

func NewVPNClient(serverAddr string, encryption bool, key []byte) *VPNClient {
	return &VPNClient{
		serverAddr: serverAddr,
		encryption: encryption,
		key:        key,
		enabled:    false,
	}
}

func (c *VPNClient) setupTUN() error {
	// Load TUN module
	exec.Command("modprobe", "tun").Run()

	// Delete existing TUN device if it exists
	exec.Command("ip", "link", "delete", TUN_DEVICE).Run()

	// Create TUN device
	cmd := exec.Command("ip", "tuntap", "add", "mode", "tun", "dev", TUN_DEVICE)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create TUN device: %v", err)
	}

	// Assign IP address
	cmd = exec.Command("ip", "addr", "add", CLIENT_IP+"/24", "dev", TUN_DEVICE)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to assign IP: %v", err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", TUN_DEVICE, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %v", err)
	}

	// Open TUN device
	tunFile, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open TUN device: %v", err)
	}
	c.tunFile = tunFile

	log.Printf("TUN device %s configured with IP %s", TUN_DEVICE, CLIENT_IP)
	return nil
}

func (c *VPNClient) getDefaultGateway() (string, error) {
	cmd := exec.Command("sh", "-c", "ip route | grep default | awk '{print $3}'")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output[:len(output)-1]), nil // Remove trailing newline
}

func (c *VPNClient) routeAllTraffic() error {
	// Save original default gateway
	gw, err := c.getDefaultGateway()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %v", err)
	}
	c.originalGW = gw
	log.Printf("Original gateway: %s", c.originalGW)

	// Add route to VPN server through original gateway
	serverHost, _, _ := net.SplitHostPort(c.serverAddr)
	cmd := exec.Command("ip", "route", "add", serverHost, "via", c.originalGW)
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: failed to add server route: %v", err)
	}

	// Delete default route
	cmd = exec.Command("ip", "route", "del", "default")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete default route: %v", err)
	}

	// Add default route through VPN
	cmd = exec.Command("ip", "route", "add", "default", "via", SERVER_IP, "dev", TUN_DEVICE)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add VPN route: %v", err)
	}

	log.Println("All traffic now routed through VPN")
	return nil
}

func (c *VPNClient) restoreRouting() error {
	// Delete VPN default route
	cmd := exec.Command("ip", "route", "del", "default", "dev", TUN_DEVICE)
	if err := cmd.Run(); err != nil {
		log.Printf("Warning: failed to delete VPN route: %v", err)
	}

	// Restore original default route
	if c.originalGW != "" {
		cmd = exec.Command("ip", "route", "add", "default", "via", c.originalGW)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to restore default route: %v", err)
		}
		log.Println("Routing restored to original gateway")
	}

	return nil
}

func (c *VPNClient) cleanupTUN() error {
	if c.tunFile != nil {
		c.tunFile.Close()
	}

	cmd := exec.Command("ip", "link", "set", "dev", TUN_DEVICE, "down")
	cmd.Run()

	cmd = exec.Command("ip", "tuntap", "del", "mode", "tun", "dev", TUN_DEVICE)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete TUN device: %v", err)
	}

	log.Printf("TUN device %s removed", TUN_DEVICE)
	return nil
}

func (c *VPNClient) encrypt(data []byte) ([]byte, error) {
	if !c.encryption {
		return data, nil
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (c *VPNClient) decrypt(data []byte) ([]byte, error) {
	if !c.encryption {
		return data, nil
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (c *VPNClient) Connect() error {
	// Connect to server
	conn, err := net.Dial("tcp", c.serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %v", err)
	}
	c.conn = conn
	log.Printf("Connected to VPN server at %s", c.serverAddr)

	// Send encryption preference to server
	encryptByte := byte(0)
	if c.encryption {
		encryptByte = byte(1)
	}
	if _, err := conn.Write([]byte{encryptByte}); err != nil {
		return fmt.Errorf("failed to send encryption preference: %v", err)
	}
	log.Printf("Encryption: %v", c.encryption)

	// Setup TUN
	if err := c.setupTUN(); err != nil {
		return err
	}

	// Route traffic
	if err := c.routeAllTraffic(); err != nil {
		c.cleanupTUN()
		return err
	}

	c.enabled = true
	done := make(chan bool)

	// TUN -> Server (egress)
	go func() {
		buffer := make([]byte, MTU)
		for c.enabled {
			n, err := c.tunFile.Read(buffer)
			if err != nil {
				log.Printf("TUN read error: %v", err)
				done <- true
				return
			}

			packet := buffer[:n]
			encrypted, err := c.encrypt(packet)
			if err != nil {
				log.Printf("Encryption error: %v", err)
				continue
			}

			// Send packet length first, then packet
			length := make([]byte, 4)
			binary.BigEndian.PutUint32(length, uint32(len(encrypted)))
			if _, err := conn.Write(length); err != nil {
				log.Printf("Failed to send length: %v", err)
				done <- true
				return
			}
			if _, err := conn.Write(encrypted); err != nil {
				log.Printf("Failed to send packet: %v", err)
				done <- true
				return
			}
		}
	}()

	// Server -> TUN (ingress)
	go func() {
		lengthBuf := make([]byte, 4)
		for c.enabled {
			// Read packet length
			if _, err := io.ReadFull(conn, lengthBuf); err != nil {
				log.Printf("Failed to read length: %v", err)
				done <- true
				return
			}

			length := binary.BigEndian.Uint32(lengthBuf)
			if length > MTU*2 { // Sanity check
				log.Printf("Invalid packet length: %d", length)
				done <- true
				return
			}

			buffer := make([]byte, length)
			if _, err := io.ReadFull(conn, buffer); err != nil {
				log.Printf("Failed to read packet: %v", err)
				done <- true
				return
			}

			packet, err := c.decrypt(buffer)
			if err != nil {
				log.Printf("Decryption error: %v", err)
				continue
			}

			if _, err := c.tunFile.Write(packet); err != nil {
				log.Printf("TUN write error: %v", err)
				done <- true
				return
			}
		}
	}()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-done:
		log.Println("Connection lost")
	case <-sigChan:
		log.Println("Shutting down...")
	}

	return c.Disconnect()
}

func (c *VPNClient) Disconnect() error {
	c.enabled = false

	if err := c.restoreRouting(); err != nil {
		log.Printf("Failed to restore routing: %v", err)
	}

	if c.conn != nil {
		c.conn.Close()
	}

	if err := c.cleanupTUN(); err != nil {
		log.Printf("Failed to cleanup TUN: %v", err)
	}

	log.Println("VPN disconnected")
	return nil
}

func main() {
	server := flag.String("server", "", "VPN server address (e.g., 95.217.238.72:8888)")
	encrypt := flag.Bool("encrypt", false, "Enable encryption")
	flag.Parse()

	if *server == "" {
		log.Fatal("Server address is required. Use -server flag")
	}

	// Use same key as server (in production, use proper key exchange)
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes for AES-256

	client := NewVPNClient(*server, *encrypt, key)
	if err := client.Connect(); err != nil {
		log.Fatal(err)
	}
}
