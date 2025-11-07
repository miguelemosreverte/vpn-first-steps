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
	"runtime"
	"syscall"

	"github.com/songgao/water"
)

const (
	MTU         = 1400  // Reduced to account for encryption overhead (GCM adds ~28 bytes)
	TUN_DEVICE  = "tun0"
	CLIENT_IP   = "10.8.0.2"
	SERVER_IP   = "10.8.0.1"
)

type VPNClient struct {
	serverAddr string
	encryption bool
	key        []byte
	tunIface   *water.Interface
	conn       net.Conn
	enabled    bool
	originalGW string
	tunName    string
}

func NewVPNClient(serverAddr string, encryption bool, key []byte) *VPNClient {
	return &VPNClient{
		serverAddr: serverAddr,
		encryption: encryption,
		key:        key,
		enabled:    false,
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (c *VPNClient) setupTUN() error {
	// Create TUN interface using water library (cross-platform)
	config := water.Config{
		DeviceType: water.TUN,
	}

	// On Linux, we can specify the device name
	if runtime.GOOS == "linux" {
		config.Name = TUN_DEVICE
	}

	iface, err := water.New(config)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %v", err)
	}
	c.tunIface = iface
	c.tunName = iface.Name()

	log.Printf("Created TUN device: %s", c.tunName)

	// Configure IP address based on OS
	if runtime.GOOS == "darwin" {
		// macOS uses ifconfig
		cmd := exec.Command("ifconfig", c.tunName, CLIENT_IP, SERVER_IP, "up")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to configure %s: %v", c.tunName, err)
		}
	} else {
		// Linux uses ip command
		cmd := exec.Command("ip", "addr", "add", CLIENT_IP+"/24", "dev", c.tunName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to assign IP: %v", err)
		}

		cmd = exec.Command("ip", "link", "set", "dev", c.tunName, "up")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to bring interface up: %v", err)
		}
	}

	log.Printf("TUN device %s configured with IP %s", c.tunName, CLIENT_IP)
	return nil
}

func (c *VPNClient) getDefaultGateway() (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("sh", "-c", "route -n get default | grep gateway | awk '{print $2}'")
	} else {
		cmd = exec.Command("sh", "-c", "ip route | grep default | awk '{print $3}'")
	}
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	result := string(output)
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}
	return result, nil
}

func (c *VPNClient) routeAllTraffic() error {
	// Save original default gateway
	gw, err := c.getDefaultGateway()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %v", err)
	}
	c.originalGW = gw
	log.Printf("Original gateway: %s", c.originalGW)

	serverHost, _, _ := net.SplitHostPort(c.serverAddr)

	if runtime.GOOS == "darwin" {
		// macOS routing
		// Add route to VPN server through original gateway
		cmd := exec.Command("route", "-n", "add", "-host", serverHost, c.originalGW)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to add server route: %v", err)
		}

		// Delete default route
		cmd = exec.Command("route", "-n", "delete", "default")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to delete default route: %v", err)
		}

		// Add default route through VPN
		cmd = exec.Command("route", "-n", "add", "-net", "default", SERVER_IP)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add VPN route: %v", err)
		}
	} else {
		// Linux routing
		cmd := exec.Command("ip", "route", "add", serverHost, "via", c.originalGW)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to add server route: %v", err)
		}

		cmd = exec.Command("ip", "route", "del", "default")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to delete default route: %v", err)
		}

		cmd = exec.Command("ip", "route", "add", "default", "via", SERVER_IP, "dev", c.tunName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add VPN route: %v", err)
		}
	}

	log.Println("All traffic now routed through VPN")
	return nil
}

func (c *VPNClient) restoreRouting() error {
	if runtime.GOOS == "darwin" {
		// macOS routing restoration
		cmd := exec.Command("route", "-n", "delete", "default")
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to delete VPN route: %v", err)
		}

		if c.originalGW != "" {
			cmd = exec.Command("route", "-n", "add", "-net", "default", c.originalGW)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to restore default route: %v", err)
			}
			log.Println("Routing restored to original gateway")
		}
	} else {
		// Linux routing restoration
		cmd := exec.Command("ip", "route", "del", "default", "dev", c.tunName)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to delete VPN route: %v", err)
		}

		if c.originalGW != "" {
			cmd = exec.Command("ip", "route", "add", "default", "via", c.originalGW)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to restore default route: %v", err)
			}
			log.Println("Routing restored to original gateway")
		}
	}

	return nil
}

func (c *VPNClient) cleanupTUN() error {
	if c.tunIface != nil {
		c.tunIface.Close()
	}

	if runtime.GOOS == "darwin" {
		// macOS cleanup - utun devices are automatically removed when closed
		log.Printf("TUN device %s closed", c.tunName)
	} else {
		// Linux cleanup
		cmd := exec.Command("ip", "link", "set", "dev", c.tunName, "down")
		cmd.Run()

		cmd = exec.Command("ip", "tuntap", "del", "mode", "tun", "dev", c.tunName)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to delete TUN device: %v", err)
		}
		log.Printf("TUN device %s removed", c.tunName)
	}

	return nil
}

func (c *VPNClient) encrypt(data []byte) ([]byte, error) {
	if !c.encryption {
		return data, nil
	}

	log.Printf("[ENCRYPT DEBUG] Input size: %d bytes", len(data))
	log.Printf("[ENCRYPT DEBUG] Input first 4 bytes: %x", data[:min(4, len(data))])

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

	log.Printf("[ENCRYPT DEBUG] Nonce size: %d", gcm.NonceSize())
	log.Printf("[ENCRYPT DEBUG] Nonce: %x", nonce)

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	log.Printf("[ENCRYPT DEBUG] Output size: %d bytes", len(ciphertext))
	log.Printf("[ENCRYPT DEBUG] Output first 16 bytes: %x", ciphertext[:min(16, len(ciphertext))])

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
			n, err := c.tunIface.Read(buffer)
			if err != nil {
				log.Printf("TUN read error: %v", err)
				done <- true
				return
			}

			packet := buffer[:n]

			// DEBUG: Log packet details when encryption is on
			if c.encryption {
				log.Printf("[CLIENT OUT] Read from TUN: %d bytes, first 4 bytes: %x", n, packet[:min(4, len(packet))])
			}

			encrypted, err := c.encrypt(packet)
			if err != nil {
				log.Printf("Encryption error: %v", err)
				continue
			}

			if c.encryption {
				log.Printf("[CLIENT OUT] After encrypt: %d bytes", len(encrypted))
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

			if c.encryption {
				log.Printf("[CLIENT IN] Received encrypted: %d bytes", len(buffer))
			}

			packet, err := c.decrypt(buffer)
			if err != nil {
				log.Printf("Decryption error: %v", err)
				continue
			}

			if c.encryption {
				log.Printf("[CLIENT IN] After decrypt: %d bytes, first 4 bytes: %x", len(packet), packet[:min(4, len(packet))])
			}

			if _, err := c.tunIface.Write(packet); err != nil {
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
