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
	"os/exec"

	"github.com/songgao/water"
)

const (
	MTU         = 1500
	TUN_DEVICE  = "tun0"
	VPN_NETWORK = "10.8.0.0/24"
	SERVER_IP   = "10.8.0.1"
)

type VPNServer struct {
	listenAddr string
	encryption bool
	key        []byte
	tunIface   *water.Interface
}

func NewVPNServer(listenAddr string, encryption bool, key []byte) *VPNServer {
	return &VPNServer{
		listenAddr: listenAddr,
		encryption: encryption,
		key:        key,
	}
}

func (s *VPNServer) setupTUN() error {
	// Create TUN interface using water library
	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: TUN_DEVICE,
		},
	}

	iface, err := water.New(config)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %v", err)
	}
	s.tunIface = iface

	log.Printf("Created TUN device: %s", iface.Name())

	// Assign IP address
	cmd := exec.Command("ip", "addr", "add", SERVER_IP+"/24", "dev", iface.Name())
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to assign IP: %v", err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", iface.Name(), "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %v", err)
	}

	// Enable IP forwarding
	cmd = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}

	log.Printf("TUN device %s configured with IP %s", iface.Name(), SERVER_IP)
	return nil
}

func (s *VPNServer) encrypt(data []byte) ([]byte, error) {
	if !s.encryption {
		return data, nil
	}

	block, err := aes.NewCipher(s.key)
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

func (s *VPNServer) decrypt(data []byte) ([]byte, error) {
	if !s.encryption {
		return data, nil
	}

	block, err := aes.NewCipher(s.key)
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

func (s *VPNServer) handleClient(conn net.Conn) {
	defer conn.Close()
	log.Printf("Client connected from %s", conn.RemoteAddr())

	// Read client's encryption preference
	encryptByte := make([]byte, 1)
	if _, err := conn.Read(encryptByte); err != nil {
		log.Printf("Failed to read client encryption preference: %v", err)
		return
	}
	clientWantsEncryption := encryptByte[0] == 1
	log.Printf("Client encryption preference: %v", clientWantsEncryption)

	// Channel for graceful shutdown
	done := make(chan bool)

	// TUN -> Client (egress)
	go func() {
		buffer := make([]byte, MTU)
		for {
			n, err := s.tunIface.Read(buffer)
			if err != nil {
				log.Printf("TUN read error: %v", err)
				done <- true
				return
			}

			packet := buffer[:n]
			var encrypted []byte
			if clientWantsEncryption {
				encrypted, err = s.encrypt(packet)
				if err != nil {
					log.Printf("Encryption error: %v", err)
					continue
				}
			} else {
				encrypted = packet
			}

			// Send packet length first (4 bytes), then packet
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

	// Client -> TUN (ingress)
	go func() {
		lengthBuf := make([]byte, 4)
		for {
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

			var packet []byte
			var err error
			if clientWantsEncryption {
				packet, err = s.decrypt(buffer)
				if err != nil {
					log.Printf("Decryption error: %v", err)
					continue
				}
			} else {
				packet = buffer
			}

			if _, err := s.tunIface.Write(packet); err != nil {
				log.Printf("TUN write error: %v", err)
				done <- true
				return
			}
		}
	}()

	<-done
	log.Printf("Client %s disconnected", conn.RemoteAddr())
}

func (s *VPNServer) Start() error {
	if err := s.setupTUN(); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	defer listener.Close()

	log.Printf("VPN server listening on %s (encryption: %v)", s.listenAddr, s.encryption)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go s.handleClient(conn)
	}
}

func main() {
	port := flag.String("port", "8888", "Port to listen on")
	flag.Parse()

	// Generate or use a fixed key (in production, use proper key management)
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes for AES-256

	server := NewVPNServer(":"+*port, false, key)
	log.Fatal(server.Start())
}
