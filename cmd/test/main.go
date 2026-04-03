package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	openvpn "github.com/airofm/sing-openvpn"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	ovpnPath := "path/to/your/profile.ovpn"
	username := "your_username"
	password := "your_password"

	log.Printf("Parsing OpenVPN config: %s", ovpnPath)
	client, err := openvpn.NewClientFromFile(ovpnPath, username, password)
	if err != nil {
		log.Fatalf("Init error: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Println("Dialing OpenVPN server...")
	if err := client.Dial(ctx); err != nil {
		log.Fatalf("Failed to connect OpenVPN: %v", err)
	}
	log.Println("OpenVPN connected successfully! TUN device is up.")

	// Test HTTP request through the VPN tunnel
	targetURL := "https://example.com/"
	log.Printf("Testing connection to %s via VPN...", targetURL)

	// Create a custom HTTP client that uses our VPN tunnel
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				log.Printf("Dialing %s via VPN...", addr)
				
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				
				// Use a custom resolver that queries the pushed DNS server through the VPN
				resolver := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						// You should replace this with the DNS server pushed by your OpenVPN server
						dnsServer := "8.8.8.8:53"
						log.Printf("Dialing DNS %s via VPN...", dnsServer)
						return client.DialContext(ctx, "udp", dnsServer)
					},
				}

				// Resolve host to IP first since DialContext expects an IP
				ips, err := resolver.LookupIPAddr(ctx, host)
				if err != nil || len(ips) == 0 {
					return nil, fmt.Errorf("failed to resolve %s via VPN DNS: %v", host, err)
				}
				ipAddr := net.JoinHostPort(ips[0].IP.String(), port)
				log.Printf("Resolved to %s, dialing via VPN...", ipAddr)

				return client.DialContext(ctx, network, ipAddr)
			},
			// Disable HTTP/2 for simpler testing if needed, though usually fine
			ForceAttemptHTTP2: true,
		},
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequestWithContext(context.Background(), "GET", targetURL, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("HTTP Status: %s", resp.Status)
	
	// Read a small portion of the body to verify
	body := make([]byte, 512)
	n, _ := io.ReadFull(resp.Body, body)
	log.Printf("Response Body (first %d bytes):\n%s", n, string(body[:n]))
	
	log.Println("Test completed successfully!")
}
