package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	openvpn "github.com/airofm/sing-openvpn"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if len(os.Args) < 3 {
		log.Fatalf("Usage: %s <profile.ovpn> <target-url> [clash-yaml proxy-name]", os.Args[0])
	}
	ovpnPath := os.Args[1]
	targetURL := os.Args[2]
	username := os.Getenv("OPENVPN_USERNAME")
	password := os.Getenv("OPENVPN_PASSWORD")
	if username == "" && password == "" && len(os.Args) >= 5 {
		loadedUsername, loadedPassword, found, err := loadProxyCredentials(os.Args[3], os.Args[4])
		if err != nil {
			log.Fatalf("Failed to load proxy credentials: %v", err)
		}
		if !found {
			log.Fatalf("Proxy %q not found in %s", os.Args[4], os.Args[3])
		}
		username = loadedUsername
		password = loadedPassword
		log.Printf("Loaded proxy credentials for %s (values hidden)", os.Args[4])
	}

	log.Printf("Parsing OpenVPN config: %s", ovpnPath)
	ovpnContent, err := os.ReadFile(ovpnPath)
	if err != nil {
		log.Fatalf("Failed to read ovpn file: %v", err)
	}

	client, err := openvpn.NewClient(ovpnContent, username, password, nil)
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
	log.Printf("Testing connection to %s via VPN...", targetURL)

	// Create a custom HTTP client that uses our VPN tunnel
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: os.Getenv("OPENVPN_TEST_INSECURE_SKIP_VERIFY") == "1"},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				log.Printf("Dialing %s via VPN...", addr)

				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}

				if parsedIP := net.ParseIP(host); parsedIP != nil {
					ipAddr := net.JoinHostPort(parsedIP.String(), port)
					log.Printf("Target is already an IP, dialing %s via VPN...", ipAddr)
					return client.DialContext(ctx, network, ipAddr)
				}

				// Use a custom resolver that queries the pushed DNS server through the VPN
				resolver := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						dnsServer := "8.8.8.8:53"
						cfg := client.GetConfig()
						if len(cfg.DNS) > 0 {
							dnsServer = cfg.DNS[0] + ":53"
						}
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

func loadProxyCredentials(path, proxyName string) (string, string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", false, err
	}
	defer file.Close()

	var username, password string
	inProxy := false
	found := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- name:") {
			if inProxy {
				break
			}
			name := yamlScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "- name:")))
			if name == proxyName {
				inProxy = true
				found = true
			}
			continue
		}
		if !inProxy {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "username:"):
			username = yamlScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "username:")))
		case strings.HasPrefix(trimmed, "password:"):
			password = yamlScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "password:")))
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", false, err
	}
	return username, password, found, nil
}

func yamlScalar(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"') {
			return value[1 : len(value)-1]
		}
	}
	return value
}
