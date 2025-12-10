package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// API-based client for load testing the Mobius server
// This client simulates device interactions purely through the public API

type Client struct {
	serverURL    string
	httpClient   *http.Client
	enrollSecret string
	nodeKey      string
}

type EnrollRequest struct {
	EnrollSecret   string `json:"enroll_secret"`
	HostIdentifier string `json:"host_identifier"`
}

type EnrollResponse struct {
	NodeKey string `json:"node_key"`
}

type ConfigRequest struct {
	NodeKey string `json:"node_key"`
}

type ConfigResponse struct {
	// Configuration from server
}

func NewClient(serverURL, enrollSecret string) *Client {
	return &Client{
		serverURL:    serverURL,
		enrollSecret: enrollSecret,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) Enroll() error {
	req := EnrollRequest{
		EnrollSecret:   c.enrollSecret,
		HostIdentifier: uuid.New().String(),
	}

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(
		fmt.Sprintf("%s/api/osquery/enroll", c.serverURL),
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enrollment failed with status: %d", resp.StatusCode)
	}

	var enrollResp EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return err
	}

	c.nodeKey = enrollResp.NodeKey
	log.Printf("Successfully enrolled with node key: %s", c.nodeKey)
	return nil
}

func (c *Client) GetConfig() error {
	req := ConfigRequest{
		NodeKey: c.nodeKey,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(
		fmt.Sprintf("%s/api/osquery/config", c.serverURL),
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("config request failed with status: %d", resp.StatusCode)
	}

	log.Printf("Successfully retrieved configuration")
	return nil
}

func (c *Client) RunLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.GetConfig(); err != nil {
				log.Printf("Config request failed: %v", err)
			}
		}
	}
}

func main() {
	var (
		serverURL    = flag.String("server_url", "https://localhost:8080", "URL of Mobius server")
		enrollSecret = flag.String("enroll_secret", "", "Enroll secret")
		hostCount    = flag.Int("host_count", 10, "Number of simulated hosts")
		interval     = flag.Duration("interval", 1*time.Minute, "Request interval")
	)
	flag.Parse()

	if *enrollSecret == "" {
		log.Fatal("enroll_secret is required")
	}

	log.Printf("Starting %d simulated clients against %s", *hostCount, *serverURL)

	// Start simulated clients
	for i := 0; i < *hostCount; i++ {
		go func(clientID int) {
			// Spread out enrollment over time
			time.Sleep(time.Duration(rand.Intn(10)) * time.Second)

			client := NewClient(*serverURL, *enrollSecret)

			if err := client.Enroll(); err != nil {
				log.Printf("Client %d enrollment failed: %v", clientID, err)
				return
			}

			log.Printf("Client %d starting request loop", clientID)
			client.RunLoop(*interval)
		}(i)
	}

	// Keep main running
	select {}
}
