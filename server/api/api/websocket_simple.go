package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// Simple WebSocket implementation for MDM real-time features
// This is a minimal implementation that integrates with the existing test server

// WebSocketManager handles WebSocket connections for real-time updates
type WebSocketManager struct {
	clients     map[*websocket.Conn]bool
	broadcaster chan []byte
	upgrader    websocket.Upgrader
}

// NewWebSocketManager creates a new WebSocket manager
func NewWebSocketManager() *WebSocketManager {
	return &WebSocketManager{
		clients:     make(map[*websocket.Conn]bool),
		broadcaster: make(chan []byte),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for testing
			},
		},
	}
}

// Start runs the WebSocket manager
func (wsm *WebSocketManager) Start(ctx context.Context) {
	log.Println("WebSocket manager started")
	go wsm.run(ctx)
}

// run handles WebSocket broadcasting
func (wsm *WebSocketManager) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case message := <-wsm.broadcaster:
			for client := range wsm.clients {
				if err := client.WriteMessage(websocket.TextMessage, message); err != nil {
					log.Printf("WebSocket write error: %v", err)
					client.Close()
					delete(wsm.clients, client)
				}
			}
		}
	}
}

// HandleWebSocket handles WebSocket connection requests
func (wsm *WebSocketManager) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := wsm.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	wsm.clients[conn] = true
	log.Printf("WebSocket client connected, total clients: %d", len(wsm.clients))

	// Send welcome message
	welcomeMsg := map[string]interface{}{
		"type":      "connection",
		"timestamp": time.Now(),
		"message":   "Connected to Mobius MDM WebSocket",
	}
	if msgBytes, err := json.Marshal(welcomeMsg); err == nil {
		conn.WriteMessage(websocket.TextMessage, msgBytes)
	}

	// Keep connection alive and handle disconnection
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}

	delete(wsm.clients, conn)
	log.Printf("WebSocket client disconnected, remaining clients: %d", len(wsm.clients))
}

// BroadcastDeviceStatusChange broadcasts device status changes
func (wsm *WebSocketManager) BroadcastDeviceStatusChange(deviceID, oldStatus, newStatus string) {
	event := map[string]interface{}{
		"type":      "device_status_change",
		"timestamp": time.Now(),
		"data": map[string]string{
			"device_id":  deviceID,
			"old_status": oldStatus,
			"new_status": newStatus,
		},
	}

	if msgBytes, err := json.Marshal(event); err == nil {
		select {
		case wsm.broadcaster <- msgBytes:
		default:
			log.Println("WebSocket broadcast channel full, dropping message")
		}
	}
}

// BroadcastPolicyAssignment broadcasts policy assignment events
func (wsm *WebSocketManager) BroadcastPolicyAssignment(policyID, deviceID, groupID, action string) {
	data := map[string]string{
		"policy_id": policyID,
		"action":    action,
	}
	if deviceID != "" {
		data["device_id"] = deviceID
	}
	if groupID != "" {
		data["group_id"] = groupID
	}

	event := map[string]interface{}{
		"type":      "policy_assignment",
		"timestamp": time.Now(),
		"data":      data,
	}

	if msgBytes, err := json.Marshal(event); err == nil {
		select {
		case wsm.broadcaster <- msgBytes:
		default:
			log.Println("WebSocket broadcast channel full, dropping message")
		}
	}
}

// BroadcastCommandExecution broadcasts command execution events
func (wsm *WebSocketManager) BroadcastCommandExecution(commandID, deviceID, command, status, result string) {
	event := map[string]interface{}{
		"type":      "command_execution",
		"timestamp": time.Now(),
		"data": map[string]string{
			"command_id": commandID,
			"device_id":  deviceID,
			"command":    command,
			"status":     status,
			"result":     result,
		},
	}

	if msgBytes, err := json.Marshal(event); err == nil {
		select {
		case wsm.broadcaster <- msgBytes:
		default:
			log.Println("WebSocket broadcast channel full, dropping message")
		}
	}
}

// BroadcastGroupMembership broadcasts group membership changes
func (wsm *WebSocketManager) BroadcastGroupMembership(groupID, deviceID, action string) {
	event := map[string]interface{}{
		"type":      "group_membership",
		"timestamp": time.Now(),
		"data": map[string]string{
			"group_id":  groupID,
			"device_id": deviceID,
			"action":    action,
		},
	}

	if msgBytes, err := json.Marshal(event); err == nil {
		select {
		case wsm.broadcaster <- msgBytes:
		default:
			log.Println("WebSocket broadcast channel full, dropping message")
		}
	}
}

// GetStatus returns WebSocket status information
func (wsm *WebSocketManager) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"connected_clients": len(wsm.clients),
		"status":           "running",
	}
}
