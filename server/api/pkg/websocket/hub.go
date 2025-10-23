package websocket

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// EventType represents the type of real-time event
type EventType string

const (
	EventDeviceStatusChange EventType = "device_status_change"
	EventPolicyAssignment   EventType = "policy_assignment"
	EventCommandExecution   EventType = "command_execution"
	EventGroupMembership    EventType = "group_membership"
)

// Event represents a real-time event to be broadcast
type Event struct {
	Type      EventType   `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// DeviceStatusChangeData represents device status change event data
type DeviceStatusChangeData struct {
	DeviceID  string `json:"device_id"`
	OldStatus string `json:"old_status"`
	NewStatus string `json:"new_status"`
}

// PolicyAssignmentData represents policy assignment event data
type PolicyAssignmentData struct {
	PolicyID string `json:"policy_id"`
	DeviceID string `json:"device_id,omitempty"`
	GroupID  string `json:"group_id,omitempty"`
	Action   string `json:"action"` // "assigned" or "unassigned"
}

// CommandExecutionData represents command execution event data
type CommandExecutionData struct {
	CommandID string `json:"command_id"`
	DeviceID  string `json:"device_id"`
	Command   string `json:"command"`
	Status    string `json:"status"` // "executing", "completed", "failed"
	Result    string `json:"result,omitempty"`
}

// GroupMembershipData represents group membership change event data
type GroupMembershipData struct {
	GroupID  string `json:"group_id"`
	DeviceID string `json:"device_id"`
	Action   string `json:"action"` // "added" or "removed"
}

// Client represents a WebSocket client connection
type Client struct {
	ID       string
	UserID   string
	Conn     *websocket.Conn
	Hub      *Hub
	Send     chan Event
	UserRole string // "admin", "user", etc.
}

// Hub maintains the set of active clients and broadcasts messages to the clients
type Hub struct {
	// Registered clients
	clients map[*Client]bool

	// Inbound messages from the clients
	broadcast chan Event

	// Register requests from the clients
	register chan *Client

	// Unregister requests from clients
	unregister chan *Client

	// Mutex for thread-safe operations
	mutex sync.RWMutex
}

// NewHub creates a new WebSocket hub
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan Event, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run starts the hub and listens for client events
func (h *Hub) Run(ctx context.Context) {
	log.Println("WebSocket hub started")
	defer log.Println("WebSocket hub stopped")

	for {
		select {
		case <-ctx.Done():
			return
		case client := <-h.register:
			h.mutex.Lock()
			h.clients[client] = true
			h.mutex.Unlock()
			log.Printf("Client %s connected", client.ID)

		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.Send)
				log.Printf("Client %s disconnected", client.ID)
			}
			h.mutex.Unlock()

		case event := <-h.broadcast:
			h.mutex.RLock()
			for client := range h.clients {
				select {
				case client.Send <- event:
				default:
					close(client.Send)
					delete(h.clients, client)
				}
			}
			h.mutex.RUnlock()
		}
	}
}

// BroadcastEvent sends an event to all connected clients
func (h *Hub) BroadcastEvent(eventType string, data interface{}) {
	event := Event{
		Type:      EventType(eventType),
		Timestamp: time.Now(),
		Data:      data,
	}

	select {
	case h.broadcast <- event:
	default:
		log.Println("Warning: Broadcast channel full, dropping event")
	}
}

// GetClientCount returns the number of connected clients
func (h *Hub) GetClientCount() int {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return len(h.clients)
}

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// HandleWebSocket handles WebSocket connection requests
func (h *Hub) HandleWebSocket(w http.ResponseWriter, r *http.Request, userID, userRole string) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	clientID := generateClientID()
	client := &Client{
		ID:       clientID,
		UserID:   userID,
		Conn:     conn,
		Hub:      h,
		Send:     make(chan Event, 256),
		UserRole: userRole,
	}

	client.Hub.register <- client

	// Start goroutines for reading and writing
	go client.writePump()
	go client.readPump()
}

// readPump pumps messages from the websocket connection to the hub
func (c *Client) readPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
	}()

	c.Conn.SetReadLimit(512)
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}
		// For now, we don't process incoming messages from clients
		// This could be extended for client-to-server commands
	}
}

// writePump pumps messages from the hub to the websocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case event, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// Send the event as JSON
			if err := c.Conn.WriteJSON(event); err != nil {
				log.Printf("WebSocket write error: %v", err)
				return
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// generateClientID generates a unique client ID
func generateClientID() string {
	// Simple timestamp-based ID for now
	// In production, use UUID or similar
	return "client_" + time.Now().Format("20060102150405") + "_" + 
		   time.Now().Format("000000")[3:] // microseconds
}

// EventPublisher interface for publishing real-time events
type EventPublisher interface {
	PublishDeviceStatusChange(deviceID, oldStatus, newStatus string)
	PublishPolicyAssignment(policyID, deviceID, groupID, action string)
	PublishCommandExecution(commandID, deviceID, command, status, result string)
	PublishGroupMembership(groupID, deviceID, action string)
}

// HubEventPublisher implements EventPublisher using the WebSocket hub
type HubEventPublisher struct {
	hub *Hub
}

// NewEventPublisher creates a new event publisher
func NewEventPublisher(hub *Hub) EventPublisher {
	return &HubEventPublisher{hub: hub}
}

// PublishDeviceStatusChange publishes a device status change event
func (p *HubEventPublisher) PublishDeviceStatusChange(deviceID, oldStatus, newStatus string) {
	data := DeviceStatusChangeData{
		DeviceID:  deviceID,
		OldStatus: oldStatus,
		NewStatus: newStatus,
	}
	p.hub.BroadcastEvent(string(EventDeviceStatusChange), data)
}

// PublishPolicyAssignment publishes a policy assignment event
func (p *HubEventPublisher) PublishPolicyAssignment(policyID, deviceID, groupID, action string) {
	data := PolicyAssignmentData{
		PolicyID: policyID,
		DeviceID: deviceID,
		GroupID:  groupID,
		Action:   action,
	}
	p.hub.BroadcastEvent(string(EventPolicyAssignment), data)
}

// PublishCommandExecution publishes a command execution event
func (p *HubEventPublisher) PublishCommandExecution(commandID, deviceID, command, status, result string) {
	data := CommandExecutionData{
		CommandID: commandID,
		DeviceID:  deviceID,
		Command:   command,
		Status:    status,
		Result:    result,
	}
	p.hub.BroadcastEvent(string(EventCommandExecution), data)
}

// PublishGroupMembership publishes a group membership change event
func (p *HubEventPublisher) PublishGroupMembership(groupID, deviceID, action string) {
	data := GroupMembershipData{
		GroupID:  groupID,
		DeviceID: deviceID,
		Action:   action,
	}
	p.hub.BroadcastEvent(string(EventGroupMembership), data)
}
