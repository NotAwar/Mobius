package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/notawar/mobius/mobius-server/pkg/websocket"
)

// WebSocketHandler handles WebSocket connections for real-time updates
type WebSocketHandler struct {
	hub *websocket.Hub
}

// NewWebSocketHandler creates a new WebSocket handler
func NewWebSocketHandler(hub *websocket.Hub) *WebSocketHandler {
	return &WebSocketHandler{
		hub: hub,
	}
}

// HandleConnection handles WebSocket connection upgrade requests
func (h *WebSocketHandler) HandleConnection(w http.ResponseWriter, r *http.Request) {
	// Extract user information from JWT token (similar to auth middleware)
	userID, userRole, err := h.extractUserFromRequest(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Upgrade the connection to WebSocket
	h.hub.HandleWebSocket(w, r, userID, userRole)
}

// HandleStatus returns WebSocket connection status
func (h *WebSocketHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := map[string]interface{}{
		"connected_clients": h.hub.GetClientCount(),
		"status":           "running",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// extractUserFromRequest extracts user information from JWT token
func (h *WebSocketHandler) extractUserFromRequest(r *http.Request) (string, string, error) {
	// Check for token in query parameter (for WebSocket connections)
	token := r.URL.Query().Get("token")
	if token == "" {
		// Check Authorization header as fallback
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if token == "" {
		return "", "", http.ErrNoCookie
	}

	// For now, use a simple mock validation
	// In production, validate the JWT token properly
	if token == "test-token" {
		return "test-user", "admin", nil
	}

	return "", "", http.ErrNoCookie
}

// WebSocketService integrates WebSocket functionality with existing services
type WebSocketService struct {
	eventPublisher websocket.EventPublisher
}

// NewWebSocketService creates a new WebSocket service
func NewWebSocketService(eventPublisher websocket.EventPublisher) *WebSocketService {
	return &WebSocketService{
		eventPublisher: eventPublisher,
	}
}

// NotifyDeviceStatusChange notifies clients of device status changes
func (s *WebSocketService) NotifyDeviceStatusChange(deviceID, oldStatus, newStatus string) {
	s.eventPublisher.PublishDeviceStatusChange(deviceID, oldStatus, newStatus)
}

// NotifyPolicyAssignment notifies clients of policy assignments
func (s *WebSocketService) NotifyPolicyAssignment(policyID, deviceID, groupID, action string) {
	s.eventPublisher.PublishPolicyAssignment(policyID, deviceID, groupID, action)
}

// NotifyCommandExecution notifies clients of command execution status
func (s *WebSocketService) NotifyCommandExecution(commandID, deviceID, command, status, result string) {
	s.eventPublisher.PublishCommandExecution(commandID, deviceID, command, status, result)
}

// NotifyGroupMembership notifies clients of group membership changes
func (s *WebSocketService) NotifyGroupMembership(groupID, deviceID, action string) {
	s.eventPublisher.PublishGroupMembership(groupID, deviceID, action)
}

// SetupWebSocketRoutes sets up WebSocket-related routes
func SetupWebSocketRoutes(mux *http.ServeMux, handler *WebSocketHandler) {
	// WebSocket connection endpoint
	mux.HandleFunc("/ws", handler.HandleConnection)
	
	// WebSocket status endpoint
	mux.HandleFunc("/api/v1/websocket/status", handler.HandleStatus)
}

// Integration helper functions for existing services

// DeviceStatusChangeWrapper wraps device status updates with WebSocket notifications
type DeviceStatusChangeWrapper struct {
	originalService interface{} // The original device service
	wsService      *WebSocketService
}

// WrapDeviceService wraps an existing device service with WebSocket notifications
func WrapDeviceService(originalService interface{}, wsService *WebSocketService) *DeviceStatusChangeWrapper {
	return &DeviceStatusChangeWrapper{
		originalService: originalService,
		wsService:      wsService,
	}
}

// PolicyAssignmentWrapper wraps policy assignments with WebSocket notifications
type PolicyAssignmentWrapper struct {
	originalService interface{} // The original policy service
	wsService      *WebSocketService
}

// WrapPolicyService wraps an existing policy service with WebSocket notifications
func WrapPolicyService(originalService interface{}, wsService *WebSocketService) *PolicyAssignmentWrapper {
	return &PolicyAssignmentWrapper{
		originalService: originalService,
		wsService:      wsService,
	}
}

// CommandExecutionWrapper wraps command execution with WebSocket notifications
type CommandExecutionWrapper struct {
	originalService interface{} // The original command service
	wsService      *WebSocketService
}

// WrapCommandService wraps an existing command service with WebSocket notifications
func WrapCommandService(originalService interface{}, wsService *WebSocketService) *CommandExecutionWrapper {
	return &CommandExecutionWrapper{
		originalService: originalService,
		wsService:      wsService,
	}
}
