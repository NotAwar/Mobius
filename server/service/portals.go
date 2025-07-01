package service

import (
	"context"
	"fmt"
	"time"

	"github.com/notawar/mobius/v4/server/contexts/ctxerr"
	"github.com/notawar/mobius/v4/server/mobius"
)

type InternalPortalStatsResponse struct {
	TotalUsers      int    `json:"total_users"`
	ActiveTeams     int    `json:"active_teams"`
	EnrolledDevices int    `json:"enrolled_devices"`
	PendingDevices  int    `json:"pending_devices"`
	SystemHealth    string `json:"system_health"`
	LastSync        string `json:"last_sync"`
	Err             error  `json:"error,omitempty"`
}

func (r InternalPortalStatsResponse) Error() error { return r.Err }

type InternalPortalLogsResponse struct {
	Logs []*mobius.Activity `json:"logs"`
	Err  error             `json:"error,omitempty"`
}

func (r InternalPortalLogsResponse) Error() error { return r.Err }

type UserPortalDevicesResponse struct {
	Devices []*mobius.Host `json:"devices"`
	Err     error         `json:"error,omitempty"`
}

func (r UserPortalDevicesResponse) Error() error { return r.Err }

type UserPortalEnrollmentResponse struct {
	EnrollmentCode string `json:"enrollment_code"`
	ProfileURL     string `json:"profile_url"`
	Instructions   string `json:"instructions"`
	Err            error  `json:"error,omitempty"`
}

func (r UserPortalEnrollmentResponse) Error() error { return r.Err }

func internalPortalStatsEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	// Get system statistics for internal portal
	users, err := svc.ListUsers(ctx, mobius.UserListOptions{})
	if err != nil {
		return InternalPortalStatsResponse{Err: err}, nil
	}

	teams, err := svc.ListTeams(ctx, mobius.ListOptions{})
	if err != nil {
		return InternalPortalStatsResponse{Err: err}, nil
	}

	hosts, err := svc.ListHosts(ctx, mobius.HostListOptions{})
	if err != nil {
		return InternalPortalStatsResponse{Err: err}, nil
	}

	enrolledCount := 0
	pendingCount := 0
	now := time.Now()
	for _, host := range hosts {
		if host.Status(now) == mobius.StatusOnline {
			enrolledCount++
		} else {
			pendingCount++
		}
	}

	return InternalPortalStatsResponse{
		TotalUsers:      len(users),
		ActiveTeams:     len(teams),
		EnrolledDevices: enrolledCount,
		PendingDevices:  pendingCount,
		SystemHealth:    "healthy",
		LastSync:        time.Now().Format(time.RFC3339),
	}, nil
}

func internalPortalLogsEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	// Get recent system activity logs
	activities, _, err := svc.ListActivities(ctx, mobius.ListActivitiesOptions{
		ListOptions: mobius.ListOptions{
			PerPage: 50,
		},
	})
	if err != nil {
		return InternalPortalLogsResponse{Err: err}, nil
	}

	return InternalPortalLogsResponse{
		Logs: activities,
	}, nil
}

func userPortalDevicesEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	// Get devices for the current user
	hosts, err := svc.ListHosts(ctx, mobius.HostListOptions{
		ListOptions: mobius.ListOptions{},
		// Filter by user email or other identifier
	})
	if err != nil {
		return UserPortalDevicesResponse{Err: err}, nil
	}

	// For now, return all hosts (in a real implementation, filter by user)
	userHosts := make([]*mobius.Host, 0)
	currentUser := currentUserFromContext(ctx)
	if currentUser != nil {
		// TODO: Implement proper user-host association
		userHosts = hosts
	}

	return UserPortalDevicesResponse{
		Devices: userHosts,
	}, nil
}

type userPortalDevicesRequest struct {
	UserID uint `url:"user_id"`
}

type userPortalEnrollmentRequest struct {
	UserID uint `json:"user_id"`
}

func userPortalEnrollmentEndpoint(ctx context.Context, request interface{}, svc mobius.Service) (mobius.Errorer, error) {
	req := request.(*userPortalEnrollmentRequest)

	// Generate enrollment code and instructions for user
	currentUser := currentUserFromContext(ctx)
	if currentUser == nil {
		return UserPortalEnrollmentResponse{Err: ctxerr.New(ctx, "unauthorized")}, nil
	}

	enrollmentCode := fmt.Sprintf("MOBIUS-%d-%d", currentUser.ID, time.Now().Unix())
	profileURL := fmt.Sprintf("/api/latest/mobius/user-portal/profile?user_id=%d", req.UserID)

	instructions := `
1. Download the appropriate enrollment profile for your device
2. Install the profile following your platform's instructions
3. Use the enrollment code during device setup
4. Contact support if you need assistance
`

	return UserPortalEnrollmentResponse{
		EnrollmentCode: enrollmentCode,
		ProfileURL:     profileURL,
		Instructions:   instructions,
	}, nil
}

// Helper function to get current user from context
func currentUserFromContext(ctx context.Context) *mobius.User {
	// This would need to be implemented based on Mobius's context structure
	// For now, return nil - this should be replaced with actual implementation
	return nil
}
