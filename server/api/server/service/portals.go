package service

import (
	"github.com/notawar/mobius/mobius-server/server/mobius"
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
	Err  error              `json:"error,omitempty"`
}

func (r InternalPortalLogsResponse) Error() error { return r.Err }

type UserPortalDevicesResponse struct {
	Devices []*mobius.Host `json:"devices"`
	Err     error          `json:"error,omitempty"`
}

func (r UserPortalDevicesResponse) Error() error { return r.Err }

type UserPortalEnrollmentResponse struct {
	EnrollmentCode string `json:"enrollment_code"`
	ProfileURL     string `json:"profile_url"`
	Instructions   string `json:"instructions"`
	Err            error  `json:"error,omitempty"`
}

func (r UserPortalEnrollmentResponse) Error() error { return r.Err }


