package ansible

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/notawar/mobius/server/mobius"
)

// AnsibleService provides Ansible integration for MDM functionality
type AnsibleService struct {
	playbookPath string
	inventoryPath string
	logger       mobius.Logger
}

// NewAnsibleService creates a new Ansible service instance
func NewAnsibleService(playbookPath, inventoryPath string, logger mobius.Logger) *AnsibleService {
	return &AnsibleService{
		playbookPath:  playbookPath,
		inventoryPath: inventoryPath,
		logger:        logger,
	}
}

// Host represents a host managed by Ansible
type Host struct {
	ID              string                 `json:"id"`
	Hostname        string                 `json:"hostname"`
	IPAddress       string                 `json:"ip_address"`
	OperatingSystem string                 `json:"operating_system"`
	Status          string                 `json:"status"`
	LastSeen        time.Time              `json:"last_seen"`
	AnsibleFacts    map[string]interface{} `json:"ansible_facts,omitempty"`
	OsqueryEnrolled bool                   `json:"osquery_enrolled"`
}

// Playbook represents an Ansible playbook
type Playbook struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Path        string                 `json:"path"`
	Tags        []string               `json:"tags"`
	Variables   map[string]interface{} `json:"variables,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Job represents an Ansible job execution
type Job struct {
	ID         string    `json:"id"`
	PlaybookID string    `json:"playbook_id"`
	HostIDs    []string  `json:"host_ids"`
	Status     string    `json:"status"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Output     string    `json:"output,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// ListHosts returns all hosts from Ansible inventory
func (s *AnsibleService) ListHosts(ctx context.Context) ([]Host, error) {
	cmd := exec.CommandContext(ctx, "ansible-inventory", "-i", s.inventoryPath, "--list", "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list ansible hosts: %w", err)
	}

	var inventory map[string]interface{}
	if err := json.Unmarshal(output, &inventory); err != nil {
		return nil, fmt.Errorf("failed to parse ansible inventory: %w", err)
	}

	return s.parseInventoryHosts(inventory), nil
}

// ListPlaybooks returns available Ansible playbooks
func (s *AnsibleService) ListPlaybooks(ctx context.Context) ([]Playbook, error) {
	// This would typically read from a database or configuration
	// For now, return some example playbooks
	playbooks := []Playbook{
		{
			ID:          "site",
			Name:        "Complete Device Setup",
			Description: "Full device configuration including osquery, security policies, and monitoring",
			Path:        filepath.Join(s.playbookPath, "site.yml"),
			Tags:        []string{"setup", "security", "monitoring"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "security-only",
			Name:        "Security Policies Only",
			Description: "Apply security configurations without full setup",
			Path:        filepath.Join(s.playbookPath, "security.yml"),
			Tags:        []string{"security"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "osquery-setup",
			Name:        "osquery Installation",
			Description: "Install and configure osquery with Mobius enrollment",
			Path:        filepath.Join(s.playbookPath, "osquery.yml"),
			Tags:        []string{"osquery", "monitoring"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	return playbooks, nil
}

// RunPlaybook executes an Ansible playbook on specified hosts
func (s *AnsibleService) RunPlaybook(ctx context.Context, playbookID string, hostIDs []string, variables map[string]interface{}) (*Job, error) {
	playbooks, err := s.ListPlaybooks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list playbooks: %w", err)
	}

	var playbook *Playbook
	for _, p := range playbooks {
		if p.ID == playbookID {
			playbook = &p
			break
		}
	}

	if playbook == nil {
		return nil, fmt.Errorf("playbook not found: %s", playbookID)
	}

	job := &Job{
		ID:         generateJobID(),
		PlaybookID: playbookID,
		HostIDs:    hostIDs,
		Status:     "pending",
	}

	// Start playbook execution in background
	go s.executePlaybook(ctx, job, playbook, hostIDs, variables)

	return job, nil
}

// executePlaybook runs the actual Ansible playbook
func (s *AnsibleService) executePlaybook(ctx context.Context, job *Job, playbook *Playbook, hostIDs []string, variables map[string]interface{}) {
	job.Status = "running"
	now := time.Now()
	job.StartedAt = &now

	// Build ansible-playbook command
	args := []string{
		"-i", s.inventoryPath,
		playbook.Path,
	}

	// Add host limit
	if len(hostIDs) > 0 {
		hostList := ""
		for i, hostID := range hostIDs {
			if i > 0 {
				hostList += ","
			}
			hostList += hostID
		}
		args = append(args, "--limit", hostList)
	}

	// Add extra variables
	if len(variables) > 0 {
		extraVars, _ := json.Marshal(variables)
		args = append(args, "--extra-vars", string(extraVars))
	}

	cmd := exec.CommandContext(ctx, "ansible-playbook", args...)
	output, err := cmd.CombinedOutput()

	finishedAt := time.Now()
	job.FinishedAt = &finishedAt
	job.Output = string(output)

	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		s.logger.Log("level", "error", "msg", "ansible playbook execution failed", "job_id", job.ID, "error", err)
	} else {
		job.Status = "completed"
		s.logger.Log("level", "info", "msg", "ansible playbook execution completed", "job_id", job.ID)
	}
}

// parseInventoryHosts converts Ansible inventory to Host structs
func (s *AnsibleService) parseInventoryHosts(inventory map[string]interface{}) []Host {
	hosts := []Host{}

	if meta, ok := inventory["_meta"].(map[string]interface{}); ok {
		if hostvars, ok := meta["hostvars"].(map[string]interface{}); ok {
			for hostname, vars := range hostvars {
				if hostVars, ok := vars.(map[string]interface{}); ok {
					host := Host{
						ID:              hostname,
						Hostname:        hostname,
						Status:          "unknown",
						LastSeen:        time.Now(),
						AnsibleFacts:    hostVars,
						OsqueryEnrolled: false,
					}

					if ip, ok := hostVars["ansible_host"].(string); ok {
						host.IPAddress = ip
					}
					if os, ok := hostVars["ansible_os_family"].(string); ok {
						host.OperatingSystem = os
					}

					hosts = append(hosts, host)
				}
			}
		}
	}

	return hosts
}

// generateJobID creates a unique job identifier
func generateJobID() string {
	return fmt.Sprintf("job_%d", time.Now().UnixNano())
}
