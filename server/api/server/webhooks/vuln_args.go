package webhooks

import (
	"time"

	"github.com/MobiusDM/mobius/server/api/server/mobius"
)

type VulnArgs struct {
	Vulnerablities []mobius.SoftwareVulnerability
	Meta           map[string]mobius.CVEMeta
	AppConfig      *mobius.AppConfig
	Time           time.Time
}
