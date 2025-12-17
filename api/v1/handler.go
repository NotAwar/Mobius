package v1

import (
	"mobius/pkg/services"

	"github.com/sirupsen/logrus"
)

// Handler handles HTTP requests for API v1
type Handler struct {
	logger           *logrus.Logger
	clusterService   services.ClusterService
	postgresService  services.PostgresService
	headscaleService services.HeadscaleService
}

// NewHandler creates a new v1 API handler
func NewHandler(
	logger *logrus.Logger,
	clusterService services.ClusterService,
	postgresService services.PostgresService,
	headscaleService services.HeadscaleService,
) *Handler {
	return &Handler{
		logger:           logger,
		clusterService:   clusterService,
		postgresService:  postgresService,
		headscaleService: headscaleService,
	}
}
