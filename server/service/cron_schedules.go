package service

import (
	"context"

	"github.com/notawar/mobius/server/mobius"
)

// TriggerCronSchedule attempts to trigger an ad-hoc run of the named cron schedule.
func (svc *Service) TriggerCronSchedule(ctx context.Context, name string) error {
	if err := svc.authz.Authorize(ctx, &mobius.CronSchedules{}, mobius.ActionWrite); err != nil {
		return err
	}
	return svc.cronSchedulesService.TriggerCronSchedule(name)
}
