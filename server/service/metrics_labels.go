package service

import (
	"context"
	"fmt"
	"time"

	"github.com/notawar/mobius/server/mobius"
)

func (mw metricsMiddleware) ModifyLabel(ctx context.Context, id uint, p mobius.ModifyLabelPayload) (*mobius.Label, []uint, error) {
	var (
		lic  *mobius.Label
		hids []uint
		err  error
	)
	defer func(begin time.Time) {
		lvs := []string{"method", "ModifyLabel", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())
	lic, hids, err = mw.Service.ModifyLabel(ctx, id, p)
	return lic, hids, err
}
