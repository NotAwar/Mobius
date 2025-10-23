package mobius

type GlobalSchedulePayload struct {
	GlobalSchedule []*ScheduledQuery `json:"global_schedule"`
}
