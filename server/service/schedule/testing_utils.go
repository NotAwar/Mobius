package schedule

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/notawar/mobius/server/mobius"
)

type NopLocker struct{}

func (NopLocker) Lock(context.Context, string, string, time.Duration) (bool, error) {
	return true, nil
}

func (NopLocker) Unlock(context.Context, string, string) error {
	return nil
}

type NopStatsStore struct{}

func (NopStatsStore) GetLatestCronStats(ctx context.Context, name string) ([]mobius.CronStats, error) {
	return []mobius.CronStats{}, nil
}

func (NopStatsStore) InsertCronStats(ctx context.Context, statsType mobius.CronStatsType, name string, instance string, status mobius.CronStatsStatus) (int, error) {
	return 0, nil
}

func (NopStatsStore) UpdateCronStats(ctx context.Context, id int, status mobius.CronStatsStatus, cronErrors *mobius.CronScheduleErrors) error {
	return nil
}

func SetupMockLocker(name string, owner string, expiresAt time.Time) *MockLock {
	return &MockLock{name: name, owner: owner, expiresAt: expiresAt}
}

type MockLock struct {
	mu sync.Mutex

	name      string
	owner     string
	expiresAt time.Time

	Locked    chan struct{}
	LockCount int

	Unlocked    chan struct{}
	UnlockCount int
}

func (ml *MockLock) Lock(ctx context.Context, name string, owner string, expiration time.Duration) (bool, error) {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	if name != ml.name {
		return false, errors.New("name doesn't match")
	}

	now := time.Now()
	if ml.owner == owner || now.After(ml.expiresAt) {
		ml.owner = owner
		ml.expiresAt = now.Add(expiration)
		ml.LockCount++
		if ml.Locked != nil {
			ml.Locked <- struct{}{}
		}
		return true, nil
	}

	return false, nil
}

func (ml *MockLock) Unlock(ctx context.Context, name string, owner string) error {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	if name != ml.name {
		return errors.New("name doesn't match")
	}
	if owner != ml.owner {
		return errors.New("owner doesn't match")
	}
	ml.UnlockCount++
	if ml.Unlocked != nil {
		ml.Unlocked <- struct{}{}
	}
	ml.expiresAt = time.Now()
	return nil
}

func (ml *MockLock) GetLockCount() int {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	return ml.LockCount
}

func (ml *MockLock) GetExpiration() time.Time {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	return ml.expiresAt
}

func (ml *MockLock) AddChannels(t *testing.T, chanNames ...string) error {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	for _, n := range chanNames {
		switch n {
		case "locked":
			ml.Locked = make(chan struct{})
		case "unlocked":
			ml.Unlocked = make(chan struct{})
		default:
			t.Errorf("unrecognized channel name")
			t.FailNow()
		}
	}

	return nil
}

type MockStatsStore struct {
	sync.Mutex
	stats map[int]mobius.CronStats

	GetStatsCalled    chan struct{}
	InsertStatsCalled chan struct{}
	UpdateStatsCalled chan struct{}
}

func (m *MockStatsStore) GetLatestCronStats(ctx context.Context, name string) ([]mobius.CronStats, error) {
	m.Lock()
	defer m.Unlock()

	if m.GetStatsCalled != nil {
		m.GetStatsCalled <- struct{}{}
	}

	latest := make(map[mobius.CronStatsType]mobius.CronStats)
	for _, s := range m.stats {
		if s.Name != name {
			continue
		}
		curr := latest[s.StatsType]
		if s.CreatedAt.Before(curr.CreatedAt) {
			continue
		}
		latest[s.StatsType] = s
	}

	res := []mobius.CronStats{}
	if s, ok := latest[mobius.CronStatsTypeScheduled]; ok {
		res = append(res, s)
	}
	if s, ok := latest[mobius.CronStatsTypeTriggered]; ok {
		res = append(res, s)
	}

	return res, nil
}

func (m *MockStatsStore) InsertCronStats(ctx context.Context, statsType mobius.CronStatsType, name string, instance string, status mobius.CronStatsStatus) (int, error) {
	m.Lock()
	defer m.Unlock()

	if m.InsertStatsCalled != nil {
		m.InsertStatsCalled <- struct{}{}
	}

	id := len(m.stats) + 1
	m.stats[id] = mobius.CronStats{ID: id, StatsType: statsType, Name: name, Instance: instance, Status: status, CreatedAt: time.Now().Truncate(1 * time.Second), UpdatedAt: time.Now().Truncate(time.Second)}

	return id, nil
}

func (m *MockStatsStore) UpdateCronStats(ctx context.Context, id int, status mobius.CronStatsStatus, cronErrors *mobius.CronScheduleErrors) error {
	m.Lock()
	defer m.Unlock()

	if m.UpdateStatsCalled != nil {
		m.UpdateStatsCalled <- struct{}{}
	}

	s, ok := m.stats[id]
	if !ok {
		return errors.New("update failed, id not found")
	}
	s.Status = status
	s.UpdatedAt = time.Now().Truncate(1 * time.Second)
	m.stats[id] = s

	return nil
}

func (m *MockStatsStore) AddChannels(t *testing.T, chanNames ...string) error {
	m.Lock()
	defer m.Unlock()
	for _, n := range chanNames {
		switch n {
		case "GetStatsCalled":
			m.GetStatsCalled = make(chan struct{})
		case "InsertStatsCalled":
			m.InsertStatsCalled = make(chan struct{})
		case "UpdateStatsCalled":
			m.UpdateStatsCalled = make(chan struct{})
		default:
			t.Errorf("unrecognized channel name")
			t.FailNow()
		}
	}
	return nil
}

func SetUpMockStatsStore(name string, initialStats ...mobius.CronStats) *MockStatsStore {
	stats := make(map[int]mobius.CronStats)
	for _, s := range initialStats {
		stats[s.ID] = s
	}
	store := MockStatsStore{stats: stats}

	return &store
}
