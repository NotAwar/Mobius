// Automatically generated by mockimpl. DO NOT EDIT!

package mock

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/notawar/mobius/server/mobius"
)

var _ mobius.MDMBootstrapPackageStore = (*MDMBootstrapPackageStore)(nil)

type GetFunc func(ctx context.Context, packageID string) (io.ReadCloser, int64, error)

type PutFunc func(ctx context.Context, packageID string, content io.ReadSeeker) error

type ExistsFunc func(ctx context.Context, packageID string) (bool, error)

type CleanupFunc func(ctx context.Context, usedPackageIDs []string, removeCreatedBefore time.Time) (int, error)

type SignFunc func(ctx context.Context, fileID string) (string, error)

type MDMBootstrapPackageStore struct {
	GetFunc        GetFunc
	GetFuncInvoked bool

	PutFunc        PutFunc
	PutFuncInvoked bool

	ExistsFunc        ExistsFunc
	ExistsFuncInvoked bool

	CleanupFunc        CleanupFunc
	CleanupFuncInvoked bool

	SignFunc        SignFunc
	SignFuncInvoked bool

	mu sync.Mutex
}

func (s *MDMBootstrapPackageStore) Get(ctx context.Context, packageID string) (io.ReadCloser, int64, error) {
	s.mu.Lock()
	s.GetFuncInvoked = true
	s.mu.Unlock()
	return s.GetFunc(ctx, packageID)
}

func (s *MDMBootstrapPackageStore) Put(ctx context.Context, packageID string, content io.ReadSeeker) error {
	s.mu.Lock()
	s.PutFuncInvoked = true
	s.mu.Unlock()
	return s.PutFunc(ctx, packageID, content)
}

func (s *MDMBootstrapPackageStore) Exists(ctx context.Context, packageID string) (bool, error) {
	s.mu.Lock()
	s.ExistsFuncInvoked = true
	s.mu.Unlock()
	return s.ExistsFunc(ctx, packageID)
}

func (s *MDMBootstrapPackageStore) Cleanup(ctx context.Context, usedPackageIDs []string, removeCreatedBefore time.Time) (int, error) {
	s.mu.Lock()
	s.CleanupFuncInvoked = true
	s.mu.Unlock()
	return s.CleanupFunc(ctx, usedPackageIDs, removeCreatedBefore)
}

func (s *MDMBootstrapPackageStore) Sign(ctx context.Context, fileID string) (string, error) {
	s.mu.Lock()
	s.SignFuncInvoked = true
	s.mu.Unlock()
	return s.SignFunc(ctx, fileID)
}
