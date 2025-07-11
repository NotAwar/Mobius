// Automatically generated by mockimpl. DO NOT EDIT!

package mock

import (
	"crypto/tls"
	"sync"

	"github.com/notawar/mobius/server/mdm/nanomdm/push"
)

var _ push.PushProviderFactory = (*APNSPushProviderFactory)(nil)

type NewPushProviderFunc func(p0 *tls.Certificate) (push.PushProvider, error)

type APNSPushProviderFactory struct {
	NewPushProviderFunc        NewPushProviderFunc
	NewPushProviderFuncInvoked bool

	mu sync.Mutex
}

func (s *APNSPushProviderFactory) NewPushProvider(p0 *tls.Certificate) (push.PushProvider, error) {
	s.mu.Lock()
	s.NewPushProviderFuncInvoked = true
	s.mu.Unlock()
	return s.NewPushProviderFunc(p0)
}
