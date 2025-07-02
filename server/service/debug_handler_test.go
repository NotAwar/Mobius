package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/notawar/mobius/server/config"
	"github.com/notawar/mobius/server/mobius"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockService struct {
	mock.Mock
	mobius.Service
}

func (m *mockService) GetSessionByKey(ctx context.Context, sessionKey string) (*mobius.Session, error) {
	args := m.Called(ctx, sessionKey)
	if ret := args.Get(0); ret != nil {
		return ret.(*mobius.Session), nil
	}
	return nil, args.Error(1)
}

func (m *mockService) UserUnauthorized(ctx context.Context, userId uint) (*mobius.User, error) {
	args := m.Called(ctx, userId)
	if ret := args.Get(0); ret != nil {
		return ret.(*mobius.User), nil
	}
	return nil, args.Error(1)
}

var testConfig = config.MobiusConfig{
	Auth: config.AuthConfig{},
}

func TestDebugHandlerAuthenticationTokenMissing(t *testing.T) {
	handler := MakeDebugHandler(&mockService{}, testConfig, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "https://mobiusmdm.com/debug/pprof/profile", nil)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)
	assert.Equal(t, http.StatusUnauthorized, res.Code)
}

func TestDebugHandlerAuthenticationSessionInvalid(t *testing.T) {
	svc := &mockService{}
	svc.On(
		"GetSessionByKey",
		mock.Anything,
		"fake_session_key",
	).Return(nil, errors.New("invalid session"))

	handler := MakeDebugHandler(svc, testConfig, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "https://mobiusmdm.com/debug/pprof/profile", nil)
	req.Header.Add("Authorization", "BEARER fake_session_key")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)
	assert.Equal(t, http.StatusUnauthorized, res.Code)
}

func TestDebugHandlerAuthenticationSuccess(t *testing.T) {
	svc := &mockService{}
	svc.On(
		"GetSessionByKey",
		mock.Anything,
		"fake_session_key",
	).Return(&mobius.Session{UserID: 42, ID: 1}, nil)
	svc.On(
		"UserUnauthorized",
		mock.Anything,
		uint(42),
	).Return(&mobius.User{}, nil)

	handler := MakeDebugHandler(svc, testConfig, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "https://mobiusmdm.com/debug/pprof/cmdline", nil)
	req.Header.Add("Authorization", "BEARER fake_session_key")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)
	assert.Equal(t, http.StatusOK, res.Code)
}
