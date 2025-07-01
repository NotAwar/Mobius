package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/mock"
	"github.com/notawar/mobius/v4/server/ptr"
	"github.com/notawar/mobius/v4/server/test"
	"github.com/stretchr/testify/require"
	"gopkg.in/guregu/null.v3"
)

type notTestFoundError struct{}

func (e *notTestFoundError) Error() string {
	return "not found"
}

func (e *notTestFoundError) IsNotFound() bool {
	return true
}

func newTestNotFoundError() *notTestFoundError {
	return &notTestFoundError{}
}

// Is is implemented so that errors.Is(err, sql.ErrNoRows) returns true for an
// error of type *notFoundError, without having to wrap sql.ErrNoRows
// explicitly.
func (e *notTestFoundError) Is(other error) bool {
	return other == sql.ErrNoRows
}

func TestMailService(t *testing.T) {
	// This mail test requires mailpit running on localhost:1026.
	if _, ok := os.LookupEnv("MAIL_TEST"); !ok {
		t.Skip("Mail tests are disabled")
	}

	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil, &TestServerOpts{
		UseMailService: true,
	})

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{
			SMTPSettings: &mobius.SMTPSettings{
				SMTPEnabled:              true,
				SMTPConfigured:           true,
				SMTPAuthenticationType:   mobius.AuthTypeNameUserNamePassword,
				SMTPAuthenticationMethod: mobius.AuthMethodNamePlain,
				SMTPUserName:             "mailpit-username",
				SMTPPassword:             "mailpit-password",
				SMTPEnableTLS:            false,
				SMTPVerifySSLCerts:       false,
				SMTPPort:                 1026,
				SMTPServer:               "localhost",
				SMTPSenderAddress:        "foobar@example.com",
			},
		}, nil
	}

	ds.UserByEmailFunc = func(ctx context.Context, email string) (*mobius.User, error) {
		return nil, newTestNotFoundError()
	}

	var invite *mobius.Invite
	ds.NewInviteFunc = func(ctx context.Context, i *mobius.Invite) (*mobius.Invite, error) {
		invite = i
		return invite, nil
	}

	ds.SaveAppConfigFunc = func(ctx context.Context, info *mobius.AppConfig) error {
		return nil
	}

	ds.InviteFunc = func(ctx context.Context, id uint) (*mobius.Invite, error) {
		return invite, nil
	}

	ds.SaveABMTokenFunc = func(ctx context.Context, tok *mobius.ABMToken) error {
		return nil
	}

	ds.ListVPPTokensFunc = func(ctx context.Context) ([]*mobius.VPPTokenDB, error) {
		return []*mobius.VPPTokenDB{}, nil
	}

	ds.ListABMTokensFunc = func(ctx context.Context) ([]*mobius.ABMToken, error) {
		return []*mobius.ABMToken{}, nil
	}

	ctx = test.UserContext(ctx, test.UserAdmin)

	// (1) Modifying the app config `sender_address` field to trigger a test e-mail send.
	_, err := svc.ModifyAppConfig(ctx, []byte(`{
  "org_info": {
	"org_name": "Acme"
  },
  "server_settings": {
	"server_url": "http://someurl"
  },
  "smtp_settings": {
    "enable_smtp": true,
    "configured": true,
    "authentication_type": "authtype_username_password",
    "authentication_method": "authmethod_plain",
    "user_name": "mailpit-username",
    "password": "mailpit-password",
    "enable_ssl_tls": false,
    "verify_ssl_certs": false,
    "port": 1026,
    "server": "127.0.0.1",
    "sender_address": "foobar_updated@example.com"
  }
}`), mobius.ApplySpecOptions{})
	require.NoError(t, err)

	getLastMailPitMessage := func() map[string]interface{} {
		resp, err := http.Get("http://localhost:8026/api/v1/messages?limit=1")
		require.NoError(t, err)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		var m map[string]interface{}
		err = json.Unmarshal(b, &m)
		require.NoError(t, err)
		require.NotNil(t, m["messages"])
		require.Len(t, m["messages"], 1)
		lm := (m["messages"]).([]interface{})[0]
		require.NotNil(t, lm)
		lastMessage := lm.(map[string]interface{})
		fmt.Printf("%+v\n", lastMessage)
		return lastMessage
	}

	lastMessage := getLastMailPitMessage()
	require.Equal(t, "Hello from Mobius", lastMessage["Subject"])

	// (2) Inviting a user should send an e-mail to join.
	_, err = svc.InviteNewUser(ctx, mobius.InvitePayload{
		Email:      ptr.String("foobar_recipient@example.com"),
		Name:       ptr.String("Foobar"),
		GlobalRole: null.NewString("observer", true),
	})
	require.NoError(t, err)

	lastMessage = getLastMailPitMessage()
	require.Equal(t, "You have been invited to Mobius!", lastMessage["Subject"])

	ds.UserByIDFunc = func(ctx context.Context, id uint) (*mobius.User, error) {
		if id == 1 {
			return test.UserAdmin, nil
		}
		return nil, newNotFoundError()
	}
	ds.InviteByEmailFunc = func(ctx context.Context, email string) (*mobius.Invite, error) {
		return nil, newTestNotFoundError()
	}
	ds.PendingEmailChangeFunc = func(ctx context.Context, userID uint, newEmail, token string) error {
		return nil
	}
	ds.SaveUserFunc = func(ctx context.Context, user *mobius.User) error {
		return nil
	}

	// (3) Changing e-mail address should send an e-mail for confirmation.
	_, err = svc.ModifyUser(ctx, 1, mobius.UserPayload{
		Email: ptr.String("useradmin_2@example.com"),
	})
	require.NoError(t, err)

	lastMessage = getLastMailPitMessage()
	require.Equal(t, "Confirm Mobius Email Change", lastMessage["Subject"])
}
