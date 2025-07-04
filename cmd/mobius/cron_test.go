package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/notawar/mobius/server/datastore/mysql"
	"github.com/notawar/mobius/server/mobius"
	apple_mdm "github.com/notawar/mobius/server/mdm/apple"
	nanodep_client "github.com/notawar/mobius/server/mdm/nanodep/client"
	"github.com/notawar/mobius/server/mdm/nanodep/godep"
	"github.com/notawar/mobius/server/mock"
	mdmmock "github.com/notawar/mobius/server/mock/mdm"
	"github.com/notawar/mobius/server/test"
	"github.com/go-kit/log"
	kitlog "github.com/go-kit/log"
)

func TestNewAppleMDMProfileManagerWithoutConfig(t *testing.T) {
	ctx := context.Background()
	mdmStorage := &mdmmock.MDMAppleStore{}
	ds := new(mock.Store)
	cmdr := apple_mdm.NewMDMAppleCommander(mdmStorage, nil)
	logger := kitlog.NewNopLogger()

	sch, err := newAppleMDMProfileManagerSchedule(ctx, "foo", ds, cmdr, logger)
	require.NotNil(t, sch)
	require.NoError(t, err)
}

func TestNewWindowsMDMProfileManagerWithoutConfig(t *testing.T) {
	ctx := context.Background()
	ds := new(mock.Store)
	logger := kitlog.NewNopLogger()

	sch, err := newWindowsMDMProfileManagerSchedule(ctx, "foo", ds, logger)
	require.NotNil(t, sch)
	require.NoError(t, err)
}

func TestMigrateABMTokenDuringDEPCronJob(t *testing.T) {
	ctx := context.Background()
	ds := mysql.CreateMySQLDS(t)

	depStorage, err := ds.NewMDMAppleDEPStorage()
	require.NoError(t, err)
	// to avoid issues with syncer, use that constant as org name for now
	const tokenOrgName = "mobius"

	// insert an ABM token as if it had been migrated by the DB migration script
	tok := mysql.SetTestABMAssets(t, ds, "")
	// tok, err := ds.InsertABMToken(ctx, &mobius.ABMToken{EncryptedToken: abmToken, RenewAt: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)})
	// require.NoError(t, err)
	require.Empty(t, tok.OrganizationName)

	// start a server that will mock the Apple DEP API
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		encoder := json.NewEncoder(w)
		switch r.URL.Path {
		case "/session":
			_, _ = w.Write([]byte(`{"auth_session_token": "session123"}`))
		case "/account":
			_, _ = w.Write([]byte(fmt.Sprintf(`{"admin_id": "admin123", "org_name": "%s"}`, tokenOrgName)))
		case "/profile":
			err := encoder.Encode(godep.ProfileResponse{ProfileUUID: "profile123"})
			require.NoError(t, err)
		case "/server/devices":
			err := encoder.Encode(godep.DeviceResponse{Devices: nil})
			require.NoError(t, err)
		case "/devices/sync":
			err := encoder.Encode(godep.DeviceResponse{Devices: nil})
			require.NoError(t, err)
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	err = depStorage.StoreConfig(ctx, tokenOrgName, &nanodep_client.Config{BaseURL: srv.URL})
	require.NoError(t, err)
	err = depStorage.StoreConfig(ctx, apple_mdm.UnsavedABMTokenOrgName, &nanodep_client.Config{BaseURL: srv.URL})
	require.NoError(t, err)

	logger := log.NewNopLogger()
	syncFn := appleMDMDEPSyncerJob(ds, depStorage, logger)
	err = syncFn(ctx)
	require.NoError(t, err)

	// token has been updated with its org name/apple id
	tok, err = ds.GetABMTokenByOrgName(ctx, tokenOrgName)
	require.NoError(t, err)
	require.Equal(t, tokenOrgName, tok.OrganizationName)
	require.Equal(t, "admin123", tok.AppleID)
	require.Nil(t, tok.MacOSDefaultTeamID)
	require.Nil(t, tok.IOSDefaultTeamID)
	require.Nil(t, tok.IPadOSDefaultTeamID)

	// empty-name token does not exist anymore
	_, err = ds.GetABMTokenByOrgName(ctx, "")
	require.Error(t, err)
	var nfe mobius.NotFoundError
	require.ErrorAs(t, err, &nfe)

	// the default profile was created
	defProf, err := ds.GetMDMAppleEnrollmentProfileByType(ctx, mobius.MDMAppleEnrollmentTypeAutomatic)
	require.NoError(t, err)
	require.NotNil(t, defProf)
	require.NotEmpty(t, defProf.Token)

	// no profile UUID was assigned for no-team (because there are no hosts right now)
	_, _, err = ds.GetMDMAppleDefaultSetupAssistant(ctx, nil, "")
	require.Error(t, err)
	require.ErrorAs(t, err, &nfe)

	// no teams, so no team-specific custom setup assistants
	teams, err := ds.ListTeams(ctx, mobius.TeamFilter{User: test.UserAdmin}, mobius.ListOptions{})
	require.NoError(t, err)
	require.Empty(t, teams)

	// no no-team custom setup assistant
	_, err = ds.GetMDMAppleSetupAssistant(ctx, nil)
	require.ErrorIs(t, err, sql.ErrNoRows)

	// no host got created
	hosts, err := ds.ListHosts(ctx, mobius.TeamFilter{User: test.UserAdmin}, mobius.HostListOptions{})
	require.NoError(t, err)
	require.Empty(t, hosts)
}
