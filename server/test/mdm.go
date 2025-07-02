package test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/notawar/mobius/server/mobius"
	"github.com/stretchr/testify/require"
	"github.com/tj/assert"
)

func CreateVPPTokenData(expiration time.Time, orgName, location string) (*mobius.VPPTokenData, error) {
	var randBytes [32]byte
	_, err := rand.Read(randBytes[:])
	if err != nil {
		return nil, fmt.Errorf("generating random bytes: %w", err)
	}
	token := base64.StdEncoding.EncodeToString(randBytes[:])
	raw := mobius.VPPTokenRaw{
		OrgName: orgName,
		Token:   token,
		ExpDate: expiration.Format("2006-01-02T15:04:05Z0700"),
	}
	rawJson, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshalling vpp raw token: %w", err)
	}

	base64Token := base64.StdEncoding.EncodeToString(rawJson)
	return &mobius.VPPTokenData{Token: base64Token, Location: location}, nil
}

func CreateInsertGlobalVPPToken(t *testing.T, ds mobius.Datastore) *mobius.VPPTokenDB {
	ctx := context.Background()
	dataToken, err := CreateVPPTokenData(time.Now().Add(24*time.Hour), "Donkey Kong", "Jungle")
	require.NoError(t, err)
	tok1, err := ds.InsertVPPToken(ctx, dataToken)
	assert.NoError(t, err)
	tok1New, err := ds.UpdateVPPTokenTeams(ctx, tok1.ID, []uint{})
	assert.NoError(t, err)

	return tok1New
}

func CreateVPPTokenEncoded(expiration time.Time, orgName, location string) ([]byte, error) {
	dataToken, err := CreateVPPTokenData(expiration, orgName, location)
	if err != nil {
		return nil, err
	}
	return []byte(dataToken.Token), nil
}

func CreateVPPTokenEncodedAfterMigration(expiration time.Time, orgName, location string) ([]byte, error) {
	dataToken, err := CreateVPPTokenData(expiration, orgName, location)
	if err != nil {
		return nil, err
	}

	dataTokenJson, err := json.Marshal(dataToken)
	if err != nil {
		return nil, fmt.Errorf("marshalling vpp data token: %w", err)
	}
	return dataTokenJson, nil
}

func GenerateMDMAppleProfile(ident, displayName, uuid string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array/>
	<key>PayloadIdentifier</key>
	<string>%s</string>
	<key>PayloadDisplayName</key>
	<string>%s</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, ident, displayName, uuid)
}

func ToMDMAppleConfigProfile(p *mobius.MDMConfigProfilePayload) *mobius.MDMAppleConfigProfile {
	return &mobius.MDMAppleConfigProfile{
		Identifier:   p.Identifier,
		Name:         p.Name,
		ProfileUUID:  p.ProfileUUID,
		Mobileconfig: p.Checksum, // not important for the test
	}
}

func ToMDMWindowsConfigProfile(p *mobius.MDMConfigProfilePayload) *mobius.MDMWindowsConfigProfile {
	return &mobius.MDMWindowsConfigProfile{
		Name:        p.Name,
		SyncML:      p.Checksum, // not important for the test
		ProfileUUID: p.ProfileUUID,
	}
}

func ToMDMAppleDecl(p *mobius.MDMConfigProfilePayload) *mobius.MDMAppleDeclaration {
	return &mobius.MDMAppleDeclaration{
		Name:            p.Name,
		Identifier:      p.Identifier,
		DeclarationUUID: p.ProfileUUID,
	}
}
