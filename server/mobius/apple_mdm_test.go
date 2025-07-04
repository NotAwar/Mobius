package mobius

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/notawar/mobius/server/mdm"
	"github.com/notawar/mobius/server/mdm/apple/mobileconfig"
	"github.com/notawar/mobius/server/mdm/scep/depot"
	"github.com/notawar/mobius/server/ptr"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/smallstep/pkcs7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMDMAppleConfigProfile(t *testing.T) {
	cases := []struct {
		testName     string
		mobileconfig mobileconfig.Mobileconfig
		shouldFail   bool
	}{
		{
			testName:     "TestParseConfigProfileOK",
			mobileconfig: MobileconfigForTest("ValidName", "ValidIdentifier", uuid.NewString(), ""),
			shouldFail:   false,
		},
		{
			testName:     "TestParseConfigProfileLeadingSpace",
			mobileconfig: append([]byte{' '}, []byte(MobileconfigForTest("ValidName", "ValidIdentifier", uuid.NewString(), ""))...),
			shouldFail:   false,
		},
		{
			testName:     "TestParseConfigProfileNoIdentifier",
			mobileconfig: MobileconfigForTest("ValidName", "", uuid.NewString(), ""),
			shouldFail:   true,
		},
		{
			testName:     "TestParseConfigProfileNoName",
			mobileconfig: MobileconfigForTest("", "ValidIdentifier", uuid.NewString(), ""),
			shouldFail:   true,
		},
		{
			testName:     "TestParseConfigProfileNoNameNoIdentifier",
			mobileconfig: MobileconfigForTest("", "", uuid.NewString(), ""),
			shouldFail:   true,
		},
		{
			testName: "TestParseConfigProfileInvalidEncoding",
			mobileconfig: func() []byte {
				b, err := json.Marshal(MDMAppleConfigProfile{Name: "ValidName", Identifier: "ValidIdentifier"})
				require.NoError(t, err)
				return b
			}(),
			shouldFail: true,
		},
		{
			testName: "TestParseConfigProfilePKCS7Encoding",
			mobileconfig: func() []byte {
				// generate certificate for signed data test
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				crtBytes, err := depot.NewCACert().SelfSign(rand.Reader, key.Public(), key)
				require.NoError(t, err)
				crt, err := x509.ParseCertificate(crtBytes)
				require.NoError(t, err)

				// encode mobileconfig as PKCS7 signed data
				signedData, err := pkcs7.NewSignedData(MobileconfigForTest("ValidName", "ValidIdentifier", uuid.NewString(), ""))
				require.NoError(t, err)
				err = signedData.AddSigner(crt, key, pkcs7.SignerInfoConfig{})
				require.NoError(t, err)
				signedBytes, err := signedData.Finish()
				require.NoError(t, err)
				p7, err := pkcs7.Parse(signedBytes)
				require.NoError(t, err)
				require.NoError(t, p7.Verify())

				return signedBytes
			}(),
			shouldFail: false,
		},
	}

	for _, c := range cases {
		t.Run(c.testName, func(t *testing.T) {
			parsed, err := NewMDMAppleConfigProfile(c.mobileconfig, nil)
			if c.shouldFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, "ValidName", parsed.Name)
				require.Equal(t, "ValidIdentifier", parsed.Identifier)
			}
		})
	}
}

func TestMDMAppleConfigProfileScreenPayloadContent(t *testing.T) {
	cases := []struct {
		testName     string
		payloadTypes []string
		shouldFail   []string
	}{
		{
			testName:     "AllFileVaultScreened",
			payloadTypes: []string{"com.apple.security.FDERecoveryKeyEscrow", "com.apple.MCX.FileVault2", "com.apple.security.FDERecoveryRedirect"},
			shouldFail:   []string{mobileconfig.DiskEncryptionProfileRestrictionErrMsg},
		},
		{
			testName:     "FileVault2Screened",
			payloadTypes: []string{"com.apple.security.firewall", "com.apple.MCX.FileVault2"},
			shouldFail:   []string{mobileconfig.DiskEncryptionProfileRestrictionErrMsg},
		},
		{
			testName:     "FDERecoveryKeyEscrowScreened",
			payloadTypes: []string{"com.apple.security.FDERecoveryKeyEscrow"},
			shouldFail:   []string{mobileconfig.DiskEncryptionProfileRestrictionErrMsg},
		},
		{
			testName:     "FDERecoveryRedirectScreened",
			payloadTypes: []string{"com.apple.security.FDERecoveryRedirect"},
			shouldFail:   []string{"com.apple.security.FDERecoveryRedirect"},
		},
		{
			testName:     "OtherPayloadTypesOK",
			payloadTypes: []string{"com.apple.security.firewall", "com.apple.MCX"},
			shouldFail:   nil,
		},
		{
			testName:     "FileVaultMixedWithOtherPayloadTypes",
			payloadTypes: []string{"com.apple.MCX.FileVault2", "com.apple.security.firewall", "com.apple.security.FDERecoveryKeyEscrow", "com.apple.MCX"},
			shouldFail:   []string{mobileconfig.DiskEncryptionProfileRestrictionErrMsg},
		},
		{
			testName:     "NoPayloadContent",
			payloadTypes: nil,
			shouldFail:   nil,
		},
	}

	for _, c := range cases {
		t.Run(c.testName, func(t *testing.T) {
			mc := MobileconfigForTest("ValidName", "ValidIdentifier", uuid.NewString(), mcPayloadContentForTest(c.payloadTypes))
			parsed, err := NewMDMAppleConfigProfile(mc, nil)
			require.NoError(t, err)
			require.Equal(t, "ValidName", parsed.Name)
			require.Equal(t, "ValidIdentifier", parsed.Identifier)

			err = parsed.ValidateUserProvided()
			for _, pt := range c.shouldFail {
				require.Error(t, err)
				require.ErrorContains(t, err, pt)
			}
			if len(c.shouldFail) == 0 {
				require.NoError(t, err)
			}
		})
	}
}

func TestMDMAppleConfigProfileScreenPayloadIdentifiers(t *testing.T) {
	cases := []struct {
		testName           string
		payloadIdentifiers []string
		shouldFail         []string
	}{
		{
			testName:           "AllMobiusProfilesScreened",
			payloadIdentifiers: []string{"com.mobiusmdm.mobius.mdm.filevault", "com.mobiusmdm.mobiusdaemon.config"},
			shouldFail:         []string{"com.mobiusmdm.mobius.mdm.filevault", "com.mobiusmdm.mobiusdaemon.config"},
		},
		{
			testName:           "FileVault",
			payloadIdentifiers: []string{"com.mobiusmdm.mobius.mdm.filevault"},
			shouldFail:         []string{"com.mobiusmdm.mobius.mdm.filevault"},
		},
		{
			testName:           "Mobiusd config",
			payloadIdentifiers: []string{"com.mobiusmdm.mobiusdaemon.config"},
			shouldFail:         []string{"com.mobiusmdm.mobiusdaemon.config"},
		},
		{
			testName:           "OtherPayloadTypesOK",
			payloadIdentifiers: []string{"com.my.custom.profile", "com.test.example"},
			shouldFail:         nil,
		},
		{
			testName:           "Mixed",
			payloadIdentifiers: []string{"com.mobiusmdm.mobius.mdm.filevault", "com.my.custom.profile", "com.test.example"},
			shouldFail:         []string{"com.mobiusmdm.mobius.mdm.filevault"},
		},
		{
			testName:           "NoPayloadContent",
			payloadIdentifiers: nil,
			shouldFail:         nil,
		},
	}

	for _, c := range cases {
		t.Run(c.testName, func(t *testing.T) {
			mc := MobileconfigForTest("ValidName", "ValidIdentifier", uuid.NewString(), mcPayloadContentForTest(c.payloadIdentifiers))
			parsed, err := NewMDMAppleConfigProfile(mc, nil)
			require.NoError(t, err)
			require.Equal(t, "ValidName", parsed.Name)
			require.Equal(t, "ValidIdentifier", parsed.Identifier)

			err = parsed.ValidateUserProvided()
			for _, pt := range c.shouldFail {
				require.Error(t, err)
				require.ErrorContains(t, err, pt)
			}
		})
	}
}

func TestMDMAppleConfigProfileScreenReservedNames(t *testing.T) {
	type testcase struct {
		toplevelName string
		contentName  string
		shouldFail   bool
	}
	cases := []testcase{
		{"unreserved name", "unreserved name", false},
	}
	mobiusNames := mdm.MobiusReservedProfileNames()
	for name := range mobiusNames {
		cases = append(cases, testcase{name, "unreserved name", true})
		cases = append(cases, testcase{"unreserved name", name, true})
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%s-%s", c.toplevelName, c.contentName), func(t *testing.T) {
			payloadContent := fmt.Sprintf(`
				<dict>
					<key>PayloadDisplayName</key>
					<string>%s</string>
					<key>PayloadIdentifier</key>
					<string>ValidIdentitifer</string>
					<key>PayloadType</key>
					<string>ValidType</string>
					<key>PayloadUUID</key>
					<string>%s</string>
					<key>PayloadVersion</key>
					<integer>1</integer>
				</dict>`, c.contentName, uuid.NewString())

			mc := MobileconfigForTest(c.toplevelName, "ValidIdentifier", uuid.NewString(), payloadContent)
			parsed, err := NewMDMAppleConfigProfile(mc, nil)
			require.NoError(t, err)
			require.Equal(t, c.toplevelName, parsed.Name)
			require.Equal(t, "ValidIdentifier", parsed.Identifier)

			err = parsed.ValidateUserProvided()
			if c.shouldFail {
				require.Error(t, err)
				if c.toplevelName == "unreserved name" {
					require.ErrorContains(t, err, c.contentName)
				} else {
					require.ErrorContains(t, err, c.toplevelName)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func MobileconfigForTest(name string, identifier string, uuid string, payloadContent string) mobileconfig.Mobileconfig {
	pc := "<array/>"
	if payloadContent != "" {
		pc = fmt.Sprintf(`<array>%s
	</array>`, payloadContent)
	}
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	%s
	<key>PayloadDisplayName</key>
	<string>%s</string>
	<key>PayloadIdentifier</key>
	<string>%s</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, pc, name, identifier, uuid))
}

func mcPayloadContentForTest(refs []string) string {
	formatted := ""
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		ss := strings.Split(ref, ".")
		uuid := uuid.New()
		formatted += fmt.Sprintf(`
		<dict>
			<key>PayloadDisplayName</key>
			<string>%s</string>
			<key>PayloadIdentifier</key>
			<string>%s</string>
			<key>PayloadType</key>
			<string>%s</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>`, ss[len(ss)-1], ref, ref, uuid)
	}

	return formatted
}

func TestHostDEPAssignment(t *testing.T) {
	cases := []struct {
		testName string
		input    HostDEPAssignment
		expect   bool
	}{
		{
			testName: "assigned to Mobius",
			input: HostDEPAssignment{
				HostID:    1,
				AddedAt:   time.Now(),
				DeletedAt: nil,
			},
			expect: true,
		},
		{
			testName: "was assigned Mobius but now deleted",
			input: HostDEPAssignment{
				HostID:    1,
				AddedAt:   time.Now(),
				DeletedAt: ptr.Time(time.Now()),
			},
			expect: false,
		},
		{
			testName: "empty struct",
			input:    HostDEPAssignment{},
			expect:   false,
		},
		{
			testName: "empty added at",
			input: HostDEPAssignment{
				HostID: 1,
			},
			expect: false,
		},
	}

	for _, c := range cases {
		t.Run(c.testName, func(t *testing.T) {
			require.Equal(t, c.expect, c.input.IsDEPAssignedToMobius())
		})
	}
}

func TestMDMProfileIsWithinGracePeriod(t *testing.T) {
	// create a test profile
	var b bytes.Buffer
	params := mobileconfig.MobiusdProfileOptions{
		EnrollSecret: t.Name(),
		ServerURL:    "https://example.com",
		PayloadType:  mobileconfig.MobiusdConfigPayloadIdentifier,
		PayloadName:  mdm.MobiusdConfigProfileName,
	}
	err := mobileconfig.MobiusdProfileTemplate.Execute(&b, params)
	require.NoError(t, err)
	testProfile, err := NewMDMAppleConfigProfile(b.Bytes(), nil)
	require.NoError(t, err)

	// set profile updated at 2 hours ago
	testProfile.UploadedAt = time.Now().Truncate(time.Second).Add(-2 * time.Hour)
	// set profile created at 24 hours ago (irrelevant but included for completeness)
	testProfile.CreatedAt = testProfile.UploadedAt.Add(-24 * time.Hour)

	cases := []struct {
		testName            string
		hostDetailUpdatedAt time.Time
		expect              bool
	}{
		{
			testName:            "outside grace period",
			hostDetailUpdatedAt: testProfile.UploadedAt.Add(61 * time.Minute), // more than 1 hour grace period
			expect:              false,
		},
		{
			testName:            "online host within grace period",
			hostDetailUpdatedAt: testProfile.UploadedAt.Add(59 * time.Minute), // less than 1 hour grace period
			expect:              true,
		},
		{
			testName:            "offline host within grace period",
			hostDetailUpdatedAt: testProfile.UploadedAt.Add(-48 * time.Hour), // grace period doesn't start until host is online (i.e. host detail updated at is after profile updated at)
			expect:              true,
		},
	}

	for _, c := range cases {
		t.Run(c.testName, func(t *testing.T) {
			ep := ExpectedMDMProfile{Identifier: testProfile.Identifier, EarliestInstallDate: testProfile.UploadedAt}
			require.Equal(t, c.expect, ep.IsWithinGracePeriod(c.hostDetailUpdatedAt))
		})
	}
}

func TestMDMAppleHostDeclarationEqual(t *testing.T) {
	t.Parallel()

	// This test is intended to ensure that the Equal method on MDMAppleHostDeclaration is updated when new fields are added.
	// The Equal method is used to identify whether database update is needed.

	items := [...]MDMAppleHostDeclaration{{}, {}}

	numberOfFields := 0
	for i := 0; i < len(items); i++ {
		rValue := reflect.ValueOf(&items[i]).Elem()
		numberOfFields = rValue.NumField()
		for j := 0; j < numberOfFields; j++ {
			field := rValue.Field(j)
			switch field.Kind() {
			case reflect.String:
				valueToSet := fmt.Sprintf("test %d", i)
				field.SetString(valueToSet)
			case reflect.Int:
				field.SetInt(int64(i))
			case reflect.Bool:
				field.SetBool(i%2 == 0)
			case reflect.Pointer:
				field.Set(reflect.New(field.Type().Elem()))
			default:
				t.Fatalf("unhandled field type %s", field.Kind())
			}
		}
	}

	status0 := MDMDeliveryStatus("status")
	status1 := MDMDeliveryStatus("status")
	items[0].Status = &status0
	assert.False(t, items[0].Equal(items[1]))

	// Set known fields to be equal
	fieldsInEqualMethod := 0
	items[1].HostUUID = items[0].HostUUID
	fieldsInEqualMethod++
	items[1].DeclarationUUID = items[0].DeclarationUUID
	fieldsInEqualMethod++
	items[1].Name = items[0].Name
	fieldsInEqualMethod++
	items[1].Identifier = items[0].Identifier
	fieldsInEqualMethod++
	items[1].OperationType = items[0].OperationType
	fieldsInEqualMethod++
	items[1].Detail = items[0].Detail
	fieldsInEqualMethod++
	items[1].Token = items[0].Token
	fieldsInEqualMethod++
	items[1].Status = &status1
	fieldsInEqualMethod++
	items[1].SecretsUpdatedAt = items[0].SecretsUpdatedAt
	fieldsInEqualMethod++
	assert.Equal(t, fieldsInEqualMethod, numberOfFields, "MDMAppleHostDeclaration.Equal needs to be updated for new/updated field(s)")
	assert.True(t, items[0].Equal(items[1]))

	// Set pointers to nil
	items[0].Status = nil
	items[1].Status = nil
	assert.True(t, items[0].Equal(items[1]))
}

func TestMDMManagedCertificateEqual(t *testing.T) {
	t.Parallel()

	// Create two different time values for testing
	now := time.Now().Truncate(time.Second)
	later := now.Add(1 * time.Hour)

	// Create a serial string for testing
	serial1 := "serial1"
	serial2 := "serial2"

	// Create two instances with different values for all fields
	cert1 := MDMManagedCertificate{
		ProfileUUID:          "profile1",
		HostUUID:             "host1",
		ChallengeRetrievedAt: &now,
		NotValidBefore:       &now,
		NotValidAfter:        &later,
		Type:                 "type1",
		CAName:               "ca1",
		Serial:               &serial1,
	}

	cert2 := MDMManagedCertificate{
		ProfileUUID:          "profile2",
		HostUUID:             "host2",
		ChallengeRetrievedAt: &later,
		NotValidBefore:       &later,
		NotValidAfter:        &now,
		Type:                 "type2",
		CAName:               "ca2",
		Serial:               &serial2,
	}

	// Initial assertion - should not be equal
	assert.False(t, cert1.Equal(cert2))

	// Make fields equal one by one and test
	cert2.ProfileUUID = cert1.ProfileUUID
	assert.False(t, cert1.Equal(cert2))

	cert2.HostUUID = cert1.HostUUID
	assert.False(t, cert1.Equal(cert2))

	cert2.Type = cert1.Type
	assert.False(t, cert1.Equal(cert2))

	cert2.CAName = cert1.CAName
	assert.False(t, cert1.Equal(cert2))

	// Make time pointers equal
	cert2.ChallengeRetrievedAt = cert1.ChallengeRetrievedAt
	assert.False(t, cert1.Equal(cert2))

	cert2.NotValidBefore = cert1.NotValidBefore
	assert.False(t, cert1.Equal(cert2))

	cert2.NotValidAfter = cert1.NotValidAfter
	assert.False(t, cert1.Equal(cert2))

	// Make serial equal
	cert2.Serial = cert1.Serial
	assert.True(t, cert1.Equal(cert2))

	// Test nil pointer scenarios
	cert1.ChallengeRetrievedAt = nil
	assert.False(t, cert1.Equal(cert2))
	cert2.ChallengeRetrievedAt = nil
	assert.True(t, cert1.Equal(cert2))

	cert1.NotValidBefore = nil
	assert.False(t, cert1.Equal(cert2))
	cert2.NotValidBefore = nil
	assert.True(t, cert1.Equal(cert2))

	cert1.NotValidAfter = nil
	assert.False(t, cert1.Equal(cert2))
	cert2.NotValidAfter = nil
	assert.True(t, cert1.Equal(cert2))

	cert1.Serial = nil
	assert.False(t, cert1.Equal(cert2))
	cert2.Serial = nil
	assert.True(t, cert1.Equal(cert2))

	// Test time fields with same value but different memory addresses
	time1 := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	time2 := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)

	// Verify these are different objects with the same value
	assert.NotSame(t, &time1, &time2)
	assert.True(t, time1.Equal(time2))

	cert1.ChallengeRetrievedAt = &time1
	cert2.ChallengeRetrievedAt = &time2
	assert.True(t, cert1.Equal(cert2))

	cert1.NotValidBefore = &time1
	cert2.NotValidBefore = &time2
	assert.True(t, cert1.Equal(cert2))

	cert1.NotValidAfter = &time1
	cert2.NotValidAfter = &time2
	assert.True(t, cert1.Equal(cert2))

	// Test serial with same value but different memory addresses
	serialStr1 := "same-serial"
	serialStr2 := "same-serial"
	assert.NotSame(t, &serialStr1, &serialStr2)

	cert1.Serial = &serialStr1
	cert2.Serial = &serialStr2
	assert.True(t, cert1.Equal(cert2))
}

func TestConfigurationProfileLabelEqual(t *testing.T) {
	t.Parallel()

	// This test is intended to ensure that the cmp.Equal method on ConfigurationProfileLabel is updated when new fields are added.
	// The cmp.Equal method is used to identify whether database update is needed.

	items := [...]ConfigurationProfileLabel{{}, {}}

	numberOfFields := 0
	for i := 0; i < len(items); i++ {
		rValue := reflect.ValueOf(&items[i]).Elem()
		numberOfFields = rValue.NumField()
		for j := 0; j < numberOfFields; j++ {
			field := rValue.Field(j)
			switch field.Kind() {
			case reflect.String:
				valueToSet := fmt.Sprintf("test %d", i)
				field.SetString(valueToSet)
			case reflect.Int:
				field.SetInt(int64(i))
			case reflect.Uint:
				field.SetUint(uint64(i))
			case reflect.Bool:
				field.SetBool(i%2 == 0)
			case reflect.Pointer:
				field.Set(reflect.New(field.Type().Elem()))
			default:
				t.Fatalf("unhandled field type %s", field.Kind())
			}
		}
	}

	assert.False(t, cmp.Equal(items[0], items[1]))

	// Set known fields to be equal
	fieldsInEqualMethod := 0
	items[1].ProfileUUID = items[0].ProfileUUID
	fieldsInEqualMethod++
	items[1].LabelName = items[0].LabelName
	fieldsInEqualMethod++
	items[1].LabelID = items[0].LabelID
	fieldsInEqualMethod++
	items[1].Broken = items[0].Broken
	fieldsInEqualMethod++
	items[1].Exclude = items[0].Exclude
	fieldsInEqualMethod++
	items[1].RequireAll = items[0].RequireAll
	fieldsInEqualMethod++

	assert.Equal(t, fieldsInEqualMethod, numberOfFields,
		"Does cmp.Equal for ConfigurationProfileLabel needs to be updated for new/updated field(s)?")
	assert.True(t, cmp.Equal(items[0], items[1]))
}
