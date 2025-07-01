package service

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/notawar/mobius/v4/server/config"
	"github.com/notawar/mobius/v4/server/mobius"
	"github.com/notawar/mobius/v4/server/mock"
	"github.com/notawar/mobius/v4/server/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanupURL(t *testing.T) {
	tests := []struct {
		in       string
		expected string
		name     string
	}{
		{"  http://foo.bar.com  ", "http://foo.bar.com", "leading and trailing whitespace"},
		{"\n http://foo.com \t", "http://foo.com", "whitespace"},
		{"http://foo.com", "http://foo.com", "noop"},
		{"http://foo.com/", "http://foo.com", "trailing slash"},
	}
	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			actual := cleanupURL(test.in)
			assert.Equal(tt, test.expected, actual)
		})
	}
}

func TestCreateAppConfig(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}

	appConfigTests := []struct {
		configPayload mobius.AppConfig
	}{
		{
			configPayload: mobius.AppConfig{
				OrgInfo: mobius.OrgInfo{
					OrgLogoURL: "acme.co/images/logo.png",
					OrgName:    "Acme",
				},
				ServerSettings: mobius.ServerSettings{
					ServerURL:         "https://acme.co:8080/",
					LiveQueryDisabled: true,
				},
			},
		},
	}

	for _, tt := range appConfigTests {
		var result *mobius.AppConfig
		ds.NewAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) (*mobius.AppConfig, error) {
			result = config
			return config, nil
		}

		var gotSecrets []*mobius.EnrollSecret
		ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
			gotSecrets = secrets
			return nil
		}

		ctx = test.UserContext(ctx, test.UserAdmin)
		_, err := svc.NewAppConfig(ctx, tt.configPayload)
		require.Nil(t, err)

		payload := tt.configPayload
		assert.Equal(t, payload.OrgInfo.OrgLogoURL, result.OrgInfo.OrgLogoURL)
		assert.Equal(t, payload.OrgInfo.OrgName, result.OrgInfo.OrgName)
		assert.Equal(t, "https://acme.co:8080/", result.ServerSettings.ServerURL)
		assert.Equal(t, payload.ServerSettings.LiveQueryDisabled, result.ServerSettings.LiveQueryDisabled)

		// Ensure enroll secret was set
		require.NotNil(t, gotSecrets)
		require.Len(t, gotSecrets, 1)
		assert.Len(t, gotSecrets[0].Secret, 32)
	}
}

func TestEmptyEnrollSecret(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
		return nil
	}
	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return &mobius.AppConfig{}, nil
	}

	err := svc.ApplyEnrollSecretSpec(
		test.UserContext(ctx, test.UserAdmin),
		&mobius.EnrollSecretSpec{
			Secrets: []*mobius.EnrollSecret{{}},
		},
		mobius.ApplySpecOptions{},
	)
	require.Error(t, err)

	err = svc.ApplyEnrollSecretSpec(
		test.UserContext(ctx, test.UserAdmin),
		&mobius.EnrollSecretSpec{Secrets: []*mobius.EnrollSecret{{Secret: ""}}},
		mobius.ApplySpecOptions{},
	)
	require.Error(t, err, "empty secret should be disallowed")

	err = svc.ApplyEnrollSecretSpec(
		test.UserContext(ctx, test.UserAdmin),
		&mobius.EnrollSecretSpec{
			Secrets: []*mobius.EnrollSecret{{Secret: "foo"}},
		},
		mobius.ApplySpecOptions{},
	)
	require.NoError(t, err)
}

func TestNewAppConfigWithGlobalEnrollConfig(t *testing.T) {
	ds := new(mock.Store)
	cfg := config.TestConfig()
	cfg.Packaging.GlobalEnrollSecret = "xyz"
	svc, ctx := newTestServiceWithConfig(t, ds, cfg, nil, nil)

	ds.NewAppConfigFunc = func(ctx context.Context, config *mobius.AppConfig) (*mobius.AppConfig, error) {
		return config, nil
	}

	var gotSecrets []*mobius.EnrollSecret
	ds.ApplyEnrollSecretsFunc = func(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
		gotSecrets = secrets
		return nil
	}

	ctx = test.UserContext(ctx, test.UserAdmin)
	_, err := svc.NewAppConfig(ctx, mobius.AppConfig{ServerSettings: mobius.ServerSettings{ServerURL: "https://acme.co"}})
	require.NoError(t, err)
	require.NotNil(t, gotSecrets)
	require.Len(t, gotSecrets, 1)
	require.Equal(t, gotSecrets[0].Secret, "xyz")
}

func TestService_LoggingConfig(t *testing.T) {
	logFile := "/dev/null"
	if runtime.GOOS == "windows" {
		logFile = "NUL"
	}

	fileSystemConfig := mobius.FilesystemConfig{FilesystemConfig: config.FilesystemConfig{
		StatusLogFile:        logFile,
		ResultLogFile:        logFile,
		AuditLogFile:         logFile,
		EnableLogRotation:    false,
		EnableLogCompression: false,
		MaxSize:              500,
	}}

	firehoseConfig := mobius.FirehoseConfig{
		Region:       testFirehosePluginConfig().Firehose.Region,
		StatusStream: testFirehosePluginConfig().Firehose.StatusStream,
		ResultStream: testFirehosePluginConfig().Firehose.ResultStream,
		AuditStream:  testFirehosePluginConfig().Firehose.AuditStream,
	}

	kinesisConfig := mobius.KinesisConfig{
		Region:       testKinesisPluginConfig().Kinesis.Region,
		StatusStream: testKinesisPluginConfig().Kinesis.StatusStream,
		ResultStream: testKinesisPluginConfig().Kinesis.ResultStream,
		AuditStream:  testKinesisPluginConfig().Kinesis.AuditStream,
	}

	lambdaConfig := mobius.LambdaConfig{
		Region:         testLambdaPluginConfig().Lambda.Region,
		StatusFunction: testLambdaPluginConfig().Lambda.StatusFunction,
		ResultFunction: testLambdaPluginConfig().Lambda.ResultFunction,
		AuditFunction:  testLambdaPluginConfig().Lambda.AuditFunction,
	}

	pubsubConfig := mobius.PubSubConfig{
		PubSubConfig: config.PubSubConfig{
			Project:       testPubSubPluginConfig().PubSub.Project,
			StatusTopic:   testPubSubPluginConfig().PubSub.StatusTopic,
			ResultTopic:   testPubSubPluginConfig().PubSub.ResultTopic,
			AuditTopic:    testPubSubPluginConfig().PubSub.AuditTopic,
			AddAttributes: false,
		},
	}

	type fields struct {
		config config.MobiusConfig
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *mobius.Logging
		wantErr bool
	}{
		{
			name:   "test default test config (aka filesystem)",
			fields: fields{config: config.TestConfig()},
			args:   args{ctx: test.UserContext(context.Background(), test.UserAdmin)},
			want: &mobius.Logging{
				Debug: true,
				Json:  false,
				Result: mobius.LoggingPlugin{
					Plugin: "filesystem",
					Config: fileSystemConfig,
				},
				Status: mobius.LoggingPlugin{
					Plugin: "filesystem",
					Config: fileSystemConfig,
				},
				Audit: mobius.LoggingPlugin{
					Plugin: "filesystem",
					Config: fileSystemConfig,
				},
			},
		},
		{
			name:   "test firehose config",
			fields: fields{config: testFirehosePluginConfig()},
			args:   args{ctx: test.UserContext(context.Background(), test.UserAdmin)},
			want: &mobius.Logging{
				Debug: true,
				Json:  false,
				Result: mobius.LoggingPlugin{
					Plugin: "firehose",
					Config: firehoseConfig,
				},
				Status: mobius.LoggingPlugin{
					Plugin: "firehose",
					Config: firehoseConfig,
				},
				Audit: mobius.LoggingPlugin{
					Plugin: "firehose",
					Config: firehoseConfig,
				},
			},
		},
		{
			name:   "test kinesis config",
			fields: fields{config: testKinesisPluginConfig()},
			args:   args{ctx: test.UserContext(context.Background(), test.UserAdmin)},
			want: &mobius.Logging{
				Debug: true,
				Json:  false,
				Result: mobius.LoggingPlugin{
					Plugin: "kinesis",
					Config: kinesisConfig,
				},
				Status: mobius.LoggingPlugin{
					Plugin: "kinesis",
					Config: kinesisConfig,
				},
				Audit: mobius.LoggingPlugin{
					Plugin: "kinesis",
					Config: kinesisConfig,
				},
			},
		},
		{
			name:   "test lambda config",
			fields: fields{config: testLambdaPluginConfig()},
			args:   args{ctx: test.UserContext(context.Background(), test.UserAdmin)},
			want: &mobius.Logging{
				Debug: true,
				Json:  false,
				Result: mobius.LoggingPlugin{
					Plugin: "lambda",
					Config: lambdaConfig,
				},
				Status: mobius.LoggingPlugin{
					Plugin: "lambda",
					Config: lambdaConfig,
				},
				Audit: mobius.LoggingPlugin{
					Plugin: "lambda",
					Config: lambdaConfig,
				},
			},
		},
		{
			name:   "test pubsub config",
			fields: fields{config: testPubSubPluginConfig()},
			args:   args{ctx: test.UserContext(context.Background(), test.UserAdmin)},
			want: &mobius.Logging{
				Debug: true,
				Json:  false,
				Result: mobius.LoggingPlugin{
					Plugin: "pubsub",
					Config: pubsubConfig,
				},
				Status: mobius.LoggingPlugin{
					Plugin: "pubsub",
					Config: pubsubConfig,
				},
				Audit: mobius.LoggingPlugin{
					Plugin: "pubsub",
					Config: pubsubConfig,
				},
			},
		},
		{
			name:   "test stdout config",
			fields: fields{config: testStdoutPluginConfig()},
			args:   args{ctx: test.UserContext(context.Background(), test.UserAdmin)},
			want: &mobius.Logging{
				Debug: true,
				Json:  false,
				Result: mobius.LoggingPlugin{
					Plugin: "stdout",
					Config: nil,
				},
				Status: mobius.LoggingPlugin{
					Plugin: "stdout",
					Config: nil,
				},
				Audit: mobius.LoggingPlugin{
					Plugin: "stdout",
					Config: nil,
				},
			},
		},
		{
			name:    "test unrecognized config",
			fields:  fields{config: testUnrecognizedPluginConfig()},
			args:    args{ctx: test.UserContext(context.Background(), test.UserAdmin)},
			wantErr: true,
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := new(mock.Store)
			svc, _ := newTestServiceWithConfig(t, ds, tt.fields.config, nil, nil)
			got, err := svc.LoggingConfig(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoggingConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !assert.Equal(t, tt.want, got) {
				t.Errorf("LoggingConfig() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModifyAppConfigPatches(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)

	storedConfig := &mobius.AppConfig{OrgInfo: mobius.OrgInfo{OrgName: "MobiusTest"}, ServerSettings: mobius.ServerSettings{ServerURL: "https://example.org"}}

	ds.AppConfigFunc = func(ctx context.Context) (*mobius.AppConfig, error) {
		return storedConfig, nil
	}

	ds.SaveAppConfigFunc = func(ctx context.Context, info *mobius.AppConfig) error {
		storedConfig = info
		return nil
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

	configJSON := []byte(`{"org_info": { "org_name": "Acme", "org_logo_url": "somelogo.jpg" }}`)

	ctx = test.UserContext(ctx, test.UserAdmin)
	_, err := svc.ModifyAppConfig(ctx, configJSON, mobius.ApplySpecOptions{})
	require.NoError(t, err)

	assert.Equal(t, "Acme", storedConfig.OrgInfo.OrgName)

	configJSON = []byte(`{"server_settings": { "server_url": "http://someurl" }}`)

	_, err = svc.ModifyAppConfig(ctx, configJSON, mobius.ApplySpecOptions{})
	require.NoError(t, err)

	assert.Equal(t, "Acme", storedConfig.OrgInfo.OrgName)
	assert.Equal(t, "http://someurl", storedConfig.ServerSettings.ServerURL)
}

func TestService_EmailConfig(t *testing.T) {
	type fields struct {
		config config.MobiusConfig
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *mobius.EmailConfig
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "configuring the ses email backend should return ses configurations",
			fields: fields{
				config: testSESPluginConfig(),
			},
			args: args{
				ctx: test.UserContext(context.Background(), test.UserAdmin),
			},
			want: &mobius.EmailConfig{
				Backend: "ses",
				Config: mobius.SESConfig{
					Region:    "us-east-1",
					SourceARN: "qux",
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "no configured email backend should return nil",
			fields: fields{
				config: config.TestConfig(),
			},
			args: args{
				ctx: test.UserContext(context.Background(), test.UserAdmin),
			},
			want:    nil,
			wantErr: assert.NoError,
		},
		{
			name: "accessing without roles should return forbidden",
			fields: fields{
				config: testSESPluginConfig(),
			},
			args: args{
				ctx: test.UserContext(context.Background(), test.UserNoRoles),
			},
			want: nil,
			wantErr: func(tt assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(tt, err, "forbidden")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := new(mock.Store)
			svc, _ := newTestServiceWithConfig(t, ds, tt.fields.config, nil, nil)
			got, err := svc.EmailConfig(tt.args.ctx)
			if !tt.wantErr(t, err, fmt.Sprintf("EmailConfig(%v)", tt.args.ctx)) {
				return
			}
			assert.Equalf(t, tt.want, got, "EmailConfig(%v)", tt.args.ctx)
		})
	}
}
