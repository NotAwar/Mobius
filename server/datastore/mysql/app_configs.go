package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/notawar/mobius/server/contexts/ctxdb"
	"github.com/notawar/mobius/server/contexts/ctxerr"
	"github.com/notawar/mobius/server/mobius"
	"github.com/jmoiron/sqlx"
)

func (ds *Datastore) NewAppConfig(ctx context.Context, info *mobius.AppConfig) (*mobius.AppConfig, error) {
	info.ApplyDefaultsForNewInstalls()

	if err := ds.SaveAppConfig(ctx, info); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "new app config")
	}

	return info, nil
}

func (ds *Datastore) AppConfig(ctx context.Context) (*mobius.AppConfig, error) {
	return appConfigDB(ctx, ds.reader(ctx))
}

func appConfigDB(ctx context.Context, q sqlx.QueryerContext) (*mobius.AppConfig, error) {
	info := &mobius.AppConfig{}
	var bytes []byte
	err := sqlx.GetContext(ctx, q, &bytes, `SELECT json_value FROM app_config_json LIMIT 1`)
	if err != nil && err != sql.ErrNoRows {
		return nil, ctxerr.Wrap(ctx, err, "selecting app config")
	}
	if err == sql.ErrNoRows {
		return &mobius.AppConfig{}, nil
	}

	info.ApplyDefaults()

	err = json.Unmarshal(bytes, info)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "unmarshaling config")
	}
	return info, nil
}

func (ds *Datastore) SaveAppConfig(ctx context.Context, info *mobius.AppConfig) error {
	return ds.withTx(ctx, func(tx sqlx.ExtContext) error {
		err := ds.saveCAAssets(ctx, tx, info)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "saving CA assets")
		}

		configBytes, err := json.Marshal(info)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "marshaling config")
		}

		_, err = tx.ExecContext(ctx,
			`INSERT INTO app_config_json(json_value) VALUES(?) ON DUPLICATE KEY UPDATE json_value = VALUES(json_value)`,
			configBytes,
		)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "insert app_config_json")
		}

		return nil
	})
}

// saveCAAssets encrypts and saves the CA assets (passwords, API tokens, etc.) to the database.
func (ds *Datastore) saveCAAssets(ctx context.Context, tx sqlx.ExtContext, info *mobius.AppConfig) error {
	if info.Integrations.NDESSCEPProxy.Valid {
		if info.Integrations.NDESSCEPProxy.Set &&
			info.Integrations.NDESSCEPProxy.Value.Password != "" &&
			info.Integrations.NDESSCEPProxy.Value.Password != mobius.MaskedPassword {
			err := ds.insertOrReplaceConfigAsset(ctx, tx, mobius.MDMConfigAsset{
				Name:  mobius.MDMAssetNDESPassword,
				Value: []byte(info.Integrations.NDESSCEPProxy.Value.Password),
			})
			if err != nil {
				return ctxerr.Wrap(ctx, err, "processing NDES SCEP proxy password")
			}
		}
		info.Integrations.NDESSCEPProxy.Value.Password = mobius.MaskedPassword
	}

	if info.Integrations.DigiCert.Valid || info.Integrations.CustomSCEPProxy.Valid {
		tokensToSave := make([]mobius.CAConfigAsset, 0, len(info.Integrations.DigiCert.Value)+len(info.Integrations.CustomSCEPProxy.Value))
		if info.Integrations.DigiCert.Valid {
			for i, ca := range info.Integrations.DigiCert.Value {
				if ca.APIToken != "" && ca.APIToken != mobius.MaskedPassword {
					tokensToSave = append(tokensToSave, mobius.CAConfigAsset{
						Name:  ca.Name,
						Value: []byte(ca.APIToken),
						Type:  mobius.CAConfigDigiCert,
					})
				}
				info.Integrations.DigiCert.Value[i].APIToken = mobius.MaskedPassword
			}
		}

		if info.Integrations.CustomSCEPProxy.Valid {
			for i, ca := range info.Integrations.CustomSCEPProxy.Value {
				if ca.Challenge != "" && ca.Challenge != mobius.MaskedPassword {
					tokensToSave = append(tokensToSave, mobius.CAConfigAsset{
						Name:  ca.Name,
						Value: []byte(ca.Challenge),
						Type:  mobius.CAConfigCustomSCEPProxy,
					})
				}
				info.Integrations.CustomSCEPProxy.Value[i].Challenge = mobius.MaskedPassword
			}
		}
		err := ds.saveCAConfigAssets(ctx, tx, tokensToSave)
		if err != nil {
			return ctxerr.Wrap(ctx, err, "saving CA assets")
		}
	}

	return nil
}

func (ds *Datastore) InsertOrReplaceMDMConfigAsset(ctx context.Context, asset mobius.MDMConfigAsset) error {
	return ds.insertOrReplaceConfigAsset(ctx, ds.writer(ctx), asset)
}

func (ds *Datastore) insertOrReplaceConfigAsset(ctx context.Context, tx sqlx.ExtContext, asset mobius.MDMConfigAsset) error {
	assets, err := ds.GetAllMDMConfigAssetsByName(ctx, []mobius.MDMAssetName{asset.Name}, tx)
	if err != nil {
		if mobius.IsNotFound(err) {
			return ds.InsertMDMConfigAssets(ctx, []mobius.MDMConfigAsset{asset}, tx)
		}
		return ctxerr.Wrap(ctx, err, "get all mdm config assets by name")
	}
	if len(assets) == 0 {
		// Should never happen
		return ctxerr.New(ctx, fmt.Sprintf("no asset found for name %s", asset.Name))
	}
	currentAsset, ok := assets[asset.Name]
	if !ok {
		// Should never happen
		return ctxerr.New(ctx, fmt.Sprintf("asset not found for name %s", asset.Name))
	}
	if !bytes.Equal(currentAsset.Value, asset.Value) {
		return ds.ReplaceMDMConfigAssets(ctx, []mobius.MDMConfigAsset{asset}, tx)
	}
	// asset already exists and is the same, so not need to update
	return nil
}

func (ds *Datastore) SetAndroidEnabledAndConfigured(ctx context.Context, configured bool) error {
	ctx = ctxdb.RequirePrimary(ctx, true)
	appConfig, err := ds.AppConfig(ctx)
	if err != nil {
		return err
	}
	appConfig.MDM.AndroidEnabledAndConfigured = configured
	return ds.SaveAppConfig(ctx, appConfig)
}

func (ds *Datastore) VerifyEnrollSecret(ctx context.Context, secret string) (*mobius.EnrollSecret, error) {
	var s mobius.EnrollSecret
	err := sqlx.GetContext(ctx, ds.reader(ctx), &s, "SELECT team_id FROM enroll_secrets WHERE secret = ?", secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ctxerr.Wrap(ctx, notFound("EnrollSecret"), "no matching secret found")
		}
		return nil, ctxerr.Wrap(ctx, err, "verify enroll secret")
	}

	return &s, nil
}

func (ds *Datastore) IsEnrollSecretAvailable(ctx context.Context, secret string, isNew bool, teamID *uint) (bool, error) {
	secretTeamID := sql.NullInt64{}
	err := sqlx.GetContext(ctx, ds.reader(ctx), &secretTeamID, "SELECT team_id FROM enroll_secrets WHERE secret = ?", secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		return false, ctxerr.Wrap(ctx, err, "check enroll secret availability")
	}
	if isNew {
		// Secret is already in use, so a new team can't use it
		return false, nil
	}
	// Secret is in use, but we're checking if it's already assigned to the team
	if (teamID == nil && !secretTeamID.Valid) || (teamID != nil && secretTeamID.Valid && uint(secretTeamID.Int64) == *teamID) { //nolint:gosec // dismiss G115
		return true, nil
	}

	// Secret is in use by another team or globally
	return false, nil
}

func (ds *Datastore) ApplyEnrollSecrets(ctx context.Context, teamID *uint, secrets []*mobius.EnrollSecret) error {
	return ds.withRetryTxx(ctx, func(tx sqlx.ExtContext) error {
		return applyEnrollSecretsDB(ctx, tx, teamID, secrets)
	})
}

func applyEnrollSecretsDB(ctx context.Context, q sqlx.ExtContext, teamID *uint, secrets []*mobius.EnrollSecret) error {
	// NOTE: this is called from within a transaction (either from
	// ApplyEnrollSecrets or saveTeamSecretsDB). We don't do a simple DELETE then
	// INSERT as we need to keep the existing created_at timestamps of
	// already-existing secrets. We also can't do a DELETE unused ones and then
	// UPSERT new ones, because we need to fail the INSERT if the secret already
	// exists for a different team or globally (i.e. the `secret` column is
	// unique across all values of team_id, NULL or not). An "ON DUPLICATE KEY
	// UPDATE" clause would silence such errors.
	//
	// For this reason, we first read the existing secrets to have their
	// created_at timestamps, then we delete and re-insert them, failing the call
	// if the insert failed (due to a secret existing at a different team/global
	// level).

	var args []interface{}
	teamWhere := "team_id IS NULL"
	if teamID != nil {
		teamWhere = "team_id = ?"
		args = append(args, *teamID)
	}

	// first, load the existing secrets and their created_at timestamp
	const loadStmt = `SELECT secret, created_at FROM enroll_secrets WHERE `
	var existingSecrets []*mobius.EnrollSecret
	if err := sqlx.SelectContext(ctx, q, &existingSecrets, loadStmt+teamWhere, args...); err != nil {
		return ctxerr.Wrap(ctx, err, "load existing secrets")
	}
	secretsCreatedAt := make(map[string]*time.Time, len(existingSecrets))
	for _, es := range existingSecrets {
		es := es
		secretsCreatedAt[es.Secret] = &es.CreatedAt
	}

	// next, remove all existing secrets for that team or global
	const delStmt = `DELETE FROM enroll_secrets WHERE `
	if _, err := q.ExecContext(ctx, delStmt+teamWhere, args...); err != nil {
		return ctxerr.Wrap(ctx, err, "clear before insert")
	}

	newSecrets := make([]string, len(secrets))
	for i, s := range secrets {
		newSecrets[i] = s.Secret
	}

	// finally, insert the new secrets, using the existing created_at timestamp
	// if available.
	const insStmt = `INSERT INTO enroll_secrets (secret, team_id, created_at) VALUES %s`
	if len(newSecrets) > 0 {
		var args []interface{}
		defaultCreatedAt := time.Now()
		sql := fmt.Sprintf(insStmt, strings.TrimSuffix(strings.Repeat(`(?,?,?),`, len(newSecrets)), ","))

		for _, s := range secrets {
			secretCreatedAt := defaultCreatedAt
			if ts := secretsCreatedAt[s.Secret]; ts != nil {
				secretCreatedAt = *ts
			}
			args = append(args, s.Secret, teamID, secretCreatedAt)
		}
		if _, err := q.ExecContext(ctx, sql, args...); err != nil {
			if IsDuplicate(err) {
				// Obfuscate the secret in the error message
				err = alreadyExists("secret", mobius.MaskedPassword)
			}
			return ctxerr.Wrap(ctx, err, "insert secrets")
		}
	}
	return nil
}

func (ds *Datastore) GetEnrollSecrets(ctx context.Context, teamID *uint) ([]*mobius.EnrollSecret, error) {
	return getEnrollSecretsDB(ctx, ds.reader(ctx), teamID)
}

func getEnrollSecretsDB(ctx context.Context, q sqlx.QueryerContext, teamID *uint) ([]*mobius.EnrollSecret, error) {
	var args []interface{}
	sql := "SELECT secret, team_id, created_at FROM enroll_secrets WHERE "
	// MySQL requires comparing NULL with IS. NULL = NULL evaluates to FALSE.
	if teamID == nil {
		sql += "team_id IS NULL"
	} else {
		sql += "team_id = ?"
		args = append(args, teamID)
	}
	var secrets []*mobius.EnrollSecret
	if err := sqlx.SelectContext(ctx, q, &secrets, sql, args...); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "get secrets")
	}
	return secrets, nil
}

func (ds *Datastore) AggregateEnrollSecretPerTeam(ctx context.Context) ([]*mobius.EnrollSecret, error) {
	query := `
          SELECT
             COALESCE((
             SELECT
                es.secret
             FROM
                enroll_secrets es
             WHERE
                es.team_id = t.id
             ORDER BY
                es.created_at DESC LIMIT 1), '') as secret,
                t.id as team_id
             FROM
                teams t
             UNION
          (
             SELECT
                COALESCE(secret, '') as secret, team_id
             FROM
                enroll_secrets
             WHERE
                team_id IS NULL
             ORDER BY
                created_at DESC LIMIT 1)
	`
	var secrets []*mobius.EnrollSecret
	if err := sqlx.SelectContext(ctx, ds.reader(ctx), &secrets, query); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "get secrets")
	}
	return secrets, nil
}

func (ds *Datastore) GetConfigEnableDiskEncryption(ctx context.Context, teamID *uint) (bool, error) {
	if teamID != nil && *teamID > 0 {
		tc, err := ds.TeamMDMConfig(ctx, *teamID)
		if err != nil {
			return false, err
		}
		return tc.EnableDiskEncryption, nil
	}
	ac, err := ds.AppConfig(ctx)
	if err != nil {
		return false, err
	}
	return ac.MDM.EnableDiskEncryption.Value, nil
}

func (ds *Datastore) ApplyYaraRules(ctx context.Context, rules []mobius.YaraRule) error {
	return ds.withRetryTxx(ctx, func(tx sqlx.ExtContext) error {
		return applyYaraRulesDB(ctx, tx, rules)
	})
}

func applyYaraRulesDB(ctx context.Context, q sqlx.ExtContext, rules []mobius.YaraRule) error {
	const delStmt = "DELETE FROM yara_rules"
	if _, err := q.ExecContext(ctx, delStmt); err != nil {
		return ctxerr.Wrap(ctx, err, "clear before insert")
	}

	if len(rules) > 0 {
		const insStmt = `INSERT INTO yara_rules (name, contents) VALUES %s`
		var args []interface{}
		sql := fmt.Sprintf(insStmt, strings.TrimSuffix(strings.Repeat(`(?, ?),`, len(rules)), ","))
		for _, r := range rules {
			args = append(args, r.Name, r.Contents)
		}

		if _, err := q.ExecContext(ctx, sql, args...); err != nil {
			return ctxerr.Wrap(ctx, err, "insert yara rules")
		}
	}

	return nil
}

func (ds *Datastore) GetYaraRules(ctx context.Context) ([]mobius.YaraRule, error) {
	sql := "SELECT name, contents FROM yara_rules"
	rules := []mobius.YaraRule{}
	if err := sqlx.SelectContext(ctx, ds.reader(ctx), &rules, sql); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "get yara rules")
	}
	return rules, nil
}

func (ds *Datastore) YaraRuleByName(ctx context.Context, name string) (*mobius.YaraRule, error) {
	query := "SELECT name, contents FROM yara_rules WHERE name = ?"
	rule := mobius.YaraRule{}
	if err := sqlx.GetContext(ctx, ds.reader(ctx), &rule, query, name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ctxerr.Wrap(ctx, notFound("YaraRule"), "no yara rule with provided name")
		}
		return nil, ctxerr.Wrap(ctx, err, "get yara rule by name")
	}
	return &rule, nil
}
