package goval_dictionary

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/vulnerabilities/oval"
	"github.com/notawar/mobius/server/vulnerabilities/utils"
	kitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

func NewDB(db *sql.DB, platform oval.Platform) *Database {
	return &Database{sqlite: db, platform: platform}
}

type Database struct {
	sqlite   *sql.DB
	platform oval.Platform
}

const baseSearchStmt = `SELECT packages.version, cves.cve_id
    FROM packages join definitions on definitions.id = packages.definition_id
    JOIN advisories ON advisories.definition_id = definitions.id JOIN cves ON cves.advisory_id = advisories.id`

func (db Database) Verfiy() error {
	searchStmt := fmt.Sprintf("%s LIMIT 1", baseSearchStmt)
	affectedSoftwareRows, err := db.sqlite.Query(searchStmt)
	if err != nil {
		return fmt.Errorf("could not query database: %w", err)
	}

	defer affectedSoftwareRows.Close()

	if affectedSoftwareRows.Err() != nil {
		return affectedSoftwareRows.Err()
	}

	return nil
}

// Eval evaluates the current goval_dictionary database against an OS version and a list of installed software,
// returns all software vulnerabilities found. Logs on any errors so we return as many vulnerabilities as we can.
func (db Database) Eval(software []mobius.Software, logger kitlog.Logger) []mobius.SoftwareVulnerability {
	searchStmt := fmt.Sprintf("%s WHERE packages.name = ? AND packages.arch = ? ORDER BY cve_id, version", baseSearchStmt)
	vulnerabilities := make([]mobius.SoftwareVulnerability, 0)

	for _, swItem := range software {
		err := func() error {
			affectedSoftwareRows, err := db.sqlite.Query(searchStmt, swItem.Name, swItem.Arch)
			if err != nil {
				return fmt.Errorf("could not query database: %w", err)
			}
			defer affectedSoftwareRows.Close()
			for affectedSoftwareRows.Next() {
				var fixedVersionWithEpochPrefix, cve string
				if err := affectedSoftwareRows.Scan(&fixedVersionWithEpochPrefix, &cve); err != nil {
					level.Error(logger).Log(
						"msg", "could not read package vulnerability result",
						"package", swItem.Name,
						"arch", swItem.Arch,
						"platform", db.platform,
						"err", err,
					)
					continue
				}

				var currentVersion string
				if swItem.Release != "" {
					currentVersion = fmt.Sprintf("%s-%s", swItem.Version, swItem.Release)
				} else {
					currentVersion = swItem.Version
				}
				fixedVersion := strings.Split(fixedVersionWithEpochPrefix, ":")[1]

				if utils.Rpmvercmp(currentVersion, fixedVersion) < 0 {
					vulnerabilities = append(vulnerabilities, mobius.SoftwareVulnerability{
						SoftwareID:        swItem.ID,
						CVE:               cve,
						ResolvedInVersion: &fixedVersion,
					})
				}
			}

			if affectedSoftwareRows.Err() != nil {
				return affectedSoftwareRows.Err()
			}

			return nil
		}()
		if err != nil {
			level.Error(logger).Log(
				"msg", "could not read package vulnerabilities",
				"package", swItem.Name,
				"arch", swItem.Arch,
				"platform", db.platform,
				"err", err,
			)
		}
	}

	return vulnerabilities
}
