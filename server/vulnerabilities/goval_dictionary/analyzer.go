package goval_dictionary

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/notawar/mobius/server/mobius"
	"github.com/notawar/mobius/server/vulnerabilities/oval"
	"github.com/notawar/mobius/server/vulnerabilities/utils"
	kitlog "github.com/go-kit/log"
)

const (
	hostsBatchSize = 500
	vulnBatchSize  = 500
)

var ErrUnsupportedPlatform = errors.New("unsupported platform")

// Analyze scans all hosts for vulnerabilities based on the sqlite output of goval-dictionary
// for their platform,  inserting any new vulnerabilities and deleting anything patched.
// Returns nil, nil when the platform isn't supported.
func Analyze(
	ctx context.Context,
	ds mobius.Datastore,
	ver mobius.OSVersion,
	vulnPath string,
	collectVulns bool,
	logger kitlog.Logger,
) ([]mobius.SoftwareVulnerability, error) {
	platform := oval.NewPlatform(ver.Platform, ver.Name)
	source := mobius.GovalDictionarySource
	if !platform.IsGovalDictionarySupported() {
		return nil, ErrUnsupportedPlatform
	}
	db, err := LoadDb(platform, vulnPath)
	if err != nil {
		return nil, err
	}

	// Since hosts and software have a M:N relationship, the following sets are used to
	// avoid doing duplicated inserts/delete operations (a vulnerable software might be
	// present in many hosts).
	toInsertSet := make(map[string]mobius.SoftwareVulnerability)
	toDeleteSet := make(map[string]mobius.SoftwareVulnerability)

	var offset int
	for {
		hostIDs, err := ds.HostIDsByOSVersion(ctx, ver, offset, hostsBatchSize)
		if err != nil {
			return nil, err
		}

		if len(hostIDs) == 0 {
			break
		}
		offset += hostsBatchSize

		foundInBatch := make(map[uint][]mobius.SoftwareVulnerability)
		for _, hostID := range hostIDs {
			hostID := hostID
			software, err := ds.ListSoftwareForVulnDetection(ctx, mobius.VulnSoftwareFilter{HostID: &hostID})
			if err != nil {
				return nil, err
			}

			vulnerabilities := db.Eval(software, logger)
			foundInBatch[hostID] = vulnerabilities
		}

		existingInBatch, err := ds.ListSoftwareVulnerabilitiesByHostIDsSource(ctx, hostIDs, source)
		if err != nil {
			return nil, err
		}

		for _, hostID := range hostIDs {
			inserts, deletes := utils.VulnsDelta(foundInBatch[hostID], existingInBatch[hostID])
			for _, i := range inserts {
				toInsertSet[i.Key()] = i
			}
			for _, d := range deletes {
				toDeleteSet[d.Key()] = d
			}
		}
	}

	err = utils.BatchProcess(toDeleteSet, func(v []mobius.SoftwareVulnerability) error {
		return ds.DeleteSoftwareVulnerabilities(ctx, v)
	}, vulnBatchSize)
	if err != nil {
		return nil, err
	}

	var inserted []mobius.SoftwareVulnerability
	if collectVulns {
		inserted = make([]mobius.SoftwareVulnerability, 0, len(toInsertSet))
	}

	err = utils.BatchProcess(toInsertSet, func(vulns []mobius.SoftwareVulnerability) error {
		for _, v := range vulns {
			ok, err := ds.InsertSoftwareVulnerability(ctx, v, source)
			if err != nil {
				return err
			}

			if collectVulns && ok {
				inserted = append(inserted, v)
			}
		}
		return nil
	}, vulnBatchSize)
	if err != nil {
		return nil, err
	}

	return inserted, nil
}

// LoadDb returns the latest goval_dictionary database for the given platform.
func LoadDb(platform oval.Platform, vulnPath string) (*Database, error) {
	if !platform.IsGovalDictionarySupported() {
		return nil, fmt.Errorf("platform %q not supported", platform)
	}

	fileName := platform.ToGovalDictionaryFilename()
	latest, err := utils.LatestFile(fileName, vulnPath)
	if err != nil {
		return nil, err
	}

	sqlite, err := sql.Open("sqlite3", latest)
	if err != nil {
		return nil, err
	}

	db := NewDB(sqlite, platform)
	return db, nil
}
