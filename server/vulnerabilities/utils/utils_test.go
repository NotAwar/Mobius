package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/notawar/mobius/server/mobius"
	"github.com/stretchr/testify/require"
)

func TestRecentVulns(t *testing.T) {
	meta := []mobius.CVEMeta{
		{CVE: "cve-recent-1"},
		{CVE: "cve-recent-2"},
		{CVE: "cve-recent-3"},
	}

	t.Run("no NVD nor OVAL vulns", func(t *testing.T) {
		vulns, meta := RecentVulns[mobius.SoftwareVulnerability](nil, meta)
		require.Empty(t, vulns)
		require.Empty(t, meta)
	})

	t.Run("filters vulnerabilities based on max age", func(t *testing.T) {
		ovalVulns := []mobius.SoftwareVulnerability{
			{CVE: "cve-recent-1"},
			{CVE: "cve-recent-2"},
			{CVE: "cve-recent-2"},
			{CVE: "cve-outdated-1"},
		}

		nvdVulns := []mobius.SoftwareVulnerability{
			{CVE: "cve-recent-1"},
			{CVE: "cve-recent-3"},
			{CVE: "cve-outdated-2"},
			{CVE: "cve-outdated-3"},
		}

		expected := []string{
			"cve-recent-1",
			"cve-recent-2",
			"cve-recent-3",
		}

		var input []mobius.SoftwareVulnerability
		input = append(input, ovalVulns...)
		input = append(input, nvdVulns...)

		var actual []string
		vulns, meta := RecentVulns(input, meta)
		for _, r := range vulns {
			actual = append(actual, r.GetCVE())
		}

		expectedMeta := map[string]mobius.CVEMeta{
			"cve-recent-1": {CVE: "cve-recent-1"},
			"cve-recent-2": {CVE: "cve-recent-2"},
			"cve-recent-3": {CVE: "cve-recent-3"},
		}

		require.Equal(t, len(expected), len(actual))
		require.ElementsMatch(t, expected, actual)
		require.Equal(t, expectedMeta, meta)
	})
}

func TestVulnsDelta(t *testing.T) {
	t.Run("no existing vulnerabilities", func(t *testing.T) {
		var found []mobius.SoftwareVulnerability
		var existing []mobius.SoftwareVulnerability

		toInsert, toDelete := VulnsDelta(found, existing)
		require.Empty(t, toInsert)
		require.Empty(t, toDelete)
	})

	t.Run("existing match found", func(t *testing.T) {
		found := []mobius.SoftwareVulnerability{
			{SoftwareID: 1, CVE: "cve_1"},
			{SoftwareID: 1, CVE: "cve_2"},
			{SoftwareID: 2, CVE: "cve_3"},
			{SoftwareID: 2, CVE: "cve_4"},
		}

		existing := []mobius.SoftwareVulnerability{
			{SoftwareID: 1, CVE: "cve_1"},
			{SoftwareID: 1, CVE: "cve_2"},
			{SoftwareID: 2, CVE: "cve_3"},
			{SoftwareID: 2, CVE: "cve_4"},
		}

		toInsert, toDelete := VulnsDelta(found, existing)
		require.Empty(t, toInsert)
		require.Empty(t, toDelete)
	})

	t.Run("existing differ from found", func(t *testing.T) {
		found := []mobius.SoftwareVulnerability{
			{SoftwareID: 1, CVE: "cve_1"},
			{SoftwareID: 1, CVE: "cve_2"},
			{SoftwareID: 3, CVE: "cve_5"},
			{SoftwareID: 3, CVE: "cve_6"},
		}

		existing := []mobius.SoftwareVulnerability{
			{SoftwareID: 1, CVE: "cve_1"},
			{SoftwareID: 1, CVE: "cve_2"},
			{SoftwareID: 2, CVE: "cve_3"},
			{SoftwareID: 2, CVE: "cve_4"},
		}

		expectedToInsert := []mobius.SoftwareVulnerability{
			{SoftwareID: 3, CVE: "cve_5"},
			{SoftwareID: 3, CVE: "cve_6"},
		}

		expectedToDelete := []mobius.SoftwareVulnerability{
			{SoftwareID: 2, CVE: "cve_3"},
			{SoftwareID: 2, CVE: "cve_4"},
		}

		toInsert, toDelete := VulnsDelta(found, existing)
		require.Equal(t, expectedToInsert, toInsert)
		require.ElementsMatch(t, expectedToDelete, toDelete)
	})

	t.Run("nothing found but vulns exist", func(t *testing.T) {
		var found []mobius.SoftwareVulnerability

		existing := []mobius.SoftwareVulnerability{
			{SoftwareID: 1, CVE: "cve_1"},
			{SoftwareID: 1, CVE: "cve_2"},
			{SoftwareID: 2, CVE: "cve_3"},
			{SoftwareID: 2, CVE: "cve_4"},
		}

		toInsert, toDelete := VulnsDelta(found, existing)
		require.Empty(t, toInsert)
		require.ElementsMatch(t, existing, toDelete)
	})
}

func TestProductsIntersect(t *testing.T) {
	a := map[string]bool{
		"1": true,
		"2": true,
		"3": true,
	}

	b := map[string]bool{
		"1": true,
	}

	c := map[string]bool{
		"10": true,
	}

	d := make(map[string]bool)

	require.True(t, ProductIDsIntersect(a, b))
	require.True(t, ProductIDsIntersect(b, a))

	require.False(t, ProductIDsIntersect(b, c))
	require.False(t, ProductIDsIntersect(c, b))

	require.False(t, ProductIDsIntersect(b, d))
	require.False(t, ProductIDsIntersect(d, b))
}

func TestLatestFile(t *testing.T) {
	t.Run("file exists", func(t *testing.T) {
		dir := t.TempDir()

		today := time.Now()
		fileName := fmt.Sprintf("file1-%d_%02d_%02d.%s", today.Year(), today.Month(), today.Day(), "json")

		f1, err := os.Create(filepath.Join(dir, fileName))
		require.NoError(t, err)
		f1.Close()

		result, err := LatestFile(fileName, dir)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(dir, fileName), result)
	})

	t.Run("file exists but not for date", func(t *testing.T) {
		dir := t.TempDir()

		today := time.Now()
		yesterday := today.Add(-24 * time.Hour)

		todayFile := fmt.Sprintf("file1-%d_%02d_%02d.%s", today.Year(), today.Month(), today.Day(), "json")
		yesterdayFile := fmt.Sprintf("file1-%d_%02d_%02d.%s", yesterday.Year(), yesterday.Month(), yesterday.Day(), "json")

		f1, err := os.Create(filepath.Join(dir, yesterdayFile))
		require.NoError(t, err)
		f1.Close()

		result, err := LatestFile(todayFile, dir)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(dir, yesterdayFile), result)
	})

	t.Run("file does not exists", func(t *testing.T) {
		dir := t.TempDir()

		today := time.Now()

		wantedFile := fmt.Sprintf("file1-%d_%02d_%02d.%s", today.Year(), today.Month(), today.Day(), "json")
		existingFile := fmt.Sprintf("file2-%d_%02d_%02d.%s", today.Year(), today.Month(), today.Day(), "json")

		f1, err := os.Create(filepath.Join(dir, existingFile))
		require.NoError(t, err)
		f1.Close()

		_, err = LatestFile(wantedFile, dir)
		require.Error(t, err, "file not found")
	})
}
