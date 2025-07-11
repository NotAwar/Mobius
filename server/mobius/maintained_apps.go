package mobius

import "net/http"

// MaintainedApp represents an app in the Mobius library of maintained apps,
// as stored in the mobius_library_apps table.
type MaintainedApp struct {
	ID                    uint     `json:"id" db:"id"`
	Name                  string   `json:"name" db:"name"`
	Slug                  string   `json:"slug" db:"slug"`
	Version               string   `json:"version,omitempty"`
	Platform              string   `json:"platform" db:"platform"`
	TitleID               *uint    `json:"software_title_id" db:"software_title_id"`
	InstallerURL          string   `json:"url,omitempty"`
	SHA256                string   `json:"-"`
	UniqueIdentifier      string   `json:"-" db:"unique_identifier"`
	InstallScript         string   `json:"install_script,omitempty"`
	UninstallScript       string   `json:"uninstall_script,omitempty"`
	AutomaticInstallQuery string   `json:"-"`
	Categories            []string `json:"categories"`
}

func (s *MaintainedApp) Source() string {
	if s.Platform == "windows" {
		return "programs"
	}

	return "apps"
}

func (s *MaintainedApp) BundleIdentifier() string {
	if s.Platform == "windows" {
		return ""
	}

	return s.UniqueIdentifier
}

// AuthzType implements authz.AuthzTyper.
func (s *MaintainedApp) AuthzType() string {
	return "maintained_app"
}

// NoMaintainedAppsInDatabaseError is the error type for no Mobius Maintained Apps in the database
type NoMaintainedAppsInDatabaseError struct {
	ErrorWithUUID
}

// Error implements the error interface.
func (e *NoMaintainedAppsInDatabaseError) Error() string {
	return `Mobius was unable to ingest the maintained apps list. Run mobiuscli trigger name=maintained_apps to try repopulating the apps list.`
}

// StatusCode implements the go-kit http StatusCoder interface.
func (e *NoMaintainedAppsInDatabaseError) StatusCode() int {
	return http.StatusNotFound
}

func (e *NoMaintainedAppsInDatabaseError) Is(target error) bool {
	return target.Error() == e.Error()
}
