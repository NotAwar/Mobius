package mobiusdbase

import "github.com/notawar/mobius/pkg/mobiusdaemonbase"

// Deprecated: use mobiusdaemonbase instead.
type Metadata = mobiusdaemonbase.Metadata

// GetMetadata calls mobiusdaemonbase.GetMetadata.
func GetMetadata() (*Metadata, error) {
	return mobiusdaemonbase.GetMetadata()
}

// GetPKGManifestURL calls mobiusdaemonbase.GetPKGManifestURL.
func GetPKGManifestURL() string {
	return mobiusdaemonbase.GetPKGManifestURL()
}
