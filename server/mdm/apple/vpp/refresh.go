package vpp

import (
	"context"

	"github.com/notawar/mobius/v4/server/contexts/ctxerr"
	"github.com/notawar/mobius set/v4/server/mobius"
	"github.com/notawar/mobius set/v4/server/mdm/apple/itunes"
)

// RefreshVersions updatest the LatestVersion fields for the VPP apps stored in Mobius.
func RefreshVersions(ctx context.Context, ds mobius.Datastore) error {
	apps, err := ds.GetAllVPPApps(ctx)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting all VPP apps")
	}

	if len(apps) == 0 {
		// nothing to do
		return nil
	}

	var adamIDs []string
	appsByAdamID := make(map[string]*mobius.VPPApp)
	for _, app := range apps {
		adamIDs = append(adamIDs, app.AdamID)
		appsByAdamID[app.AdamID] = app
	}

	meta, err := itunes.GetAssetMetadata(adamIDs, &itunes.AssetMetadataFilter{Entity: "software"})
	if err != nil {
		return ctxerr.Wrap(ctx, err, "getting VPP app metadata from iTunes API")
	}

	var appsToUpdate []*mobius.VPPApp
	for _, adamID := range adamIDs {
		if m, ok := meta[adamID]; ok {
			if m.Version != appsByAdamID[adamID].LatestVersion {
				appsByAdamID[adamID].LatestVersion = m.Version
				appsToUpdate = append(appsToUpdate, appsByAdamID[adamID])
			}
		}
	}

	if len(appsToUpdate) == 0 {
		// nothing to do
		return nil
	}

	if err := ds.InsertVPPApps(ctx, appsToUpdate); err != nil {
		return ctxerr.Wrap(ctx, err, "inserting VPP apps with new versions")
	}

	return nil
}
