package mdmcrypto

import (
	"context"
	"fmt"

	"github.com/micromdm/micromdm/pkg/crypto/profileutil"
	"github.com/notawar/mobius/mobius-server/server/mdm/assets"
	"github.com/notawar/mobius/mobius-server/server/mobius"
)

// Sign signs an enrollment profile using a certificate from the datastore
func Sign(ctx context.Context, profile []byte, ds mobius.MDMAssetRetriever) ([]byte, error) {
	cert, err := assets.CAKeyPair(ctx, ds)
	if err != nil {
		return nil, err
	}
	signed, err := profileutil.Sign(cert.PrivateKey, cert.Leaf, profile)
	if err != nil {
		return nil, fmt.Errorf("signing profile with the specified key: %w", err)
	}

	return signed, nil
}
