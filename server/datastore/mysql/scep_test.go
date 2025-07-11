package mysql

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	scep_depot "github.com/notawar/mobius/server/mdm/scep/depot"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T) scep_depot.Depot {
	ds := CreateNamedMySQLDS(t, t.Name())
	depot, err := ds.NewSCEPDepot()
	require.NoError(t, err)
	return depot
}

func TestAppleMDMSCEPSerial(t *testing.T) {
	depot := setup(t)
	tests := []struct {
		name    string
		want    *big.Int
		wantErr bool
	}{
		{
			name: "two is the default value.",
			want: big.NewInt(2),
		},
	}
	for _, tt := range tests {
		got, err := depot.Serial()
		require.NoError(t, err)
		require.Equal(t, tt.want, got)
	}
}

func TestAppleMDMPutAndHasCN(t *testing.T) {
	depot := setup(t)

	name := "Mobius Identity"
	serial, err := depot.Serial()
	require.NoError(t, err)
	cert := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: name,
		},
	}

	err = depot.Put(name, &cert)
	require.NoError(t, err)

	has, err := depot.HasCN(name, 0, &cert, false)
	require.NoError(t, err)
	require.True(t, has)

	has, err = depot.HasCN("non-existent", 0, &cert, true)
	require.NoError(t, err)
	require.False(t, has)
}
