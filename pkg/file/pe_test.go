package file

import (
	"testing"

	"github.com/notawar/mobius/server/mobius"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractPEMetadata(t *testing.T) {
	t.Parallel()

	tfr, err := mobius.NewKeepFileReader("testdata/software-installers/hello-world-installer.exe")
	require.NoError(t, err)
	defer tfr.Close()

	meta, err := ExtractPEMetadata(tfr)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, "Hello world", meta.Name)
	assert.Equal(t, "1.0.0", meta.Version)
	assert.Equal(t, []string{"Hello world"}, meta.PackageIDs)
}
