package pac

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetOutput(t *testing.T) {
	path := path.Join(os.TempDir(), "pac")
	err := EnsureHelperToolPresent(path, "For test purpose", "")
	assert.NoError(t, err, "should install helper tool")
	err = On("http://localhost:8888/xxx?a=1&b=2")
	assert.NoError(t, err, "should set PAC on")
	err = Off("http://not-matched-prefix")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unexpected output")
	err = Off("http://localhost:8888/xxx?a=1")
	assert.NoError(t, err, "should set PAC off with matched prefix")
}
