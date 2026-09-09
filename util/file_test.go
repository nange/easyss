package util

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileExists(t *testing.T) {
	e, err := FileExists("./file.go")
	assert.Nil(t, err)
	assert.True(t, e)
}

func TestCurrentDir(t *testing.T) {
	d := CurrentDir()
	assert.NotEmpty(t, d)
}

func TestDirFileList(t *testing.T) {
	list, err := DirFileList(".")
	assert.Nil(t, err)
	assert.Contains(t, list, "file.go")
}

func TestWriteToTemp(t *testing.T) {
	filePath, err := WriteToTemp("test.dat", []byte("Hello world!"))
	assert.Nil(t, err)

	e, err := FileExists(filePath)
	assert.Nil(t, err)
	assert.True(t, e)
}

func TestReadFileLinesMap(t *testing.T) {
	filePath, err := WriteToTemp("test.dat", []byte("Hello world!\nNi hao!"))
	assert.Nil(t, err)

	m, err := ReadFileLinesMap(filePath)
	assert.Nil(t, err)
	assert.Len(t, m, 2)
	_, ok := m["Ni hao!"]
	assert.True(t, ok)
}

func TestReadFileLinesMapMissingFile(t *testing.T) {
	// A missing file must be reported as an error rather than silently
	// treated as empty lines (a misconfigured rule file path must not be
	// invisible to the caller).
	_, err := ReadFileLinesMap("definitely-not-exists.txt")
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

func TestResolvePath(t *testing.T) {
	// Empty string is returned unchanged.
	assert.Equal(t, "", ResolvePath(""))

	// Absolute paths are returned unchanged.
	abs, err := filepath.Abs("direct.txt")
	assert.Nil(t, err)
	assert.True(t, filepath.IsAbs(abs))
	assert.Equal(t, abs, ResolvePath(abs))

	// Relative paths that exist in the cwd are kept as-is.
	relExisting := "file.go"
	e, err := FileExists(relExisting)
	assert.Nil(t, err)
	assert.True(t, e)
	assert.Equal(t, relExisting, ResolvePath(relExisting))

	// Relative paths missing from the cwd fall back to the executable dir.
	relMissing := "direct.txt"
	want := filepath.Join(CurrentDir(), relMissing)
	assert.Equal(t, want, ResolvePath(relMissing))
}
