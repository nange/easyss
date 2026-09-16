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
	// 缺失的文件必须作为错误上报，而不是被静默当作空行列表处理
	// （配置错误的规则文件路径不能被调用方忽视）。
	_, err := ReadFileLinesMap("definitely-not-exists.txt")
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

func TestResolvePath(t *testing.T) {
	// 空字符串原样返回。
	assert.Equal(t, "", ResolvePath(""))

	// 绝对路径原样返回。
	abs, err := filepath.Abs("direct.txt")
	assert.Nil(t, err)
	assert.True(t, filepath.IsAbs(abs))
	assert.Equal(t, abs, ResolvePath(abs))

	// 存在于当前工作目录中的相对路径保持原样。
	relExisting := "file.go"
	e, err := FileExists(relExisting)
	assert.Nil(t, err)
	assert.True(t, e)
	assert.Equal(t, relExisting, ResolvePath(relExisting))

	// 当前工作目录中不存在的相对路径回退到可执行文件所在目录。
	relMissing := "direct.txt"
	want := filepath.Join(CurrentDir(), relMissing)
	assert.Equal(t, want, ResolvePath(relMissing))
}
