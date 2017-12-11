package utils

import (
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/pkg/errors"
)

func FileExists(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err == nil {
		if fi.Mode()&os.ModeType == 0 {
			return true, nil
		}
		return false, errors.New(path + " exists but is not regular file")
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, errors.WithStack(err)
}

func GetFileOutputWriter(binpath string) (io.Writer, error) {
	dir, _ := path.Split(binpath)
	y, m, d := time.Now().Date()
	filename := fmt.Sprintf("easyss-%d%d%d.log", y, m, d)

	return os.OpenFile(path.Join(dir, filename), os.O_APPEND|os.O_CREATE, os.ModeAppend)
}
