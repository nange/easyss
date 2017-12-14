package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
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

func GetCurrentDir() string {
	return filepath.Dir(os.Args[0])
}

func GetLogFilePath() string {
	dir := GetCurrentDir()
	y, m, d := time.Now().Date()
	filename := fmt.Sprintf("easyss-%d%d%d.log", y, m, d)
	return filepath.Join(dir, filename)
}

func GetLogFileWriter() (io.Writer, error) {
	logfile := GetLogFilePath()
	return os.OpenFile(logfile, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
}
