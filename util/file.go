package util

import (
	"io"
	"os"
	"path/filepath"
	"time"

	rotatelogs "github.com/lestrrat/go-file-rotatelogs"
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

func GetLogFileName() string {
	return "easyss.log"
}

func GetLogFilePath() string {
	dir := GetCurrentDir()
	filename := GetLogFileName()
	return filepath.Join(dir, filename)
}

func GetLogFileWriter(maxAge time.Duration, rotationTime time.Duration) (io.Writer, error) {
	return rotatelogs.New(
		GetLogFilePath()+".%Y%m%d%H%M",
		rotatelogs.WithLinkName(GetLogFilePath()),
		rotatelogs.WithMaxAge(maxAge),
		rotatelogs.WithRotationTime(rotationTime),
	)
}
