package util

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	rotate "github.com/snowzach/rotatefilehook"
)

const (
	LogMaxAge     = 1  // one day
	LogMaxBackups = 1  // one backup
	LogMaxSize    = 10 // 10Mb
	LogFileName   = "easyss.log"
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

func CurrentDir() string {
	return filepath.Dir(os.Args[0])
}

func LogFilePath() string {
	dir := CurrentDir()
	filename := LogFileName
	return filepath.Join(dir, filename)
}

func RotateFileHook() (log.Hook, error) {
	return rotate.NewRotateFileHook(rotate.RotateFileConfig{
		Filename:   LogFileName,
		MaxSize:    LogMaxSize,
		MaxBackups: LogMaxBackups,
		MaxAge:     LogMaxAge,
		Level:      log.InfoLevel,
		Formatter:  &log.JSONFormatter{TimestampFormat: "2006-01-02 15:04:05.000"},
	})
}

func SetLogFileHook(logDir string) {
	logFilePath := filepath.Join(logDir, LogFileName)
	hook, err := rotate.NewRotateFileHook(rotate.RotateFileConfig{
		Filename:   logFilePath,
		MaxSize:    LogMaxSize,
		MaxBackups: LogMaxBackups,
		MaxAge:     LogMaxAge,
		Level:      log.InfoLevel,
		Formatter:  &log.JSONFormatter{TimestampFormat: "2006-01-02 15:04:05.000"},
	})
	if err != nil {
		panic(err)
	}
	log.AddHook(hook)
}
