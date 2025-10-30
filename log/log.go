package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	sf "github.com/samber/slog-formatter"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logger = slog.New(DefaultHandler(slog.LevelInfo))

var (
	projectRootOnce sync.Once
	projectRoot     string
)

func getProjectRoot() string {
	projectRootOnce.Do(func() {
		_, currentFile, _, ok := runtime.Caller(0)
		if !ok {
			wd, err := os.Getwd()
			if err != nil {
				projectRoot = ""
				return
			}
			currentFile = wd
		}

		dir := filepath.Dir(currentFile)
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				projectRoot = dir
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				projectRoot = ""
				return
			}
			dir = parent
		}
	})
	return projectRoot
}

func SetLogger(l *slog.Logger) {
	logger = l
}

func Logger() *slog.Logger {
	return logger
}

func Debug(msg string, args ...any) {
	log(slog.LevelDebug, msg, args...)
}

func Info(msg string, args ...any) {
	log(slog.LevelInfo, msg, args...)
}

func Warn(msg string, args ...any) {
	log(slog.LevelWarn, msg, args...)
}

func Error(msg string, args ...any) {
	log(slog.LevelError, msg, args...)
}

func log(level slog.Level, msg string, args ...any) {
	if !logger.Enabled(context.Background(), level) {
		return
	}
	var pcs [1]uintptr
	// skip [runtime.Callers, log.log, log.Info] a total of 3
	runtime.Callers(3, pcs[:])
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(args...)
	_ = logger.Handler().Handle(context.Background(), r)
}

func newReplaceAttrFunc(cn *time.Location) func([]string, slog.Attr) slog.Attr {
	return func(_ []string, a slog.Attr) slog.Attr {
		switch a.Key {
		case slog.SourceKey:
			source := a.Value.Any().(*slog.Source)

			root := getProjectRoot()
			var rel string
			if root != "" {
				var err error
				rel, err = filepath.Rel(root, source.File)
				if err != nil {
					rel = source.File // fallback
				}
			} else {
				wd, _ := os.Getwd()
				var err error
				rel, err = filepath.Rel(wd, source.File)
				if err != nil {
					rel = source.File
				}
			}

			parts := strings.Split(rel, string(filepath.Separator))
			if len(parts) > 2 {
				rel = filepath.Join(parts[len(parts)-2:]...)
			}
			a.Value = slog.StringValue(rel + ":" + strconv.Itoa(source.Line))
		case slog.TimeKey:
			newTime := a.Value.Time().In(cn)
			return slog.Time(a.Key, newTime)
		}
		return a
	}
}

func DefaultHandler(level slog.Level) slog.Handler {
	cn, _ := time.LoadLocation("Asia/Shanghai")
	return sf.NewFormatterHandler(sf.TimeFormatter(time.DateTime, time.UTC))(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			AddSource:   true,
			Level:       level,
			ReplaceAttr: newReplaceAttrFunc(cn),
		}),
	)
}

func JSONHandler(w io.Writer, level slog.Level) slog.Handler {
	cn, _ := time.LoadLocation("Asia/Shanghai")
	return sf.NewFormatterHandler(sf.TimeFormatter(time.DateTime, time.UTC))(
		slog.NewJSONHandler(w, &slog.HandlerOptions{
			AddSource:   true,
			Level:       level,
			ReplaceAttr: newReplaceAttrFunc(cn),
		}),
	)
}

func TextHandler(w io.Writer, level slog.Level) slog.Handler {
	cn, _ := time.LoadLocation("Asia/Shanghai")
	return sf.NewFormatterHandler(sf.TimeFormatter(time.DateTime, time.UTC))(
		slog.NewTextHandler(w, &slog.HandlerOptions{
			AddSource:   true,
			Level:       level,
			ReplaceAttr: newReplaceAttrFunc(cn),
		}),
	)
}

func FileWriter(outputFile string) io.WriteCloser {
	return &lumberjack.Logger{
		Filename:   outputFile,
		MaxSize:    10,
		MaxAge:     1,
		MaxBackups: 1,
		LocalTime:  true,
	}
}

func Init(outputFile, level string) {
	l := slog.LevelInfo
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	}

	if outputFile != "" {
		SetLogger(slog.New(TextHandler(FileWriter(outputFile), l)))
	} else {
		SetLogger(slog.New(DefaultHandler(l)))
	}
}
