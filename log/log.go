package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	sf "github.com/samber/slog-formatter"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logger = slog.New(DefaultHandler(slog.LevelInfo))

// AtomicLevel is a thread-safe slog.Level that can be changed at runtime.
type AtomicLevel struct {
	level atomic.Int32
}

// Level returns the current log level.
func (al *AtomicLevel) Level() slog.Level {
	return slog.Level(al.level.Load())
}

// SetLevel sets the log level.
func (al *AtomicLevel) SetLevel(level slog.Level) {
	al.level.Store(int32(level))
}

var atomicLevel AtomicLevel

// SetLevel dynamically changes the log level at runtime.
func SetLevel(level slog.Level) {
	atomicLevel.SetLevel(level)
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

			dir, file := filepath.Split(source.File)
			parentDir := filepath.Base(filepath.Clean(dir))

			var rel string
			if parentDir == "easyss" {
				rel = file
			} else {
				rel = filepath.Join(parentDir, file)
			}

			a.Value = slog.StringValue(rel + ":" + strconv.Itoa(source.Line))
		case slog.TimeKey:
			newTime := a.Value.Time().In(cn)
			return slog.Time(a.Key, newTime)
		}
		return a
	}
}

func DefaultHandler(level slog.Leveler) slog.Handler {
	cn, _ := time.LoadLocation("Asia/Shanghai")
	if cn == nil {
		cn = time.UTC
	}
	return sf.NewFormatterHandler(sf.TimeFormatter(time.DateTime, cn))(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			AddSource:   true,
			Level:       level,
			ReplaceAttr: newReplaceAttrFunc(cn),
		}),
	)
}

func JSONHandler(w io.Writer, level slog.Leveler) slog.Handler {
	cn, _ := time.LoadLocation("Asia/Shanghai")
	if cn == nil {
		cn = time.UTC
	}
	return sf.NewFormatterHandler(sf.TimeFormatter(time.DateTime, cn))(
		slog.NewJSONHandler(w, &slog.HandlerOptions{
			AddSource:   true,
			Level:       level,
			ReplaceAttr: newReplaceAttrFunc(cn),
		}),
	)
}

func TextHandler(w io.Writer, level slog.Leveler) slog.Handler {
	cn, _ := time.LoadLocation("Asia/Shanghai")
	if cn == nil {
		cn = time.UTC
	}
	return sf.NewFormatterHandler(sf.TimeFormatter(time.DateTime, cn))(
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
	atomicLevel.SetLevel(l)

	if outputFile != "" {
		SetLogger(slog.New(slog.NewMultiHandler(TextHandler(FileWriter(outputFile), &atomicLevel), DefaultHandler(&atomicLevel))))
	} else {
		SetLogger(slog.New(DefaultHandler(&atomicLevel)))
	}
}
