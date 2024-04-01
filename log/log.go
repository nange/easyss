package log

import (
	"io"
	"log/slog"
	"os"
	"time"

	sf "github.com/samber/slog-formatter"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logger = slog.New(DefaultHandler())

func SetLogger(l *slog.Logger) {
	logger = l
}

func Logger() *slog.Logger {
	return logger
}

func Debug(msg string, args ...any) {
	logger.Debug(msg, args...)
}

func Info(msg string, args ...any) {
	logger.Info(msg, args...)
}

func Warn(msg string, args ...any) {
	logger.Warn(msg, args...)
}

func Error(msg string, args ...any) {
	logger.Error(msg, args...)
}

func DefaultHandler() slog.Handler {
	cn, _ := time.LoadLocation("Asia/Shanghai")
	return sf.NewFormatterHandler(sf.TimeFormatter(time.DateTime, time.UTC))(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
			ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
				if a.Key != "time" {
					return a
				}
				newTime := a.Value.Time().In(cn)
				return slog.Time(a.Key, newTime)
			},
		}),
	)
}

func JSONHandler(w io.Writer, level slog.Level) slog.Handler {
	cn, _ := time.LoadLocation("Asia/Shanghai")
	return sf.NewFormatterHandler(sf.TimeFormatter(time.DateTime, time.UTC))(
		slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
				if a.Key != "time" {
					return a
				}
				newTime := a.Value.Time().In(cn)
				return slog.Time(a.Key, newTime)
			},
		}),
	)

}

func TextHandler(w io.Writer, level slog.Level) slog.Handler {
	cn, _ := time.LoadLocation("Asia/Shanghai")
	return sf.NewFormatterHandler(sf.TimeFormatter(time.DateTime, time.UTC))(
		slog.NewTextHandler(w, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
				if a.Key != "time" {
					return a
				}
				newTime := a.Value.Time().In(cn)
				return slog.Time(a.Key, newTime)
			},
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

	SetLogger(slog.New(TextHandler(FileWriter(outputFile), l)))
}
