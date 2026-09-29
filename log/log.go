package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	sf "github.com/samber/slog-formatter"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logger = slog.New(DefaultHandler(slog.LevelInfo))

// fileOutput 记录当前日志器的文件输出（lumberjack 写入器），使重新初始化和显式
// 关闭都能释放底层文件句柄。没有这条记录时，句柄只能等 GC 回收——被打开的文件
// 在 Windows 上无法删除或重命名，而 Android 绑定会在同一个进程里反复走
// Start/Stop，宿主删除日志文件的操作会被遗留句柄挡住（见 CloseFileOutput）。
var (
	fileOutputMu sync.Mutex
	fileOutput   io.Closer
)

// AtomicLevel 是可在运行时修改的线程安全 slog.Level。
type AtomicLevel struct {
	level atomic.Int32
}

// Level 返回当前日志级别。
func (al *AtomicLevel) Level() slog.Level {
	return slog.Level(al.level.Load())
}

// SetLevel 设置日志级别。
func (al *AtomicLevel) SetLevel(level slog.Level) {
	al.level.Store(int32(level))
}

var atomicLevel AtomicLevel

// SetLevel 在运行时动态修改日志级别。
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
	// 跳过 [runtime.Callers, log.log, log.Info] 共 3 层
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

	// 先摘下旧的文件输出（安装完新日志器后再关闭它）：初始化可能被同一进程
	// 反复调用，不接管上一个写入器就会累积已打开的文件句柄。
	fileOutputMu.Lock()
	prev := fileOutput
	fileOutput = nil
	fileOutputMu.Unlock()

	if outputFile != "" {
		w := FileWriter(outputFile)
		fileOutputMu.Lock()
		fileOutput = w
		fileOutputMu.Unlock()
		SetLogger(slog.New(slog.NewMultiHandler(TextHandler(w, &atomicLevel), DefaultHandler(&atomicLevel))))
	} else {
		SetLogger(slog.New(DefaultHandler(&atomicLevel)))
	}

	if prev != nil {
		_ = prev.Close()
	}
}

// CloseFileOutput 关闭文件输出，并把日志器切回"只写 stdout、级别不变"的状态；
// 下一次 Init 会按传入的路径重新打开文件。没有文件输出时它是空操作，因此可以
// 重复调用。
//
// 释放句柄这件事必须由初始化日志的一方在停止时显式完成：被打开的文件在
// Windows 上无法删除/重命名，宿主（Android 绑定、托盘）在服务停止后清理或轮转
// 日志文件时会被遗留句柄挡住。
func CloseFileOutput() error {
	fileOutputMu.Lock()
	w := fileOutput
	fileOutput = nil
	fileOutputMu.Unlock()

	if w == nil {
		return nil
	}

	// 先摘掉文件处理器再关句柄：lumberjack 在句柄为 nil 时会于下一次写入重新
	// 打开文件，若日志器仍挂着文件处理器，"关闭"就会被紧随其后的写入撤销，
	// 宿主删除日志文件的操作也就白做了。
	SetLogger(slog.New(DefaultHandler(&atomicLevel)))
	return w.Close()
}
