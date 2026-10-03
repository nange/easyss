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

// logger 是当前日志器。用原子指针而非普通变量：Init/CloseFileOutput/SetLogger
// 与后台 goroutine 的日志写入天然并发（例如 runner 在后台启动 socks5 服务器并
// 输出 "listening"，宿主同时调用 Stop 关闭文件输出），普通变量在这条路径上是
// 数据竞争，-race 下会直接判失败。
var logger atomic.Pointer[slog.Logger]

func init() {
	logger.Store(slog.New(DefaultHandler(slog.LevelInfo)))
}

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
	logger.Store(l)
}

func Logger() *slog.Logger {
	return logger.Load()
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
	l := logger.Load()
	if !l.Enabled(context.Background(), level) {
		return
	}
	var pcs [1]uintptr
	// 跳过 [runtime.Callers, log.log, log.Info] 共 3 层
	runtime.Callers(3, pcs[:])
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(args...)
	_ = l.Handler().Handle(context.Background(), r)
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

// closableFileWriter 包住 lumberjack 写入器，让"关闭"成为终态。
//
// 只把包级 logger 换成 stdout-only 不足以释放句柄：后台 goroutine 可能在
// CloseFileOutput 之前就已经 Load 到带文件处理器的旧 logger（runner 正是在
// goroutine 里打 "[SOCKS5] listening"，宿主同时调用 Stop），这次写入会晚于
// Close 到达 lumberjack；而 lumberjack 的语义是"写时若句柄为 nil 就重新打开"，
// 于是刚释放的句柄被迟到的写入复活——Windows 上宿主随即删不掉日志文件，Android
// 上的轮转同样被挡（windows-arm64 上 mobile.TestStartAppliesLogConfig 的偶发
// 失败就是这条路径）。这层包装让 Close 之后的写入被丢弃，句柄不会再回来。
type closableFileWriter struct {
	mu     sync.Mutex
	writer *lumberjack.Logger
	closed bool
}

func (w *closableFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		// 丢弃而非报错：这条记录通常已经由 MultiHandler 的 stdout 分支写出，
		// 把错误冒泡给调用方只会让它看到与日志目的无关的失败。
		return len(p), nil
	}
	return w.writer.Write(p)
}

func (w *closableFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true
	return w.writer.Close()
}

func FileWriter(outputFile string) io.WriteCloser {
	return &closableFileWriter{
		writer: &lumberjack.Logger{
			Filename:   outputFile,
			MaxSize:    10,
			MaxAge:     1,
			MaxBackups: 1,
			LocalTime:  true,
		},
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

	// 两层都要做：换掉包级 logger 让后续记录只走 stdout，关掉写入器释放句柄。
	// 前者管住"之后 Load 到新 logger 的写入"，后者（closableFileWriter 的终态
	// 语义）管住"在此之前就 Load 到旧 logger、写完却晚于本次 Close 的写入"。
	SetLogger(slog.New(DefaultHandler(&atomicLevel)))
	return w.Close()
}
