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

// logger 是当前日志器。必须用原子指针：Init/CloseFileOutput 与后台 goroutine
// 的日志写入天然并发，普通变量在 -race 下会直接判数据竞争。
var logger atomic.Pointer[slog.Logger]

func init() {
	logger.Store(slog.New(DefaultHandler(slog.LevelInfo)))
}

// fileOutput 记录当前的文件输出，使重新初始化与显式关闭都能释放底层句柄。
// 只靠 GC 不够：Windows 上被打开的文件无法删除或重命名。
var (
	fileOutputMu sync.Mutex
	fileOutput   io.Closer
)

// AtomicLevel 是可在运行时修改的线程安全 slog.Level。
type AtomicLevel struct {
	level atomic.Int32
}

func (al *AtomicLevel) Level() slog.Level {
	return slog.Level(al.level.Load())
}

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

// At 以给定级别写日志，供调用点按运行期条件选择级别（如首次/重复）。source 与固定级别
// 的包装函数一样归属到调用点。
func At(level slog.Level, msg string, args ...any) {
	log(level, msg, args...)
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

// closableFileWriter 让"关闭"成为终态：后台 goroutine 可能在 Close 之前就 Load 到旧 logger，
// 而 lumberjack 的语义是"写时句柄为 nil 就重新打开"，迟到的写入会把刚释放的句柄复活。
type closableFileWriter struct {
	mu     sync.Mutex
	writer *lumberjack.Logger
	closed bool
}

func (w *closableFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		// 丢弃而不报错：这条记录通常已由 MultiHandler 的 stdout 分支写出，
		// 冒泡错误只会让调用方看到与日志目的无关的失败。
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

// Config 是日志配置的线格式（客户端与服务端共用），Init 是唯一的应用入口。
type Config struct {
	Level    string `json:"level"`
	FilePath string `json:"file_path"`
}

func Init(cfg Config) {
	l := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	}
	atomicLevel.SetLevel(l)

	// 先摘下旧的文件输出、装完新日志器后再关闭它：Init 可能被同一进程反复调用，
	// 不接管上一个写入器就会累积已打开的句柄。
	fileOutputMu.Lock()
	prev := fileOutput
	fileOutput = nil
	fileOutputMu.Unlock()

	if cfg.FilePath != "" {
		w := FileWriter(cfg.FilePath)
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

// CloseFileOutput 关闭文件输出并把日志器切回"只写 stdout、级别不变"，没有文件输出时是空操作。
// 句柄必须由初始化日志的一方显式释放，否则 Windows 上无法删除/重命名被占用的日志文件。
func CloseFileOutput() error {
	fileOutputMu.Lock()
	w := fileOutput
	fileOutput = nil
	fileOutputMu.Unlock()

	if w == nil {
		return nil
	}

	// 两层缺一不可：换掉包级 logger 管住之后的写入，关闭写入器（终态语义）管住先已 Load
	// 到旧 logger、却晚于本次 Close 的写入。
	SetLogger(slog.New(DefaultHandler(&atomicLevel)))
	return w.Close()
}
