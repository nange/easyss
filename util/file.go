package util

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	return false, err
}

// ResolvePath 在相对文件路径无法于当前工作目录中找到时，将其解析为绝对路径。
// 在 macOS 上，应用常由 Finder 或 launchd 以 cwd=/ 启动（LaunchAgent 的
// plist 没有 WorkingDirectory），因此配置文件（direct.txt、proxy.txt、
// ca_path、证书文件等）中的相对路径即使与二进制/.app bundle 位于同一目录，
// 也永远无法被找到。
//
// 空字符串和绝对路径原样返回；存在于当前工作目录中的相对路径为了向后兼容
// 保持原样；其余情况则与可执行文件所在目录拼接（参见 CurrentDir）。
func ResolvePath(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if dir := CurrentDir(); dir != "" {
		return filepath.Join(dir, p)
	}
	return p
}

func CurrentDir() string {
	path, err := ExecutablePath()
	if err != nil {
		return ""
	}

	dir := filepath.Dir(path)

	// 如果从 macOS .app bundle 内部运行，返回包含 .app 的目录，
	// 使配置文件与 bundle 放在一起。
	if isAppBundleDir(dir) {
		// dir 为 .../Easyss.app/Contents/MacOS → 向上 3 级 → .app 的父目录
		return filepath.Dir(filepath.Dir(filepath.Dir(dir)))
	}

	return dir
}

// isAppBundleDir 报告 dir 是否为 .app bundle 内的 MacOS 目录。
func isAppBundleDir(dir string) bool {
	if !strings.HasSuffix(dir, "/Contents/MacOS") {
		return false
	}
	contentsDir := filepath.Dir(dir) // .../Contents
	if !strings.HasSuffix(contentsDir, "/Contents") {
		return false
	}
	appDir := filepath.Dir(contentsDir) // .../Easyss.app
	return strings.HasSuffix(appDir, ".app")
}

func DirFileList(dir string) ([]string, error) {
	list, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, v := range list {
		if !v.IsDir() {
			files = append(files, v.Name())
		}
	}
	return files, nil
}

func WriteToTemp(filename string, content []byte) (namePath string, err error) {
	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)
	pattern := base + "_*" + ext
	tf, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}

	if _, err := tf.Write(content); err != nil {
		tf.Close()           //nolint:errcheck
		os.Remove(tf.Name()) //nolint:errcheck
		return "", err
	}

	return tf.Name(), tf.Close()
}

func ReadFileLines(file string) ([]string, error) {
	if e, err := FileExists(file); !e || err != nil {
		if err != nil {
			return nil, err
		}
		// FileExists 对不存在的文件返回 (false, nil)；这里将其转换为
		// 真正的错误返回，而不是静默返回空行列表
		// （否则会掩盖配置错误的规则文件路径）。
		return nil, fmt.Errorf("%s: %w", file, os.ErrNotExist)
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	// nolint:errcheck
	defer f.Close()

	lines := make([]string, 0, 16)
	r := bufio.NewReader(f)
	for {
		line, _, err := r.ReadLine()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		lines = append(lines, string(line))
	}

	return lines, nil
}

func ReadFileLinesMap(file string) (map[string]struct{}, error) {
	lines, err := ReadFileLines(file)
	if err != nil {
		return nil, err
	}

	m := make(map[string]struct{})
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			m[line] = struct{}{}
		}
	}
	return m, nil
}
