package util

import (
	"bufio"
	"errors"
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

// ResolvePath resolves a possibly-relative file path to an absolute one when
// it cannot be found in the current working directory. On macOS the app is
// often launched by Finder or launchd with cwd=/ (LaunchAgent plists have no
// WorkingDirectory), so relative paths in config files (direct.txt, proxy.txt,
// ca_path, cert files, ...) would otherwise never be found even though they
// sit next to the binary/.app bundle.
//
// Empty strings and absolute paths are returned unchanged; relative paths that
// exist in the cwd are kept as-is for backward compatibility; anything else is
// joined with the executable directory (see CurrentDir).
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
	path, err := os.Executable()
	if err != nil {
		return ""
	}

	a, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ""
	}

	dir := filepath.Dir(a)

	// If running from inside a macOS .app bundle, return the directory
	// containing the .app so that config files live alongside the bundle.
	if isAppBundleDir(dir) {
		// dir is .../Easyss.app/Contents/MacOS → go up 3 → parent of .app
		return filepath.Dir(filepath.Dir(filepath.Dir(dir)))
	}

	return dir
}

// isAppBundleDir reports whether dir is the MacOS directory inside a .app bundle.
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
		return nil, err
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
