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

func CurrentDir() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(path)
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
	tf, err := os.CreateTemp("", filename)
	if err != nil {
		return "", err
	}

	if _, err := tf.Write(content); err != nil {
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
	defer f.Close()

	lines := make([]string, 0, 16)
	r := bufio.NewReader(f)
	for {
		line, _, err := r.ReadLine()
		if err == io.EOF {
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
