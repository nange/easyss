package rule

import (
	"errors"
	"fmt"

	"github.com/nange/easyss/v3/util"
)

// ParseFile 读取并解析一个规则文件。返回的 Set 永不为 nil；无法解析的行被跳过并连同
// 行号一起返回。"路径写错"与"某几行写错"因此是两种严重程度不同的问题，由调用方分别处置。
func ParseFile(path string, opts Options) (*Set, []*Error, error) {
	if path == "" {
		return New(), nil, nil
	}
	lines, err := util.ReadFileLines(path)
	if err != nil {
		return New(), nil, err
	}
	set, errs := ParseLines(lines, opts)
	return set, errs, nil
}

// FileError 把行级错误汇总成单个错误，供"加载失败即致命"的调用方使用。最多列出 3 条：
// 规则文件出错时通常一次错一片，逐条列出只会把启动日志刷满。
func FileError(path string, errs []*Error) error {
	if len(errs) == 0 {
		return nil
	}
	const maxShown = 3
	shown := errs
	var extra error
	if len(errs) > maxShown {
		shown = errs[:maxShown]
		extra = fmt.Errorf("... and %d more", len(errs)-maxShown)
	}
	joined := make([]error, 0, len(shown)+1)
	for _, e := range shown {
		joined = append(joined, e)
	}
	if extra != nil {
		joined = append(joined, extra)
	}
	return fmt.Errorf("%s: %w", path, errors.Join(joined...))
}
