//go:build !headless && windows

package tray

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFormatTitleUsesAcceleratorColumn 固定 Windows 的排布契约：标签与指标之间只放一个
// "\t"，由 Win32 把指标右对齐到加速键列——补空格会在菜单右端留下大段空白，也不能右对齐。
func TestFormatTitleUsesAcceleratorColumn(t *testing.T) {
	t.Parallel()

	title := formatTitle("香港DV", 60, "649 B/s", 0)
	require.Equal(t, "香港DV\t60ms  ↓649 B/s", title)
	require.NotContains(t, title, "\u2003", "Windows 上不该再补空格")
}

// TestFormatTitleTabColumnKeepsLongLabelBounded 超长标签仍要先截断：否则标签会把加速键列
// 推得很远，菜单宽到屏幕外时指标就看不见了。
func TestFormatTitleTabColumnKeepsLongLabelBounded(t *testing.T) {
	t.Parallel()

	label := "very.long.hostname.for.a.branch.office.example.com:443"
	title := formatTitle(label, 60, "649 B/s", 0)

	text, metrics, ok := strings.Cut(title, "\t")
	require.True(t, ok, "长标签也要保留加速键列: %q", title)
	require.NotEqual(t, label, text, "长标签必须被截断: %q", text)
	require.True(t, strings.HasSuffix(text, "…"), "截断后要带省略号: %q", text)
	require.Equal(t, "60ms  ↓649 B/s", metrics)
}
