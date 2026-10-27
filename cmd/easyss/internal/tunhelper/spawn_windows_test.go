//go:build windows

package tunhelper

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHelperStatusError 固定 helper 状态行到父进程错误的映射：只有未提权能拿到
// ErrElevationRequired（同时是 fs.ErrPermission），引擎失败仍要保持原始原因。
func TestHelperStatusError(t *testing.T) {
	require.NoError(t, helperStatusError("READY"))

	err := helperStatusError("ERROR " + elevationRequiredStatus + ": ShellExecuteEx runas 未提权")
	require.ErrorIs(t, err, ErrElevationRequired)
	require.ErrorIs(t, err, fs.ErrPermission)

	engineErr := helperStatusError("ERROR start tun engine: create tun: Access is denied.")
	require.NotErrorIs(t, engineErr, ErrElevationRequired)
	require.Contains(t, engineErr.Error(), "start tun engine")

	bogus := helperStatusError("BOGUS")
	require.Error(t, bogus)
	require.False(t, errors.Is(bogus, ErrElevationRequired))
}
