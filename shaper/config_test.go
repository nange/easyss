package shaper

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// 固定 shaper.* 的键名与平铺结构（JSON 对象键序不属于契约）：客户端与服务端直接
// 复用 Config，键名或结构一旦漂移，用户配置会静默失效。
func TestConfigJSONShape(t *testing.T) {
	cfg := Config{BatchWindowMS: 3, BudgetRatio: 0.03, BudgetCap: 16384}

	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.JSONEq(t, `{"batch_window_ms":3,"cover_budget_ratio":0.03,"cover_budget_cap":16384}`, string(data))

	var got Config
	require.NoError(t, json.Unmarshal([]byte(`{"batch_window_ms":7,"cover_budget_ratio":0.5,"cover_budget_cap":4096}`), &got))
	require.Equal(t, Config{BatchWindowMS: 7, BudgetRatio: 0.5, BudgetCap: 4096}, got)
}
