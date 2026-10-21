package shaper

import (
	"encoding/json"
	"testing"
)

// 固定 shaper.* 的线格式：客户端与服务端直接复用 Config，键名或平铺结构一旦漂移，
// 用户配置会静默失效。
func TestConfigJSONShape(t *testing.T) {
	cfg := Config{BatchWindowMS: 3, BudgetRatio: 0.03, BudgetCap: 16384}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"batch_window_ms":3,"cover_budget_ratio":0.03,"cover_budget_cap":16384}`
	if string(data) != want {
		t.Fatalf("Marshal = %s, want %s", data, want)
	}

	var got Config
	if err := json.Unmarshal([]byte(`{"batch_window_ms":7,"cover_budget_ratio":0.5,"cover_budget_cap":4096}`), &got); err != nil {
		t.Fatal(err)
	}
	if got.BatchWindowMS != 7 || got.BudgetRatio != 0.5 || got.BudgetCap != 4096 {
		t.Fatalf("Unmarshal = %+v", got)
	}
}
