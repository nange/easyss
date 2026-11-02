package config

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckPassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"empty 留给 DeriveMasterKey", "", false},
		{"7 字符拒绝", strings.Repeat("a", 7), true},
		{"8 字符通过", strings.Repeat("a", 8), false},
		{"15 字符通过但告警", strings.Repeat("a", 15), false},
		{"16 字符通过", strings.Repeat("a", 16), false},
		// 按字符数而不是字节数：6 个汉字是 18 字节，不能因为字节数够就放行。
		{"多字节按字符计", "口令口令口令", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPassword(tc.password)
			if tc.wantErr {
				if !errors.Is(err, ErrPasswordTooShort) {
					t.Fatalf("CheckPassword(%q) = %v, want ErrPasswordTooShort", tc.password, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckPassword(%q) = %v, want nil", tc.password, err)
			}
		})
	}
}

func TestPasswordWeak(t *testing.T) {
	t.Parallel()

	tests := []struct {
		password string
		want     bool
	}{
		{"", false},
		{strings.Repeat("a", 7), true},
		{strings.Repeat("a", 8), true},
		{strings.Repeat("a", 15), true},
		{strings.Repeat("a", 16), false},
		{strings.Repeat("口令", 8), false},
	}
	for _, tc := range tests {
		if got := PasswordWeak(tc.password); got != tc.want {
			t.Errorf("PasswordWeak(%q) = %v, want %v", tc.password, got, tc.want)
		}
	}
}
