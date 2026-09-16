package util

import "testing"

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/home/nange/Easyss/easyss.log", "/home/nange/Easyss/easyss.log"},
		{"", "''"},
		{"/tmp/a b.log", "'/tmp/a b.log'"},
		{"/tmp/it's.log", `'/tmp/it'\''s.log'`},
		{"/tmp/$HOME.log", "'/tmp/$HOME.log'"},
		{"/tmp/back\\slash.log", "'/tmp/back\\slash.log'"},
	}

	for _, c := range cases {
		if got := shellQuote(c.in); got != c.want {
			t.Fatalf("shellQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestShellJoin(t *testing.T) {
	got := ShellJoin([]string{"tail", "-n", "50", "-f", "/tmp/a b.log"})
	if want := "tail -n 50 -f '/tmp/a b.log'"; got != want {
		t.Fatalf("ShellJoin = %q, want %q", got, want)
	}
}
