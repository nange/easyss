package util

import "strings"

// ShellQuote quotes a single argument for the shell. Arguments without any
// character the shell treats specially are left untouched.
func ShellQuote(s string) string {
	const specials = " \t\n\"'\\$`&|;<>()*?[]{}~#!"

	if s != "" && !strings.ContainsAny(s, specials) {
		return s
	}

	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ShellJoin quotes every argument and joins them with spaces, so the result
// can be handed to a shell or to a terminal emulator that expects one shell
// command string.
func ShellJoin(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, ShellQuote(arg))
	}

	return strings.Join(quoted, " ")
}
