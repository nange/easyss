package util

import (
	"strings"
)

func removeProxyEnv(env []string) []string {
	proxyEnv := []string{"http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}
	var newEnv []string
	for _, e := range env {
		shouldSkip := false
		for _, p := range proxyEnv {
			if strings.HasPrefix(e, p+"=") {
				shouldSkip = true
				break
			}
		}
		if !shouldSkip {
			newEnv = append(newEnv, e)
		}
	}
	return newEnv
}
