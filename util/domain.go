package util

import "strings"

// SubDomains returns all parent domains for subdomain matching.
// For "www.example.com", returns ["example.com"].
func SubDomains(domain string) []string {
	if domain == "" {
		return nil
	}
	subs := make([]string, 0, 8)
	i := strings.Index(domain, ".")
	for i > 0 {
		domain = domain[i+1:]
		subs = append(subs, domain)
		i = strings.Index(domain, ".")
	}
	if len(subs) > 1 {
		return subs[:len(subs)-1]
	}
	return nil
}
