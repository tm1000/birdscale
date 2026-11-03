package routes

import (
	"strings"
)

// DomainEntries splits the domain-resource entries out of a networks list.
// exact are plain names ("wiki.example.internal"); wildcards are the suffixes
// of "*.suffix" entries ("example.internal"). Names are lower-cased with no
// trailing dot. CIDRs, bare IPs and anything with characters that cannot be
// in a DNS name are ignored.
func DomainEntries(networks []string) (exact, wildcards []string) {
	seenE, seenW := map[string]bool{}, map[string]bool{}
	for _, n := range networks {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" {
			continue
		}
		if _, ok := ParseNetwork(n); ok {
			continue
		}
		if suf, ok := strings.CutPrefix(n, "*."); ok {
			if validName(suf) && !seenW[suf] {
				seenW[suf] = true
				wildcards = append(wildcards, suf)
			}
			continue
		}
		if validName(n) && !seenE[n] {
			seenE[n] = true
			exact = append(exact, n)
		}
	}
	return exact, wildcards
}

// MatchDomain reports whether name falls under a domain resource: an exact
// entry, or a name strictly below a wildcard suffix.
func MatchDomain(name string, exact, wildcards []string) bool {
	name = NormalizeName(name)
	for _, e := range exact {
		if name == e {
			return true
		}
	}
	for _, w := range wildcards {
		if strings.HasSuffix(name, "."+w) {
			return true
		}
	}
	return false
}

// NormalizeName lower-cases a DNS name and strips the trailing dot.
func NormalizeName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// validName accepts letters, digits, '-', '_' and dots, with at least one dot-free label.
func validName(s string) bool {
	if s == "" || len(s) > 253 || strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
