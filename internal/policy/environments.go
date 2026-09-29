package policy

import (
	"github.com/grantlinehq/grantline/internal/model"
	"fmt"
	"regexp"
	"strings"
)

type EnvironmentPair struct{ First, Second string }
type SharedIdentity struct {
	EnvironmentPair
	SourceID, Kind, NativeID, Reason string
}

var environmentID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$`)

func pairKey(p EnvironmentPair) string {
	if p.First < p.Second {
		return p.First + "\x00" + p.Second
	}
	return p.Second + "\x00" + p.First
}
func validateEnvironments(id string, rule Rule) error {
	if id != "IL008" {
		if len(rule.SeparatedEnvironments)+len(rule.AllowedSharedIdentities) > 0 {
			return fmt.Errorf("environment settings require IL008")
		}
		return nil
	}
	if len(rule.SeparatedEnvironments) == 0 || len(rule.SeparatedEnvironments) > 100 || len(rule.AllowedSharedIdentities) > 1000 {
		return fmt.Errorf("IL008 needs 1–100 separated environment pairs and at most 1000 exceptions")
	}
	pairs := map[string]bool{}
	for _, p := range rule.SeparatedEnvironments {
		key := pairKey(p)
		if !environmentID.MatchString(p.First) || !environmentID.MatchString(p.Second) || p.First == p.Second || pairs[key] {
			return fmt.Errorf("IL008 needs unique distinct exact environment pairs")
		}
		pairs[key] = true
	}
	seen := map[string]bool{}
	for _, e := range rule.AllowedSharedIdentities {
		key := e.SourceID + "\x00" + e.Kind + "\x00" + e.NativeID + "\x00" + pairKey(e.EnvironmentPair)
		if !pairs[pairKey(e.EnvironmentPair)] || e.SourceID == "" || e.NativeID == "" || len(e.NativeID) > 2048 || strings.ContainsAny(e.NativeID, "\x00\r\n") || !PrincipalKind(e.Kind) || strings.Trim(e.Reason, " \t\r\n\"'") == "" || !model.GitHubText(e.Reason, 300) || seen[key] {
			return fmt.Errorf("IL008 exceptions need exact native principals, a configured pair and a bounded reason")
		}
		seen[key] = true
	}
	return nil
}
func PrincipalKind(kind string) bool {
	return kind == "service_account" || kind == "service_principal" || kind == "spiffe_identity"
}
func parseEnvironmentEntries(lines []yamlLine, position int, kind string) ([]map[string]string, int, error) {
	var entries []map[string]string
	for position < len(lines) && lines[position].indent > 4 {
		line := lines[position]
		if line.indent != 6 || !strings.HasPrefix(line.text, "- ") {
			return nil, 0, lineError(line, "entries need six-space list indentation")
		}
		entry := map[string]string{}
		set := func(line yamlLine, text string) error {
			key, value, err := splitMappingText(line, text)
			if err != nil {
				return err
			}
			if _, ok := entry[key]; ok {
				return lineError(line, "duplicate entry key")
			}
			allowed := key == "first" || key == "second"
			if kind == "allowed_shared_identities" {
				allowed = allowed || key == "source_id" || key == "kind" || key == "native_id" || key == "reason"
			}
			if !allowed {
				return lineError(line, "unsupported environment entry key")
			}
			scalar, err := parseScalar(line, value)
			entry[key] = scalar
			return err
		}
		if err := set(line, line.text[2:]); err != nil {
			return nil, 0, err
		}
		position++
		for position < len(lines) && lines[position].indent > 6 {
			line = lines[position]
			if line.indent != 8 {
				return nil, 0, lineError(line, "entry fields need eight-space indentation")
			}
			if err := set(line, line.text); err != nil {
				return nil, 0, err
			}
			position++
		}
		entries = append(entries, entry)
	}
	return entries, position, nil
}
