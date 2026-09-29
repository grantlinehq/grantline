package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type SpireSelector struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
type SpireIssuance struct {
	ObservedAt      time.Time `json:"observed_at"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	ClientReference string    `json:"client_reference"`
}

var SpireEntryID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var SpireSelectorType = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func SpiffeURI(s string) bool {
	id, err := spiffeid.FromString(s)
	return err == nil && len(s) <= 2048 && id.String() == s && id.Path() != ""
}
func SpireTrustDomain(s string) bool {
	td, err := spiffeid.TrustDomainFromString(s)
	return err == nil && td.String() == s && len(s) <= 255
}
func SpireURIInDomain(s, domain string) bool {
	id, err := spiffeid.FromString(s)
	return err == nil && SpiffeURI(s) && id.TrustDomain().String() == domain
}

func validateSpireAttribute(key string, raw json.RawMessage) error {
	bad := fmt.Errorf("attribute %q has an unsupported SPIRE metadata shape", key)
	decode := func(v any) bool {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		return d.Decode(v) == nil && ensureSingleJSONValue(d) == nil
	}
	switch key {
	case "selectors":
		var values []SpireSelector
		if !decode(&values) || values == nil || len(values) == 0 || len(values) > 100 {
			return bad
		}
		seen := map[SpireSelector]bool{}
		for _, s := range values {
			if !SpireSelectorType.MatchString(s.Type) || s.Value == "" || !GitHubText(s.Value, 1024) || seen[s] {
				return bad
			}
			seen[s] = true
		}
	case "parent_entry_ids", "parent_attestor_types", "federates_with":
		var values []string
		if !decode(&values) || values == nil || len(values) > 100 {
			return bad
		}
		seen := map[string]bool{}
		for _, s := range values {
			if seen[s] {
				return bad
			}
			seen[s] = true
			switch key {
			case "parent_entry_ids":
				if !SpireEntryID.MatchString(s) {
					return bad
				}
			case "parent_attestor_types":
				if !SpireSelectorType.MatchString(s) {
					return bad
				}
			case "federates_with":
				if !SpireTrustDomain(s) {
					return bad
				}
			}
		}
	case "x509_svid_ttl_seconds", "jwt_svid_ttl_seconds", "revision_number", "entry_expires_at", "entry_created_at":
		var n *int64
		if !decode(&n) || n == nil || *n < 0 {
			return bad
		}
		if strings.HasSuffix(key, "ttl_seconds") && (*n == 0 || *n > 2147483647) {
			return bad
		}
	case "admin", "downstream":
		var b *bool
		if !decode(&b) || b == nil {
			return bad
		}
	case "x509_issuance":
		var values []SpireIssuance
		if !decode(&values) || values == nil || len(values) > 20 {
			return bad
		}
		for _, v := range values {
			if v.ObservedAt.IsZero() || v.NotBefore.IsZero() || !v.NotAfter.After(v.NotBefore) || v.ObservedAt.Before(v.NotBefore) || !v.ObservedAt.Before(v.NotAfter) || v.ClientReference == "" || !GitHubText(v.ClientReference, 240) {
				return bad
			}
		}
	default:
		var s string
		if !decode(&s) || s == "" {
			return bad
		}
		switch key {
		case "trust_domain":
			if !SpireTrustDomain(s) {
				return bad
			}
		case "entry_id":
			if !SpireEntryID.MatchString(s) {
				return bad
			}
		case "spiffe_id", "parent_spiffe_id":
			if !SpiffeURI(s) {
				return bad
			}
		case "entry_kind":
			if s != "node_alias" && s != "workload" {
				return bad
			}
		case "x509_ttl_mode", "jwt_ttl_mode":
			if s != "explicit" && s != "inherited" {
				return bad
			}
		default:
			return bad
		}
	}
	return nil
}

func validateSpireIdentity(e Entity, source Source) error {
	read := func(k string) string {
		var s string
		if e.FieldStatus[k] == FieldKnown {
			json.Unmarshal(e.Attributes[k], &s)
		}
		return s
	}
	domain := read("trust_domain")
	if !SpireTrustDomain(domain) || e.Scope != source.Scope {
		return fmt.Errorf("SPIRE source/trust-domain scope is inconsistent")
	}
	switch e.Kind {
	case "spire_entry":
		entry, id, parent, kind := read("entry_id"), read("spiffe_id"), read("parent_spiffe_id"), read("entry_kind")
		if !SpireEntryID.MatchString(entry) || e.NativeID != "entry/"+entry || !SpireURIInDomain(id, domain) || !SpireURIInDomain(parent, domain) {
			return fmt.Errorf("SPIRE entry native identity is inconsistent")
		}
		if (kind == "node_alias") != (parent == "spiffe://"+domain+"/spire/server") || kind != "node_alias" && kind != "workload" {
			return fmt.Errorf("SPIRE parent/entry kind is inconsistent")
		}
		for _, typ := range []string{"x509", "jwt"} {
			mode, key := read(typ+"_ttl_mode"), typ+"_svid_ttl_seconds"
			if mode == "explicit" && e.FieldStatus[key] != FieldKnown || mode == "inherited" && e.FieldStatus[key] != FieldUnknown || mode != "explicit" && mode != "inherited" {
				return fmt.Errorf("SPIRE TTL mode/coverage is inconsistent")
			}
		}
	case "spiffe_identity":
		if !SpireURIInDomain(read("spiffe_id"), domain) || e.NativeID != read("spiffe_id") {
			return fmt.Errorf("SPIFFE URI identity is inconsistent")
		}
	case "trust_domain":
		if e.NativeID != "spiffe://"+domain {
			return fmt.Errorf("SPIRE trust-domain identity is inconsistent")
		}
	default:
		return fmt.Errorf("unsupported SPIRE entity kind")
	}
	return nil
}
