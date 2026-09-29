package entra

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const GraphAddress = "https://graph.microsoft.com/v1.0"
const maxTargets = 100
const maxResources = 100
const maxPages = 50
const maxItems = 5000
const maxResponseBytes = 2 << 20

var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var assignmentID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

type Config struct {
	ID, Scope, TenantID, Address, TokenEnv string
	Applications, ServicePrincipals        []string
}

func (c Config) Validate() error {
	if c.ID == "" || !guid.MatchString(c.TenantID) || c.Scope != "tenant/"+c.TenantID || !environmentName.MatchString(c.TokenEnv) {
		return fmt.Errorf("Entra requires id, lowercase tenant UUID, matching tenant scope and token_env")
	}
	if c.Address != "" && c.Address != GraphAddress {
		return fmt.Errorf("Entra supports only the global Microsoft Graph v1.0 endpoint")
	}
	if len(c.Applications)+len(c.ServicePrincipals) == 0 || len(c.Applications)+len(c.ServicePrincipals) > maxTargets {
		return fmt.Errorf("Entra requires 1..100 explicitly selected application/service principal object IDs")
	}
	for _, items := range [][]string{c.Applications, c.ServicePrincipals} {
		seen := map[string]bool{}
		for _, id := range items {
			if !guid.MatchString(id) || seen[id] {
				return fmt.Errorf("Entra targets must be unique lowercase object UUIDs")
			}
			seen[id] = true
		}
	}
	return nil
}

func objectNative(tenant, id string) string { return tenant + "/" + id }
func childNative(tenant, collection, parent, kind, id string) string {
	return tenant + "/" + collection + "/" + parent + "/" + kind + "/" + id
}

// A pagination link must stay on the exact requested collection and retain its
// field projection. Opaque cursor values are forwarded but never recorded.
func pageURL(base, endpoint, selectFields, next string) (string, bool) {
	u, err := url.Parse(next)
	if err != nil || !u.IsAbs() || u.User != nil || u.Fragment != "" || u.RawPath != "" || len(next) > 16384 {
		return "", false
	}
	origin, _ := url.Parse(base)
	if u.Scheme != origin.Scheme || u.Host != origin.Host || u.Path != origin.Path+endpoint {
		return "", false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || query.Get("$select") != selectFields {
		return "", false
	}
	for key, values := range query {
		if len(values) != 1 || (key != "$select" && key != "$skiptoken" && key != "$skip" && key != "$top") {
			return "", false
		}
	}
	return u.String(), true
}

func safeText(s string, max int) bool { return len(s) <= max && !strings.ContainsAny(s, "\x00\r\n") }
