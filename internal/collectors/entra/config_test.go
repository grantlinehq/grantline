package entra

import (
	"strings"
	"testing"
)

func TestEntraConfigScopeAndEndpoint(t *testing.T) {
	c := Config{ID: "entra", TenantID: strings.Repeat("1", 8) + "-1111-1111-1111-111111111111", TokenEnv: "GRAPH_AUTH", Applications: []string{"22222222-2222-2222-2222-222222222222"}}
	c.Scope = "tenant/" + c.TenantID
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Address = "https://attacker.invalid/v1.0" }, func(c *Config) { c.Scope = "tenant/wrong" }, func(c *Config) { c.TokenEnv = "raw token" }, func(c *Config) { c.Applications = []string{"name-not-object-id"} }, func(c *Config) { c.Applications = append(c.Applications, c.Applications[0]) }} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("unsafe or ambiguous config accepted")
		}
	}
}
