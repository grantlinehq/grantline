package platform

import (
	"testing"

	"github.com/grantlinehq/grantline/internal/config"
)

func TestDefaultPolicyAcceptsEntraApplicationTargets(t *testing.T) {
	sources := []config.Source{{
		ID: "entra", Kind: "entra",
		Applications: []string{"00000000-0000-4000-8000-000000000001"},
	}}
	p := defaultPolicy(sources)
	if err := p.Validate(); err != nil {
		t.Fatalf("default policy must allow collection of selected Entra applications: %v", err)
	}
	targets := p.Rules["IL004"].RequireOwnersFor
	if len(targets) != 1 || targets[0].ObjectKind != "application_registration" {
		t.Fatalf("owner check must target the collected application registration: %#v", targets)
	}
}
