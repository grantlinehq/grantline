package model_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/snapshot"
)

func TestEntityIDDoesNotUseDisplayName(t *testing.T) {
	t.Parallel()

	first := model.Entity{
		ID:       model.EntityID("k8s-lab", "service_account", "sa-uid-payments-runner"),
		Name:     "payments-runner",
		SourceID: "k8s-lab",
		Kind:     "service_account",
		NativeID: "sa-uid-payments-runner",
	}
	second := first
	second.Name = "renamed-payments-runner"

	if first.Name == second.Name {
		t.Fatal("test setup requires distinct display names")
	}
	if first.ID != second.ID {
		t.Fatalf("display name changed a stable entity ID: %q != %q", first.ID, second.ID)
	}
	if first.ID == model.EntityID("other-k8s-lab", "service_account", "sa-uid-payments-runner") {
		t.Fatal("source instance must be part of an entity ID")
	}
	if first.ID == model.EntityID("k8s-lab", "service_account", "different-native-id") {
		t.Fatal("native ID must be part of an entity ID")
	}
}

func TestValidationRejectsSecretCanaryWithoutLeakingValue(t *testing.T) {
	t.Parallel()

	input, err := snapshot.Load("../../testdata/synthetic/restricted-rbac.snapshot.json")
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}

	const canary = "M0-SYNTHETIC-SECRET-CANARY"
	input.Entities[0].Attributes["client_secret"] = json.RawMessage(`"` + canary + `"`)
	input.Entities[0].FieldStatus["client_secret"] = model.FieldKnown

	err = input.Validate()
	if err == nil {
		t.Fatal("expected sensitive attribute validation to fail")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("validation error leaked secret canary: %q", err)
	}
}
