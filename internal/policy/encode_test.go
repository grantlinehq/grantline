package policy

import (
	"github.com/grantlinehq/grantline/internal/model"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEncodeRoundTripPreservesAllExceptionsAndDisabledRules(t *testing.T) {
	yes := true
	uuid := "11111111-1111-1111-1111-111111111111"
	p := Policy{SchemaVersion: 1, RequiredSources: []string{"cluster", "vault", "entra", "spire"}, MaxClientSecretValidity: 168 * time.Hour, MaxX509SVIDTTL: 24 * time.Hour, MaxJWTSVIDTTL: time.Hour, Rules: map[string]Rule{
		"IL001": {Severity: model.SeverityHigh, AllowedGrants: []AllowedGrant{{"cluster", "role-uid", "sa-uid", "cluster/prod"}}},
		"IL002": {Severity: model.SeverityMedium, AllowedVaultKubernetesBindings: []AllowedVaultKubernetesBinding{{"vault", "auth/kubernetes/role/worker", "cluster", "sa-uid"}}},
		"IL003": {Severity: model.SeverityMedium},
		"IL004": {Severity: model.SeverityMedium, RequireOwnersFor: []EntraOwnerTarget{{"entra", uuid, "application_registration"}}},
		"IL005": {Severity: model.SeverityMedium, AllowedAppRoles: []EntraAppRole{{"entra", uuid, uuid, uuid}}},
		"IL006": {Severity: model.SeverityHigh, ForbidNamespaceOnly: &yes},
		"IL007": {Severity: model.SeverityMedium},
		"IL008": {Severity: model.SeverityMedium, SeparatedEnvironments: []EnvironmentPair{{"production", "staging"}}, AllowedSharedIdentities: []SharedIdentity{{EnvironmentPair: EnvironmentPair{"production", "staging"}, SourceID: "cluster", Kind: "service_account", NativeID: "sa-uid", Reason: "Temporary reviewed migration"}}},
	}}
	for _, partial := range []bool{false, true} {
		if partial {
			delete(p.Rules, "IL003")
			delete(p.Rules, "IL007")
			p.MaxClientSecretValidity = 0
			p.MaxX509SVIDTTL = 0
			p.MaxJWTSVIDTTL = 0
		}
		raw, err := Encode(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, p) {
			t.Fatalf("policy changed during encoding: got %#v want %#v", got, p)
		}
		if partial && strings.Contains(raw, "limits:") {
			t.Fatal("zero limits emitted")
		}
	}
}
func TestEncodeRejectsMultilineAndUnsupportedScalars(t *testing.T) {
	for _, value := range []string{"source\nrules:", "source # hidden", " source", "source\x00", "[source]"} {
		p := Policy{SchemaVersion: 1, RequiredSources: []string{value}, Rules: map[string]Rule{"IL001": {Severity: model.SeverityMedium}}}
		if _, err := Encode(p); err == nil {
			t.Fatal("unsafe scalar accepted")
		}
	}
}
