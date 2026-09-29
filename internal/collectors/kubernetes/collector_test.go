package kubernetes

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/grantlinehq/grantline/internal/model"
)

func TestCollectProducesValidatedUIDBasedSnapshot(t *testing.T) {
	t.Parallel()

	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo-prod", UID: "namespace-uid"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "demo-prod", UID: "service-account-uid"}},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "demo-prod", UID: "deployment-uid"},
			Spec:       appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "payments"}}},
		},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "payments-123", Namespace: "demo-prod", UID: "pod-uid"}, Spec: corev1.PodSpec{ServiceAccountName: "payments"}},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "wildcard", UID: "cluster-role-uid"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "payments-wildcard", Namespace: "demo-prod", UID: "binding-uid"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "wildcard"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "demo-prod", Name: "payments"}},
		},
	)
	collected, err := (Collector{
		Client: client,
		Source: Source{
			ID: "k8s-lab", KubeconfigPath: "/outside/source/tree/observer.kubeconfig", Scope: "cluster/kind-grantline-m1",
		},
		Now: func() time.Time { return time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC) },
	}).Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if err := collected.Validate(); err != nil {
		t.Fatalf("validate snapshot: %v", err)
	}
	if !collected.Sources[0].Complete || collected.Sources[0].Status != model.SourceOK {
		t.Fatalf("source coverage = %#v, want complete ok", collected.Sources[0])
	}

	serviceAccountID := model.EntityID("k8s-lab", "service_account", "service-account-uid")
	roleBindingID := model.EntityID("k8s-lab", "role_binding", "binding-uid")
	if !hasEntity(collected, serviceAccountID) {
		t.Fatalf("service account did not retain immutable UID identity %q", serviceAccountID)
	}
	if !hasRelationship(collected, roleBindingID, serviceAccountID, "bound_to", "cluster/kind-grantline-m1/namespaces/demo-prod") {
		t.Fatal("role binding did not retain namespace scope")
	}
	if !hasRelationship(collected, roleBindingID, model.EntityID("k8s-lab", "role", "cluster-role-uid"), "grants_role", "cluster/kind-grantline-m1/namespaces/demo-prod") {
		t.Fatal("role binding did not preserve ClusterRole reference within RoleBinding namespace scope")
	}
}

func TestCollectMarksForbiddenCollectionPartial(t *testing.T) {
	t.Parallel()

	client := fake.NewSimpleClientset()
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", fmt.Errorf("observer cannot list pods"))
	})
	collected, err := (Collector{
		Client: client,
		Source: Source{
			ID: "k8s-lab", KubeconfigPath: "/outside/source/tree/observer.kubeconfig", Scope: "cluster/kind-grantline-m1",
		},
	}).Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if collected.Sources[0].Complete || collected.Sources[0].Status != model.SourcePartial {
		t.Fatalf("source coverage = %#v, want partial", collected.Sources[0])
	}
	if !contains(collected.Sources[0].Warnings, "core/v1/pods:list was forbidden") {
		t.Fatalf("warnings = %#v", collected.Sources[0].Warnings)
	}
	if err := collected.Validate(); err != nil {
		t.Fatalf("partial snapshot must remain valid: %v", err)
	}
}

func hasEntity(snapshot model.Snapshot, id string) bool {
	for _, entity := range snapshot.Entities {
		if entity.ID == id {
			return true
		}
	}
	return false
}

func hasRelationship(snapshot model.Snapshot, from, to, relationshipType, scope string) bool {
	for _, relationship := range snapshot.Relationships {
		if relationship.From == from && relationship.To == to && relationship.Type == relationshipType && relationship.Scope == scope {
			return true
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	return strings.Contains(strings.Join(values, "\n"), wanted)
}
