package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/grantlinehq/grantline/internal/model"
)

const pageSize int64 = 500

type Collector struct {
	Client kubernetes.Interface
	Source Source
	Now    func() time.Time
}

type Source struct {
	ID             string
	KubeconfigPath string
	Context        string
	Scope          string
}

func (source Source) Validate() error {
	if source.ID == "" || source.KubeconfigPath == "" || source.Scope == "" {
		return fmt.Errorf("id, kubeconfig_path, and scope are required")
	}
	return nil
}

func (collector Collector) Collect(ctx context.Context) (model.Snapshot, error) {
	if collector.Client == nil {
		return model.Snapshot{}, fmt.Errorf("Kubernetes client is required")
	}
	if err := collector.Source.Validate(); err != nil {
		return model.Snapshot{}, err
	}

	now := time.Now
	if collector.Now != nil {
		now = collector.Now
	}
	observedAt := now().UTC()
	result := collection{
		source: model.Source{
			ID:         collector.Source.ID,
			Kind:       "kubernetes",
			Scope:      collector.Source.Scope,
			Status:     model.SourceOK,
			Complete:   true,
			Provenance: model.ProvenanceLiveAPI,
		},
		observedAt: observedAt,
	}

	namespaces, ok := result.listNamespaces(ctx, collector.Client)
	serviceAccounts, serviceAccountsOK := result.listServiceAccounts(ctx, collector.Client)
	pods, podsOK := result.listPods(ctx, collector.Client)
	deployments, deploymentsOK := result.listDeployments(ctx, collector.Client)
	roles, rolesOK := result.listRoles(ctx, collector.Client)
	roleBindings, roleBindingsOK := result.listRoleBindings(ctx, collector.Client)
	clusterRoles, clusterRolesOK := result.listClusterRoles(ctx, collector.Client)
	clusterRoleBindings, clusterRoleBindingsOK := result.listClusterRoleBindings(ctx, collector.Client)

	if ok {
		for _, item := range namespaces {
			result.addEvidence(string(item.UID), "api/v1/namespaces/"+item.Name, []string{"metadata.uid", "metadata.name"})
		}
	}
	serviceAccountIDs := make(map[string]string)
	if serviceAccountsOK {
		for _, item := range serviceAccounts {
			entity := result.addServiceAccount(item)
			serviceAccountIDs[namespacedName(item.Namespace, item.Name)] = entity.ID
		}
	}
	if deploymentsOK && serviceAccountsOK {
		for _, item := range deployments {
			result.addDeployment(item, serviceAccountIDs)
		}
	}
	if podsOK && serviceAccountsOK {
		for _, item := range pods {
			result.addPod(item, serviceAccountIDs)
		}
	}

	roleIDs := make(map[string]string)
	if rolesOK {
		for _, item := range roles {
			entity := result.addRole(item)
			roleIDs["Role:"+namespacedName(item.Namespace, item.Name)] = entity.ID
		}
	}
	if clusterRolesOK {
		for _, item := range clusterRoles {
			entity := result.addClusterRole(item)
			roleIDs["ClusterRole:"+item.Name] = entity.ID
		}
	}
	if roleBindingsOK {
		for _, item := range roleBindings {
			result.addRoleBinding(item, roleIDs, serviceAccountIDs)
		}
	}
	if clusterRoleBindingsOK {
		for _, item := range clusterRoleBindings {
			result.addClusterRoleBinding(item, roleIDs, serviceAccountIDs)
		}
	}

	if !(ok && serviceAccountsOK && podsOK && deploymentsOK && rolesOK && roleBindingsOK && clusterRolesOK && clusterRoleBindingsOK) {
		result.source.Complete = false
		if len(result.source.PermissionsObserved) == 0 {
			result.source.Status = model.SourceError
		} else {
			result.source.Status = model.SourcePartial
		}
	}
	result.source.PaginationComplete = result.source.Complete
	result.sort()

	return model.Snapshot{
		SchemaVersion: model.SnapshotSchemaVersion,
		CollectedAt:   observedAt,
		Entities:      result.entities,
		Relationships: result.relationships,
		Evidence:      result.evidence,
		Sources:       []model.Source{result.source},
	}, nil
}

type collection struct {
	source        model.Source
	observedAt    time.Time
	entities      []model.Entity
	relationships []model.Relationship
	evidence      []model.Evidence
	evidenceIDs   map[string]string
}

func (collection *collection) listNamespaces(ctx context.Context, client kubernetes.Interface) ([]corev1.Namespace, bool) {
	items, err := listAll(func(options metav1.ListOptions) (*corev1.NamespaceList, error) {
		return client.CoreV1().Namespaces().List(ctx, options)
	}, func(list *corev1.NamespaceList) []corev1.Namespace { return list.Items })
	if err != nil {
		collection.recordListError("core/v1/namespaces:list", err)
		return nil, false
	}
	collection.recordPermission("core/v1/namespaces:list")
	return items, true
}

func (collection *collection) listServiceAccounts(ctx context.Context, client kubernetes.Interface) ([]corev1.ServiceAccount, bool) {
	items, err := listAll(func(options metav1.ListOptions) (*corev1.ServiceAccountList, error) {
		return client.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, options)
	}, func(list *corev1.ServiceAccountList) []corev1.ServiceAccount { return list.Items })
	if err != nil {
		collection.recordListError("core/v1/serviceaccounts:list", err)
		return nil, false
	}
	collection.recordPermission("core/v1/serviceaccounts:list")
	return items, true
}

func (collection *collection) listPods(ctx context.Context, client kubernetes.Interface) ([]corev1.Pod, bool) {
	items, err := listAll(func(options metav1.ListOptions) (*corev1.PodList, error) {
		return client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, options)
	}, func(list *corev1.PodList) []corev1.Pod { return list.Items })
	if err != nil {
		collection.recordListError("core/v1/pods:list", err)
		return nil, false
	}
	collection.recordPermission("core/v1/pods:list")
	return items, true
}

func (collection *collection) listDeployments(ctx context.Context, client kubernetes.Interface) ([]appsv1.Deployment, bool) {
	items, err := listAll(func(options metav1.ListOptions) (*appsv1.DeploymentList, error) {
		return client.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, options)
	}, func(list *appsv1.DeploymentList) []appsv1.Deployment { return list.Items })
	if err != nil {
		collection.recordListError("apps/v1/deployments:list", err)
		return nil, false
	}
	collection.recordPermission("apps/v1/deployments:list")
	return items, true
}

func (collection *collection) listRoles(ctx context.Context, client kubernetes.Interface) ([]rbacv1.Role, bool) {
	items, err := listAll(func(options metav1.ListOptions) (*rbacv1.RoleList, error) {
		return client.RbacV1().Roles(metav1.NamespaceAll).List(ctx, options)
	}, func(list *rbacv1.RoleList) []rbacv1.Role { return list.Items })
	if err != nil {
		collection.recordListError("rbac.authorization.k8s.io/v1/roles:list", err)
		return nil, false
	}
	collection.recordPermission("rbac.authorization.k8s.io/v1/roles:list")
	return items, true
}

func (collection *collection) listRoleBindings(ctx context.Context, client kubernetes.Interface) ([]rbacv1.RoleBinding, bool) {
	items, err := listAll(func(options metav1.ListOptions) (*rbacv1.RoleBindingList, error) {
		return client.RbacV1().RoleBindings(metav1.NamespaceAll).List(ctx, options)
	}, func(list *rbacv1.RoleBindingList) []rbacv1.RoleBinding { return list.Items })
	if err != nil {
		collection.recordListError("rbac.authorization.k8s.io/v1/rolebindings:list", err)
		return nil, false
	}
	collection.recordPermission("rbac.authorization.k8s.io/v1/rolebindings:list")
	return items, true
}

func (collection *collection) listClusterRoles(ctx context.Context, client kubernetes.Interface) ([]rbacv1.ClusterRole, bool) {
	items, err := listAll(func(options metav1.ListOptions) (*rbacv1.ClusterRoleList, error) {
		return client.RbacV1().ClusterRoles().List(ctx, options)
	}, func(list *rbacv1.ClusterRoleList) []rbacv1.ClusterRole { return list.Items })
	if err != nil {
		collection.recordListError("rbac.authorization.k8s.io/v1/clusterroles:list", err)
		return nil, false
	}
	collection.recordPermission("rbac.authorization.k8s.io/v1/clusterroles:list")
	return items, true
}

func (collection *collection) listClusterRoleBindings(ctx context.Context, client kubernetes.Interface) ([]rbacv1.ClusterRoleBinding, bool) {
	items, err := listAll(func(options metav1.ListOptions) (*rbacv1.ClusterRoleBindingList, error) {
		return client.RbacV1().ClusterRoleBindings().List(ctx, options)
	}, func(list *rbacv1.ClusterRoleBindingList) []rbacv1.ClusterRoleBinding { return list.Items })
	if err != nil {
		collection.recordListError("rbac.authorization.k8s.io/v1/clusterrolebindings:list", err)
		return nil, false
	}
	collection.recordPermission("rbac.authorization.k8s.io/clusterrolebindings:list")
	return items, true
}

func listAll[T any, L interface{ GetContinue() string }](list func(metav1.ListOptions) (L, error), items func(L) []T) ([]T, error) {
	var result []T
	continueToken := ""
	seenTokens := make(map[string]struct{})
	for {
		page, err := list(metav1.ListOptions{Limit: pageSize, Continue: continueToken})
		if err != nil {
			return nil, err
		}
		result = append(result, items(page)...)
		continueToken = page.GetContinue()
		if continueToken == "" {
			return result, nil
		}
		if _, repeated := seenTokens[continueToken]; repeated {
			return nil, fmt.Errorf("pagination returned a repeated continue token")
		}
		seenTokens[continueToken] = struct{}{}
	}
}

func (collection *collection) recordPermission(permission string) {
	collection.source.PermissionsObserved = append(collection.source.PermissionsObserved, permission)
}

func (collection *collection) recordListError(collectionName string, err error) {
	if apierrors.IsForbidden(err) {
		collection.source.Warnings = append(collection.source.Warnings, collectionName+" was forbidden")
		return
	}
	collection.source.Warnings = append(collection.source.Warnings, collectionName+" failed: "+safeErrorCode(err))
}

func safeErrorCode(err error) string {
	if statusError, ok := err.(apierrors.APIStatus); ok {
		return fmt.Sprintf("HTTP_%d", statusError.Status().Code)
	}
	return "request_error"
}

func (collection *collection) addServiceAccount(item corev1.ServiceAccount) model.Entity {
	scope := namespaceScope(collection.source.Scope, item.Namespace)
	evidenceID := collection.addEvidence(string(item.UID), "api/v1/namespaces/"+item.Namespace+"/serviceaccounts/"+item.Name, []string{"metadata.uid", "metadata.namespace", "metadata.name"})
	entity := collection.addEntity("service_account", string(item.UID), scope, item.Name)
	_ = evidenceID
	return entity
}

func (collection *collection) addDeployment(item appsv1.Deployment, serviceAccountIDs map[string]string) {
	scope := namespaceScope(collection.source.Scope, item.Namespace)
	entity := collection.addEntity("workload", string(item.UID), scope, item.Name)
	evidenceID := collection.addEvidence(string(item.UID), "apis/apps/v1/namespaces/"+item.Namespace+"/deployments/"+item.Name, []string{"metadata.uid", "metadata.namespace", "metadata.name", "spec.template.spec.serviceAccountName"})
	collection.addRunsAs(entity, item.Namespace, item.Spec.Template.Spec.ServiceAccountName, scope, evidenceID, serviceAccountIDs)
}

func (collection *collection) addPod(item corev1.Pod, serviceAccountIDs map[string]string) {
	scope := namespaceScope(collection.source.Scope, item.Namespace)
	entity := collection.addEntity("workload", string(item.UID), scope, item.Name)
	evidenceID := collection.addEvidence(string(item.UID), "api/v1/namespaces/"+item.Namespace+"/pods/"+item.Name, []string{"metadata.uid", "metadata.namespace", "metadata.name", "spec.serviceAccountName", "metadata.ownerReferences"})
	collection.addRunsAs(entity, item.Namespace, item.Spec.ServiceAccountName, scope, evidenceID, serviceAccountIDs)
}

func (collection *collection) addRole(item rbacv1.Role) model.Entity {
	scope := namespaceScope(collection.source.Scope, item.Namespace)
	return collection.addRBACRole(string(item.UID), scope, item.Name, "Role", item.Rules, "apis/rbac.authorization.k8s.io/v1/namespaces/"+item.Namespace+"/roles/"+item.Name)
}

func (collection *collection) addClusterRole(item rbacv1.ClusterRole) model.Entity {
	return collection.addRBACRole(string(item.UID), collection.source.Scope, item.Name, "ClusterRole", item.Rules, "apis/rbac.authorization.k8s.io/v1/clusterroles/"+item.Name)
}

func (collection *collection) addRBACRole(nativeID, scope, name, roleKind string, rules []rbacv1.PolicyRule, locator string) model.Entity {
	evidenceID := collection.addEvidence(nativeID, locator, []string{"metadata.uid", "rules"})
	attributes := map[string]json.RawMessage{"role_kind": json.RawMessage(fmt.Sprintf("%q", roleKind))}
	fieldStatus := map[string]model.FieldStatus{"role_kind": model.FieldKnown}
	if convertedRules, supported := convertRules(rules); supported {
		encoded, _ := json.Marshal(convertedRules)
		attributes["rbac_rules"] = encoded
		fieldStatus["rbac_rules"] = model.FieldKnown
	} else {
		fieldStatus["rbac_rules"] = model.FieldUnsupported
	}
	entity := model.Entity{
		ID:          model.EntityID(collection.source.ID, "role", nativeID),
		Kind:        "role",
		SourceID:    collection.source.ID,
		NativeID:    nativeID,
		Scope:       scope,
		Name:        name,
		Attributes:  attributes,
		FieldStatus: fieldStatus,
		ObservedAt:  collection.observedAt,
		Provenance:  model.ProvenanceLiveAPI,
	}
	collection.entities = append(collection.entities, entity)
	_ = evidenceID
	return entity
}

func (collection *collection) addRoleBinding(item rbacv1.RoleBinding, roleIDs, serviceAccountIDs map[string]string) {
	collection.addBinding(string(item.UID), item.Name, item.Namespace, namespaceScope(collection.source.Scope, item.Namespace), "RoleBinding", item.RoleRef, item.Subjects, "apis/rbac.authorization.k8s.io/v1/namespaces/"+item.Namespace+"/rolebindings/"+item.Name, roleIDs, serviceAccountIDs)
}

func (collection *collection) addClusterRoleBinding(item rbacv1.ClusterRoleBinding, roleIDs, serviceAccountIDs map[string]string) {
	collection.addBinding(string(item.UID), item.Name, "", collection.source.Scope, "ClusterRoleBinding", item.RoleRef, item.Subjects, "apis/rbac.authorization.k8s.io/v1/clusterrolebindings/"+item.Name, roleIDs, serviceAccountIDs)
}

func (collection *collection) addBinding(nativeID, name, bindingNamespace, scope, bindingKind string, roleRef rbacv1.RoleRef, subjects []rbacv1.Subject, locator string, roleIDs, serviceAccountIDs map[string]string) {
	evidenceID := collection.addEvidence(nativeID, locator, []string{"metadata.uid", "roleRef", "subjects", "metadata.namespace"})
	entity := model.Entity{
		ID:          model.EntityID(collection.source.ID, "role_binding", nativeID),
		Kind:        "role_binding",
		SourceID:    collection.source.ID,
		NativeID:    nativeID,
		Scope:       scope,
		Name:        name,
		Attributes:  map[string]json.RawMessage{"binding_kind": json.RawMessage(fmt.Sprintf("%q", bindingKind))},
		FieldStatus: map[string]model.FieldStatus{"binding_kind": model.FieldKnown},
		ObservedAt:  collection.observedAt,
		Provenance:  model.ProvenanceLiveAPI,
	}
	collection.entities = append(collection.entities, entity)

	roleKey := roleRef.Kind + ":" + roleRef.Name
	if roleRef.Kind == "Role" {
		roleKey = "Role:" + namespacedName(bindingNamespace, roleRef.Name)
	}
	roleID, found := roleIDs[roleKey]
	if !found {
		collection.recordObservationWarning("Role binding " + nativeID + " references an unavailable " + roleRef.Kind + ".")
	} else {
		collection.addRelationship(entity.ID, roleID, "grants_role", scope, []string{evidenceID})
	}
	for _, subject := range subjects {
		if subject.Kind != "ServiceAccount" {
			continue
		}
		subjectNamespace := subject.Namespace
		if subjectNamespace == "" && bindingKind == "RoleBinding" {
			subjectNamespace = bindingNamespace
		}
		serviceAccountID, found := serviceAccountIDs[namespacedName(subjectNamespace, subject.Name)]
		if !found {
			collection.recordObservationWarning("Role binding " + nativeID + " references an unavailable service account.")
			continue
		}
		collection.addRelationship(entity.ID, serviceAccountID, "bound_to", scope, []string{evidenceID})
	}
}

func (collection *collection) addRunsAs(workload model.Entity, namespace, serviceAccountName, scope, evidenceID string, serviceAccountIDs map[string]string) {
	if serviceAccountName == "" {
		serviceAccountName = "default"
	}
	serviceAccountID, found := serviceAccountIDs[namespacedName(namespace, serviceAccountName)]
	if !found {
		collection.recordObservationWarning("Workload " + workload.NativeID + " references an unavailable service account.")
		return
	}
	collection.addRelationship(workload.ID, serviceAccountID, "runs_as", scope, []string{evidenceID})
}

func (collection *collection) addEntity(kind, nativeID, scope, name string) model.Entity {
	entity := model.Entity{
		ID:          model.EntityID(collection.source.ID, kind, nativeID),
		Kind:        kind,
		SourceID:    collection.source.ID,
		NativeID:    nativeID,
		Scope:       scope,
		Name:        name,
		Attributes:  map[string]json.RawMessage{},
		FieldStatus: map[string]model.FieldStatus{},
		ObservedAt:  collection.observedAt,
		Provenance:  model.ProvenanceLiveAPI,
	}
	collection.entities = append(collection.entities, entity)
	return entity
}

func (collection *collection) addEvidence(nativeID, locator string, fields []string) string {
	if collection.evidenceIDs == nil {
		collection.evidenceIDs = make(map[string]string)
	}
	key := nativeID + "\x00" + locator
	if existing, found := collection.evidenceIDs[key]; found {
		return existing
	}
	id := model.EvidenceID(collection.source.ID, nativeID, locator)
	collection.evidenceIDs[key] = id
	collection.evidence = append(collection.evidence, model.Evidence{ID: id, SourceID: collection.source.ID, NativeID: nativeID, Locator: "kubernetes://" + collection.source.ID + "/" + locator, Fields: fields, ObservedAt: collection.observedAt, AssertionKind: model.AssertionObserved})
	return id
}

func (collection *collection) addRelationship(from, to, relationshipType, scope string, evidenceIDs []string) {
	collection.relationships = append(collection.relationships, model.Relationship{ID: model.RelationshipID(from, to, relationshipType, scope), From: from, To: to, Type: relationshipType, AssertionKind: model.AssertionObserved, EvidenceIDs: evidenceIDs, Scope: scope, ObservedAt: collection.observedAt})
}

func (collection *collection) recordObservationWarning(warning string) {
	collection.source.Warnings = append(collection.source.Warnings, warning)
}

func (collection *collection) sort() {
	sort.Strings(collection.source.PermissionsObserved)
	collection.source.PermissionsObserved = compact(collection.source.PermissionsObserved)
	sort.Strings(collection.source.Warnings)
	collection.source.Warnings = compact(collection.source.Warnings)
	sort.Slice(collection.entities, func(left, right int) bool { return collection.entities[left].ID < collection.entities[right].ID })
	sort.Slice(collection.evidence, func(left, right int) bool { return collection.evidence[left].ID < collection.evidence[right].ID })
	sort.Slice(collection.relationships, func(left, right int) bool {
		return collection.relationships[left].ID < collection.relationships[right].ID
	})
}

func compact(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if values[read] != values[write-1] {
			values[write] = values[read]
			write++
		}
	}
	return values[:write]
}

func convertRules(rules []rbacv1.PolicyRule) ([]model.RBACRule, bool) {
	converted := make([]model.RBACRule, 0, len(rules))
	for _, rule := range rules {
		if len(rule.NonResourceURLs) > 0 {
			return nil, false
		}
		converted = append(converted, model.RBACRule{APIGroups: append([]string(nil), rule.APIGroups...), Resources: append([]string(nil), rule.Resources...), Verbs: append([]string(nil), rule.Verbs...), ResourceNames: append([]string(nil), rule.ResourceNames...)})
	}
	return converted, true
}

func namespaceScope(clusterScope, namespace string) string {
	return clusterScope + "/namespaces/" + namespace
}

func namespacedName(namespace, name string) string {
	return namespace + "\x00" + name
}
