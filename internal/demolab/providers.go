package demolab

import (
	"fmt"
	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	"strings"
	"time"
)

func (c *catalog) kubernetes() []model.Entity {
	accounts := []model.Entity{}
	variants := []model.RBACRule{
		{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"*"}},
		{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{"*"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list"}},
	}
	for i := 0; i < 36; i++ {
		n := name(i)
		c.bindings.Applications = append(c.bindings.Applications, bindings.Application{ID: n, Name: strings.ReplaceAll(n, "-", " "), OwnerHint: services[i%12] + " demo team", Members: []bindings.Member{}})
		sa := c.entity("service_account", "demo-kubernetes", "sa/"+n, n+"-runtime", nil)
		workload := c.entity("workload", "demo-kubernetes", "deployment/"+n, n+"-api", nil)
		c.edge(workload, sa, "runs_as", model.AssertionConfigured)
		rbac := variants[i%4]
		if i >= 20 {
			rbac = model.RBACRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}
		}
		role := c.entity("role", "demo-kubernetes", "role/"+n, n+"-permissions", map[string]any{"role_kind": "Role", "rbac_rules": []model.RBACRule{rbac}})
		binding := c.entity("role_binding", "demo-kubernetes", "binding/"+n, n+"-runtime-binding", map[string]any{"binding_kind": "RoleBinding"})
		c.edge(binding, sa, "bound_to", model.AssertionConfigured)
		c.edge(binding, role, "grants_role", model.AssertionConfigured)
		c.member(i, workload, "production")
		if i < 12 {
			env := "development"
			if i%2 == 1 {
				env = "staging"
			}
			c.member(i, workload, env)
		} else {
			c.control("IL008", sa)
		}
		if i >= 20 {
			c.control("IL001", sa)
		}
		accounts = append(accounts, sa)
	}
	return accounts
}

func (c *catalog) vault(accounts []model.Entity) {
	for i := 0; i < 24; i++ {
		n := name(i)
		names := []string{n + "-runtime"}
		namespaces := []string{"production"}
		if i < 6 {
			names = []string{"*"}
		} else if i < 12 {
			namespaces = []string{"*"}
		}
		role := c.entity("vault_auth_role", "demo-vault", "auth/kubernetes/role/"+n, n+"-vault-role", map[string]any{"auth_mount": "kubernetes", "auth_type": "kubernetes", "bound_service_account_names": names, "bound_service_account_namespaces": namespaces, "policy_names": []string{n + "-read"}})
		p := c.entity("policy", "demo-vault", n+"-read", n+"-metadata-policy", map[string]any{"policy_kind": "acl"})
		c.edge(role, p, "uses_policy", model.AssertionConfigured)
		c.edge(role, accounts[i], "trusts_subject", model.AssertionDeclared)
		if i >= 18 {
			r := c.policy.Rules["IL002"]
			r.AllowedVaultKubernetesBindings = append(r.AllowedVaultKubernetesBindings, policy.AllowedVaultKubernetesBinding{VaultSourceID: role.SourceID, RoleNativeID: role.NativeID, KubernetesSourceID: accounts[i].SourceID, ServiceAccountID: accounts[i].NativeID})
			c.policy.Rules["IL002"] = r
			c.control("IL002", role)
		}
	}
}

func (c *catalog) entra() []model.Entity {
	apps := []model.Entity{}
	resourceID := uuid(9000)
	c.entity("service_principal", "demo-entra", tenant+"/"+resourceID, "Demo business API", map[string]any{"tenant_id": tenant, "object_id": resourceID, "app_id": uuid(9001), "collection_role": "grant_resource", "principal_type": "Application"})
	for i := 0; i < 24; i++ {
		n := name(i)
		appID, principalID, clientID := uuid(100+i), uuid(200+i), uuid(300+i)
		owners := 1
		if i < 10 {
			owners = 0
		}
		federationCount := 0
		if i < 12 {
			federationCount = 1
		}
		app := c.entity("application_registration", "demo-entra", tenant+"/"+appID, n+"-application", map[string]any{"tenant_id": tenant, "object_id": appID, "app_id": clientID, "collection_role": "selected", "owners_count": owners, "client_credentials_count": 1, "key_credentials_count": 0, "federated_credentials_count": federationCount, "requested_permissions": []model.EntraRequestedPermission{}})
		principal := c.entity("service_principal", "demo-entra", tenant+"/"+principalID, n+"-principal", map[string]any{"tenant_id": tenant, "object_id": principalID, "app_id": clientID, "collection_role": "selected", "principal_type": "Application", "owners_count": owners, "client_credentials_count": 0, "key_credentials_count": 0, "app_role_assignments_count": 1})
		c.edge(app, principal, "registered_as", model.AssertionConfigured)
		c.member(i, app, "production")
		ownerRule := c.policy.Rules["IL004"]
		for _, e := range []model.Entity{app, principal} {
			object := appID
			if e.Kind == "service_principal" {
				object = principalID
			}
			ownerRule.RequireOwnersFor = append(ownerRule.RequireOwnersFor, policy.EntraOwnerTarget{SourceID: e.SourceID, ObjectID: object, ObjectKind: e.Kind})
			if i >= 10 {
				c.control("IL004", e)
			}
		}
		c.policy.Rules["IL004"] = ownerRule
		if owners > 0 {
			ownerID := uuid(400 + i)
			owner := c.entity("owner", "demo-entra", tenant+"/"+ownerID, n+" demo owner", map[string]any{"tenant_id": tenant, "object_id": ownerID, "owner_type": "user"})
			c.edge(app, owner, "owned_by", model.AssertionConfigured)
			c.edge(principal, owner, "owned_by", model.AssertionConfigured)
		}
		days := []int{90, 180, 365, 730}[i%4]
		if i >= 20 {
			days = 14
		}
		// Credential configuration stays fixed when observation time is refreshed.
		start := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
		keyID := uuid(500 + i)
		credential := c.entity("credential_metadata", "demo-entra", tenant+"/applications/"+appID+"/passwordCredentials/"+keyID, fmt.Sprintf("%s / %d-day client credential", n, days), map[string]any{"tenant_id": tenant, "parent_object_id": appID, "parent_kind": "application_registration", "key_id": keyID, "credential_type": "client_secret", "start_time": start.Format(time.RFC3339), "end_time": start.Add(time.Duration(days) * 24 * time.Hour).Format(time.RFC3339)})
		c.edge(app, credential, "references_credential", model.AssertionConfigured)
		if i >= 20 {
			c.control("IL003", credential)
		}
		roleID := uuid(600 + i)
		role := c.entity("role", "demo-entra", tenant+"/servicePrincipals/"+resourceID+"/appRoles/"+roleID, services[i%12]+".Manage.All", map[string]any{"tenant_id": tenant, "resource_object_id": resourceID, "resource_app_id": uuid(9001), "app_role_id": roleID, "role_value": services[i%12] + ".Manage.All", "role_enabled": true})
		assignmentID := uuid(700 + i)
		assignment := c.entity("role_binding", "demo-entra", tenant+"/servicePrincipals/"+principalID+"/appRoleAssignments/"+assignmentID, n+"-business-api-grant", map[string]any{"tenant_id": tenant, "binding_kind": "entra_app_role_assignment", "assignment_id": assignmentID, "principal_object_id": principalID, "resource_object_id": resourceID, "app_role_id": roleID, "role_definition_id": role.NativeID})
		c.edge(assignment, principal, "bound_to", model.AssertionConfigured)
		c.edge(assignment, role, "grants_role", model.AssertionConfigured)
		if i >= 12 {
			r := c.policy.Rules["IL005"]
			r.AllowedAppRoles = append(r.AllowedAppRoles, policy.EntraAppRole{SourceID: principal.SourceID, PrincipalObjectID: principalID, ResourceObjectID: resourceID, AppRoleID: roleID})
			c.policy.Rules["IL005"] = r
			c.control("IL005", assignment)
		}
		apps = append(apps, app)
	}
	return apps
}

func (c *catalog) spire() {
	parentID := uuid(10000)
	parentURI := "spiffe://" + domain + "/spire/agent/demo-cluster"
	c.entity("spire_entry", "demo-spire", "entry/"+parentID, "Demo Kubernetes node alias", map[string]any{"trust_domain": domain, "entry_id": parentID, "spiffe_id": parentURI, "parent_spiffe_id": "spiffe://" + domain + "/spire/server", "entry_kind": "node_alias", "selectors": []model.SpireSelector{{Type: "k8s_psat", Value: "cluster:demo-offline"}}, "x509_ttl_mode": "explicit", "jwt_ttl_mode": "explicit", "x509_svid_ttl_seconds": 3600, "jwt_svid_ttl_seconds": 900})
	for i := 0; i < 20; i++ {
		n := name(i)
		entryID := uuid(10100 + i)
		uri := "spiffe://" + domain + "/production/" + n
		selectors := []model.SpireSelector{{Type: "k8s", Value: "ns:" + n}}
		if i >= 14 {
			selectors = append(selectors, model.SpireSelector{Type: "k8s", Value: "sa:" + n + "-runtime"})
		}
		x509, jwt := 3600, 900
		if i < 6 {
			x509 = 4500 + i*300
		} else if i < 12 {
			jwt = 1200 + (i-6)*60
		}
		entry := c.entity("spire_entry", "demo-spire", "entry/"+entryID, n+"-registration", map[string]any{"trust_domain": domain, "entry_id": entryID, "spiffe_id": uri, "parent_spiffe_id": parentURI, "entry_kind": "workload", "selectors": selectors, "parent_entry_ids": []string{parentID}, "parent_attestor_types": []string{"k8s_psat"}, "x509_ttl_mode": "explicit", "jwt_ttl_mode": "explicit", "x509_svid_ttl_seconds": x509, "jwt_svid_ttl_seconds": jwt})
		identity := c.entity("spiffe_identity", "demo-spire", uri, n+"-spiffe", map[string]any{"trust_domain": domain, "spiffe_id": uri})
		c.edge(entry, identity, "assigned_spiffe_id", model.AssertionConfigured)
		c.member(i, entry, "production")
		if i >= 14 {
			c.control("IL006", entry)
		}
		if i >= 12 {
			c.control("IL007", entry)
		}
	}
}

func (c *catalog) automation(apps []model.Entity) {
	for i := 0; i < 12; i++ {
		n := name(i)
		job := c.entity("job", "demo-jenkins", "job/"+n+"/deploy", n+"-deploy", map[string]any{"job_kind": "job", "buildable": true, "credential_reference_count": 1, "builds": []any{}})
		ref := c.entity("credential_reference", "demo-jenkins", "job/"+n+"/credential/vault-observer", n+"-vault-reference", map[string]any{"credential_id": n + "-vault-observer", "job_native_id": job.NativeID})
		c.edge(job, ref, "references_credential", model.AssertionConfigured)
		appRole := c.entity("vault_auth_role", "demo-vault", "auth/approle/role/"+n, n+"-automation-approle", map[string]any{"auth_mount": "approle", "auth_type": "approle", "policy_names": []string{n + "-read"}})
		c.bindings.JenkinsVault = append(c.bindings.JenkinsVault, bindings.JenkinsVault{JenkinsSourceID: job.SourceID, CredentialNativeID: ref.NativeID, VaultSourceID: appRole.SourceID, RoleNativeID: appRole.NativeID})
		repo := fmt.Sprint(80000 + i)
		path := ".github/workflows/deploy.yml"
		workflow := c.entity("workflow", "demo-github", repo+"/"+path, n+"-release-workflow", map[string]any{"repository_id": repo, "repository_owner_id": "80000", "repository_name": "demo-catalog/" + n, "workflow_id": fmt.Sprint(90000 + i), "workflow_path": path, "workflow_state": "active", "subject_format": "default_legacy", "revisions": []model.GitHubRevision{}, "smoke_results": []model.GitHubSmokeResult{}})
		fic := c.entity("federated_credential", "demo-entra", tenant+"/applications/"+uuid(100+i)+"/federatedIdentityCredentials/"+uuid(800+i), n+"-github-federation", map[string]any{"tenant_id": tenant, "parent_object_id": uuid(100 + i), "app_id": uuid(300 + i), "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:demo-catalog/" + n + ":environment:production", "audiences": []string{"api://AzureADTokenExchange"}})
		c.edge(apps[i], fic, "references_credential", model.AssertionConfigured)
		c.edge(fic, workflow, "trusts_subject", model.AssertionDeclared)
	}
}
