package github

import (
	"bytes"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/grantlinehq/grantline/internal/model"
	"go.yaml.in/yaml/v3"
)

var referenceExpression = regexp.MustCompile(`^\$\{\{\s*((?:secrets|vars)\.[A-Za-z_][A-Za-z0-9_]{0,99})\s*\}\}$`)

// Parse only a bounded YAML AST; no decoding into arbitrary provider fields,
// alias expansion, merge keys, scripts, expression evaluation, or reusable calls.
func parseWorkflow(data []byte, ref, sha, prefix string) model.GitHubRevision {
	r := model.GitHubRevision{Ref: ref, CommitSHA: sha, Status: model.FieldKnown, Jobs: []model.GitHubJob{}}
	bad := func() model.GitHubRevision { r.Status = model.FieldUnsupported; return r }
	if len(data) > 256<<10 {
		return bad()
	}
	var document yaml.Node
	d := yaml.NewDecoder(bytes.NewReader(data))
	if d.Decode(&document) != nil {
		return bad()
	}
	var extra yaml.Node
	if d.Decode(&extra) != io.EOF || len(document.Content) != 1 {
		return bad()
	}
	count := 0
	if !safeNode(&document, 0, &count) {
		return bad()
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return bad()
	}
	jobs := child(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode || len(jobs.Content) == 0 || len(jobs.Content) > 200 {
		return bad()
	}
	rootPermission := permission(child(root, "permissions"), "unknown")
	events, eventsKnown := workflowEvents(child(root, "on"), ref)
	if !eventsKnown {
		r.Status = model.FieldUnsupported
	}
	for i := 0; i < len(jobs.Content); i += 2 {
		id, node := scalar(jobs.Content[i]), jobs.Content[i+1]
		if !model.GitHubJobID.MatchString(id) || node.Kind != yaml.MappingNode {
			return bad()
		}
		j := model.GitHubJob{ID: id, IDTokenPermission: permission(child(node, "permissions"), rootPermission), EnvironmentStatus: model.FieldKnown, Contexts: []model.GitHubContext{}, Logins: []model.GitHubLogin{}}
		if env := child(node, "environment"); env != nil {
			if env.Kind == yaml.MappingNode {
				env = child(env, "name")
			}
			value := scalar(env)
			if value == "" || strings.Contains(value, "${{") || !model.GitHubText(value, 255) {
				j.EnvironmentStatus = model.FieldUnknown
				r.Status = model.FieldUnsupported
			} else {
				j.Environment = value
			}
		}
		if child(node, "uses") != nil {
			j.Reusable = true
			r.Status = model.FieldUnsupported
		}
		if prefix != "" && eventsKnown && j.EnvironmentStatus == model.FieldKnown && !j.Reusable {
			for _, event := range events {
				context := "ref:" + ref
				if event == "pull_request" {
					context = "pull_request"
				}
				if j.Environment != "" {
					context = "environment:" + strings.ReplaceAll(j.Environment, ":", "%3A")
				}
				j.Contexts = append(j.Contexts, model.GitHubContext{Event: event, Subject: prefix + ":" + context})
			}
		}
		steps := child(node, "steps")
		if steps != nil && (steps.Kind != yaml.SequenceNode || len(steps.Content) > 100) {
			return bad()
		}
		if steps != nil {
			for index, step := range steps.Content {
				if step.Kind != yaml.MappingNode {
					return bad()
				}
				action := scalar(child(step, "uses"))
				if !strings.HasPrefix(strings.ToLower(action), "azure/login@") {
					continue
				}
				l := model.GitHubLogin{Step: index + 1, Action: action, Status: model.FieldKnown, IdentityAssertion: model.AssertionConfigured, Audience: "api://AzureADTokenExchange"}
				if action != "azure/login@v2" && action != "azure/login@v3" {
					l.Action = "azure/login@unsupported"
					l.Status = model.FieldUnsupported
				}
				inputs := child(step, "with")
				l.TenantID, l.TenantReference = identityInput(child(inputs, "tenant-id"))
				l.ClientID, l.ClientReference = identityInput(child(inputs, "client-id"))
				if l.TenantID == "" || l.ClientID == "" {
					l.Status = model.FieldUnknown
				}
				if aud := child(inputs, "audience"); aud != nil {
					v := scalar(aud)
					if v == "" || strings.Contains(v, "${{") || !model.GitHubText(v, 512) {
						l.Audience = ""
						l.Status = model.FieldUnknown
					} else {
						l.Audience = v
					}
				}
				// creds, non-public clouds, managed identity and conditions are outside
				// the supported direct service-principal OIDC configuration subset.
				if inputs == nil || inputs.Kind != yaml.MappingNode || child(inputs, "creds") != nil || !defaultInput(inputs, "auth-type", "SERVICE_PRINCIPAL") || !defaultInput(inputs, "environment", "AzureCloud") || !unconditional(child(node, "if")) || !unconditional(child(step, "if")) || child(step, "run") != nil || l.Action == "azure/login@unsupported" {
					l.Status = model.FieldUnsupported
				}
				j.Logins = append(j.Logins, l)
			}
		}
		// Unknown inherited permission is represented even for jobs with no
		// direct azure/login step. No default read/write policy is guessed.
		if j.IDTokenPermission == "unknown" {
			r.Status = model.FieldUnsupported
		}
		r.Jobs = append(r.Jobs, j)
	}
	sort.Slice(r.Jobs, func(i, j int) bool { return r.Jobs[i].ID < r.Jobs[j].ID })
	return r
}

func safeNode(n *yaml.Node, depth int, count *int) bool {
	*count++
	if depth > 40 || *count > 20000 || n.Kind == yaml.AliasNode || n.Anchor != "" {
		return false
	}
	if n.Kind == yaml.ScalarNode {
		if n.Tag != "!!str" && n.Tag != "!!int" && n.Tag != "!!float" && n.Tag != "!!bool" && n.Tag != "!!null" && n.Tag != "!!timestamp" {
			return false
		}
	}
	if n.Kind == yaml.MappingNode {
		if len(n.Content)%2 != 0 {
			return false
		}
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || seen[k.Value] {
				return false
			}
			seen[k.Value] = true
		}
	}
	for _, c := range n.Content {
		if !safeNode(c, depth+1, count) {
			return false
		}
	}
	return true
}
func child(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
func scalar(n *yaml.Node) string {
	if n != nil && n.Kind == yaml.ScalarNode && n.Tag == "!!str" {
		return n.Value
	}
	return ""
}
func unconditional(n *yaml.Node) bool {
	return n == nil || n.Kind == yaml.ScalarNode && n.Tag == "!!bool" && n.Value == "true"
}
func defaultInput(n *yaml.Node, key, value string) bool {
	v := child(n, key)
	return v == nil || scalar(v) == value
}
func identityInput(n *yaml.Node) (string, string) {
	v := scalar(n)
	if guid.MatchString(strings.ToLower(v)) {
		return strings.ToLower(v), ""
	}
	if m := referenceExpression.FindStringSubmatch(v); m != nil {
		return "", m[1]
	}
	return "", ""
}
func permission(n *yaml.Node, inherited string) string {
	if n == nil {
		return inherited
	}
	if n.Kind == yaml.MappingNode {
		p := child(n, "id-token")
		if p == nil {
			return "none"
		}
		switch scalar(p) {
		case "write":
			return "write"
		case "none":
			return "none"
		}
		return "unknown"
	}
	switch scalar(n) {
	case "write-all":
		return "write"
	case "read-all":
		return "none"
	}
	return "unknown"
}
func workflowEvents(n *yaml.Node, ref string) ([]string, bool) {
	var names []string
	if n == nil {
		return nil, false
	}
	switch n.Kind {
	case yaml.ScalarNode:
		names = []string{scalar(n)}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			names = append(names, scalar(c))
		}
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			names = append(names, scalar(n.Content[i]))
		}
	default:
		return nil, false
	}
	if len(names) == 0 || len(names) > 10 {
		return nil, false
	}
	result := []string{}
	seen := map[string]bool{}
	for _, event := range names {
		if seen[event] {
			return nil, false
		}
		seen[event] = true
		if event != "push" && event != "workflow_dispatch" && event != "pull_request" {
			return nil, false
		}
		if event == "pull_request" {
			result = append(result, event)
			continue
		}
		if event == "push" {
			filters := child(n, event)
			if filters != nil && filters.Kind != yaml.MappingNode && filters.Tag != "!!null" {
				return nil, false
			}
			branch := strings.HasPrefix(ref, "refs/heads/")
			key, other, name := "tags", "branches", strings.TrimPrefix(ref, "refs/tags/")
			if branch {
				key, other, name = "branches", "tags", strings.TrimPrefix(ref, "refs/heads/")
			}
			if child(filters, "branches-ignore") != nil || child(filters, "tags-ignore") != nil {
				return nil, false
			}
			filter := child(filters, key)
			if filter == nil && child(filters, other) != nil {
				continue
			}
			if filter != nil {
				if filter.Kind != yaml.SequenceNode || len(filter.Content) == 0 {
					return nil, false
				}
				match := false
				for _, item := range filter.Content {
					v := scalar(item)
					if v == "" || strings.ContainsAny(v, "*!?+[]") || strings.Contains(v, "${{") {
						return nil, false
					}
					if v == name {
						match = true
					}
				}
				if !match {
					continue
				}
			}
		}
		result = append(result, event)
	}
	sort.Strings(result)
	return result, true
}

func applyMappings(r *model.GitHubRevision, path string, mappings []IdentityMapping, used map[int]bool) {
	for ji := range r.Jobs {
		j := &r.Jobs[ji]
		for li := range j.Logins {
			l := &j.Logins[li]
			for i, m := range mappings {
				if m.WorkflowPath != path || m.Ref != r.Ref || m.CommitSHA != r.CommitSHA || m.JobID != j.ID || m.Step != l.Step {
					continue
				}
				if m.Field == "tenant_id" && l.TenantID == "" && m.Reference == l.TenantReference {
					l.TenantID = m.Value
					used[i] = true
					l.IdentityAssertion = model.AssertionDeclared
				}
				if m.Field == "client_id" && l.ClientID == "" && m.Reference == l.ClientReference {
					l.ClientID = m.Value
					used[i] = true
					l.IdentityAssertion = model.AssertionDeclared
				}
			}
			if l.Status == model.FieldUnknown && l.TenantID != "" && l.ClientID != "" && l.Audience != "" {
				l.Status = model.FieldKnown
			}
		}
	}
}
