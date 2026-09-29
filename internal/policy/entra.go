package policy

import "regexp"

var objectUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validObjectID(s string) bool { return objectUUID.MatchString(s) }

func parseEntraEntries(lines []yamlLine, position int, kind string) ([]map[string]string, int, error) {
	var result []map[string]string
	for position < len(lines) && lines[position].indent > 4 {
		line := lines[position]
		if line.indent != 6 || len(line.text) < 3 || line.text[:2] != "- " {
			return nil, 0, lineError(line, "Entra entries must be six-space list items")
		}
		entry := map[string]string{}
		set := func(line yamlLine, text string) error {
			key, value, err := splitMappingText(line, text)
			if err != nil {
				return err
			}
			if _, exists := entry[key]; exists {
				return lineError(line, "duplicate Entra entry key")
			}
			allowed := key == "source_id"
			if kind == "require_owners_for" {
				allowed = allowed || key == "object_id" || key == "object_kind"
			} else {
				allowed = allowed || key == "principal_object_id" || key == "resource_object_id" || key == "app_role_id"
			}
			if !allowed {
				return lineError(line, "unsupported Entra entry key")
			}
			scalar, err := parseScalar(line, value)
			if err != nil {
				return err
			}
			entry[key] = scalar
			return nil
		}
		if err := set(line, line.text[2:]); err != nil {
			return nil, 0, err
		}
		position++
		for position < len(lines) && lines[position].indent > 6 {
			child := lines[position]
			if child.indent != 8 {
				return nil, 0, lineError(child, "Entra entry keys must be indented by eight spaces")
			}
			if err := set(child, child.text); err != nil {
				return nil, 0, err
			}
			position++
		}
		result = append(result, entry)
	}
	return result, position, nil
}

func (rule Rule) AllowsAppRole(source, principal, resource, role string) bool {
	for _, allowed := range rule.AllowedAppRoles {
		if allowed.SourceID == source && allowed.PrincipalObjectID == principal && allowed.ResourceObjectID == resource && allowed.AppRoleID == role {
			return true
		}
	}
	return false
}
