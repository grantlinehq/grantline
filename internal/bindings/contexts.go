package bindings

import (
	"github.com/grantlinehq/grantline/internal/model"
	"fmt"
	"regexp"
	"strings"
)

type Reference struct {
	SourceID string `json:"source_id"`
	Kind     string `json:"kind"`
	NativeID string `json:"native_id"`
}
type Member struct {
	Reference
	Environment string `json:"environment"`
}
type Application struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	OwnerHint string   `json:"owner_hint"`
	Members   []Member `json:"members"`
}
type SpireKubernetes struct {
	SpireSourceID      string `json:"spire_source_id"`
	ParentID           string `json:"parent_id"`
	KubernetesSourceID string `json:"kubernetes_source_id"`
	Cluster            string `json:"cluster"`
}

var contextID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$`)

func (c Config) validateContexts(kinds map[string]string) error {
	if len(c.VaultKubernetes) > 100 {
		return fmt.Errorf("too many Vault mount declarations")
	}
	mounts := map[string]bool{}
	for _, b := range c.VaultKubernetes {
		key := b.VaultSourceID + "\x00" + b.Mount
		if kinds[b.VaultSourceID] != "vault" || kinds[b.KubernetesSourceID] != "kubernetes" || !contextID.MatchString(b.Mount) || mounts[key] {
			return fmt.Errorf("Vault mappings need unique exact mounts and typed source IDs")
		}
		mounts[key] = true
	}
	if len(c.Applications) > 100 || len(c.SpireKubernetes) > 100 {
		return fmt.Errorf("too many business or SPIRE declarations")
	}
	seen := map[string]bool{}
	total := 0
	for _, app := range c.Applications {
		if !contextID.MatchString(app.ID) || app.Name == "" || !model.GitHubText(app.Name, 160) || !model.GitHubText(app.OwnerHint, 160) || seen[app.ID] || len(app.Members) == 0 {
			return fmt.Errorf("business applications need unique IDs, bounded names and explicit members")
		}
		seen[app.ID] = true
		members := map[Member]bool{}
		for _, m := range app.Members {
			total++
			if total > 2000 || kinds[m.SourceID] == "" || m.Kind == "" || m.NativeID == "" || len(m.NativeID) > 2048 || strings.ContainsAny(m.NativeID, "\r\n\x00") || !contextID.MatchString(m.Environment) || members[m] {
				return fmt.Errorf("business members need known sources, exact native references and explicit environments")
			}
			members[m] = true
		}
	}
	parents := map[string]bool{}
	for _, b := range c.SpireKubernetes {
		key := b.SpireSourceID + "\x00" + b.ParentID
		if kinds[b.SpireSourceID] != "spire" || kinds[b.KubernetesSourceID] != "kubernetes" || !model.SpiffeURI(b.ParentID) || !contextID.MatchString(b.Cluster) || parents[key] {
			return fmt.Errorf("SPIRE parent mappings need unique exact parents and typed source IDs")
		}
		parents[key] = true
	}
	return nil
}
