package demolab

import (
	"errors"
	"time"

	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
)

const Notice = "Demo lab collection: synthetic scenarios evaluated by the rule engine. Severity follows the demo policy."

type Inputs struct {
	Snapshot   model.Snapshot
	Policy     policy.Policy
	Bindings   bindings.Config
	PolicyText string
}

// Collect creates fresh scenario inputs, never precomputed findings or a report.
// Native IDs are synthetic; source IDs match the six enabled local connections.
func Collect(now time.Time, sources []config.Source) (Inputs, error) {
	kinds := map[string]bool{"kubernetes": true, "vault": true, "jenkins": true, "entra": true, "github": true, "spire": true}
	aliases := map[string]string{}
	ids := map[string]bool{}
	for _, s := range sources {
		if !kinds[s.Kind] || s.ID == "" || ids[s.ID] || aliases["demo-"+s.Kind] != "" {
			return Inputs{}, errors.New("demo lab requires one enabled connection of each of the six source kinds")
		}
		aliases["demo-"+s.Kind] = s.ID
		ids[s.ID] = true
	}
	if len(aliases) != 6 {
		return Inputs{}, errors.New("demo lab requires all six source kinds enabled")
	}
	c := buildCatalogWithIDs(now, aliases)
	if err := c.snapshot.Validate(); err != nil {
		return Inputs{}, err
	}
	if err := c.policy.Validate(); err != nil {
		return Inputs{}, err
	}
	return Inputs{Snapshot: c.snapshot, Policy: c.policy, Bindings: c.bindings, PolicyText: c.policyYAML()}, nil
}
