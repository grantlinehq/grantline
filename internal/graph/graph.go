package graph

import (
	"fmt"
	"sort"

	"github.com/grantlinehq/grantline/internal/model"
)

type Graph struct {
	Entities map[string]model.Entity
	outgoing map[string][]model.Relationship
}

func Build(snapshot model.Snapshot) (Graph, error) {
	if err := snapshot.Validate(); err != nil {
		return Graph{}, fmt.Errorf("validate snapshot before graph construction: %w", err)
	}

	result := Graph{
		Entities: make(map[string]model.Entity, len(snapshot.Entities)),
		outgoing: make(map[string][]model.Relationship, len(snapshot.Entities)),
	}
	for _, entity := range snapshot.Entities {
		result.Entities[entity.ID] = entity
	}
	for _, relationship := range snapshot.Relationships {
		result.outgoing[relationship.From] = append(result.outgoing[relationship.From], relationship)
	}
	for entityID := range result.outgoing {
		sort.Slice(result.outgoing[entityID], func(left, right int) bool {
			return result.outgoing[entityID][left].ID < result.outgoing[entityID][right].ID
		})
	}

	return result, nil
}

func (graph Graph) Outgoing(entityID, relationshipType string) []model.Relationship {
	relationships := graph.outgoing[entityID]
	result := make([]model.Relationship, 0, len(relationships))
	for _, relationship := range relationships {
		if relationship.Type == relationshipType {
			result = append(result, relationship)
		}
	}
	return result
}
