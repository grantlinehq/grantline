package model_test

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCommittedSchemasAreValidJSON(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"../../schema/snapshot/schema.json",
		"../../schema/report/schema.json",
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		if document["$schema"] == nil || document["$id"] == nil {
			t.Fatalf("%s is missing JSON Schema metadata", path)
		}
	}
}
