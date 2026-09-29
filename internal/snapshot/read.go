package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/grantlinehq/grantline/internal/model"
)

const MaxSnapshotBytes = 10 << 20

func Load(path string) (model.Snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("open snapshot: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, MaxSnapshotBytes+1))
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("read snapshot: %w", err)
	}
	if len(data) > MaxSnapshotBytes {
		return model.Snapshot{}, fmt.Errorf("snapshot exceeds the %d-byte M0 limit", MaxSnapshotBytes)
	}
	return Parse(data)
}

func Parse(data []byte) (model.Snapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var result model.Snapshot
	if err := decoder.Decode(&result); err != nil {
		return model.Snapshot{}, fmt.Errorf("invalid snapshot JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return model.Snapshot{}, fmt.Errorf("snapshot must contain exactly one JSON value")
	}
	if err := result.Validate(); err != nil {
		return model.Snapshot{}, fmt.Errorf("invalid snapshot: %w", err)
	}
	return result, nil
}
