package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/grantlinehq/grantline/internal/model"
)

func Write(path string, value model.Snapshot) error {
	if err := value.Validate(); err != nil {
		return fmt.Errorf("validate snapshot before write: %w", err)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	data = append(data, '\n')

	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".grantline-snapshot-*")
	if err != nil {
		return fmt.Errorf("create temporary snapshot: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("set temporary snapshot permissions: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write temporary snapshot: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary snapshot: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace snapshot: %w", err)
	}
	return nil
}
