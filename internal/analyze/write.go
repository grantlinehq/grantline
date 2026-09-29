package analyze

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/grantlinehq/grantline/internal/model"
)

func WriteReport(path string, report model.Report) error {
	if path == "" {
		return fmt.Errorf("report output path is required")
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".grantline-report-*")
	if err != nil {
		return fmt.Errorf("create report temporary file: %w", err)
	}
	temporaryPath := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("set report permissions: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		_ = file.Close()
		return fmt.Errorf("encode report: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close report temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("atomically replace report: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("set report permissions after replacement: %w", err)
	}
	cleanup = false
	return nil
}
