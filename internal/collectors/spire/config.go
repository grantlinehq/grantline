package spire

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/grantlinehq/grantline/internal/model"
)

const SDKVersion = "v1.2.5-0.20240916165922-16526993814a"
const ExportSchemaVersion = "1"
const MaxExportBytes = 10 << 20

type Options struct {
	TrustDomain          string   `json:"trust_domain"`
	ParentIDs            []string `json:"parent_ids"`
	SocketPath           string   `json:"socket_path,omitempty"`
	ExportPath           string   `json:"export_path,omitempty"`
	WorkloadEvidencePath string   `json:"workload_evidence_path,omitempty"`
}
type Config struct {
	ID, Scope string
	Options
}

func (c Config) Validate() error {
	if c.SocketPath != "" && c.WorkloadEvidencePath != "" {
		return fmt.Errorf("workload evidence can only accompany a controlled export import")
	}
	if c.ID == "" || strings.ContainsAny(c.ID, " \t\r\n") || !strings.HasPrefix(c.Scope, "spire/") || len(c.Scope) <= 6 || !model.GitHubText(c.Scope, 240) || !model.SpireTrustDomain(c.TrustDomain) {
		return fmt.Errorf("SPIRE source requires instance scope and canonical trust domain")
	}
	if (c.SocketPath == "") == (c.ExportPath == "") {
		return fmt.Errorf("SPIRE source requires exactly one local socket_path or export_path")
	}
	if c.SocketPath != "" && (!filepath.IsAbs(c.SocketPath) || strings.ContainsAny(c.SocketPath, "\x00\r\n") || len(c.SocketPath) > 100) {
		return fmt.Errorf("SPIRE socket_path must be a bounded absolute Unix socket path")
	}
	if len(c.ParentIDs) == 0 || len(c.ParentIDs) > 50 {
		return fmt.Errorf("SPIRE source requires 1 to 50 explicit parent SPIFFE IDs")
	}
	seen := map[string]bool{}
	for _, id := range c.ParentIDs {
		if !model.SpireURIInDomain(id, c.TrustDomain) || seen[id] {
			return fmt.Errorf("SPIRE parent IDs must be unique canonical IDs in the configured trust domain")
		}
		seen[id] = true
	}
	return nil
}
