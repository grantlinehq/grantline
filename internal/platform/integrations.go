package platform

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/grantlinehq/grantline/internal/collectors/spire"
	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/model"
	"net/http"
	"strings"
	"time"
)

type Connection struct {
	Source         config.Source       `json:"source"`
	AuthMode       string              `json:"auth_mode"`
	ClientID       string              `json:"client_id,omitempty"`
	AppID          string              `json:"app_id,omitempty"`
	InstallationID string              `json:"installation_id,omitempty"`
	Jenkinsfiles   []LinkedJenkinsfile `json:"jenkinsfiles,omitempty"`
}
type LinkedJenkinsfile struct {
	Job            string `json:"job"`
	GitHubSourceID string `json:"github_source_id"`
	Repository     string `json:"repository"`
	RepositoryID   string `json:"repository_id"`
	Commit         string `json:"commit"`
	Path           string `json:"path"`
}
type IntegrationInput struct {
	Name        string            `json:"name"`
	Config      Connection        `json:"config"`
	Credentials map[string]string `json:"credentials,omitempty"`
	SecretRef   string            `json:"secret_ref"`
	Enabled     bool              `json:"enabled"`
	Revision    int               `json:"revision"`
}

func (s *Server) registerIntegrations() {
	s.mux.HandleFunc("GET /api/v1/integrations", s.auth(s.integrations, false))
	s.mux.HandleFunc("POST /api/v1/integrations", s.require("admin", s.saveIntegration))
	s.mux.HandleFunc("PUT /api/v1/integrations/{id}", s.require("admin", s.saveIntegration))
	s.mux.HandleFunc("DELETE /api/v1/integrations/{id}", s.require("admin", s.deleteIntegration))
	s.mux.HandleFunc("POST /api/v1/integrations/{id}/test", s.require("admin", s.testIntegration))
	s.mux.HandleFunc("POST /api/v1/runs", s.require("analyst", s.enqueue))
	s.mux.HandleFunc("POST /api/v1/runs/{id}/cancel", s.require("analyst", s.cancelRun))
}
func normalizeConnection(c *Connection, id string) error {
	c.Source.ID = id
	c.Source.TokenEnv = "GRANTLINE_TOKEN"
	if len(c.Jenkinsfiles) > 100 || (len(c.Jenkinsfiles) > 0 && c.Source.Kind != "jenkins") {
		return errors.New("invalid Jenkinsfile mapping")
	}
	seen := map[string]bool{}
	for _, v := range c.Jenkinsfiles {
		jobFound := false
		for _, j := range c.Source.Jobs {
			if j.Path == v.Job && j.Kind == "job" {
				jobFound = true
			}
		}
		if !jobFound || seen[v.Job] || v.GitHubSourceID == "" || !model.GitHubRepoName.MatchString(v.Repository) || !model.GitHubNumericID.MatchString(v.RepositoryID) || !model.GitHubSHA.MatchString(v.Commit) || v.Path == "" || strings.HasPrefix(v.Path, "/") || strings.ContainsAny(v.Path, "\\\x00\r\n") {
			return errors.New("explicit immutable Jenkinsfile mapping required")
		}
		for _, segment := range strings.Split(v.Path, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return errors.New("invalid file path")
			}
		}
		seen[v.Job] = true
	}
	switch c.Source.Kind {
	case "kubernetes":
		c.Source.KubeconfigPath = "managed"
		c.Source.TokenEnv = ""
		if c.AuthMode != "kubeconfig" {
			return errors.New("unsupported authentication")
		}
	case "jenkins":
		if c.AuthMode != "token" {
			return errors.New("unsupported authentication")
		}
		c.Source.UsernameEnv = "GRANTLINE_USERNAME"
		for _, job := range c.Source.Jobs {
			if job.Jenkinsfile != nil {
				return errors.New("server does not accept local repository paths")
			}
		}
	case "entra":
		if c.AuthMode != "client_secret" && c.AuthMode != "token" {
			return errors.New("unsupported authentication")
		}
		if c.AuthMode == "client_secret" && !connectionUUID.MatchString(c.ClientID) {
			return errors.New("invalid application client ID")
		}
	case "github":
		if c.AuthMode != "github_app" && c.AuthMode != "token" {
			return errors.New("unsupported authentication")
		}
		if c.AuthMode == "github_app" && (!model.GitHubNumericID.MatchString(c.AppID) || !model.GitHubNumericID.MatchString(c.InstallationID)) {
			return errors.New("invalid GitHub App identifiers")
		}
	case "vault":
		if c.AuthMode != "token" {
			return errors.New("unsupported authentication")
		}
	case "spire":
		c.Source.TokenEnv = ""
		if c.Source.Spire == nil {
			c.Source.Spire = &spire.Options{}
		}
		if c.Source.Spire.SocketPath != "" || c.Source.Spire.WorkloadEvidencePath != "" {
			return errors.New("SPIRE requires a metadata export")
		}
		c.Source.Spire.ExportPath = "managed"
		if c.AuthMode != "export" {
			return errors.New("SPIRE requires a metadata export")
		}
	default:
		return errors.New("unsupported provider")
	}
	return c.Source.Validate()
}
func (s *Server) integrations(w http.ResponseWriter, r *http.Request) {
	query := `SELECT jsonb_build_object('id',id,'name',name,'kind',kind,'enabled',enabled,'revision',revision,'tested_at',tested_at,'test_result',test_result,'configured',credentials IS NOT NULL OR secret_ref<>'','updated_at',updated_at) FROM integrations ORDER BY name`
	if privileged(actor(r).Role) {
		query = `SELECT jsonb_build_object('id',id,'name',name,'kind',kind,'config',config,'secret_ref',secret_ref,'enabled',enabled,'revision',revision,'tested_at',tested_at,'test_result',test_result,'configured',credentials IS NOT NULL OR secret_ref<>'','updated_at',updated_at) FROM integrations ORDER BY name`
	}
	rows, e := jsonRows(r.Context(), s.db, query)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	send(w, 200, rows)
}
func (s *Server) saveIntegration(w http.ResponseWriter, r *http.Request) {
	var in IntegrationInput
	if decode(r, &in) != nil || len(in.Name) < 1 || len(in.Name) > 100 {
		fail(w, 400, "invalid_integration")
		return
	}
	id := r.PathValue("id")
	fresh := id == ""
	if fresh {
		id = randomID()
	}
	if e := normalizeConnection(&in.Config, id); e != nil {
		issues := integrationIssues(in.Config)
		if len(issues) == 0 {
			issues = []fieldIssue{{Field: "config", Message: "Review the provider scope, authentication method and resource fields."}}
		}
		invalidFields(w, issues)
		return
	}
	if in.SecretRef != "" && (strings.ContainsAny(in.SecretRef, "/\\") || len(in.Credentials) > 0) {
		fail(w, 400, "choose_credentials_or_secret_reference")
		return
	}
	var cipher []byte
	if in.Credentials != nil {
		allowed := map[string]bool{"token": true, "username": true, "kubeconfig": true, "client_secret": true, "private_key": true, "export": true}
		for k, v := range in.Credentials {
			if !allowed[k] || len(v) > 10<<20 {
				fail(w, 400, "invalid_credentials")
				return
			}
		}
		b, _ := json.Marshal(in.Credentials)
		var e error
		cipher, e = seal(s.cfg.EncryptionKey, "connection:"+id, b)
		if e != nil {
			fail(w, 500, "credential_storage_failed")
			return
		}
	}
	if fresh && len(cipher) == 0 && in.SecretRef == "" {
		fail(w, 400, "credentials_required")
		return
	}
	data, _ := json.Marshal(in.Config)
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	if fresh {
		if _, e = tx.ExecContext(r.Context(), "SELECT pg_advisory_xact_lock(714290004)"); e != nil {
			fail(w, 503, "database_unavailable")
			return
		}
		var count int
		if tx.QueryRowContext(r.Context(), "SELECT count(*) FROM integrations").Scan(&count) != nil || count >= 20 {
			fail(w, 409, "integration_limit_20")
			return
		}
		_, e = tx.ExecContext(r.Context(), "INSERT INTO integrations(id,name,kind,config,credentials,secret_ref,enabled) VALUES($1,$2,$3,$4,$5,$6,$7)", id, in.Name, in.Config.Source.Kind, data, cipher, in.SecretRef, in.Enabled)
	} else {
		var result sql.Result
		result, e = tx.ExecContext(r.Context(), `UPDATE integrations SET name=$2,config=$3,credentials=CASE WHEN $5<>'' THEN NULL WHEN $4::bytea IS NOT NULL THEN $4 ELSE credentials END,secret_ref=$5,enabled=$6,revision=revision+1,tested_at=CASE WHEN config=$3::jsonb AND $4::bytea IS NULL AND secret_ref=$5 THEN tested_at ELSE NULL END,test_result=CASE WHEN config=$3::jsonb AND $4::bytea IS NULL AND secret_ref=$5 THEN test_result ELSE NULL END,updated_at=now() WHERE id=$1 AND revision=$7 AND kind=$8 AND ($5<>'' OR $4::bytea IS NOT NULL OR credentials IS NOT NULL)`, id, in.Name, data, cipher, in.SecretRef, in.Enabled, in.Revision, in.Config.Source.Kind)
		if e == nil {
			n, _ := result.RowsAffected()
			if n == 0 {
				fail(w, 409, "integration_changed_reload")
				return
			}
		}
	}
	if e == nil {
		revision := in.Revision + 1
		if fresh {
			revision = 1
		}
		e = recordVersion(r.Context(), tx, "integration", id, revision, map[string]any{"name": in.Name, "config": in.Config, "enabled": in.Enabled}, actor(r).ID)
	}
	if e == nil {
		e = audit(r.Context(), tx, actor(r).ID, "integration.saved", id)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 500, "integration_save_failed")
		return
	}
	send(w, 201, map[string]string{"id": id})
}
func (s *Server) deleteIntegration(w http.ResponseWriter, r *http.Request) {
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	id := r.PathValue("id")
	_, e = tx.ExecContext(r.Context(), "DELETE FROM integrations WHERE id=$1", id)
	if e == nil {
		e = audit(r.Context(), tx, actor(r).ID, "integration.deleted", id)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 500, "integration_delete_failed")
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (s *Server) connection(ctx context.Context, id string) (Connection, map[string]string, int, error) {
	var c Connection
	var b, cipher []byte
	var ref string
	var revision int
	if e := s.db.QueryRowContext(ctx, "SELECT config,credentials,secret_ref,revision FROM integrations WHERE id=$1", id).Scan(&b, &cipher, &ref, &revision); e != nil {
		return c, nil, 0, errors.New("connection unavailable")
	}
	if json.Unmarshal(b, &c) != nil {
		return c, nil, 0, errors.New("connection invalid")
	}
	var clear []byte
	var e error
	if ref != "" {
		clear, e = s.secretReference(ref)
	} else {
		clear, e = unseal(s.cfg.EncryptionKey, "connection:"+id, cipher)
	}
	if e != nil {
		return c, nil, 0, errors.New("credentials unavailable")
	}
	var credentials map[string]string
	if json.Unmarshal(clear, &credentials) != nil {
		return c, nil, 0, errors.New("credentials invalid")
	}
	return c, credentials, revision, nil
}
func (s *Server) testIntegration(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	c, credentials, revision, e := s.connection(ctx, id)
	if e != nil {
		fail(w, 400, "credentials_unavailable")
		return
	}
	result, e := s.collect(ctx, c, credentials)
	failed := e != nil
	if e != nil {
		result.Sources = []model.Source{{ID: id, Kind: c.Source.Kind, Scope: c.Source.Scope, Status: model.SourceError, Complete: false, ErrorCode: "connection_test_failed", Warnings: []string{"Connection could not be verified. Check credentials, endpoint and scope."}}}
	}
	b, _ := json.Marshal(result.Sources)
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	update, e := tx.ExecContext(r.Context(), "UPDATE integrations SET tested_at=now(),test_result=$2 WHERE id=$1 AND revision=$3", id, b, revision)
	if e != nil {
		fail(w, 500, "test_result_unavailable")
		return
	}
	if n, _ := update.RowsAffected(); n == 0 {
		fail(w, 409, "integration_changed_repeat_test")
		return
	}
	if audit(r.Context(), tx, actor(r).ID, "integration.tested", id) != nil || tx.Commit() != nil {
		fail(w, 500, "test_result_unavailable")
		return
	}
	if failed {
		fail(w, 422, "connection_test_failed")
		return
	}
	send(w, 200, result.Sources)
}
func (s *Server) integrationSources(ctx context.Context) ([]config.Source, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT config FROM integrations ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	sources := []config.Source{}
	for rows.Next() {
		var b []byte
		var c Connection
		if rows.Scan(&b) != nil || json.Unmarshal(b, &c) != nil {
			return nil, errors.New("invalid connection")
		}
		sources = append(sources, c.Source)
	}
	return sources, rows.Err()
}
