package platform

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/grantlinehq/grantline/internal/analyze"
	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/correlate"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	"net/http"
	"sigs.k8s.io/yaml"
	"time"
)

func (s *Server) enqueue(w http.ResponseWriter, r *http.Request) {
	id := randomID()
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	result, e := tx.ExecContext(r.Context(), "INSERT INTO runs(id,kind,state,actor_id) SELECT $1,'collection','queued',$2 WHERE EXISTS(SELECT 1 FROM integrations WHERE enabled) ON CONFLICT DO NOTHING", id, actor(r).ID)
	if e != nil {
		fail(w, 500, "queue_unavailable")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		fail(w, 409, "collection_active_or_no_integrations")
		return
	}
	if audit(r.Context(), tx, actor(r).ID, "collection.queued", id) != nil || tx.Commit() != nil {
		fail(w, 500, "queue_unavailable")
		return
	}
	send(w, 202, map[string]string{"run_id": id})
}
func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, e := s.db.ExecContext(r.Context(), "UPDATE runs SET cancel_requested=true,finished_at=CASE WHEN state='queued' THEN now() ELSE finished_at END,state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END WHERE id=$1 AND state IN ('queued','running')", id)
	if e != nil {
		fail(w, 500, "cancel_failed")
		return
	}
	send(w, 202, map[string]bool{"ok": true})
}
func (s *Server) StartWorker(ctx context.Context) (<-chan struct{}, error) {
	lease, e := s.db.Conn(ctx)
	if e != nil {
		return nil, e
	}
	var acquired bool
	if e = lease.QueryRowContext(ctx, "SELECT pg_try_advisory_lock(714290005)").Scan(&acquired); e != nil || !acquired {
		lease.Close()
		return nil, errors.New("only one active server instance is supported")
	}
	if _, e = s.db.ExecContext(ctx, "UPDATE runs SET state='interrupted',finished_at=now(),error_code='server_restarted' WHERE state='running'"); e == nil {
		e = s.recoverRun(ctx)
	}
	if e != nil {
		lease.ExecContext(ctx, "SELECT pg_advisory_unlock(714290005)")
		lease.Close()
		return nil, e
	}
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(ctx)
	s.workerHealthy.Store(true)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ping, stop := context.WithTimeout(ctx, 2*time.Second)
				err := lease.PingContext(ping)
				stop()
				if err != nil {
					s.workerHealthy.Store(false)
					cancel()
					return
				}
			}
		}
	}()
	go func() {
		defer close(done)
		defer cancel()
		defer s.workerHealthy.Store(false)
		defer lease.Close()
		defer func() {
			c, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			lease.ExecContext(c, "SELECT pg_advisory_unlock(714290005)")
		}()
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		lastCleanup := time.Time{}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.recoverRun(ctx)
				s.db.ExecContext(ctx, `WITH due AS (UPDATE workspace SET next_run=now()+(schedule_minutes*interval '1 minute') WHERE id=1 AND next_run<=now() AND EXISTS(SELECT 1 FROM integrations WHERE enabled) RETURNING id) INSERT INTO runs(id,kind,state) SELECT $1,'collection','queued' FROM due ON CONFLICT DO NOTHING`, randomID())
				s.deliverEmail(ctx)
				if time.Since(lastCleanup) > time.Hour {
					s.db.ExecContext(ctx, "DELETE FROM runs WHERE state NOT IN ('queued','running') AND created_at<now()-((SELECT retention_days FROM workspace WHERE id=1)*interval '1 day')")
					s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<now()")
					s.db.ExecContext(ctx, "DELETE FROM tickets WHERE expires_at<now()")
					s.db.ExecContext(ctx, "DELETE FROM email_jobs WHERE created_at<now()-interval '1 day'")
					s.db.ExecContext(ctx, "DELETE FROM auth_attempts WHERE until_at<now()-interval '1 day'")
					s.db.ExecContext(ctx, `WITH expired AS (UPDATE triage SET state='in_review',revision=revision+1,updated_at=now() WHERE state='accepted_risk' AND expires_at<=now() RETURNING finding_id) INSERT INTO audit(action,subject) SELECT 'risk_acceptance.expired',finding_id FROM expired`)
					lastCleanup = time.Now()
				}
				var id string
				e := s.db.QueryRowContext(ctx, `UPDATE runs SET state='running',started_at=now(),attempts=attempts+1 WHERE id=(SELECT id FROM runs WHERE state='queued' ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id`).Scan(&id)
				if e == nil {
					s.run(ctx, id)
				}
			}
		}
	}()
	return done, nil
}

// Recover one abandoned collection without replacing a currently queued request.
func (s *Server) recoverRun(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET state='queued',finished_at=NULL WHERE id=(SELECT id FROM runs WHERE kind='collection' AND state='interrupted' AND error_code IN ('server_stopped','server_restarted') AND attempts<3 AND NOT cancel_requested AND NOT EXISTS(SELECT 1 FROM runs WHERE kind='collection' AND state IN ('queued','running')) ORDER BY created_at LIMIT 1)`)
	return err
}

type runConnection struct {
	Config      Connection
	Credentials map[string]string
	Failure     bool
}

type sourceCollection struct {
	SourceID   string     `json:"source_id"`
	Kind       string     `json:"kind"`
	Method     string     `json:"method"`
	State      string     `json:"state"`
	DurationMS int64      `json:"duration_ms"`
	Entities   int        `json:"entities"`
	Evidence   int        `json:"evidence"`
	ErrorCode  string     `json:"error_code,omitempty"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
}
type collectionProgress struct {
	Phase   string             `json:"phase"`
	Sources []sourceCollection `json:"sources"`
}

func (s *Server) collectionProgress(ctx context.Context, id string, progress collectionProgress) error {
	data, err := json.Marshal(progress)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "UPDATE runs SET configuration=jsonb_set(configuration,'{collection}',$2::jsonb) WHERE id=$1", id, data)
	return err
}

func (s *Server) run(parent context.Context, id string) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func(watchCtx context.Context) {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-watchCtx.Done():
				return
			case <-t.C:
				var stop bool
				if s.db.QueryRowContext(watchCtx, "SELECT cancel_requested FROM runs WHERE id=$1", id).Scan(&stop) == nil && stop {
					cancel()
					return
				}
			}
		}
	}(ctx)
	state, code := "failed", "collection_failed"
	committed := false
	defer func() {
		if committed {
			return
		}
		if ctx.Err() != nil {
			if parent.Err() != nil {
				state, code = "interrupted", "server_stopped"
			} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				state, code = "failed", "collection_timeout"
			} else {
				state, code = "cancelled", "cancelled"
			}
		}
		finish, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		s.db.ExecContext(finish, "UPDATE runs SET state=$2,error_code=$3,finished_at=now() WHERE id=$1", id, state, code)
	}()
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return
	}
	defer tx.Rollback()
	var policyText, bindingText string
	var revision int
	if tx.QueryRowContext(ctx, "SELECT policy,bindings,revision FROM workspace WHERE id=1").Scan(&policyText, &bindingText, &revision) != nil {
		return
	}
	rows, e := tx.QueryContext(ctx, "SELECT id,config,credentials,secret_ref FROM integrations WHERE enabled ORDER BY id")
	if e != nil {
		return
	}
	connections := []runConnection{}
	sources := []config.Source{}
	for rows.Next() {
		var sourceID, ref string
		var b, cipher []byte
		if rows.Scan(&sourceID, &b, &cipher, &ref) != nil {
			rows.Close()
			return
		}
		var c Connection
		if json.Unmarshal(b, &c) != nil {
			rows.Close()
			return
		}
		credentials := map[string]string{}
		failed := false
		var clear []byte
		if ref != "" {
			clear, e = s.secretReference(ref)
		} else {
			clear, e = unseal(s.cfg.EncryptionKey, "connection:"+sourceID, cipher)
		}
		failed = e != nil
		if !failed {
			failed = json.Unmarshal(clear, &credentials) != nil
		}

		connections = append(connections, runConnection{c, credentials, failed})
		sources = append(sources, c.Source)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || tx.Commit() != nil {
		return
	}
	if len(connections) == 0 {
		code = "no_enabled_integrations"
		return
	}
	linked := map[string]runConnection{}
	for _, c := range connections {
		linked[c.Config.Source.ID] = c
	}
	ctx = context.WithValue(ctx, connectionSnapshotKey{}, linked)
	configs := []Connection{}
	for _, c := range connections {
		configs = append(configs, c.Config)
	}
	configuration, _ := json.Marshal(map[string]any{"connections": configs, "policy": policyText, "bindings": bindingText})
	if _, e = s.db.ExecContext(ctx, "UPDATE runs SET config_revision=$2,configuration=$3 WHERE id=$1", id, revision, configuration); e != nil {
		return
	}
	declared := bindings.Config{SchemaVersion: 1}
	configured := policy.Policy{}
	snapshot := model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, CollectedAt: time.Now().UTC(), Entities: []model.Entity{}, Relationships: []model.Relationship{}, Evidence: []model.Evidence{}, Sources: []model.Source{}}
	progress := collectionProgress{Phase: "collecting", Sources: []sourceCollection{}}
	for _, connection := range connections {
		method := "live_api"
		if connection.Config.Source.Kind == "spire" {
			method = "provider_export"
		}
		progress.Sources = append(progress.Sources, sourceCollection{SourceID: connection.Config.Source.ID, Kind: connection.Config.Source.Kind, Method: method, State: "pending"})
	}
	for index, connection := range connections {
		if ctx.Err() != nil {
			return
		}
		c := connection.Config
		step := &progress.Sources[index]
		step.State = "running"
		if s.collectionProgress(ctx, id, progress) != nil {
			code = "progress_save_failed"
			return
		}
		started := time.Now()
		var next model.Snapshot
		var err error
		if !connection.Failure {
			next, err = s.collect(ctx, c, connection.Credentials)
		}
		step.DurationMS = time.Since(started).Milliseconds()
		step.Entities = len(next.Entities)
		step.Evidence = len(next.Evidence)
		step.State = "completed"
		if !next.CollectedAt.IsZero() {
			observed := next.CollectedAt
			step.ObservedAt = &observed
		}
		for _, source := range next.Sources {
			if !source.Complete {
				step.State = "partial"
				step.ErrorCode = source.ErrorCode
			}
			if source.Status == model.SourceError {
				step.State = "failed"
			}
		}
		if connection.Failure || err != nil {
			step.State = "failed"
			step.ErrorCode = "connection_unavailable"
		}
		if s.collectionProgress(ctx, id, progress) != nil {
			code = "progress_save_failed"
			return
		}
		if connection.Failure || err != nil {
			provenance := model.ProvenanceLiveAPI
			if c.Source.Kind == "spire" {
				provenance = model.ProvenanceProviderExport
			}
			snapshot.Sources = append(snapshot.Sources, model.Source{ID: c.Source.ID, Kind: c.Source.Kind, Scope: c.Source.Scope, Status: model.SourceError, ErrorCode: "connection_unavailable", Provenance: provenance, PermissionsObserved: []string{}, Warnings: []string{"Collection failed; review the connection credentials and scope."}})
			continue
		}
		snapshot.Entities = append(snapshot.Entities, next.Entities...)
		snapshot.Relationships = append(snapshot.Relationships, next.Relationships...)
		snapshot.Evidence = append(snapshot.Evidence, next.Evidence...)
		snapshot.Sources = append(snapshot.Sources, next.Sources...)
	}
	progress.Phase = "analyzing"
	if s.collectionProgress(ctx, id, progress) != nil {
		code = "progress_save_failed"
		return
	}
	if bindingText != "" && (yaml.UnmarshalStrict([]byte(bindingText), &declared) != nil || declared.Validate(sources) != nil) {
		code = "invalid_bindings"
		return
	}
	maps := []correlate.VaultKubernetesBinding{}
	for _, source := range sources {
		if source.Kind == "vault" && source.KubernetesSourceID != "" {
			maps = append(maps, correlate.VaultKubernetesBinding{VaultSourceID: source.ID, KubernetesSourceID: source.KubernetesSourceID})
		}
	}
	if correlate.AddVaultKubernetesTrusts(&snapshot, maps) != nil {
		return
	}
	correlate.AddJenkinsVaultBindings(&snapshot, declared.JenkinsVault)
	correlate.AddGitHubEntraTrusts(&snapshot)
	configured = defaultPolicy(sources)
	if policyText != "" {
		configured, e = policy.Parse([]byte(policyText))
		if e != nil {
			code = "invalid_policy"
			return
		}
	}

	report, e := (analyze.Analyzer{Bindings: &declared}).Analyze(snapshot, configured)
	if e != nil {
		code = "analysis_failed"
		return
	}
	write, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return
	}
	defer write.Rollback()
	if e = saveReport(ctx, write, id, report); e != nil {
		code = "report_save_failed"
		return
	}
	if audit(ctx, write, "", "collection.finished", id) != nil {
		code = "audit_save_failed"
		return
	}
	finalState := "completed"
	if !report.Completeness.Complete {
		finalState = "partial"
	}
	// Commit the immutable report and terminal run state together. A crash cannot
	// leave a saved report attached to a job that will be retried on restart.
	progress.Phase = "finished"
	progressJSON, _ := json.Marshal(progress)
	if _, e = write.ExecContext(ctx, "UPDATE runs SET state=$2,error_code='',finished_at=now(),configuration=jsonb_set(configuration,'{collection}',$3::jsonb) WHERE id=$1", id, finalState, progressJSON); e != nil || write.Commit() != nil {
		return
	}
	committed = true
}
func defaultPolicy(sources []config.Source) policy.Policy {
	p := policy.Policy{SchemaVersion: 1, Rules: map[string]policy.Rule{}, MaxClientSecretValidity: 168 * time.Hour, MaxX509SVIDTTL: 24 * time.Hour, MaxJWTSVIDTTL: time.Hour}
	for _, id := range []string{"IL001", "IL002", "IL003", "IL004", "IL005", "IL006", "IL007", "IL008", "IL009"} {
		p.Rules[id] = policy.Rule{Severity: model.SeverityMedium}
	}
	yes := true
	p.Rules["IL006"] = policy.Rule{Severity: model.SeverityHigh, ForbidNamespaceOnly: &yes}
	p.Rules["IL008"] = policy.Rule{Severity: model.SeverityMedium, SeparatedEnvironments: []policy.EnvironmentPair{{First: "production", Second: "development"}, {First: "production", Second: "staging"}}}
	p.Rules["IL009"] = policy.Rule{Severity: model.SeverityMedium, SeparatedEnvironments: append([]policy.EnvironmentPair{}, p.Rules["IL008"].SeparatedEnvironments...)}
	owners := p.Rules["IL004"]
	for _, source := range sources {
		p.RequiredSources = append(p.RequiredSources, source.ID)
		for _, id := range source.Applications {
			owners.RequireOwnersFor = append(owners.RequireOwnersFor, policy.EntraOwnerTarget{SourceID: source.ID, ObjectID: id, ObjectKind: "application_registration"})
		}
	}
	p.Rules["IL004"] = owners
	return p
}
