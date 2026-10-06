package platform

import (
	"database/sql"
	"encoding/json"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/viewer"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) registerData() {
	for path, handler := range map[string]http.HandlerFunc{"GET /api/v1/overview": s.overview, "GET /api/v1/runs": s.runs, "GET /api/v1/objects/{category}": s.objects, "GET /api/v1/objects/{category}/{id}": s.object, "GET /api/v1/report": s.report, "GET /api/v1/graph": s.graph, "GET /api/v1/activity": s.activity, "GET /api/v1/settings": s.settings} {
		s.mux.HandleFunc(path, s.auth(handler, false))
	}
	s.mux.HandleFunc("POST /api/v1/reports/import", s.require("admin", s.importReport))
	s.mux.HandleFunc("PUT /api/v1/settings", s.require("admin", s.saveSettings))
	s.mux.HandleFunc("GET /api/v1/settings/policy", s.require("admin", s.policyEditor))
	s.mux.HandleFunc("POST /api/v1/settings/policy/validate", s.require("admin", s.validatePolicy))
	s.mux.HandleFunc("PUT /api/v1/triage/{id}", s.require("analyst", s.saveTriage))
	s.mux.HandleFunc("POST /api/v1/comments/{id}", s.require("analyst", s.comment))
}
func (s *Server) latest(r *http.Request) string {
	id := r.URL.Query().Get("run")
	if id != "" {
		return id
	}
	s.db.QueryRowContext(r.Context(), "SELECT run_id FROM reports ORDER BY created_at DESC,run_id DESC LIMIT 1").Scan(&id)
	return id
}
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	id := s.latest(r)
	if id == "" {
		send(w, 200, map[string]any{"run_id": "", "identities": 0, "findings": 0, "sources": []any{}, "rule_results": []any{}})
		return
	}
	var summary []byte
	e := s.db.QueryRowContext(r.Context(), `SELECT jsonb_build_object('run_id',run_id,'generated_at',report->'generated_at','snapshot_collected_at',report->'snapshot_collected_at','fixture_notice',report->'fixture_notice','completeness',report->'completeness','rule_results',report->'rule_results','sources',report->'snapshot'->'sources','identities',(SELECT count(*) FROM objects WHERE run_id=$1 AND category='identities' AND kind IN ('service_account','service_principal','spiffe_identity')),'findings',(SELECT count(*) FROM objects WHERE run_id=$1 AND category='findings'),'relationships',(SELECT count(*) FROM objects WHERE run_id=$1 AND category='relationships')) FROM reports WHERE run_id=$1`, id).Scan(&summary)
	if e != nil {
		fail(w, 404, "report_not_found")
		return
	}
	var out map[string]any
	if json.Unmarshal(summary, &out) != nil {
		fail(w, 500, "report_unavailable")
		return
	}
	var kind string
	s.db.QueryRowContext(r.Context(), "SELECT kind FROM runs WHERE id=$1", id).Scan(&kind)
	out["run_kind"] = kind
	var lastSuccess sql.NullTime
	s.db.QueryRowContext(r.Context(), "SELECT max(finished_at) FROM runs WHERE kind='collection' AND state='completed'").Scan(&lastSuccess)
	if lastSuccess.Valid {
		out["last_success"] = lastSuccess.Time
	}
	send(w, 200, out)
}
func (s *Server) objects(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")
	if category != "identities" && category != "findings" && category != "relationships" && category != "evidence" {
		fail(w, 404, "not_found")
		return
	}
	run := s.latest(r)
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 0 || page > 100000 {
		fail(w, 400, "invalid_page")
		return
	}
	search := q.Get("q")
	if len(search) > 256 {
		fail(w, 400, "query_too_long")
		return
	}
	where := objectListWhere(category, q.Get("source"), search)
	args := []any{run, category, search, q.Get("source"), q.Get("kind"), q.Get("native") == "true", q.Get("state")}
	var total int
	projection := "o.body || CASE WHEN o.category='findings' THEN jsonb_build_object('triage_state',COALESCE(t.state,'open'),'assignee_id',t.assignee_id) ELSE '{}'::jsonb END"
	selectSQL := "SELECT " + projection
	if category == "findings" {
		// Evaluate the federation set once and keep triage pagination consistent.
		selectSQL = "SELECT jsonb_build_object('total',count(*) OVER(),'item'," + projection + ")"
	} else if e := s.db.QueryRowContext(r.Context(), "SELECT count(*)"+where, args...).Scan(&total); e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	items, e := jsonRows(r.Context(), s.db, selectSQL+where+" ORDER BY o.severity DESC,o.name,o.id LIMIT 50 OFFSET $8", append(args, page*50)...)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	if category == "findings" {
		for i, raw := range items {
			var row struct {
				Total int             `json:"total"`
				Item  json.RawMessage `json:"item"`
			}
			if json.Unmarshal(raw, &row) != nil {
				fail(w, 500, "finding_unavailable")
				return
			}
			total, items[i] = row.Total, row.Item
		}
		if len(items) == 0 && page > 0 {
			if e := s.db.QueryRowContext(r.Context(), "SELECT count(*)"+where, args...).Scan(&total); e != nil {
				fail(w, 503, "database_unavailable")
				return
			}
		}
	}
	if category == "findings" && len(items) > 0 {
		findings := make([]model.Finding, len(items))
		for i, raw := range items {
			if json.Unmarshal(raw, &findings[i]) != nil {
				fail(w, 500, "finding_unavailable")
				return
			}
		}
		contexts, err := s.findingContexts(r.Context(), run, findings)
		if err != nil {
			fail(w, 500, "finding_context_unavailable")
			return
		}
		for i, raw := range items {
			var item map[string]any
			json.Unmarshal(raw, &item)
			item["context"] = contexts[findings[i].ID]
			items[i], _ = json.Marshal(item)
		}
	}
	send(w, 200, map[string]any{"run_id": run, "items": items, "total": total, "page": page, "page_size": 50})
}
func (s *Server) object(w http.ResponseWriter, r *http.Request) {
	run := s.latest(r)
	id := r.PathValue("id")
	category := r.PathValue("category")
	var b []byte
	if e := s.db.QueryRowContext(r.Context(), "SELECT body FROM objects WHERE run_id=$1 AND category=$2 AND id=$3", run, category, id).Scan(&b); e != nil {
		fail(w, 404, "object_not_found")
		return
	}
	var v struct {
		EvidenceIDs []string `json:"evidence_ids"`
		Affected    []string `json:"affected_entity_ids"`
	}
	json.Unmarshal(b, &v)
	if category == "identities" {
		rows, e := jsonRows(r.Context(), s.db, `SELECT body FROM objects WHERE run_id=$1 AND category='evidence' AND source_id=(SELECT source_id FROM objects WHERE run_id=$1 AND category='identities' AND id=$2) AND body->>'native_id'=(SELECT body->>'native_id' FROM objects WHERE run_id=$1 AND category='identities' AND id=$2) ORDER BY id LIMIT 101`, run, id)
		if e != nil {
			fail(w, 500, "evidence_unavailable")
			return
		}
		send(w, 200, map[string]any{"item": json.RawMessage(b), "evidence": rows[:min(len(rows), 100)], "evidence_truncated": len(rows) > 100})
		return
	}
	evidence, e := jsonRows(r.Context(), s.db, "SELECT body FROM objects WHERE run_id=$1 AND category='evidence' AND id=ANY($2) ORDER BY id LIMIT 101", run, v.EvidenceIDs)
	if e != nil {
		fail(w, 500, "evidence_unavailable")
		return
	}
	entities, e := jsonRows(r.Context(), s.db, "SELECT body FROM objects WHERE run_id=$1 AND category='identities' AND id=ANY($2) ORDER BY id LIMIT 101", run, v.Affected)
	if e != nil {
		fail(w, 500, "entities_unavailable")
		return
	}
	var triage json.RawMessage = json.RawMessage(`{"state":"open","revision":0}`)
	var tb []byte
	if s.db.QueryRowContext(r.Context(), "SELECT to_jsonb(t) FROM triage t WHERE finding_id=$1", id).Scan(&tb) == nil {
		triage = tb
	}
	comments, e := jsonRows(r.Context(), s.db, "SELECT jsonb_build_object('id',c.id,'body',c.body,'name',u.name,'created_at',c.created_at) FROM comments c JOIN users u ON u.id=c.actor_id WHERE finding_id=$1 ORDER BY c.created_at DESC,c.id LIMIT 101", id)
	if e != nil {
		fail(w, 500, "comments_unavailable")
		return
	}
	out := map[string]any{"item": json.RawMessage(b), "evidence": evidence[:min(len(evidence), 100)], "entities": entities[:min(len(entities), 100)], "triage": triage, "comments": comments[:min(len(comments), 100)], "evidence_truncated": len(evidence) > 100, "entities_truncated": len(entities) > 100, "comments_truncated": len(comments) > 100}
	if category == "findings" {
		var finding model.Finding
		json.Unmarshal(b, &finding)
		contexts, err := s.findingContexts(r.Context(), run, []model.Finding{finding})
		if err != nil {
			fail(w, 500, "finding_context_unavailable")
			return
		}
		out["context"] = contexts[finding.ID]
	}
	send(w, 200, out)
}
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	var b []byte
	if e := s.db.QueryRowContext(r.Context(), "SELECT report FROM reports WHERE run_id=$1", s.latest(r)).Scan(&b); e != nil {
		fail(w, 404, "report_not_found")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="grantline-report.json"`)
	send(w, 200, json.RawMessage(b))
}
func (s *Server) graph(w http.ResponseWriter, r *http.Request) {
	var b []byte
	if e := s.db.QueryRowContext(r.Context(), "SELECT report FROM reports WHERE run_id=$1", s.latest(r)).Scan(&b); e != nil {
		fail(w, 404, "report_not_found")
		return
	}
	var report model.Report
	if json.Unmarshal(b, &report) != nil {
		fail(w, 500, "report_unavailable")
		return
	}
	depth := 1
	if r.URL.Query().Get("depth") == "2" {
		depth = 2
	}
	send(w, 200, viewer.Graph(report.Snapshot, r.URL.Query().Get("entity"), r.URL.Query().Get("assertion"), r.URL.Query().Get("type"), depth))
}
func (s *Server) importReport(w http.ResponseWriter, r *http.Request) {
	var report model.Report
	if decode(r, &report) != nil || viewer.Validate(report) != nil {
		fail(w, 400, "invalid_report")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	id := randomID()
	_, e = tx.ExecContext(r.Context(), "INSERT INTO runs(id,kind,state,actor_id,started_at,finished_at) VALUES($1,'import','completed',$2,now(),now())", id, actor(r).ID)
	if e == nil {
		e = saveReport(r.Context(), tx, id, report)
	}
	if e == nil {
		e = audit(r.Context(), tx, actor(r).ID, "report.imported", id)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 500, "import_failed")
		return
	}
	send(w, 201, map[string]string{"run_id": id})
}
func (s *Server) runs(w http.ResponseWriter, r *http.Request) {
	rows, e := jsonRows(r.Context(), s.db, "SELECT (to_jsonb(r)-'configuration') || jsonb_build_object('collection',configuration->'collection') FROM runs r ORDER BY created_at DESC LIMIT 100")
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	send(w, 200, rows)
}
func (s *Server) activity(w http.ResponseWriter, r *http.Request) {
	rows, e := jsonRows(r.Context(), s.db, "SELECT jsonb_build_object('id',a.id,'action',a.action,'subject',a.subject,'name',COALESCE(u.name,'System'),'created_at',a.created_at) FROM audit a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 200")
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	send(w, 200, rows)
}
func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	if !privileged(actor(r).Role) {
		fail(w, 403, "role_required")
		return
	}
	var b []byte
	if e := s.db.QueryRowContext(r.Context(), "SELECT to_jsonb(w) FROM workspace w WHERE id=1").Scan(&b); e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	send(w, 200, json.RawMessage(b))
}
func (s *Server) saveSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name                         string
		ScheduleMinutes              int `json:"schedule_minutes"`
		RetentionDays                int `json:"retention_days"`
		Policy, Bindings             string
		Revision                     int
		AcknowledgeCoverageReduction bool `json:"acknowledge_coverage_reduction"`
	}
	if decode(r, &in) != nil || len(in.Name) < 1 || len(in.Name) > 100 || in.ScheduleMinutes < 15 || in.ScheduleMinutes > 10080 || in.RetentionDays < 1 || in.RetentionDays > 365 {
		fail(w, 400, "invalid_settings")
		return
	}
	sources, e := s.integrationSources(r.Context())
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	if issues := configurationIssues(in.Policy, in.Bindings, sources); len(issues) > 0 {
		invalidFields(w, issues)
		return
	}
	enabled, e := s.enabledPolicySources(r.Context())
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	var currentName, currentPolicy string
	var currentRevision int
	if e = tx.QueryRowContext(r.Context(), "SELECT name,policy,revision FROM workspace WHERE id=1 FOR UPDATE").Scan(&currentName, &currentPolicy, &currentRevision); e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	if in.Revision != currentRevision {
		fail(w, 409, "settings_changed_reload")
		return
	}
	if in.Name != currentName && actor(r).Role != "owner" {
		fail(w, 403, "owner_required")
		return
	}
	if in.Policy != currentPolicy && !in.AcknowledgeCoverageReduction {
		before, oldErr := effectivePolicy(currentPolicy, enabled)
		after, newErr := effectivePolicy(in.Policy, enabled)
		if oldErr == nil && newErr == nil && len(coverageReduction(before, after)) > 0 {
			send(w, 409, map[string]any{"error": "coverage_acknowledgement_required", "message": "This policy reduces rule or required-source coverage. Review the change and explicitly acknowledge it before saving.", "warnings": coverageReduction(before, after)})
			return
		}
	}
	result, e := tx.ExecContext(r.Context(), "UPDATE workspace SET name=$1,schedule_minutes=$2,retention_days=$3,policy=$4,bindings=$5,revision=revision+1,next_run=now()+($2::integer*interval '1 minute') WHERE id=1 AND revision=$6", in.Name, in.ScheduleMinutes, in.RetentionDays, in.Policy, in.Bindings, in.Revision)
	if e != nil {
		fail(w, 500, "settings_failed")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		fail(w, 409, "settings_changed_reload")
		return
	}
	if recordVersion(r.Context(), tx, "workspace", "1", in.Revision+1, in, actor(r).ID) != nil || audit(r.Context(), tx, actor(r).ID, "settings.updated", "") != nil || tx.Commit() != nil {
		fail(w, 500, "settings_failed")
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (s *Server) saveTriage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		State, Assignee, Reason string
		Expires                 *time.Time `json:"expires_at"`
		Revision                int
	}
	id := r.PathValue("id")
	if decode(r, &in) != nil || len(in.Reason) > 4000 || (in.State != "open" && in.State != "in_review" && in.State != "accepted_risk" && in.State != "resolved") {
		fail(w, 400, "invalid_triage")
		return
	}
	if in.State == "accepted_risk" && (strings.TrimSpace(in.Reason) == "" || in.Expires == nil || !in.Expires.After(time.Now())) {
		fail(w, 400, "risk_requires_reason_and_future_expiry")
		return
	}
	var exists bool
	if s.db.QueryRowContext(r.Context(), "SELECT EXISTS(SELECT 1 FROM objects WHERE category='findings' AND id=$1)", id).Scan(&exists) != nil || !exists {
		fail(w, 404, "finding_not_found")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	result, e := tx.ExecContext(r.Context(), `INSERT INTO triage(finding_id,state,assignee_id,reason,expires_at) SELECT $1,$2,NULLIF($3,''),$4,$5 WHERE $6=0 ON CONFLICT(finding_id) DO NOTHING`, id, in.State, in.Assignee, in.Reason, in.Expires, in.Revision)
	if e == nil && in.Revision > 0 {
		result, e = tx.ExecContext(r.Context(), "UPDATE triage SET state=$2,assignee_id=NULLIF($3,''),reason=$4,expires_at=$5,revision=revision+1,updated_at=now() WHERE finding_id=$1 AND revision=$6", id, in.State, in.Assignee, in.Reason, in.Expires, in.Revision)
	}
	if e != nil {
		fail(w, 400, "invalid_assignee")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		fail(w, 409, "triage_changed_reload")
		return
	}
	if audit(r.Context(), tx, actor(r).ID, "finding."+in.State, id) != nil || tx.Commit() != nil {
		fail(w, 500, "triage_failed")
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (s *Server) comment(w http.ResponseWriter, r *http.Request) {
	var in struct{ Body string }
	if decode(r, &in) != nil || len(strings.TrimSpace(in.Body)) == 0 || len(in.Body) > 4000 {
		fail(w, 400, "invalid_comment")
		return
	}
	id := r.PathValue("id")
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	var exists bool
	if tx.QueryRowContext(r.Context(), "SELECT EXISTS(SELECT 1 FROM objects WHERE category='findings' AND id=$1)", id).Scan(&exists) != nil || !exists {
		fail(w, 404, "finding_not_found")
		return
	}
	_, e = tx.ExecContext(r.Context(), "INSERT INTO comments(id,finding_id,actor_id,body) VALUES($1,$2,$3,$4)", randomID(), id, actor(r).ID, in.Body)
	if e == nil {
		e = audit(r.Context(), tx, actor(r).ID, "finding.commented", id)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 500, "comment_failed")
		return
	}
	send(w, 201, map[string]bool{"ok": true})
}

var _ = sql.ErrNoRows

func objectListWhere(category, source, search string) string {
	sourceFilter := ` AND ($4='' OR o.source_id=$4 OR (o.category='findings' AND EXISTS(SELECT 1 FROM objects affected WHERE affected.run_id=o.run_id AND affected.category='identities' AND affected.source_id=$4 AND o.body->'affected_entity_ids' ? affected.id))`
	// Keep federation joins out of identity lists and unfiltered finding lists.
	if category == "findings" {
		sourceFilter = ` AND ($4='' OR o.source_id=$4 OR o.body->'affected_entity_ids' ?| ARRAY(SELECT affected.id FROM objects affected WHERE affected.run_id=$1 AND affected.category='identities' AND affected.source_id=$4)`
	}
	if category == "findings" && source != "" {
		// Build the matching application set once per request, not once per finding.
		sourceFilter += ` OR (o.body->'affected_entity_ids' ?| ARRAY(
 SELECT DISTINCT app.id FROM objects app
 JOIN objects fic ON fic.run_id=app.run_id AND fic.category='identities' AND fic.kind='federated_credential' AND fic.source_id=app.source_id
 AND app.body->'field_status'->>'object_id'='known' AND fic.body->'field_status'->>'parent_object_id'='known'
 AND fic.body->'attributes'->>'parent_object_id'=app.body->'attributes'->>'object_id'
 JOIN objects edge ON edge.run_id=app.run_id AND edge.category='relationships' AND edge.kind='trusts_subject'
 AND edge.body->>'from'=fic.id AND edge.body->>'assertion_kind' IN ('configured','declared') AND jsonb_array_length(edge.body->'evidence_ids')>0
 JOIN objects workflow ON workflow.run_id=app.run_id AND workflow.category='identities' AND workflow.kind='workflow'
 AND workflow.source_id=$4 AND workflow.id=edge.body->>'to'
 WHERE app.run_id=$1 AND app.category='identities' AND app.kind='application_registration'))`
	}
	searchFilter := ` AND ($3='' OR o.name ILIKE '%'||$3||'%' OR o.body->>'native_id' ILIKE '%'||$3||'%'`
	if category == "findings" && search != "" {
		searchFilter += ` OR (o.category='findings' AND EXISTS(SELECT 1 FROM objects affected WHERE affected.run_id=o.run_id AND affected.category='identities' AND affected.id=ANY(ARRAY(SELECT jsonb_array_elements_text(o.body->'affected_entity_ids'))) AND (affected.name ILIKE '%'||$3||'%' OR affected.body->>'native_id' ILIKE '%'||$3||'%' OR (affected.body->'field_status'->>'spiffe_id'='known' AND affected.body->'attributes'->>'spiffe_id' ILIKE '%'||$3||'%') OR (affected.kind='credential_metadata' AND affected.body->'field_status'->>'parent_object_id'='known' AND affected.body->'field_status'->>'parent_kind'='known' AND EXISTS(SELECT 1 FROM objects parent WHERE parent.run_id=affected.run_id AND parent.category='identities' AND parent.source_id=affected.source_id AND parent.kind=affected.body->'attributes'->>'parent_kind' AND parent.body->'field_status'->>'object_id'='known' AND parent.body->'attributes'->>'object_id'=affected.body->'attributes'->>'parent_object_id' AND (parent.name ILIKE '%'||$3||'%' OR parent.body->>'native_id' ILIKE '%'||$3||'%'))))))`
	}
	where := ` FROM objects o LEFT JOIN triage t ON o.category='findings' AND t.finding_id=o.id WHERE o.run_id=$1 AND o.category=$2` + searchFilter + `)` + sourceFilter + `) AND ($5='' OR o.kind=$5) AND ($6=false OR o.kind IN ('service_account','service_principal','spiffe_identity')) AND ($7='' OR COALESCE(t.state,'open')=$7 OR ($7='active' AND COALESCE(t.state,'open') IN ('open','in_review')))`
	return where
}
