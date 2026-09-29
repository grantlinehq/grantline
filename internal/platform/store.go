package platform

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/viewer"
	"time"
)

//go:embed migrations/*.sql
var migrations embed.FS

const databaseVersion = 3

func Open(ctx context.Context, url string) (*sql.DB, error) {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, errors.New("database configuration invalid")
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, errors.New("database unavailable")
	}
	return db, nil
}
func Migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(714290001)"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations(version integer PRIMARY KEY)"); err != nil {
		return err
	}
	var current int
	if err = tx.QueryRowContext(ctx, "SELECT COALESCE(max(version),0) FROM schema_migrations").Scan(&current); err != nil {
		return err
	}
	if current > databaseVersion {
		return errors.New("database schema newer than application; restore a compatible backup")
	}
	for next := current + 1; next <= databaseVersion; next++ {
		body, readErr := migrations.ReadFile(fmt.Sprintf("migrations/%03d.sql", next))
		if readErr != nil {
			return readErr
		}
		if _, err = tx.ExecContext(ctx, string(body)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations VALUES($1)", next); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func saveReport(ctx context.Context, tx *sql.Tx, run string, r model.Report) error {
	if err := viewer.Validate(r); err != nil {
		return errors.New("report validation failed")
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO reports(run_id,report) VALUES($1,$2)", run, data); err != nil {
		return err
	}
	type indexedObject struct {
		Category string          `json:"category"`
		ID       string          `json:"id"`
		Source   string          `json:"source_id"`
		Name     string          `json:"name"`
		Kind     string          `json:"kind"`
		Severity int             `json:"severity"`
		Body     json.RawMessage `json:"body"`
	}
	batch := make([]indexedObject, 0, 500)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		payload, e := json.Marshal(batch)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO objects(run_id,category,id,source_id,name,kind,severity,body) SELECT $1,x.category,x.id,x.source_id,x.name,x.kind,x.severity,x.body FROM jsonb_to_recordset($2::jsonb) AS x(category text,id text,source_id text,name text,kind text,severity integer,body jsonb)`, run, payload)
		batch = batch[:0]
		return e
	}
	add := func(category, id, source, name, kind string, severity int, value any) error {
		b, e := json.Marshal(value)
		if e != nil {
			return e
		}
		batch = append(batch, indexedObject{category, id, source, name, kind, severity, b})
		if len(batch) == 500 {
			return flush()
		}
		return nil
	}
	for _, v := range r.Snapshot.Entities {
		if err = add("identities", v.ID, v.SourceID, v.Name, v.Kind, 0, v); err != nil {
			return err
		}
	}
	for _, v := range r.Findings {
		rank := map[model.Severity]int{model.SeverityCritical: 4, model.SeverityHigh: 3, model.SeverityMedium: 2, model.SeverityLow: 1}[v.Severity]
		if err = add("findings", v.ID, "", v.Condition, v.RuleID, rank, v); err != nil {
			return err
		}
	}
	for _, v := range r.Snapshot.Relationships {
		if err = add("relationships", v.ID, "", v.Type, v.Type, 0, v); err != nil {
			return err
		}
	}
	for _, v := range r.Snapshot.Evidence {
		if err = add("evidence", v.ID, v.SourceID, v.Locator, "", 0, v); err != nil {
			return err
		}
	}
	return flush()
}

func jsonRows(ctx context.Context, db *sql.DB, query string, args ...any) ([]json.RawMessage, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(b))
	}
	return out, rows.Err()
}
func audit(ctx context.Context, tx *sql.Tx, actor, action, subject string) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO audit(actor_id,action,subject) VALUES(NULLIF($1,''),$2,$3)", actor, action, subject)
	return err
}
func databaseError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("database operation failed")
}
