package store

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/watchtower/watchtower/internal/models"
)


//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	pool *pgxpool.Pool
}

func New(databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse db config: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	s := &Store{pool: pool}
	if err := s.migrate(); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) Ping() error {
	return s.pool.Ping(context.Background())
}

func (s *Store) migrate() error {
	files := []string{
		"migrations/001_initial.sql",
		"migrations/002_cases.sql",
	}
	for _, f := range files {
		data, err := migrations.ReadFile(f)
		if err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
		if _, err := s.pool.Exec(context.Background(), string(data)); err != nil {
			return fmt.Errorf("exec %s: %w", f, err)
		}
	}
	return nil
}

// === Agent operations ===

func (s *Store) UpsertAgent(a *models.Agent) error {
	labelsJSON, _ := json.Marshal(a.Labels)
	_, err := s.pool.Exec(context.Background(), `
		INSERT INTO agents (id, hostname, os, platform, version, group_id, labels, status, ip_address, last_heartbeat, registered_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			hostname       = EXCLUDED.hostname,
			os             = EXCLUDED.os,
			platform       = EXCLUDED.platform,
			version        = EXCLUDED.version,
			labels         = EXCLUDED.labels,
			status         = EXCLUDED.status,
			ip_address     = EXCLUDED.ip_address,
			last_heartbeat = EXCLUDED.last_heartbeat`,
		a.ID, a.Hostname, a.OS, a.Platform, a.Version, a.GroupID,
		string(labelsJSON), string(a.Status), a.IPAddress, a.LastHeartbeat, a.RegisteredAt,
	)
	return err
}

func (s *Store) GetAgent(id string) (*models.Agent, error) {
	row := s.pool.QueryRow(context.Background(),
		`SELECT id, hostname, os, platform, version, group_id, labels, status, ip_address, last_heartbeat, registered_at
		 FROM agents WHERE id = $1`, id)
	return scanAgent(row)
}

func (s *Store) ListAgents(status string, limit, offset int) ([]*models.Agent, error) {
	var args []interface{}
	query := `SELECT id, hostname, os, platform, version, group_id, labels, status, ip_address, last_heartbeat, registered_at FROM agents`
	if status != "" {
		query += " WHERE status = $1"
		args = append(args, status)
	}
	query += " ORDER BY registered_at DESC"
	if limit > 0 {
		n := len(args) + 1
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", n, n+1)
		args = append(args, limit, offset)
	}

	rows, err := s.pool.Query(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*models.Agent
	for rows.Next() {
		a, err := scanAgentRows(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

func (s *Store) DeleteAgent(id string) error {
	_, err := s.pool.Exec(context.Background(), "DELETE FROM agents WHERE id = $1", id)
	return err
}

func (s *Store) UpdateAgentHeartbeat(id, status string) error {
	_, err := s.pool.Exec(context.Background(),
		"UPDATE agents SET last_heartbeat = $1, status = $2 WHERE id = $3",
		time.Now().UnixMilli(), status, id)
	return err
}

// MarkDisconnectedBefore sets all active/streaming agents whose last_heartbeat
// is older than cutoffMs to disconnected in a single query — O(1) vs O(n).
func (s *Store) MarkDisconnectedBefore(cutoffMs int64) error {
	_, err := s.pool.Exec(context.Background(), `
		UPDATE agents SET status = 'disconnected'
		WHERE status IN ('active', 'streaming')
		AND last_heartbeat > 0
		AND last_heartbeat < $1`, cutoffMs)
	return err
}

func (s *Store) UpdateAgentGroup(id, groupID string) error {
	_, err := s.pool.Exec(context.Background(),
		"UPDATE agents SET group_id = $1 WHERE id = $2", groupID, id)
	return err
}

func (s *Store) CountAgents() (total, active, disconnected int, err error) {
	rows, err := s.pool.Query(context.Background(),
		`SELECT status, COUNT(*) FROM agents GROUP BY status`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var cnt int
		if err = rows.Scan(&st, &cnt); err != nil {
			return
		}
		total += cnt
		switch st {
		case "active", "streaming":
			active += cnt
		case "disconnected":
			disconnected += cnt
		}
	}
	err = rows.Err()
	return
}

// === Group operations ===

func (s *Store) CreateGroup(g *models.AgentGroup) error {
	_, err := s.pool.Exec(context.Background(),
		"INSERT INTO agent_groups (id, name, description, config_overrides) VALUES ($1, $2, $3, $4)",
		g.ID, g.Name, g.Description, g.ConfigOverrides)
	return err
}

func (s *Store) GetGroup(id string) (*models.AgentGroup, error) {
	g := &models.AgentGroup{}
	err := s.pool.QueryRow(context.Background(),
		"SELECT id, name, description, config_overrides FROM agent_groups WHERE id = $1", id).
		Scan(&g.ID, &g.Name, &g.Description, &g.ConfigOverrides)
	if err != nil {
		return nil, err
	}
	return g, nil
}

func (s *Store) ListGroups() ([]*models.AgentGroup, error) {
	rows, err := s.pool.Query(context.Background(),
		"SELECT id, name, description, config_overrides FROM agent_groups ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []*models.AgentGroup
	for rows.Next() {
		g := &models.AgentGroup{}
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.ConfigOverrides); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (s *Store) DeleteGroup(id string) error {
	_, err := s.pool.Exec(context.Background(), "DELETE FROM agent_groups WHERE id = $1", id)
	return err
}

// === Alert operations ===

func (s *Store) InsertAlert(a *models.Alert) (int64, error) {
	groupsJSON, _ := json.Marshal(a.RuleGroups)
	var id int64
	err := s.pool.QueryRow(context.Background(), `
		INSERT INTO alerts (rule_id, level, agent_id, timestamp, title, description, event_data, rule_groups, forwarded)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id`,
		a.RuleID, a.Level, a.AgentID, a.Timestamp, a.Title, a.Description,
		a.EventData, string(groupsJSON), a.Forwarded,
	).Scan(&id)
	return id, err
}

func (s *Store) ListAlerts(agentID string, minLevel int, limit, offset int) ([]*models.Alert, error) {
	var conditions []string
	var args []interface{}

	if agentID != "" {
		args = append(args, agentID)
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", len(args)))
	}
	if minLevel > 0 {
		args = append(args, minLevel)
		conditions = append(conditions, fmt.Sprintf("level >= $%d", len(args)))
	}

	query := `SELECT id, rule_id, level, agent_id, timestamp, title, description, event_data, rule_groups, forwarded FROM alerts`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY timestamp DESC"
	if limit > 0 {
		args = append(args, limit, offset)
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	}

	rows, err := s.pool.Query(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlerts(rows)
}

func (s *Store) CountAlerts() (int, error) {
	var count int
	err := s.pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM alerts").Scan(&count)
	return count, err
}

func (s *Store) ListAlertsByType(agentID, eventType string, limit, offset int) ([]*models.Alert, error) {
	args := []interface{}{agentID, "%" + eventType + "%"}
	query := `SELECT id, rule_id, level, agent_id, timestamp, title, description, event_data, rule_groups, forwarded
		FROM alerts WHERE agent_id = $1 AND event_data LIKE $2 ORDER BY timestamp DESC`
	if limit > 0 {
		query += " LIMIT $3 OFFSET $4"
		args = append(args, limit, offset)
	}

	rows, err := s.pool.Query(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlerts(rows)
}

// === Active Response operations ===

func (s *Store) InsertActiveResponse(ar *models.ActiveResponse) error {
	_, err := s.pool.Exec(context.Background(),
		`INSERT INTO active_responses (id, agent_id, action, parameters, status, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		ar.ID, ar.AgentID, ar.Action, ar.Parameters, ar.Status, ar.CreatedAt)
	return err
}

func (s *Store) UpdateActiveResponseStatus(id, status, result string) error {
	_, err := s.pool.Exec(context.Background(),
		"UPDATE active_responses SET status = $1, result = $2, executed_at = $3 WHERE id = $4",
		status, result, time.Now().UnixMilli(), id)
	return err
}

// === Scan helpers ===

func scanAgent(row pgx.Row) (*models.Agent, error) {
	a := &models.Agent{}
	var labelsJSON, status string
	err := row.Scan(&a.ID, &a.Hostname, &a.OS, &a.Platform, &a.Version, &a.GroupID,
		&labelsJSON, &status, &a.IPAddress, &a.LastHeartbeat, &a.RegisteredAt)
	if err != nil {
		return nil, err
	}
	a.Status = models.AgentStatus(status)
	_ = json.Unmarshal([]byte(labelsJSON), &a.Labels)
	return a, nil
}

func scanAgentRows(rows pgx.Rows) (*models.Agent, error) {
	a := &models.Agent{}
	var labelsJSON, status string
	err := rows.Scan(&a.ID, &a.Hostname, &a.OS, &a.Platform, &a.Version, &a.GroupID,
		&labelsJSON, &status, &a.IPAddress, &a.LastHeartbeat, &a.RegisteredAt)
	if err != nil {
		return nil, err
	}
	a.Status = models.AgentStatus(status)
	_ = json.Unmarshal([]byte(labelsJSON), &a.Labels)
	return a, nil
}

// === Case operations ===

func (s *Store) CreateCase(c *models.Case) (int64, error) {
	now := time.Now().UnixMilli()
	c.CreatedAt = now
	c.UpdatedAt = now
	tagsJSON, _ := json.Marshal(c.Tags)
	alertsJSON, _ := json.Marshal(c.AlertIDs)
	agentsJSON, _ := json.Marshal(c.AgentIDs)
	var id int64
	err := s.pool.QueryRow(context.Background(), `
		INSERT INTO cases (title, description, status, priority, severity, assignee, created_by, created_at, updated_at, tags, alert_ids, agent_ids)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id`,
		c.Title, c.Description, string(c.Status), string(c.Priority), c.Severity,
		c.Assignee, c.CreatedBy, c.CreatedAt, c.UpdatedAt,
		string(tagsJSON), string(alertsJSON), string(agentsJSON),
	).Scan(&id)
	return id, err
}

func (s *Store) GetCase(id int64) (*models.Case, error) {
	row := s.pool.QueryRow(context.Background(), `
		SELECT c.id, c.title, c.description, c.status, c.priority, c.severity,
		       c.assignee, c.created_by, c.created_at, c.updated_at, c.closed_at,
		       c.tags, c.alert_ids, c.agent_ids,
		       (SELECT COUNT(*) FROM case_notes n WHERE n.case_id = c.id) AS note_count
		FROM cases c WHERE c.id = $1`, id)
	return scanCase(row)
}

func (s *Store) ListCases(status, priority, assignee string, limit, offset int) ([]*models.Case, error) {
	var conditions []string
	var args []interface{}

	if status != "" {
		args = append(args, status)
		conditions = append(conditions, fmt.Sprintf("c.status = $%d", len(args)))
	}
	if priority != "" {
		args = append(args, priority)
		conditions = append(conditions, fmt.Sprintf("c.priority = $%d", len(args)))
	}
	if assignee != "" {
		args = append(args, assignee)
		conditions = append(conditions, fmt.Sprintf("c.assignee = $%d", len(args)))
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}
	query := fmt.Sprintf(`
		SELECT c.id, c.title, c.description, c.status, c.priority, c.severity,
		       c.assignee, c.created_by, c.created_at, c.updated_at, c.closed_at,
		       c.tags, c.alert_ids, c.agent_ids,
		       (SELECT COUNT(*) FROM case_notes n WHERE n.case_id = c.id) AS note_count
		FROM cases c %s ORDER BY c.created_at DESC`, where)
	if limit > 0 {
		args = append(args, limit, offset)
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	}

	rows, err := s.pool.Query(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cases []*models.Case
	for rows.Next() {
		c, err := scanCaseRows(rows)
		if err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	return cases, rows.Err()
}

func (s *Store) UpdateCase(id int64, title, description, status, priority, assignee string, severity int, tags []string, alertIDs []int64, agentIDs []string) error {
	now := time.Now().UnixMilli()
	tagsJSON, _ := json.Marshal(tags)
	alertsJSON, _ := json.Marshal(alertIDs)
	agentsJSON, _ := json.Marshal(agentIDs)

	closedAt := int64(0)
	if status == string(models.CaseStatusClosed) || status == string(models.CaseStatusResolved) {
		closedAt = now
	}

	_, err := s.pool.Exec(context.Background(), `
		UPDATE cases SET title=$1, description=$2, status=$3, priority=$4, severity=$5,
		assignee=$6, updated_at=$7, closed_at=$8, tags=$9, alert_ids=$10, agent_ids=$11
		WHERE id=$12`,
		title, description, status, priority, severity, assignee,
		now, closedAt, string(tagsJSON), string(alertsJSON), string(agentsJSON), id)
	return err
}

func (s *Store) DeleteCase(id int64) error {
	_, err := s.pool.Exec(context.Background(), "DELETE FROM cases WHERE id = $1", id)
	return err
}

func (s *Store) CountCases() (total, open, investigating, resolved int, err error) {
	rows, err := s.pool.Query(context.Background(),
		`SELECT status, COUNT(*) FROM cases GROUP BY status`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var cnt int
		if err = rows.Scan(&st, &cnt); err != nil {
			return
		}
		total += cnt
		switch st {
		case "open":
			open += cnt
		case "investigating":
			investigating += cnt
		case "resolved", "closed":
			resolved += cnt
		}
	}
	err = rows.Err()
	return
}

// === Case Notes ===

func (s *Store) AddCaseNote(note *models.CaseNote) (int64, error) {
	note.CreatedAt = time.Now().UnixMilli()
	var id int64
	err := s.pool.QueryRow(context.Background(), `
		INSERT INTO case_notes (case_id, author, content, created_at)
		VALUES ($1,$2,$3,$4) RETURNING id`,
		note.CaseID, note.Author, note.Content, note.CreatedAt,
	).Scan(&id)
	return id, err
}

func (s *Store) ListCaseNotes(caseID int64) ([]*models.CaseNote, error) {
	rows, err := s.pool.Query(context.Background(),
		`SELECT id, case_id, author, content, created_at FROM case_notes
		 WHERE case_id = $1 ORDER BY created_at ASC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []*models.CaseNote
	for rows.Next() {
		n := &models.CaseNote{}
		if err := rows.Scan(&n.ID, &n.CaseID, &n.Author, &n.Content, &n.CreatedAt); err != nil {
			return nil, err
		}
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

// === Case Evidence ===

func (s *Store) AddCaseEvidence(ev *models.CaseEvidence) (int64, error) {
	ev.AddedAt = time.Now().UnixMilli()
	var id int64
	err := s.pool.QueryRow(context.Background(), `
		INSERT INTO case_evidence (case_id, title, type, content, added_by, added_at)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		ev.CaseID, ev.Title, ev.Type, ev.Content, ev.AddedBy, ev.AddedAt,
	).Scan(&id)
	return id, err
}

func (s *Store) ListCaseEvidence(caseID int64) ([]*models.CaseEvidence, error) {
	rows, err := s.pool.Query(context.Background(),
		`SELECT id, case_id, title, type, content, added_by, added_at FROM case_evidence
		 WHERE case_id = $1 ORDER BY added_at DESC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var evidence []*models.CaseEvidence
	for rows.Next() {
		e := &models.CaseEvidence{}
		if err := rows.Scan(&e.ID, &e.CaseID, &e.Title, &e.Type, &e.Content, &e.AddedBy, &e.AddedAt); err != nil {
			return nil, err
		}
		evidence = append(evidence, e)
	}
	return evidence, rows.Err()
}

// === Case scan helpers ===

func scanCase(row pgx.Row) (*models.Case, error) {
	c := &models.Case{}
	var status, priority, tagsJSON, alertsJSON, agentsJSON string
	err := row.Scan(&c.ID, &c.Title, &c.Description, &status, &priority, &c.Severity,
		&c.Assignee, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.ClosedAt,
		&tagsJSON, &alertsJSON, &agentsJSON, &c.NoteCount)
	if err != nil {
		return nil, err
	}
	c.Status = models.CaseStatus(status)
	c.Priority = models.CasePriority(priority)
	_ = json.Unmarshal([]byte(tagsJSON), &c.Tags)
	_ = json.Unmarshal([]byte(alertsJSON), &c.AlertIDs)
	_ = json.Unmarshal([]byte(agentsJSON), &c.AgentIDs)
	return c, nil
}

func scanCaseRows(rows pgx.Rows) (*models.Case, error) {
	c := &models.Case{}
	var status, priority, tagsJSON, alertsJSON, agentsJSON string
	err := rows.Scan(&c.ID, &c.Title, &c.Description, &status, &priority, &c.Severity,
		&c.Assignee, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.ClosedAt,
		&tagsJSON, &alertsJSON, &agentsJSON, &c.NoteCount)
	if err != nil {
		return nil, err
	}
	c.Status = models.CaseStatus(status)
	c.Priority = models.CasePriority(priority)
	_ = json.Unmarshal([]byte(tagsJSON), &c.Tags)
	_ = json.Unmarshal([]byte(alertsJSON), &c.AlertIDs)
	_ = json.Unmarshal([]byte(agentsJSON), &c.AgentIDs)
	return c, nil
}

func scanAlerts(rows pgx.Rows) ([]*models.Alert, error) {
	var alerts []*models.Alert
	for rows.Next() {
		a := &models.Alert{}
		var groupsJSON string
		var forwarded bool
		if err := rows.Scan(&a.ID, &a.RuleID, &a.Level, &a.AgentID, &a.Timestamp,
			&a.Title, &a.Description, &a.EventData, &groupsJSON, &forwarded); err != nil {
			return nil, err
		}
		a.Forwarded = forwarded
		_ = json.Unmarshal([]byte(groupsJSON), &a.RuleGroups)
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}
