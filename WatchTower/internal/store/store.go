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
		"migrations/003_playbooks.sql",
		"migrations/004_rule_versions.sql",
		"migrations/005_identity.sql",
		"migrations/006_ueba.sql",
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

// === Playbook operations ===

func (s *Store) CreatePlaybook(p *models.Playbook) (int64, error) {
	now := time.Now().UnixMilli()
	p.CreatedAt = now
	p.UpdatedAt = now
	triggerJSON, _ := json.Marshal(p.Trigger)
	actionsJSON, _ := json.Marshal(p.Actions)
	var id int64
	err := s.pool.QueryRow(context.Background(), `
		INSERT INTO playbooks (name, description, enabled, trigger, actions, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		p.Name, p.Description, p.Enabled,
		string(triggerJSON), string(actionsJSON), p.CreatedAt, p.UpdatedAt,
	).Scan(&id)
	return id, err
}

func (s *Store) GetPlaybook(id int64) (*models.Playbook, error) {
	row := s.pool.QueryRow(context.Background(), `
		SELECT id, name, description, enabled, trigger, actions, created_at, updated_at, run_count
		FROM playbooks WHERE id = $1`, id)
	return scanPlaybook(row)
}

func (s *Store) ListPlaybooks(enabledOnly bool) ([]*models.Playbook, error) {
	query := `SELECT id, name, description, enabled, trigger, actions, created_at, updated_at, run_count FROM playbooks`
	if enabledOnly {
		query += " WHERE enabled = TRUE"
	}
	query += " ORDER BY created_at DESC"
	rows, err := s.pool.Query(context.Background(), query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pbs []*models.Playbook
	for rows.Next() {
		pb, err := scanPlaybookRows(rows)
		if err != nil {
			return nil, err
		}
		pbs = append(pbs, pb)
	}
	return pbs, rows.Err()
}

func (s *Store) UpdatePlaybook(p *models.Playbook) error {
	p.UpdatedAt = time.Now().UnixMilli()
	triggerJSON, _ := json.Marshal(p.Trigger)
	actionsJSON, _ := json.Marshal(p.Actions)
	_, err := s.pool.Exec(context.Background(), `
		UPDATE playbooks SET name=$1, description=$2, enabled=$3, trigger=$4, actions=$5, updated_at=$6
		WHERE id=$7`,
		p.Name, p.Description, p.Enabled, string(triggerJSON), string(actionsJSON), p.UpdatedAt, p.ID)
	return err
}

func (s *Store) DeletePlaybook(id int64) error {
	_, err := s.pool.Exec(context.Background(), "DELETE FROM playbooks WHERE id = $1", id)
	return err
}

func (s *Store) IncrementPlaybookRunCount(id int64) {
	_, _ = s.pool.Exec(context.Background(),
		"UPDATE playbooks SET run_count = run_count + 1 WHERE id = $1", id)
}

// === Playbook Execution operations ===

func (s *Store) CreateExecution(ex *models.PlaybookExecution) (int64, error) {
	ex.StartedAt = time.Now().UnixMilli()
	resultsJSON, _ := json.Marshal(ex.Results)
	var id int64
	err := s.pool.QueryRow(context.Background(), `
		INSERT INTO playbook_executions (playbook_id, alert_id, agent_id, status, started_at, results)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		ex.PlaybookID, ex.AlertID, ex.AgentID, ex.Status, ex.StartedAt, string(resultsJSON),
	).Scan(&id)
	return id, err
}

func (s *Store) FinishExecution(id int64, status string, results []models.PlaybookActionResult) error {
	resultsJSON, _ := json.Marshal(results)
	_, err := s.pool.Exec(context.Background(), `
		UPDATE playbook_executions SET status=$1, completed_at=$2, results=$3 WHERE id=$4`,
		status, time.Now().UnixMilli(), string(resultsJSON), id)
	return err
}

func (s *Store) ListExecutions(playbookID int64, limit int) ([]*models.PlaybookExecution, error) {
	var args []interface{}
	query := `SELECT id, playbook_id, alert_id, agent_id, status, started_at, completed_at, results
	           FROM playbook_executions`
	if playbookID > 0 {
		args = append(args, playbookID)
		query += fmt.Sprintf(" WHERE playbook_id = $%d", len(args))
	}
	query += " ORDER BY started_at DESC"
	if limit > 0 {
		args = append(args, limit)
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	rows, err := s.pool.Query(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var execs []*models.PlaybookExecution
	for rows.Next() {
		ex := &models.PlaybookExecution{}
		var resultsJSON string
		if err := rows.Scan(&ex.ID, &ex.PlaybookID, &ex.AlertID, &ex.AgentID,
			&ex.Status, &ex.StartedAt, &ex.CompletedAt, &resultsJSON); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(resultsJSON), &ex.Results)
		execs = append(execs, ex)
	}
	return execs, rows.Err()
}

// === UEBA operations ===

// UebaBaseline holds a computed behavioral baseline for one entity+metric.
type UebaBaseline struct {
	EntityID    string  `json:"entity_id"`
	EntityType  string  `json:"entity_type"`
	Metric      string  `json:"metric"`
	AvgValue    float64 `json:"avg_value"`
	StdDev      float64 `json:"std_dev"`
	SampleCount int     `json:"sample_count"`
	ComputedAt  int64   `json:"computed_at"`
}

// UebaAnomaly is a single detected behavioral anomaly.
type UebaAnomaly struct {
	ID          int64  `json:"id"`
	EntityID    string `json:"entity_id"`
	EntityType  string `json:"entity_type"`
	AnomalyType string `json:"anomaly_type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Score       int    `json:"score"`
	DetectedAt  int64  `json:"detected_at"`
	AlertID     int64  `json:"alert_id"`
	Resolved    bool   `json:"resolved"`
}

// UebaRiskScore is the aggregated risk for one entity.
type UebaRiskScore struct {
	EntityID         string `json:"entity_id"`
	EntityType       string `json:"entity_type"`
	RiskScore        int    `json:"risk_score"`
	RiskLevel        string `json:"risk_level"`
	AlertCount7d     int    `json:"alert_count_7d"`
	CriticalCount7d  int    `json:"critical_count_7d"`
	AnomalyCount7d   int    `json:"anomaly_count_7d"`
	LastAlert        int64  `json:"last_alert"`
	UpdatedAt        int64  `json:"updated_at"`
}

func (s *Store) UpsertUebaBaseline(b *UebaBaseline) error {
	b.ComputedAt = time.Now().UnixMilli()
	_, err := s.pool.Exec(context.Background(), `
		INSERT INTO ueba_baselines (entity_id, entity_type, metric, avg_value, std_dev, sample_count, computed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (entity_id, metric) DO UPDATE SET
		  entity_type=$2, avg_value=$4, std_dev=$5, sample_count=$6, computed_at=$7`,
		b.EntityID, b.EntityType, b.Metric, b.AvgValue, b.StdDev, b.SampleCount, b.ComputedAt)
	return err
}

func (s *Store) GetUebaBaseline(entityID, metric string) (*UebaBaseline, error) {
	b := &UebaBaseline{}
	err := s.pool.QueryRow(context.Background(), `
		SELECT entity_id, entity_type, metric, avg_value, std_dev, sample_count, computed_at
		FROM ueba_baselines WHERE entity_id=$1 AND metric=$2`, entityID, metric,
	).Scan(&b.EntityID, &b.EntityType, &b.Metric, &b.AvgValue, &b.StdDev, &b.SampleCount, &b.ComputedAt)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Store) InsertUebaAnomaly(a *UebaAnomaly) (int64, error) {
	a.DetectedAt = time.Now().UnixMilli()
	var id int64
	err := s.pool.QueryRow(context.Background(), `
		INSERT INTO ueba_anomalies (entity_id, entity_type, anomaly_type, description, severity, score, detected_at, alert_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		a.EntityID, a.EntityType, a.AnomalyType, a.Description, a.Severity, a.Score, a.DetectedAt, a.AlertID,
	).Scan(&id)
	return id, err
}

func (s *Store) ListUebaAnomalies(entityID string, limit int) ([]*UebaAnomaly, error) {
	var args []interface{}
	query := `SELECT id, entity_id, entity_type, anomaly_type, description, severity, score, detected_at, alert_id, resolved
	           FROM ueba_anomalies`
	if entityID != "" {
		args = append(args, entityID)
		query += fmt.Sprintf(" WHERE entity_id = $%d", len(args))
	}
	query += " ORDER BY detected_at DESC"
	if limit > 0 {
		args = append(args, limit)
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	rows, err := s.pool.Query(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var anomalies []*UebaAnomaly
	for rows.Next() {
		a := &UebaAnomaly{}
		if err := rows.Scan(&a.ID, &a.EntityID, &a.EntityType, &a.AnomalyType,
			&a.Description, &a.Severity, &a.Score, &a.DetectedAt, &a.AlertID, &a.Resolved); err != nil {
			return nil, err
		}
		anomalies = append(anomalies, a)
	}
	return anomalies, rows.Err()
}

func (s *Store) UpsertUebaRiskScore(r *UebaRiskScore) error {
	r.UpdatedAt = time.Now().UnixMilli()
	_, err := s.pool.Exec(context.Background(), `
		INSERT INTO ueba_risk_scores
		  (entity_id, entity_type, risk_score, risk_level, alert_count_7d, critical_count_7d,
		   anomaly_count_7d, last_alert, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (entity_id) DO UPDATE SET
		  entity_type=$2, risk_score=$3, risk_level=$4, alert_count_7d=$5,
		  critical_count_7d=$6, anomaly_count_7d=$7, last_alert=$8, updated_at=$9`,
		r.EntityID, r.EntityType, r.RiskScore, r.RiskLevel,
		r.AlertCount7d, r.CriticalCount7d, r.AnomalyCount7d, r.LastAlert, r.UpdatedAt)
	return err
}

func (s *Store) ListUebaRiskScores(limit int) ([]*UebaRiskScore, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(context.Background(), `
		SELECT entity_id, entity_type, risk_score, risk_level, alert_count_7d,
		       critical_count_7d, anomaly_count_7d, last_alert, updated_at
		FROM ueba_risk_scores ORDER BY risk_score DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scores []*UebaRiskScore
	for rows.Next() {
		r := &UebaRiskScore{}
		if err := rows.Scan(&r.EntityID, &r.EntityType, &r.RiskScore, &r.RiskLevel,
			&r.AlertCount7d, &r.CriticalCount7d, &r.AnomalyCount7d, &r.LastAlert, &r.UpdatedAt); err != nil {
			return nil, err
		}
		scores = append(scores, r)
	}
	return scores, rows.Err()
}

// AlertStatsPerEntity returns alert aggregates per agent for the last N days.
// Used by the UEBA analyzer to compute baselines.
func (s *Store) AlertStatsPerEntity(days int) ([]map[string]interface{}, error) {
	cutoff := time.Now().AddDate(0, 0, -days).UnixMilli()
	rows, err := s.pool.Query(context.Background(), `
		SELECT
			agent_id,
			COUNT(*) AS total,
			MAX(level) AS max_level,
			SUM(CASE WHEN level >= 10 THEN 1 ELSE 0 END) AS critical_count,
			MAX(timestamp) AS last_alert
		FROM alerts
		WHERE timestamp > $1
		GROUP BY agent_id
		ORDER BY total DESC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []map[string]interface{}
	for rows.Next() {
		var agentID string
		var total, maxLevel, critCount int
		var lastAlert int64
		if err := rows.Scan(&agentID, &total, &maxLevel, &critCount, &lastAlert); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{
			"agent_id":      agentID,
			"total":         total,
			"max_level":     maxLevel,
			"critical_count": critCount,
			"last_alert":    lastAlert,
		})
	}
	return result, rows.Err()
}

// === Identity operations ===

func (s *Store) UpsertIdentityUser(u *models.IdentityUser) error {
	groupsJSON, _ := json.Marshal(u.Groups)
	attrsJSON, _ := json.Marshal(u.RawAttrs)
	u.SyncedAt = time.Now().UnixMilli()
	_, err := s.pool.Exec(context.Background(), `
		INSERT INTO identity_users
		  (sam_account, display_name, email, department, title, manager, groups,
		   enabled, last_logon, bad_pwd_count, raw_attrs, synced_at, source)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (sam_account) DO UPDATE SET
		  display_name=$2, email=$3, department=$4, title=$5, manager=$6,
		  groups=$7, enabled=$8, last_logon=$9, bad_pwd_count=$10,
		  raw_attrs=$11, synced_at=$12, source=$13`,
		u.SamAccount, u.DisplayName, u.Email, u.Department, u.Title, u.Manager,
		string(groupsJSON), u.Enabled, u.LastLogon, u.BadPwdCount,
		string(attrsJSON), u.SyncedAt, u.Source,
	)
	return err
}

func (s *Store) ListIdentityUsers(department string, enabledOnly bool, limit, offset int) ([]*models.IdentityUser, error) {
	var conditions []string
	var args []interface{}
	if department != "" {
		args = append(args, department)
		conditions = append(conditions, fmt.Sprintf("department = $%d", len(args)))
	}
	if enabledOnly {
		conditions = append(conditions, "enabled = TRUE")
	}
	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}
	args = append(args, limit, offset)
	query := fmt.Sprintf(`
		SELECT id, sam_account, display_name, email, department, title, manager,
		       groups, enabled, last_logon, bad_pwd_count, synced_at, source
		FROM identity_users %s
		ORDER BY display_name ASC
		LIMIT $%d OFFSET $%d`, where, len(args)-1, len(args))

	rows, err := s.pool.Query(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*models.IdentityUser
	for rows.Next() {
		u, err := scanIdentityUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) GetIdentityUser(samAccount string) (*models.IdentityUser, error) {
	row := s.pool.QueryRow(context.Background(), `
		SELECT id, sam_account, display_name, email, department, title, manager,
		       groups, enabled, last_logon, bad_pwd_count, synced_at, source
		FROM identity_users WHERE sam_account = $1`, samAccount)
	return scanIdentityUserRow(row)
}

func (s *Store) CountIdentityUsers() (total, enabled int, err error) {
	rows, err := s.pool.Query(context.Background(),
		`SELECT enabled, COUNT(*) FROM identity_users GROUP BY enabled`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var e bool
		var c int
		if err = rows.Scan(&e, &c); err != nil {
			return
		}
		total += c
		if e {
			enabled += c
		}
	}
	err = rows.Err()
	return
}

func (s *Store) DeleteIdentityUser(samAccount string) error {
	_, err := s.pool.Exec(context.Background(),
		"DELETE FROM identity_users WHERE sam_account = $1", samAccount)
	return err
}

func scanIdentityUser(rows pgx.Rows) (*models.IdentityUser, error) {
	u := &models.IdentityUser{}
	var groupsJSON string
	if err := rows.Scan(&u.ID, &u.SamAccount, &u.DisplayName, &u.Email,
		&u.Department, &u.Title, &u.Manager,
		&groupsJSON, &u.Enabled, &u.LastLogon, &u.BadPwdCount, &u.SyncedAt, &u.Source); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(groupsJSON), &u.Groups)
	return u, nil
}

func scanIdentityUserRow(row pgx.Row) (*models.IdentityUser, error) {
	u := &models.IdentityUser{}
	var groupsJSON string
	if err := row.Scan(&u.ID, &u.SamAccount, &u.DisplayName, &u.Email,
		&u.Department, &u.Title, &u.Manager,
		&groupsJSON, &u.Enabled, &u.LastLogon, &u.BadPwdCount, &u.SyncedAt, &u.Source); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(groupsJSON), &u.Groups)
	return u, nil
}

// === Rule Version operations ===

// RuleVersionMeta holds version metadata without the full content.
type RuleVersionMeta struct {
	ID        int64  `json:"id"`
	RuleFile  string `json:"rule_file"`
	Version   int    `json:"version"`
	CommitMsg string `json:"commit_msg"`
	Author    string `json:"author"`
	CreatedAt int64  `json:"created_at"`
	IsActive  bool   `json:"is_active"`
}

// RuleVersion holds the full version record including YAML content.
type RuleVersion struct {
	RuleVersionMeta
	Content string `json:"content"`
}

// SaveRuleVersion increments the version counter and inserts a new record.
func (s *Store) SaveRuleVersion(ruleFile, content, commitMsg, author string) (*RuleVersion, error) {
	var maxVer int
	_ = s.pool.QueryRow(context.Background(),
		`SELECT COALESCE(MAX(version), 0) FROM rule_versions WHERE rule_file = $1`, ruleFile,
	).Scan(&maxVer)

	now := time.Now().UnixMilli()
	v := maxVer + 1
	var id int64
	err := s.pool.QueryRow(context.Background(), `
		INSERT INTO rule_versions (rule_file, version, content, commit_msg, author, created_at, is_active)
		VALUES ($1,$2,$3,$4,$5,$6,TRUE) RETURNING id`,
		ruleFile, v, content, commitMsg, author, now,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return &RuleVersion{
		RuleVersionMeta: RuleVersionMeta{
			ID: id, RuleFile: ruleFile, Version: v,
			CommitMsg: commitMsg, Author: author, CreatedAt: now, IsActive: true,
		},
		Content: content,
	}, nil
}

// ListRuleVersions returns all versions for a file, newest first (no content).
func (s *Store) ListRuleVersions(ruleFile string) ([]*RuleVersionMeta, error) {
	rows, err := s.pool.Query(context.Background(), `
		SELECT id, rule_file, version, commit_msg, author, created_at, is_active
		FROM rule_versions WHERE rule_file = $1 ORDER BY version DESC`, ruleFile)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []*RuleVersionMeta
	for rows.Next() {
		v := &RuleVersionMeta{}
		if err := rows.Scan(&v.ID, &v.RuleFile, &v.Version, &v.CommitMsg, &v.Author, &v.CreatedAt, &v.IsActive); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// GetRuleVersion fetches the full content of a specific version.
func (s *Store) GetRuleVersion(ruleFile string, version int) (*RuleVersion, error) {
	v := &RuleVersion{}
	err := s.pool.QueryRow(context.Background(), `
		SELECT id, rule_file, version, content, commit_msg, author, created_at, is_active
		FROM rule_versions WHERE rule_file = $1 AND version = $2`, ruleFile, version,
	).Scan(&v.ID, &v.RuleFile, &v.Version, &v.Content, &v.CommitMsg, &v.Author, &v.CreatedAt, &v.IsActive)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// ListVersionedFiles returns all unique rule files in the version store with their version count.
func (s *Store) ListVersionedFiles() ([]map[string]interface{}, error) {
	rows, err := s.pool.Query(context.Background(), `
		SELECT rule_file, COUNT(*) as version_count, MAX(version) as latest_version,
		       MAX(created_at) as last_updated,
		       (SELECT author FROM rule_versions rv2
		        WHERE rv2.rule_file = rv.rule_file ORDER BY version DESC LIMIT 1) as last_author,
		       (SELECT commit_msg FROM rule_versions rv3
		        WHERE rv3.rule_file = rv.rule_file ORDER BY version DESC LIMIT 1) as last_msg
		FROM rule_versions rv GROUP BY rule_file ORDER BY rule_file`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []map[string]interface{}
	for rows.Next() {
		var file, lastAuthor, lastMsg string
		var count, latest int
		var lastUpdated int64
		if err := rows.Scan(&file, &count, &latest, &lastUpdated, &lastAuthor, &lastMsg); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{
			"rule_file":      file,
			"version_count":  count,
			"latest_version": latest,
			"last_updated":   lastUpdated,
			"last_author":    lastAuthor,
			"last_msg":       lastMsg,
		})
	}
	return result, rows.Err()
}

func scanPlaybook(row pgx.Row) (*models.Playbook, error) {
	p := &models.Playbook{}
	var triggerJSON, actionsJSON string
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled,
		&triggerJSON, &actionsJSON, &p.CreatedAt, &p.UpdatedAt, &p.RunCount)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(triggerJSON), &p.Trigger)
	_ = json.Unmarshal([]byte(actionsJSON), &p.Actions)
	return p, nil
}

func scanPlaybookRows(rows pgx.Rows) (*models.Playbook, error) {
	p := &models.Playbook{}
	var triggerJSON, actionsJSON string
	err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled,
		&triggerJSON, &actionsJSON, &p.CreatedAt, &p.UpdatedAt, &p.RunCount)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(triggerJSON), &p.Trigger)
	_ = json.Unmarshal([]byte(actionsJSON), &p.Actions)
	return p, nil
}

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
