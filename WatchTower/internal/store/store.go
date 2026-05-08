package store

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/watchtower/watchtower/internal/models"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	db *sql.DB
}

func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Ping verifies the store's underlying database connection is alive.
func (s *Store) Ping() error {
	return s.db.Ping()
}

func (s *Store) migrate() error {
	data, err := migrations.ReadFile("migrations/001_initial.sql")
	if err != nil {
		return err
	}
	_, err = s.db.Exec(string(data))
	return err
}

// === Agent operations ===

func (s *Store) UpsertAgent(a *models.Agent) error {
	labelsJSON, _ := json.Marshal(a.Labels)
	_, err := s.db.Exec(`
		INSERT INTO agents (id, hostname, os, platform, version, group_id, labels, status, ip_address, last_heartbeat, registered_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hostname=excluded.hostname, os=excluded.os, platform=excluded.platform,
			version=excluded.version, labels=excluded.labels, status=excluded.status,
			ip_address=excluded.ip_address, last_heartbeat=excluded.last_heartbeat`,
		a.ID, a.Hostname, a.OS, a.Platform, a.Version, a.GroupID,
		string(labelsJSON), string(a.Status), a.IPAddress, a.LastHeartbeat, a.RegisteredAt,
	)
	return err
}

func (s *Store) GetAgent(id string) (*models.Agent, error) {
	row := s.db.QueryRow("SELECT id, hostname, os, platform, version, group_id, labels, status, ip_address, last_heartbeat, registered_at FROM agents WHERE id = ?", id)
	return scanAgent(row)
}

func (s *Store) ListAgents(status string, limit, offset int) ([]*models.Agent, error) {
	query := "SELECT id, hostname, os, platform, version, group_id, labels, status, ip_address, last_heartbeat, registered_at FROM agents"
	var args []interface{}
	if status != "" {
		query += " WHERE status = ?"
		args = append(args, status)
	}
	query += " ORDER BY registered_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}
	rows, err := s.db.Query(query, args...)
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
	_, err := s.db.Exec("DELETE FROM agents WHERE id = ?", id)
	return err
}

func (s *Store) UpdateAgentHeartbeat(id, status string) error {
	_, err := s.db.Exec("UPDATE agents SET last_heartbeat = ?, status = ? WHERE id = ?",
		time.Now().UnixMilli(), status, id)
	return err
}

func (s *Store) UpdateAgentGroup(id, groupID string) error {
	_, err := s.db.Exec("UPDATE agents SET group_id = ? WHERE id = ?", groupID, id)
	return err
}

func (s *Store) CountAgents() (total, active, disconnected int, err error) {
	err = s.db.QueryRow("SELECT COUNT(*) FROM agents").Scan(&total)
	if err != nil {
		return
	}
	_ = s.db.QueryRow("SELECT COUNT(*) FROM agents WHERE status = 'active'").Scan(&active)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM agents WHERE status = 'disconnected'").Scan(&disconnected)
	return
}

// === Group operations ===

func (s *Store) CreateGroup(g *models.AgentGroup) error {
	_, err := s.db.Exec("INSERT INTO agent_groups (id, name, description, config_overrides) VALUES (?, ?, ?, ?)",
		g.ID, g.Name, g.Description, g.ConfigOverrides)
	return err
}

func (s *Store) GetGroup(id string) (*models.AgentGroup, error) {
	g := &models.AgentGroup{}
	err := s.db.QueryRow("SELECT id, name, description, config_overrides FROM agent_groups WHERE id = ?", id).
		Scan(&g.ID, &g.Name, &g.Description, &g.ConfigOverrides)
	if err != nil {
		return nil, err
	}
	return g, nil
}

func (s *Store) ListGroups() ([]*models.AgentGroup, error) {
	rows, err := s.db.Query("SELECT id, name, description, config_overrides FROM agent_groups ORDER BY name")
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
	_, err := s.db.Exec("DELETE FROM agent_groups WHERE id = ?", id)
	return err
}

// === Alert operations ===

func (s *Store) InsertAlert(a *models.Alert) (int64, error) {
	groupsJSON, _ := json.Marshal(a.RuleGroups)
	result, err := s.db.Exec(`INSERT INTO alerts (rule_id, level, agent_id, timestamp, title, description, event_data, rule_groups, forwarded)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.RuleID, a.Level, a.AgentID, a.Timestamp, a.Title, a.Description, a.EventData, string(groupsJSON), a.Forwarded)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) ListAlerts(agentID string, minLevel int, limit, offset int) ([]*models.Alert, error) {
	query := "SELECT id, rule_id, level, agent_id, timestamp, title, description, event_data, rule_groups, forwarded FROM alerts"
	var conditions []string
	var args []interface{}
	if agentID != "" {
		conditions = append(conditions, "agent_id = ?")
		args = append(args, agentID)
	}
	if minLevel > 0 {
		conditions = append(conditions, "level >= ?")
		args = append(args, minLevel)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY timestamp DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var alerts []*models.Alert
	for rows.Next() {
		a := &models.Alert{}
		var groupsJSON string
		if err := rows.Scan(&a.ID, &a.RuleID, &a.Level, &a.AgentID, &a.Timestamp, &a.Title, &a.Description, &a.EventData, &groupsJSON, &a.Forwarded); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(groupsJSON), &a.RuleGroups)
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func (s *Store) CountAlerts() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&count)
	return count, err
}

// ListAlertsByType returns alerts for a given agent filtered by event type prefix in event_data.
func (s *Store) ListAlertsByType(agentID, eventType string, limit, offset int) ([]*models.Alert, error) {
	query := `SELECT id, rule_id, level, agent_id, timestamp, title, description, event_data, rule_groups, forwarded 
		FROM alerts WHERE agent_id = ? AND event_data LIKE ? ORDER BY timestamp DESC`
	args := []interface{}{agentID, "%" + eventType + "%"}
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var alerts []*models.Alert
	for rows.Next() {
		a := &models.Alert{}
		var groupsJSON string
		if err := rows.Scan(&a.ID, &a.RuleID, &a.Level, &a.AgentID, &a.Timestamp, &a.Title, &a.Description, &a.EventData, &groupsJSON, &a.Forwarded); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(groupsJSON), &a.RuleGroups)
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// === Active Response operations ===

func (s *Store) InsertActiveResponse(ar *models.ActiveResponse) error {
	_, err := s.db.Exec(`INSERT INTO active_responses (id, agent_id, action, parameters, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		ar.ID, ar.AgentID, ar.Action, ar.Parameters, ar.Status, ar.CreatedAt)
	return err
}

func (s *Store) UpdateActiveResponseStatus(id, status, result string) error {
	_, err := s.db.Exec("UPDATE active_responses SET status = ?, result = ?, executed_at = ? WHERE id = ?",
		status, result, time.Now().UnixMilli(), id)
	return err
}

func scanAgent(row *sql.Row) (*models.Agent, error) {
	a := &models.Agent{}
	var labelsJSON, status string
	err := row.Scan(&a.ID, &a.Hostname, &a.OS, &a.Platform, &a.Version, &a.GroupID, &labelsJSON, &status, &a.IPAddress, &a.LastHeartbeat, &a.RegisteredAt)
	if err != nil {
		return nil, err
	}
	a.Status = models.AgentStatus(status)
	_ = json.Unmarshal([]byte(labelsJSON), &a.Labels)
	return a, nil
}

func scanAgentRows(rows *sql.Rows) (*models.Agent, error) {
	a := &models.Agent{}
	var labelsJSON, status string
	err := rows.Scan(&a.ID, &a.Hostname, &a.OS, &a.Platform, &a.Version, &a.GroupID, &labelsJSON, &status, &a.IPAddress, &a.LastHeartbeat, &a.RegisteredAt)
	if err != nil {
		return nil, err
	}
	a.Status = models.AgentStatus(status)
	_ = json.Unmarshal([]byte(labelsJSON), &a.Labels)
	return a, nil
}
