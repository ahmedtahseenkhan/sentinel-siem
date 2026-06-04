package store

import "context"

// Artifact is a forensic bundle uploaded by an agent.
type Artifact struct {
	ID        int64  `json:"id"`
	AgentID   string `json:"agent_id"`
	Filename  string `json:"filename"`
	Path      string `json:"-"` // on-disk path, never exposed to the API
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Store) InsertArtifact(a *Artifact) (int64, error) {
	var id int64
	err := s.pool.QueryRow(context.Background(), `
		INSERT INTO forensic_artifacts (agent_id, filename, path, size_bytes, created_at)
		VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		a.AgentID, a.Filename, a.Path, a.SizeBytes, a.CreatedAt).Scan(&id)
	return id, err
}

func (s *Store) ListArtifacts(agentID string, limit int) ([]*Artifact, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var (
		q    string
		args []interface{}
	)
	if agentID != "" {
		q = `SELECT id, agent_id, filename, path, size_bytes, created_at
			FROM forensic_artifacts WHERE agent_id = $1 ORDER BY created_at DESC LIMIT $2`
		args = []interface{}{agentID, limit}
	} else {
		q = `SELECT id, agent_id, filename, path, size_bytes, created_at
			FROM forensic_artifacts ORDER BY created_at DESC LIMIT $1`
		args = []interface{}{limit}
	}
	rows, err := s.pool.Query(context.Background(), q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Artifact
	for rows.Next() {
		a := &Artifact{}
		if err := rows.Scan(&a.ID, &a.AgentID, &a.Filename, &a.Path, &a.SizeBytes, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetArtifact(id int64) (*Artifact, error) {
	a := &Artifact{}
	err := s.pool.QueryRow(context.Background(), `
		SELECT id, agent_id, filename, path, size_bytes, created_at
		FROM forensic_artifacts WHERE id = $1`, id).
		Scan(&a.ID, &a.AgentID, &a.Filename, &a.Path, &a.SizeBytes, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}
