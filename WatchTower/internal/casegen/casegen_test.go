package casegen

import (
	"testing"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

// fakeStore is an in-memory implementation of the casegen.Store interface.
type fakeStore struct {
	cases    map[string]*models.Case // keyed by group_key
	nextID   int64
	created  int
	appended int
	notes    int
	history  int
}

func newFakeStore() *fakeStore { return &fakeStore{cases: map[string]*models.Case{}} }

func (f *fakeStore) FindOpenCaseByGroup(groupKey string) (*models.Case, error) {
	return f.cases[groupKey], nil
}
func (f *fakeStore) CreateCase(c *models.Case) (int64, error) {
	f.nextID++
	c.ID = f.nextID
	f.cases[c.GroupKey] = c
	f.created++
	return c.ID, nil
}
func (f *fakeStore) AppendAlertToCase(caseID, alertID int64) error {
	f.appended++
	for _, c := range f.cases {
		if c.ID == caseID {
			c.AlertIDs = append(c.AlertIDs, alertID)
		}
	}
	return nil
}
func (f *fakeStore) AddCaseNote(*models.CaseNote) (int64, error) {
	f.notes++
	return int64(f.notes), nil
}
func (f *fakeStore) AddCaseHistory(*models.CaseHistory) (int64, error) {
	f.history++
	return int64(f.history), nil
}

func newGen(st Store) *Generator {
	cfg := config.CasesConfig{}
	cfg.AutoCreate.Enabled = true
	cfg.AutoCreate.MinLevel = 10
	return New(st, cfg, zap.NewNop())
}

func TestOnAlert_BelowThreshold_NoCase(t *testing.T) {
	st := newFakeStore()
	newGen(st).OnAlert(&models.Alert{ID: 1, RuleID: 100, AgentID: "a1", Level: 9, Title: "low"}, nil)
	if st.created != 0 {
		t.Fatalf("expected no case for level 9, got %d", st.created)
	}
}

func TestOnAlert_FirstAlert_CreatesCase(t *testing.T) {
	st := newFakeStore()
	newGen(st).OnAlert(&models.Alert{ID: 1, RuleID: 100, AgentID: "a1", Level: 12, Title: "crit"}, nil)

	if st.created != 1 {
		t.Fatalf("expected 1 case, got %d", st.created)
	}
	if st.history != 1 {
		t.Fatalf("expected 1 created-history row, got %d", st.history)
	}
	c := st.cases[GroupKey(100, "a1")]
	if c == nil {
		t.Fatal("case not stored under its group key")
	}
	if c.Priority != models.CasePriorityCritical {
		t.Fatalf("expected critical priority, got %s", c.Priority)
	}
	if len(c.AlertIDs) != 1 || c.AlertIDs[0] != 1 {
		t.Fatalf("alert not linked: %v", c.AlertIDs)
	}
	if c.DueAt == 0 {
		t.Fatal("expected due_at to be stamped from the SLA default")
	}
}

func TestOnAlert_SameRuleAgent_AppendsNotDuplicates(t *testing.T) {
	st := newFakeStore()
	g := newGen(st)
	g.OnAlert(&models.Alert{ID: 1, RuleID: 100, AgentID: "a1", Level: 11, Title: "high"}, nil)
	g.OnAlert(&models.Alert{ID: 2, RuleID: 100, AgentID: "a1", Level: 11, Title: "high again"}, nil)

	if st.created != 1 {
		t.Fatalf("expected the repeat to group into 1 case, got %d", st.created)
	}
	if st.appended != 1 {
		t.Fatalf("expected 1 append, got %d", st.appended)
	}
	if st.notes != 1 {
		t.Fatalf("expected 1 recurrence note, got %d", st.notes)
	}
}

func TestOnAlert_DifferentAgent_NewCase(t *testing.T) {
	st := newFakeStore()
	g := newGen(st)
	g.OnAlert(&models.Alert{ID: 1, RuleID: 100, AgentID: "a1", Level: 12, Title: "x"}, nil)
	g.OnAlert(&models.Alert{ID: 2, RuleID: 100, AgentID: "a2", Level: 12, Title: "x"}, nil)

	if st.created != 2 {
		t.Fatalf("expected 2 cases for different agents, got %d", st.created)
	}
}

func TestPriorityForLevel(t *testing.T) {
	tests := []struct {
		level int
		want  models.CasePriority
	}{
		{15, models.CasePriorityCritical},
		{12, models.CasePriorityCritical},
		{11, models.CasePriorityHigh},
		{10, models.CasePriorityHigh},
		{8, models.CasePriorityMedium},
		{7, models.CasePriorityMedium},
		{3, models.CasePriorityLow},
	}
	for _, tc := range tests {
		if got := PriorityForLevel(tc.level); got != tc.want {
			t.Errorf("level %d: want %s got %s", tc.level, tc.want, got)
		}
	}
}
