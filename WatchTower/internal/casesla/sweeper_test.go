package casesla

import (
	"testing"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

type fakeStore struct {
	overdue    []*models.Case
	warnable   []*models.Case
	breached   []int64
	warned     []int64
	reassigned map[int64]string
	priorities map[int64]string
	history    int
}

func (f *fakeStore) ListOverdueCases(int64) ([]*models.Case, error)  { return f.overdue, nil }
func (f *fakeStore) ListWarnableCases(int64) ([]*models.Case, error) { return f.warnable, nil }
func (f *fakeStore) MarkCaseWarned(id int64) error {
	f.warned = append(f.warned, id)
	return nil
}
func (f *fakeStore) SetCaseAssignee(id int64, assignee string) error {
	if f.reassigned == nil {
		f.reassigned = map[int64]string{}
	}
	f.reassigned[id] = assignee
	return nil
}
func (f *fakeStore) MarkCaseBreached(id int64, newPriority string) error {
	f.breached = append(f.breached, id)
	if f.priorities == nil {
		f.priorities = map[int64]string{}
	}
	f.priorities[id] = newPriority
	return nil
}
func (f *fakeStore) AddCaseHistory(*models.CaseHistory) (int64, error) {
	f.history++
	return int64(f.history), nil
}

type fakeNotifier struct {
	breaches int
	warnings int
}

func (n *fakeNotifier) OnCaseBreach(*models.Case)  { n.breaches++ }
func (n *fakeNotifier) OnCaseWarning(*models.Case) { n.warnings++ }

// fakeAssigner always routes to a fixed senior on escalation.
type fakeAssigner struct{ to string }

func (a *fakeAssigner) Route(*models.Case) (string, string) { return a.to, "test" }

func TestSweep_BreachesEscalatesNotifies(t *testing.T) {
	st := &fakeStore{overdue: []*models.Case{
		{ID: 1, Priority: models.CasePriorityHigh, Status: models.CaseStatusOpen, DueAt: 1},
	}}
	n := &fakeNotifier{}
	New(st, n, config.CasesConfig{}, zap.NewNop()).Sweep()

	if len(st.breached) != 1 {
		t.Fatalf("expected 1 breach, got %d", len(st.breached))
	}
	if st.history != 1 {
		t.Fatalf("expected 1 history row, got %d", st.history)
	}
	if n.breaches != 1 {
		t.Fatalf("expected 1 breach notification, got %d", n.breaches)
	}
	if st.priorities[1] != string(models.CasePriorityCritical) {
		t.Fatalf("expected escalation high→critical, got %q", st.priorities[1])
	}
}

func TestSweep_WarningPass(t *testing.T) {
	st := &fakeStore{warnable: []*models.Case{
		{ID: 7, Priority: models.CasePriorityHigh, Status: models.CaseStatusOpen, WarnAt: 1},
	}}
	n := &fakeNotifier{}
	New(st, n, config.CasesConfig{}, zap.NewNop()).Sweep()

	if len(st.warned) != 1 || st.warned[0] != 7 {
		t.Fatalf("expected case 7 marked warned, got %v", st.warned)
	}
	if n.warnings != 1 {
		t.Fatalf("expected 1 warning notification, got %d", n.warnings)
	}
	if len(st.breached) != 0 {
		t.Fatalf("warning pass must not breach, got %v", st.breached)
	}
}

func TestSweep_BreachReassignsToSenior(t *testing.T) {
	st := &fakeStore{overdue: []*models.Case{
		{ID: 1, Priority: models.CasePriorityHigh, Assignee: "junior", Status: models.CaseStatusOpen, DueAt: 1},
	}}
	sw := New(st, &fakeNotifier{}, config.CasesConfig{}, zap.NewNop())
	sw.SetAssigner(&fakeAssigner{to: "senior"})
	sw.Sweep()

	if st.reassigned[1] != "senior" {
		t.Fatalf("expected breach to reassign case 1 to senior, got %q", st.reassigned[1])
	}
}

func TestSweep_NilNotifierDoesNotPanic(t *testing.T) {
	st := &fakeStore{overdue: []*models.Case{{ID: 1, Priority: models.CasePriorityLow}}}
	New(st, nil, config.CasesConfig{}, zap.NewNop()).Sweep()
	if len(st.breached) != 1 {
		t.Fatalf("expected breach recorded even without a notifier, got %d", len(st.breached))
	}
}

func TestEscalatePriority(t *testing.T) {
	tests := []struct{ in, want models.CasePriority }{
		{models.CasePriorityLow, models.CasePriorityMedium},
		{models.CasePriorityMedium, models.CasePriorityHigh},
		{models.CasePriorityHigh, models.CasePriorityCritical},
		{models.CasePriorityCritical, models.CasePriorityCritical},
	}
	for _, tc := range tests {
		if got := EscalatePriority(tc.in); got != tc.want {
			t.Errorf("escalate %s: want %s got %s", tc.in, tc.want, got)
		}
	}
}
