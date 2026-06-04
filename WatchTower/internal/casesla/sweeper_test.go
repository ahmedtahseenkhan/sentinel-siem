package casesla

import (
	"testing"

	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

type fakeStore struct {
	overdue    []*models.Case
	breached   []int64
	priorities map[int64]string
	history    int
}

func (f *fakeStore) ListOverdueCases(int64) ([]*models.Case, error) { return f.overdue, nil }
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

type fakeNotifier struct{ breaches int }

func (n *fakeNotifier) OnCaseBreach(*models.Case) { n.breaches++ }

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
