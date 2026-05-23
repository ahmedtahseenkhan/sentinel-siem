package engine

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/engine/alert"
	"github.com/watchtower/watchtower/internal/engine/cdb"
	"github.com/watchtower/watchtower/internal/engine/correlation"
	"github.com/watchtower/watchtower/internal/engine/dedup"
	"github.com/watchtower/watchtower/internal/engine/decoder"
	"github.com/watchtower/watchtower/internal/engine/rules"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/sigma"
	"go.uber.org/zap"
)

type EventForwarder interface {
	ForwardEvent(event *models.Event)
	ForwardAlert(alert *models.Alert)
}

type AlertStore interface {
	InsertAlert(a *models.Alert) (int64, error)
}

type ActiveResponseOrchestrator interface {
	TriggerFromRule(event *models.Event, rule *models.Rule)
}

// VulnChecker performs vulnerability lookups for package inventory events.
//
// CheckPackage takes vendor so the matcher can disambiguate same-named
// products across vendors (apache:tomcat vs eclipse:tomcat).
// CheckPackageEvent is retained for backward compatibility — implementations
// should treat it as vendor="".
type VulnChecker interface {
	CheckPackageEvent(agentID, name, version, arch string) []models.Event
	CheckPackage(agentID, vendor, name, version, arch string) []models.Event
}

// PlaybookHook is called after every stored alert so SOAR playbooks can fire.
type PlaybookHook interface {
	OnAlert(alert *models.Alert, event *models.Event)
}

// RBAHook is called after every stored alert to accumulate entity risk scores.
type RBAHook interface {
	OnAlert(alert *models.Alert, event *models.Event)
}

// NotifierHook is called after every stored alert to dispatch outbound
// notifications (Slack/Teams/email/webhook). Same signature as RBAHook so the
// hook chain can have any number of independent listeners.
type NotifierHook interface {
	OnAlert(alert *models.Alert, event *models.Event)
}

// UebaHook is called for every raw event before rule matching,
// allowing UEBA to build behavioral baselines from all event types.
type UebaHook interface {
	OnEvent(event *models.Event)
}

// AgentResolver looks up an agent's hostname by ID so it can be stamped
// onto every event and alert that flows through the engine.
type AgentResolver interface {
	GetAgent(id string) (*models.Agent, error)
}

type Engine struct {
	cfg       config.EngineConfig
	logger    *zap.Logger
	decoders  *decoder.Manager
	rules     *rules.Matcher
	cdb       *cdb.Manager
	alertOut  *alert.Output
	forwarder    EventForwarder
	store        AlertStore
	responder    ActiveResponseOrchestrator
	vulnChecker  VulnChecker
	playbookHook PlaybookHook
	rbaHook      RBAHook
	uebaHook     UebaHook
	notifierHook NotifierHook
	agentResolver AgentResolver
	deduper      *dedup.Manager
	correlation  *correlation.Manager
	eventCh      chan *models.Event
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

func New(cfg config.EngineConfig, logger *zap.Logger, forwarder EventForwarder, store AlertStore) *Engine {
	dedupWindow := time.Duration(cfg.DedupWindowSecs) * time.Second
	return &Engine{
		cfg:       cfg,
		logger:    logger,
		forwarder: forwarder,
		store:     store,
		decoders:  decoder.NewManager(logger),
		rules:     rules.NewMatcher(logger),
		cdb:       cdb.NewManager(logger),
		alertOut:  alert.NewOutput(logger),
		deduper:     dedup.New(dedupWindow, logger),
		correlation: correlation.New(logger),
		eventCh:     make(chan *models.Event, 10000),
		stopCh:      make(chan struct{}),
	}
}

func (e *Engine) LoadConfigs() error {
	if e.cfg.DecodersDir != "" {
		if err := e.decoders.LoadFromDir(e.cfg.DecodersDir); err != nil {
			e.logger.Warn("failed to load decoders", zap.Error(err))
		}
	}
	if e.cfg.RulesDir != "" {
		if err := e.rules.LoadFromDir(e.cfg.RulesDir); err != nil {
			e.logger.Warn("failed to load rules", zap.Error(err))
		}
	}
	if e.cfg.SigmaDir != "" {
		sigmaRules, errs := sigma.LoadDir(e.cfg.SigmaDir)
		if len(errs) > 0 {
			e.logger.Warn("some sigma rules failed to parse",
				zap.Int("error_count", len(errs)),
				zap.String("first_error", errs[0].Error()),
			)
		}
		loaded := 0
		for _, r := range sigmaRules {
			if err := e.rules.Add(*r); err == nil {
				loaded++
			}
		}
		e.logger.Info("sigma rules imported",
			zap.Int("loaded", loaded),
			zap.Int("attempted", len(sigmaRules)),
			zap.String("dir", e.cfg.SigmaDir),
		)
	}
	if e.cfg.CDBDir != "" {
		if err := e.cdb.LoadFromDir(e.cfg.CDBDir); err != nil {
			e.logger.Warn("failed to load CDB lists", zap.Error(err))
		}
	}
	e.rules.SetCDB(e.cdb)
	e.logger.Info("engine configs loaded",
		zap.Int("decoders", e.decoders.Count()),
		zap.Int("rules", e.rules.Count()),
		zap.Int("cdb_lists", e.cdb.Count()),
	)
	return nil
}

func (e *Engine) Start() {
	workers := e.cfg.Workers
	if workers <= 0 {
		workers = 4
	}
	for i := 0; i < workers; i++ {
		e.wg.Add(1)
		go e.worker()
	}
	e.logger.Info("engine started", zap.Int("workers", workers))
}

func (e *Engine) Ingest(event *models.Event) {
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	select {
	case e.eventCh <- event:
	default:
		e.logger.Warn("engine event channel full, dropping event")
	}
}

func (e *Engine) worker() {
	defer e.wg.Done()
	for {
		select {
		case <-e.stopCh:
			return
		case event := <-e.eventCh:
			e.process(event)
		}
	}
}

func (e *Engine) process(event *models.Event) {
	// Resolve agent hostname if not already set — fills agent_name on every
	// indexed document so Discover always shows a readable name, not just an ID.
	if event.AgentName == "" && event.AgentID != "" && e.agentResolver != nil {
		if a, err := e.agentResolver.GetAgent(event.AgentID); err == nil && a != nil {
			event.AgentName = a.Hostname
		}
	}

	decoded := e.decoders.Decode(event)
	event.Decoded = decoded

	if e.uebaHook != nil {
		e.uebaHook.OnEvent(event)
	}

	if e.forwarder != nil {
		e.forwarder.ForwardEvent(event)
	}

	matched := e.rules.Match(event)
	for _, rule := range matched {
		// Threshold rules: only fire when the frequency counter tips over.
		if !e.correlation.ShouldFire(rule, event) {
			continue
		}
		e.generateAlert(event, rule)
		if e.responder != nil {
			e.responder.TriggerFromRule(event, rule)
		}
	}

	// Vulnerability scan for package inventory events.
	if event.Type == "syscollector.packages" && e.vulnChecker != nil {
		name, _ := event.Fields["name"].(string)
		version, _ := event.Fields["version"].(string)
		arch, _ := event.Fields["arch"].(string)
		// Vendor comes from dpkg Maintainer / rpm Vendor / Windows registry
		// Publisher and lets us disambiguate same-named products across vendors.
		vendor, _ := event.Fields["vendor"].(string)
		if name != "" && version != "" {
			for _, ve := range e.vulnChecker.CheckPackage(event.AgentID, vendor, name, version, arch) {
				ve := ve // capture loop variable
				e.Ingest(&ve)
			}
		}
	}
}

func (e *Engine) generateAlert(event *models.Event, rule *models.Rule) {
	eventJSON, _ := json.Marshal(event)
	a := &models.Alert{
		RuleID:      rule.ID,
		Level:       rule.Level,
		AgentID:     event.AgentID,
		AgentName:   event.AgentName, // already resolved in process()
		Timestamp:   time.Now().UnixMilli(),
		Title:       rule.Alert.Title,
		Description: rule.Description,
		EventData:   string(eventJSON),
		RuleGroups:  rule.Groups,
		MitreAttack: rule.MitreAttack,
	}

	if e.deduper.ShouldSuppress(a) {
		e.logger.Debug("alert suppressed by dedup",
			zap.Int("rule_id", a.RuleID),
			zap.String("agent_id", a.AgentID),
		)
		return
	}

	if e.store != nil {
		id, err := e.store.InsertAlert(a)
		if err != nil {
			e.logger.Error("failed to store alert", zap.Error(err))
		} else {
			a.ID = id
		}
	}

	if e.forwarder != nil {
		e.forwarder.ForwardAlert(a)
	}

	if e.playbookHook != nil {
		e.playbookHook.OnAlert(a, event)
	}

	if e.rbaHook != nil {
		e.rbaHook.OnAlert(a, event)
	}

	if e.notifierHook != nil {
		e.notifierHook.OnAlert(a, event)
	}

	e.alertOut.Emit(a, event)
}

func (e *Engine) Stop() {
	close(e.stopCh)
	e.wg.Wait()
	e.deduper.Stop()
	e.correlation.Stop()
}

func (e *Engine) SetResponder(r ActiveResponseOrchestrator) {
	e.responder = r
}

func (e *Engine) SetVulnChecker(v VulnChecker) {
	e.vulnChecker = v
}

func (e *Engine) SetPlaybookHook(h PlaybookHook) {
	e.playbookHook = h
}

func (e *Engine) SetRBAHook(h RBAHook) {
	e.rbaHook = h
}

func (e *Engine) SetUebaHook(h UebaHook) {
	e.uebaHook = h
}

func (e *Engine) SetNotifierHook(h NotifierHook) {
	e.notifierHook = h
}

func (e *Engine) SetAgentResolver(r AgentResolver) {
	e.agentResolver = r
}

func (e *Engine) Rules() *rules.Matcher     { return e.rules }
func (e *Engine) Decoders() *decoder.Manager { return e.decoders }
func (e *Engine) CDB() *cdb.Manager         { return e.cdb }
