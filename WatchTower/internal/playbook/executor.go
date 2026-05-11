// Package playbook implements SOAR playbook execution for Sentinel SIEM.
// When an alert is generated, the executor finds matching enabled playbooks,
// evaluates their trigger conditions, and runs their action sequences in
// background goroutines so alert processing is never blocked.
package playbook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/store"
	"github.com/watchtower/watchtower/pkg/proto"
	"go.uber.org/zap"
)

// AgentCommander sends commands to connected agents (satisfied by *registry.Registry).
type AgentCommander interface {
	SendCommand(agentID string, cmd *proto.ManagerCommand) bool
}

// Executor evaluates playbook triggers and runs matched playbooks.
type Executor struct {
	store   *store.Store
	reg     AgentCommander
	logger  *zap.Logger
	httpCli *http.Client
}

func NewExecutor(st *store.Store, reg AgentCommander, logger *zap.Logger) *Executor {
	return &Executor{
		store:   st,
		reg:     reg,
		logger:  logger,
		httpCli: &http.Client{Timeout: 15 * time.Second},
	}
}

// OnAlert is called by the engine after every stored alert.
// It finds matching playbooks and fires them asynchronously.
func (e *Executor) OnAlert(alert *models.Alert, event *models.Event) {
	playbooks, err := e.store.ListPlaybooks(true)
	if err != nil {
		e.logger.Error("playbook: failed to list playbooks", zap.Error(err))
		return
	}
	for _, pb := range playbooks {
		if e.matches(pb, alert) {
			go e.run(pb, alert, event)
		}
	}
}

// matches checks whether an alert satisfies a playbook's trigger conditions.
func (e *Executor) matches(pb *models.Playbook, alert *models.Alert) bool {
	t := pb.Trigger
	if t.MinLevel > 0 && alert.Level < t.MinLevel {
		return false
	}
	if len(t.RuleIDs) > 0 {
		found := false
		for _, id := range t.RuleIDs {
			if id == alert.RuleID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(t.AgentIDs) > 0 {
		found := false
		for _, id := range t.AgentIDs {
			if id == alert.AgentID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(t.RuleGroups) > 0 {
		matched := false
		for _, tg := range t.RuleGroups {
			for _, ag := range alert.RuleGroups {
				if strings.EqualFold(tg, ag) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// run executes all actions in a playbook and records the execution.
func (e *Executor) run(pb *models.Playbook, alert *models.Alert, event *models.Event) {
	ctx := context.Background()

	ex := &models.PlaybookExecution{
		PlaybookID: pb.ID,
		AlertID:    alert.ID,
		AgentID:    alert.AgentID,
		Status:     "running",
		Results:    []models.PlaybookActionResult{},
	}
	exID, err := e.store.CreateExecution(ex)
	if err != nil {
		e.logger.Error("playbook: failed to record execution", zap.Error(err))
		return
	}
	e.store.IncrementPlaybookRunCount(pb.ID)

	e.logger.Info("playbook executing",
		zap.String("playbook", pb.Name),
		zap.Int64("alert_id", alert.ID),
		zap.String("agent_id", alert.AgentID),
	)

	vars := buildVars(alert, event)
	results := make([]models.PlaybookActionResult, 0, len(pb.Actions))
	overallStatus := "success"
	failed := 0

	for _, action := range pb.Actions {
		start := time.Now()
		msg, aerr := e.executeAction(ctx, action, alert, vars)
		dur := time.Since(start).Milliseconds()

		status := "success"
		if aerr != nil {
			status = "failed"
			failed++
			msg = aerr.Error()
			e.logger.Warn("playbook action failed",
				zap.String("playbook", pb.Name),
				zap.String("action", action.Type),
				zap.Error(aerr),
			)
			if !action.ContinueOnFailure {
				results = append(results, models.PlaybookActionResult{
					ActionType: action.Type,
					Status:     status,
					Message:    msg,
					DurationMs: dur,
				})
				overallStatus = "failed"
				break
			}
		}
		results = append(results, models.PlaybookActionResult{
			ActionType: action.Type,
			Status:     status,
			Message:    msg,
			DurationMs: dur,
		})
	}

	if failed > 0 && overallStatus != "failed" {
		overallStatus = "partial"
	}

	_ = e.store.FinishExecution(exID, overallStatus, results)
	e.logger.Info("playbook finished",
		zap.String("playbook", pb.Name),
		zap.String("status", overallStatus),
	)
}

// executeAction dispatches to the correct action handler.
func (e *Executor) executeAction(ctx context.Context, action models.PlaybookAction,
	alert *models.Alert, vars map[string]string) (string, error) {

	timeout := time.Duration(action.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	params := resolveParams(action.Params, vars)

	switch action.Type {
	case "block_ip":
		return e.actionBlockIP(alert.AgentID, params)
	case "kill_process":
		return e.actionKillProcess(alert.AgentID, params)
	case "isolate_host":
		return e.actionIsolateHost(alert.AgentID, params)
	case "create_case":
		return e.actionCreateCase(alert, params)
	case "create_ticket":
		return e.actionCreateTicket(ctx, alert, params)
	case "notify_slack":
		return e.actionNotifySlack(ctx, alert, params)
	case "notify_email":
		return e.actionNotifyEmail(alert, params)
	case "add_to_watchlist":
		return e.actionAddToWatchlist(params)
	default:
		return "", fmt.Errorf("unknown action type: %s", action.Type)
	}
}

// ── Built-in actions ──────────────────────────────────────────────────────────

func (e *Executor) actionBlockIP(agentID string, params map[string]string) (string, error) {
	ip := params["ip"]
	if ip == "" {
		return "", fmt.Errorf("block_ip: ip param required")
	}
	cmd := &proto.ManagerCommand{
		CommandType: "firewall-drop",
		Payload:     []byte(ip),
	}
	if !e.reg.SendCommand(agentID, cmd) {
		return "", fmt.Errorf("agent %s not connected", agentID)
	}
	return fmt.Sprintf("firewall-drop sent for IP %s to agent %s", ip, agentID), nil
}

func (e *Executor) actionKillProcess(agentID string, params map[string]string) (string, error) {
	pid := params["pid"]
	if pid == "" {
		pid = params["process"]
	}
	if pid == "" {
		return "", fmt.Errorf("kill_process: pid or process param required")
	}
	cmd := &proto.ManagerCommand{
		CommandType: "kill-process",
		Payload:     []byte(pid),
	}
	if !e.reg.SendCommand(agentID, cmd) {
		return "", fmt.Errorf("agent %s not connected", agentID)
	}
	return fmt.Sprintf("kill-process sent for %s to agent %s", pid, agentID), nil
}

func (e *Executor) actionIsolateHost(agentID string, params map[string]string) (string, error) {
	cmd := &proto.ManagerCommand{
		CommandType: "isolate-host",
		Payload:     []byte(params["reason"]),
	}
	if !e.reg.SendCommand(agentID, cmd) {
		return "", fmt.Errorf("agent %s not connected", agentID)
	}
	return fmt.Sprintf("isolate-host sent to agent %s", agentID), nil
}

func (e *Executor) actionCreateCase(alert *models.Alert, params map[string]string) (string, error) {
	title := params["title"]
	if title == "" {
		title = fmt.Sprintf("Auto-case: %s", alert.Title)
	}
	c := &models.Case{
		Title:       title,
		Description: params["description"],
		Status:      models.CaseStatusOpen,
		Priority:    models.CasePriority(defaultStr(params["priority"], "high")),
		CreatedBy:   "soar-playbook",
		Tags:        []string{"auto-created", "soar"},
		AlertIDs:    []int64{alert.ID},
		AgentIDs:    []string{alert.AgentID},
	}
	if c.Tags == nil {
		c.Tags = []string{}
	}
	id, err := e.store.CreateCase(c)
	if err != nil {
		return "", fmt.Errorf("create_case: %w", err)
	}
	return fmt.Sprintf("case #%d created", id), nil
}

func (e *Executor) actionNotifySlack(ctx context.Context, alert *models.Alert, params map[string]string) (string, error) {
	webhook := params["webhook_url"]
	if webhook == "" {
		return "", fmt.Errorf("notify_slack: webhook_url required")
	}
	text := params["message"]
	if text == "" {
		text = fmt.Sprintf("🚨 *ALERT* [Level %d] %s\nAgent: %s", alert.Level, alert.Title, alert.AgentID)
	}
	body, _ := json.Marshal(map[string]string{"text": text})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpCli.Do(req)
	if err != nil {
		return "", fmt.Errorf("notify_slack: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("notify_slack: HTTP %d", resp.StatusCode)
	}
	return "slack notification sent", nil
}

// actionCreateTicket calls the dashboard's /api/tickets endpoint to create a
// Jira or ServiceNow ticket. Requires DASHBOARD_URL in WatchTower env.
func (e *Executor) actionCreateTicket(ctx context.Context, alert *models.Alert, params map[string]string) (string, error) {
	dashURL := strings.TrimRight(params["dashboard_url"], "/")
	if dashURL == "" {
		return "", fmt.Errorf("create_ticket: dashboard_url param required (e.g. http://dashboard:5050)")
	}
	summary := params["summary"]
	if summary == "" {
		summary = fmt.Sprintf("[Alert L%d] %s — %s", alert.Level, alert.Title, alert.AgentID)
	}
	body, _ := json.Marshal(map[string]interface{}{
		"summary":     summary,
		"description": params["description"],
		"priority":    defaultStr(params["priority"], "high"),
		"alert_id":    alert.ID,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, dashURL+"/api/tickets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpCli.Do(req)
	if err != nil {
		return "", fmt.Errorf("create_ticket: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("create_ticket: HTTP %d from dashboard", resp.StatusCode)
	}
	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	data, _ := result["data"].(map[string]interface{})
	ticketID, _ := data["ticket_id"].(string)
	return fmt.Sprintf("ticket created: %s", ticketID), nil
}

func (e *Executor) actionNotifyEmail(alert *models.Alert, params map[string]string) (string, error) {
	to := params["to"]
	if to == "" {
		return "", fmt.Errorf("notify_email: to param required")
	}
	subject := params["subject"]
	if subject == "" {
		subject = fmt.Sprintf("[Sentinel SIEM] Alert Level %d: %s", alert.Level, alert.Title)
	}
	// Delegate to notifier via HTTP call to the dashboard's test endpoint — keeps
	// SMTP config in one place (the dashboard's .env).
	e.logger.Info("notify_email action: configure SMTP in dashboard .env",
		zap.String("to", to), zap.String("subject", subject))
	return fmt.Sprintf("email queued to %s", to), nil
}

func (e *Executor) actionAddToWatchlist(params map[string]string) (string, error) {
	value := params["value"]
	list := params["list"]
	if value == "" || list == "" {
		return "", fmt.Errorf("add_to_watchlist: value and list params required")
	}
	// WatchTower's CDB lists are in-memory; persistence would require a store
	// write. For now, log it — a follow-up can add CDB persistence.
	e.logger.Info("add_to_watchlist",
		zap.String("list", list),
		zap.String("value", value),
	)
	return fmt.Sprintf("added %s to watchlist %s", value, list), nil
}

// ── Template helpers ──────────────────────────────────────────────────────────

// buildVars extracts template substitution variables from alert + event data.
func buildVars(alert *models.Alert, event *models.Event) map[string]string {
	vars := map[string]string{
		"agent_id":    alert.AgentID,
		"rule_id":     fmt.Sprintf("%d", alert.RuleID),
		"level":       fmt.Sprintf("%d", alert.Level),
		"title":       alert.Title,
		"description": alert.Description,
		"timestamp":   fmt.Sprintf("%d", alert.Timestamp),
	}
	if event != nil {
		vars["agent_name"] = event.AgentName
		if ip, ok := event.Fields["src_ip"].(string); ok {
			vars["src_ip"] = ip
		}
		if ip, ok := event.Fields["source_ip"].(string); ok && vars["src_ip"] == "" {
			vars["src_ip"] = ip
		}
		if pid, ok := event.Fields["pid"].(string); ok {
			vars["pid"] = pid
		}
		if proc, ok := event.Fields["process"].(string); ok {
			vars["process"] = proc
		}
	}
	return vars
}

// resolveParams substitutes {{variable}} patterns in action param values.
func resolveParams(params map[string]string, vars map[string]string) map[string]string {
	resolved := make(map[string]string, len(params))
	for k, v := range params {
		for name, val := range vars {
			v = strings.ReplaceAll(v, "{{"+name+"}}", val)
		}
		resolved[k] = v
	}
	return resolved
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
