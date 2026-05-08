package sca

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/watchnode/watchnode/internal/agent"
)

// CheckResult holds the outcome of a single check evaluation.
type CheckResult struct {
	CheckID     int    `json:"check_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Rationale   string `json:"rationale"`
	Remediation string `json:"remediation"`
	Compliance  string `json:"compliance"`
	Result      string `json:"result"` // passed, failed, not_applicable
	Reason      string `json:"reason,omitempty"`
}

// EvaluatePolicy evaluates all checks in a policy and returns results.
func EvaluatePolicy(policy agent.SCAPolicy) []CheckResult {
	var results []CheckResult
	for _, check := range policy.Checks {
		result := evaluateCheck(check)
		results = append(results, result)
	}
	return results
}

func evaluateCheck(check agent.SCACheck) CheckResult {
	cr := CheckResult{
		CheckID:     check.ID,
		Title:       check.Title,
		Description: check.Description,
		Rationale:   check.Rationale,
		Remediation: check.Remediation,
		Compliance:  check.Compliance,
	}
	if len(check.Rules) == 0 {
		cr.Result = "not_applicable"
		cr.Reason = "no rules defined"
		return cr
	}

	results := make([]bool, 0, len(check.Rules))
	for _, rule := range check.Rules {
		results = append(results, evaluateRule(rule))
	}

	switch check.Condition {
	case "any":
		cr.Result = "failed"
		for _, r := range results {
			if r {
				cr.Result = "passed"
				break
			}
		}
	case "none":
		cr.Result = "passed"
		for _, r := range results {
			if r {
				cr.Result = "failed"
				break
			}
		}
	default: // "all"
		cr.Result = "passed"
		for _, r := range results {
			if !r {
				cr.Result = "failed"
				break
			}
		}
	}
	return cr
}

// evaluateRule evaluates a single rule string.
// Supported formats:
//
//	f:<path>                    - file exists
//	f:<path> -> r:<regex>       - file content matches regex
//	p:<process_name>            - process is running
//	c:<command> -> r:<regex>    - command output matches regex
//	d:<directory>               - directory exists
//	not <rule>                  - negate the rule
func evaluateRule(rule string) bool {
	rule = strings.TrimSpace(rule)

	// Handle negation
	if strings.HasPrefix(rule, "not ") {
		return !evaluateRule(strings.TrimPrefix(rule, "not "))
	}

	parts := strings.SplitN(rule, " -> ", 2)
	primary := strings.TrimSpace(parts[0])

	switch {
	case strings.HasPrefix(primary, "f:"):
		path := strings.TrimPrefix(primary, "f:")
		if len(parts) == 2 {
			return fileContentMatches(path, parts[1])
		}
		_, err := os.Stat(path)
		return err == nil

	case strings.HasPrefix(primary, "d:"):
		path := strings.TrimPrefix(primary, "d:")
		info, err := os.Stat(path)
		return err == nil && info.IsDir()

	case strings.HasPrefix(primary, "p:"):
		procName := strings.TrimPrefix(primary, "p:")
		return processRunning(procName)

	case strings.HasPrefix(primary, "c:"):
		cmd := strings.TrimPrefix(primary, "c:")
		if len(parts) == 2 {
			return commandOutputMatches(cmd, parts[1])
		}
		return commandSucceeds(cmd)
	}
	return false
}

func fileContentMatches(path, condition string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	content := string(data)
	condition = strings.TrimSpace(condition)
	if strings.HasPrefix(condition, "r:") {
		pattern := strings.TrimPrefix(condition, "r:")
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(content)
	}
	return strings.Contains(content, condition)
}

func processRunning(name string) bool {
	out, err := exec.Command("pgrep", "-x", name).Output()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(out))) > 0
}

func commandOutputMatches(cmd, condition string) bool {
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return false
	}
	output := string(out)
	condition = strings.TrimSpace(condition)
	if strings.HasPrefix(condition, "r:") {
		pattern := strings.TrimPrefix(condition, "r:")
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(output)
	}
	return strings.Contains(output, condition)
}

func commandSucceeds(cmd string) bool {
	err := exec.Command("sh", "-c", cmd).Run()
	return err == nil
}

// PolicySummary summarizes the results of a policy evaluation.
type PolicySummary struct {
	PolicyID    string `json:"policy_id"`
	PolicyName  string `json:"policy_name"`
	Total       int    `json:"total_checks"`
	Passed      int    `json:"passed"`
	Failed      int    `json:"failed"`
	NotApplicable int  `json:"not_applicable"`
	Score       float64 `json:"score"`
}

// Summarize creates a summary from check results.
func Summarize(policy agent.SCAPolicy, results []CheckResult) PolicySummary {
	s := PolicySummary{
		PolicyID:   policy.ID,
		PolicyName: policy.Name,
		Total:      len(results),
	}
	for _, r := range results {
		switch r.Result {
		case "passed":
			s.Passed++
		case "failed":
			s.Failed++
		default:
			s.NotApplicable++
		}
	}
	applicable := s.Passed + s.Failed
	if applicable > 0 {
		s.Score = float64(s.Passed) / float64(applicable) * 100
	}
	return s
}

func init() {
	// Ensure fmt is used
	_ = fmt.Sprintf
}
