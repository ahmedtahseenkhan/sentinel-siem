package decoder

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// SyslogRule is the YAML schema for one syslog decoder rule.
// Decoder concepts: parent/child chaining, program matching,
// prematch for fast filtering, regex with named captures, and static_fields.
type SyslogRule struct {
	Name         string            `yaml:"name" json:"name"`
	Description  string            `yaml:"description,omitempty" json:"description,omitempty"`
	Parent       string            `yaml:"parent,omitempty" json:"parent,omitempty"`
	Program      string            `yaml:"program,omitempty" json:"program,omitempty"`   // regex on app_name; root decoders only
	Prematch     string            `yaml:"prematch,omitempty" json:"prematch,omitempty"` // fast substring/regex filter
	Regex        string            `yaml:"regex,omitempty" json:"regex,omitempty"`       // named capture groups
	Order        []string          `yaml:"order,omitempty" json:"order,omitempty"`       // positional field names (alternative to named groups)
	StaticFields map[string]string `yaml:"static_fields,omitempty" json:"static_fields,omitempty"`
	BuiltIn      bool              `yaml:"built_in,omitempty" json:"built_in,omitempty"` // true for shipped decoders
	Group        string            `yaml:"group,omitempty" json:"group,omitempty"`       // set from file group
	Source       string            `yaml:"source,omitempty" json:"source,omitempty"`     // file path the rule came from
}

type SyslogDecoderFile struct {
	Group       string       `yaml:"group"`
	Description string       `yaml:"description,omitempty"`
	Decoders    []SyslogRule `yaml:"decoders"`
}

// SyslogDecodeResult is returned by SyslogEngine.Test().
type SyslogDecodeResult struct {
	Matched     bool              `json:"matched"`
	DecoderName string            `json:"decoder_name,omitempty"`
	Fields      map[string]string `json:"fields"`
}

// compiledSyslogRule is a rule with pre-compiled regexes.
type compiledSyslogRule struct {
	rule     SyslogRule
	program  *regexp.Regexp // nil = no program filter (matches all)
	prematch *regexp.Regexp // nil = no prematch filter
	regex    *regexp.Regexp // nil = no field extraction
	children []*compiledSyslogRule
}

// SyslogEngine is the decoder for syslog message bodies.
// Rules are loaded from YAML files; custom rules hot-reload automatically.
type SyslogEngine struct {
	mu      sync.RWMutex
	roots   []*compiledSyslogRule            // decoders with no parent (matched first by program)
	byName  map[string]*compiledSyslogRule   // all decoders indexed by name
	rules   []SyslogRule                     // raw rules (for API listing)
	dir     string                           // built-in decoders directory
	customDir string                         // custom decoders directory (hot-reloaded)
	logger  *zap.Logger
}

func NewSyslogEngine(logger *zap.Logger) *SyslogEngine {
	return &SyslogEngine{
		byName: make(map[string]*compiledSyslogRule),
		logger: logger,
	}
}

// LoadFromDir loads all *.yaml files from dir (built-ins) and dir/custom/ (custom).
func (e *SyslogEngine) LoadFromDir(dir string) error {
	e.dir = dir
	e.customDir = filepath.Join(dir, "custom")

	e.mu.Lock()
	defer e.mu.Unlock()
	return e.loadLocked()
}

func (e *SyslogEngine) loadLocked() error {
	e.roots = nil
	e.byName = make(map[string]*compiledSyslogRule)
	e.rules = nil

	dirs := []string{e.dir, e.customDir}
	for _, d := range dirs {
		entries, err := filepath.Glob(filepath.Join(d, "*.yaml"))
		if err != nil {
			continue
		}
		for _, f := range entries {
			builtIn := d == e.dir
			if err := e.loadFileLocked(f, builtIn); err != nil {
				e.logger.Warn("syslog decoder: failed to load file",
					zap.String("file", f), zap.Error(err))
			}
		}
	}

	// Second pass: wire parent→child relationships. Iterate e.rules (load order),
	// NOT e.byName — ranging a map randomises order, which let the generic
	// "^.*$" fallback win over specific decoders (pfsense, cisco, …) at random,
	// and also scrambled sibling order (e.g. tcp/udp vs no-port children).
	for i := range e.rules {
		cd := e.byName[e.rules[i].Name]
		if cd == nil {
			continue
		}
		if cd.rule.Parent == "" {
			e.roots = append(e.roots, cd)
			continue
		}
		parent, ok := e.byName[cd.rule.Parent]
		if !ok {
			e.logger.Warn("syslog decoder: parent not found",
				zap.String("decoder", cd.rule.Name),
				zap.String("parent", cd.rule.Parent))
			// Treat as root if parent is missing.
			e.roots = append(e.roots, cd)
			continue
		}
		parent.children = append(parent.children, cd)
	}

	// Catch-all roots (program "^.*$" / ".*" / empty) must be evaluated LAST so a
	// specific decoder always wins. Stable sort preserves load order otherwise.
	sort.SliceStable(e.roots, func(i, j int) bool {
		return !isCatchAllProgram(e.roots[i].rule.Program) && isCatchAllProgram(e.roots[j].rule.Program)
	})

	e.logger.Info("syslog decoders loaded",
		zap.Int("total", len(e.byName)),
		zap.Int("roots", len(e.roots)))
	return nil
}

// isCatchAllProgram reports whether a root decoder's program regex matches any
// program (so it must be tried last, after specific decoders).
func isCatchAllProgram(p string) bool {
	switch strings.TrimSpace(p) {
	case "", ".*", "^.*$", "^.*", ".*$", "(?s).*":
		return true
	}
	return false
}

func (e *SyslogEngine) loadFileLocked(path string, builtIn bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var df SyslogDecoderFile
	if err := yaml.Unmarshal(data, &df); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	for i := range df.Decoders {
		r := &df.Decoders[i]
		r.Group = df.Group
		r.Source = filepath.Base(path)
		r.BuiltIn = builtIn
		cd, err := compileSyslogRule(*r)
		if err != nil {
			e.logger.Warn("syslog decoder: compile failed",
				zap.String("name", r.Name), zap.Error(err))
			continue
		}
		if _, dup := e.byName[r.Name]; dup {
			e.logger.Warn("syslog decoder: duplicate name, skipping",
				zap.String("name", r.Name), zap.String("file", path))
			continue
		}
		e.byName[r.Name] = cd
		e.rules = append(e.rules, *r)
	}
	return nil
}

func compileSyslogRule(r SyslogRule) (*compiledSyslogRule, error) {
	cd := &compiledSyslogRule{rule: r}
	if r.Program != "" {
		re, err := regexp.Compile("(?i)" + r.Program)
		if err != nil {
			return nil, fmt.Errorf("program regex: %w", err)
		}
		cd.program = re
	}
	if r.Prematch != "" {
		re, err := regexp.Compile(r.Prematch)
		if err != nil {
			return nil, fmt.Errorf("prematch regex: %w", err)
		}
		cd.prematch = re
	}
	if r.Regex != "" {
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, fmt.Errorf("regex: %w", err)
		}
		cd.regex = re
	}
	return cd, nil
}

// Decode runs the decoder chain against the syslog app_name and message,
// writing extracted fields into the provided map.
func (e *SyslogEngine) Decode(appName, message string, fields map[string]interface{}) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	app := normaliseProgram(appName)
	for _, root := range e.roots {
		if !root.matchesProgram(app) {
			continue
		}
		if !root.matchesPrematch(message) {
			continue
		}
		// Root matched. Extract root-level fields then try children.
		root.extractInto(message, fields)
		applyStatic(root.rule.StaticFields, fields)
		fields["decoder"] = root.rule.Name

		for _, child := range root.children {
			if !child.matchesPrematch(message) {
				continue
			}
			if !child.matchesRegex(message) {
				continue
			}
			child.extractInto(message, fields)
			applyStatic(child.rule.StaticFields, fields)
			fields["decoder"] = child.rule.Name
			break // first matching child wins
		}
		return // first matching root wins
	}
}

// Test runs the decoder against a test message and returns what was extracted.
func (e *SyslogEngine) Test(appName, message string) SyslogDecodeResult {
	fields := make(map[string]interface{})
	e.Decode(appName, message, fields)
	res := SyslogDecodeResult{Fields: make(map[string]string)}
	if name, ok := fields["decoder"].(string); ok {
		res.Matched = true
		res.DecoderName = name
	}
	for k, v := range fields {
		res.Fields[k] = fmt.Sprintf("%v", v)
	}
	return res
}

// AddCustom compiles and persists a custom rule (saved to customDir/custom.yaml aggregate).
func (e *SyslogEngine) AddCustom(r SyslogRule) error {
	if r.Name == "" {
		return fmt.Errorf("decoder name is required")
	}
	r.BuiltIn = false
	r.Source = "custom.yaml"

	// Compile first to validate regexes.
	if _, err := compileSyslogRule(r); err != nil {
		return err
	}

	// Persist to custom dir.
	if err := e.saveCustomRule(r); err != nil {
		return err
	}

	// Reload to pick up the new rule with full parent wiring.
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.loadLocked()
}

func (e *SyslogEngine) saveCustomRule(r SyslogRule) error {
	if err := os.MkdirAll(e.customDir, 0755); err != nil {
		return err
	}
	path := filepath.Join(e.customDir, sanitiseFilename(r.Name)+".yaml")
	df := SyslogDecoderFile{
		Group:    "custom",
		Decoders: []SyslogRule{r},
	}
	data, err := yaml.Marshal(df)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// DeleteCustom removes a custom decoder rule by name.
func (e *SyslogEngine) DeleteCustom(name string) error {
	e.mu.RLock()
	cd, ok := e.byName[name]
	e.mu.RUnlock()
	if !ok {
		return fmt.Errorf("decoder %q not found", name)
	}
	if cd.rule.BuiltIn {
		return fmt.Errorf("cannot delete built-in decoder %q", name)
	}

	// Remove the file.
	path := filepath.Join(e.customDir, sanitiseFilename(name)+".yaml")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	return e.loadLocked()
}

// List returns all loaded decoder rules.
func (e *SyslogEngine) List() []SyslogRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]SyslogRule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Count returns number of loaded rules.
func (e *SyslogEngine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.byName)
}

// Reload re-reads all decoder files from disk.
func (e *SyslogEngine) Reload() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.loadLocked()
}

// StartWatcher polls the custom directory every 30 seconds for changes.
func (e *SyslogEngine) StartWatcher(ctx context.Context) {
	if e.customDir == "" {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		var lastMod time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mod := latestModTime(e.customDir)
				if mod.After(lastMod) {
					lastMod = mod
					if err := e.Reload(); err != nil {
						e.logger.Warn("syslog decoder hot-reload failed", zap.Error(err))
					} else {
						e.logger.Info("syslog decoders reloaded",
							zap.Int("total", e.Count()))
					}
				}
			}
		}
	}()
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (cd *compiledSyslogRule) matchesProgram(app string) bool {
	if cd.program == nil {
		return true
	}
	return cd.program.MatchString(app)
}

func (cd *compiledSyslogRule) matchesPrematch(msg string) bool {
	if cd.prematch == nil {
		return true
	}
	return cd.prematch.MatchString(msg)
}

func (cd *compiledSyslogRule) matchesRegex(msg string) bool {
	if cd.regex == nil {
		return true
	}
	return cd.regex.MatchString(msg)
}

func (cd *compiledSyslogRule) extractInto(msg string, out map[string]interface{}) {
	if cd.regex == nil {
		return
	}
	m := cd.regex.FindStringSubmatch(msg)
	if m == nil {
		return
	}
	names := cd.regex.SubexpNames()
	for i, name := range names {
		if name != "" && i < len(m) && m[i] != "" {
			out[name] = m[i]
		}
	}
	// Positional order fallback (no named groups).
	if len(cd.rule.Order) > 0 {
		for i, fieldName := range cd.rule.Order {
			idx := i + 1
			if fieldName != "" && idx < len(m) && m[idx] != "" {
				out[fieldName] = m[idx]
			}
		}
	}
}

func applyStatic(sf map[string]string, out map[string]interface{}) {
	for k, v := range sf {
		out[k] = v
	}
}

func normaliseProgram(appName string) string {
	s := strings.ToLower(strings.TrimSpace(appName))
	if i := strings.IndexByte(s, '['); i != -1 {
		s = s[:i]
	}
	return strings.TrimRight(s, ":")
}

func sanitiseFilename(name string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", " ", "_", ".", "_")
	return r.Replace(name)
}

func latestModTime(dir string) time.Time {
	var latest time.Time
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			if info.ModTime().After(latest) {
				latest = info.ModTime()
			}
		}
	}
	return latest
}
