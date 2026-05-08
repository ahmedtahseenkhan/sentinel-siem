package decoder

import (
	"os"
	"path/filepath"
	"regexp"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type Manager struct {
	logger   *zap.Logger
	decoders []*compiledDecoder
}

type compiledDecoder struct {
	def      models.Decoder
	extracts []*compiledExtract
}

type compiledExtract struct {
	field string
	regex *regexp.Regexp
}

func NewManager(logger *zap.Logger) *Manager {
	return &Manager{logger: logger}
}

func (m *Manager) LoadFromDir(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := m.loadFile(f); err != nil {
			m.logger.Warn("failed to load decoder file", zap.String("file", f), zap.Error(err))
		}
	}
	return nil
}

func (m *Manager) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var df models.DecodersFile
	if err := yaml.Unmarshal(data, &df); err != nil {
		return err
	}
	for _, d := range df.Decoders {
		cd, err := compile(d)
		if err != nil {
			m.logger.Warn("failed to compile decoder", zap.String("name", d.Name), zap.Error(err))
			continue
		}
		m.decoders = append(m.decoders, cd)
		m.logger.Debug("decoder loaded", zap.String("name", d.Name))
	}
	return nil
}

func compile(d models.Decoder) (*compiledDecoder, error) {
	cd := &compiledDecoder{def: d}
	for _, ext := range d.Extract {
		re, err := regexp.Compile(ext.Regex)
		if err != nil {
			return nil, err
		}
		cd.extracts = append(cd.extracts, &compiledExtract{field: ext.Field, regex: re})
	}
	return cd, nil
}

func (m *Manager) Decode(event *models.Event) map[string]string {
	result := make(map[string]string)
	for _, dec := range m.decoders {
		if !dec.matches(event) {
			continue
		}
		extracted := dec.extract(event)
		for k, v := range extracted {
			result[k] = v
		}
	}
	return result
}

func (cd *compiledDecoder) matches(event *models.Event) bool {
	if cd.def.Match.Type != "" && cd.def.Match.Type != event.Type {
		return false
	}
	for k, v := range cd.def.Match.Tags {
		if event.Tags[k] != v {
			return false
		}
	}
	return true
}

func (cd *compiledDecoder) extract(event *models.Event) map[string]string {
	result := make(map[string]string)
	msg := ""
	if v, ok := event.Fields["message"].(string); ok {
		msg = v
	}
	if msg == "" {
		return result
	}
	for _, ext := range cd.extracts {
		matches := ext.regex.FindStringSubmatch(msg)
		if len(matches) > 1 {
			result[ext.field] = matches[1]
		}
	}
	return result
}

func (m *Manager) Add(d models.Decoder) error {
	cd, err := compile(d)
	if err != nil {
		return err
	}
	m.decoders = append(m.decoders, cd)
	return nil
}

func (m *Manager) List() []models.Decoder {
	var result []models.Decoder
	for _, cd := range m.decoders {
		result = append(result, cd.def)
	}
	return result
}

func (m *Manager) Count() int {
	return len(m.decoders)
}
