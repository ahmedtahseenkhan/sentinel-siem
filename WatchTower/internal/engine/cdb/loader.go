package cdb

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

type Manager struct {
	logger *zap.Logger
	lists  map[string]*List
}

func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		logger: logger,
		lists:  make(map[string]*List),
	}
}

func (m *Manager) LoadFromDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		name := strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
		list, err := loadListFile(name, path)
		if err != nil {
			m.logger.Warn("failed to load CDB list", zap.String("path", path), zap.Error(err))
			return nil
		}
		m.lists[name] = list
		m.logger.Debug("CDB list loaded", zap.String("name", name), zap.Int("entries", list.Count()))
		return nil
	})
}

func loadListFile(name, path string) (*List, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	list := NewList(name)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		key := strings.TrimSpace(parts[0])
		value := ""
		if len(parts) == 2 {
			value = strings.TrimSpace(parts[1])
		}
		list.Add(key, value)
	}
	return list, scanner.Err()
}

func (m *Manager) Lookup(listName, key string) bool {
	list, ok := m.lists[listName]
	if !ok {
		return false
	}
	return list.Has(key)
}

func (m *Manager) GetList(name string) *List {
	return m.lists[name]
}

func (m *Manager) AddList(list *List) {
	m.lists[list.Name()] = list
}

func (m *Manager) ListNames() []string {
	var names []string
	for name := range m.lists {
		names = append(names, name)
	}
	return names
}

func (m *Manager) Count() int {
	return len(m.lists)
}
