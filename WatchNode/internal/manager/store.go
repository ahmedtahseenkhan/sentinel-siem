package manager

import (
	"sync"
	"time"

	"github.com/watchnode/watchnode/pkg/proto"
)

type AgentRecord struct {
	AgentID   string
	Hostname  string
	OS        string
	Platform  string
	Version   string
	Labels    map[string]string
	FirstSeen time.Time
	LastSeen  time.Time
	Status    string
}

type Store struct {
	mu       sync.RWMutex
	agents   map[string]*AgentRecord
	cmdQueue map[string]chan *proto.ManagerCommand
}

func NewStore() *Store {
	return &Store{
		agents:   make(map[string]*AgentRecord),
		cmdQueue: make(map[string]chan *proto.ManagerCommand),
	}
}

func (s *Store) UpsertAgentFromRegistration(req *proto.RegistrationRequest) *AgentRecord {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.agents[req.AgentId]
	if !ok {
		r = &AgentRecord{AgentID: req.AgentId, FirstSeen: now}
		s.agents[req.AgentId] = r
	}
	r.Hostname = req.Hostname
	r.OS = req.Os
	r.Platform = req.Platform
	r.Version = req.Version
	r.Labels = req.Labels
	r.LastSeen = now
	r.Status = "registered"
	if _, ok := s.cmdQueue[req.AgentId]; !ok {
		s.cmdQueue[req.AgentId] = make(chan *proto.ManagerCommand, 128)
	}
	return r
}

func (s *Store) TouchHeartbeat(agentID string, status string) *AgentRecord {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.agents[agentID]
	if !ok {
		r = &AgentRecord{AgentID: agentID, FirstSeen: now}
		s.agents[agentID] = r
	}
	r.LastSeen = now
	if status != "" {
		r.Status = status
	}
	if _, ok := s.cmdQueue[agentID]; !ok {
		s.cmdQueue[agentID] = make(chan *proto.ManagerCommand, 128)
	}
	return r
}

func (s *Store) EnqueueCommand(agentID string, cmd *proto.ManagerCommand) bool {
	s.mu.RLock()
	ch, ok := s.cmdQueue[agentID]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	select {
	case ch <- cmd:
		return true
	default:
		return false
	}
}

func (s *Store) CommandChannel(agentID string) <-chan *proto.ManagerCommand {
	s.mu.RLock()
	ch := s.cmdQueue[agentID]
	s.mu.RUnlock()
	return ch
}

