package registry

import (
	"github.com/google/uuid"
	"github.com/watchtower/watchtower/internal/models"
)

func (r *Registry) CreateGroup(name, description string) (*models.AgentGroup, error) {
	g := &models.AgentGroup{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
	}
	if err := r.store.CreateGroup(g); err != nil {
		return nil, err
	}
	return g, nil
}

func (r *Registry) GetGroup(id string) (*models.AgentGroup, error) {
	return r.store.GetGroup(id)
}

func (r *Registry) ListGroups() ([]*models.AgentGroup, error) {
	return r.store.ListGroups()
}

func (r *Registry) DeleteGroup(id string) error {
	return r.store.DeleteGroup(id)
}
