package auth

import (
	"crypto/subtle"
)

type Authenticator struct {
	apiKeys map[string]*Role
}

type Role struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

func NewAuthenticator() *Authenticator {
	return &Authenticator{
		apiKeys: make(map[string]*Role),
	}
}

func (a *Authenticator) AddAPIKey(key string, role *Role) {
	a.apiKeys[key] = role
}

func (a *Authenticator) Validate(key string) (*Role, bool) {
	for k, role := range a.apiKeys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(key)) == 1 {
			return role, true
		}
	}
	return nil, false
}

func (a *Authenticator) HasPermission(role *Role, permission string) bool {
	if role == nil {
		return false
	}
	for _, p := range role.Permissions {
		if p == "*" || p == permission {
			return true
		}
	}
	return false
}
