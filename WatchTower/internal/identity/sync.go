// Package identity implements LDAP/AD user synchronisation for Sentinel SIEM.
// When configured, it periodically queries Active Directory and stores user
// and group data in PostgreSQL for alert enrichment and the identity UI.
// Works gracefully without LDAP: the identity API still shows users derived
// from alert data when no LDAP source is available.
package identity

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/watchtower/watchtower/internal/config"
	"github.com/watchtower/watchtower/internal/models"
	"github.com/watchtower/watchtower/internal/store"
	"go.uber.org/zap"
)

// Manager periodically syncs users from LDAP/AD into PostgreSQL.
type Manager struct {
	cfg    config.IdentityConfig
	store  *store.Store
	logger *zap.Logger
}

func NewManager(cfg config.IdentityConfig, st *store.Store, logger *zap.Logger) *Manager {
	return &Manager{cfg: cfg, store: st, logger: logger}
}

// Start launches the periodic sync loop. Safe to call when LDAP is not configured
// — it logs a warning and returns immediately.
func (m *Manager) Start(ctx context.Context) {
	if !m.cfg.Enabled || m.cfg.URL == "" {
		m.logger.Info("identity: LDAP not configured — identity data will derive from alerts only")
		return
	}

	// Run once immediately, then on the configured interval.
	m.sync()

	interval, err := time.ParseDuration(m.cfg.SyncInterval)
	if err != nil || interval <= 0 {
		interval = time.Hour
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.sync()
		}
	}
}

// Sync triggers an immediate LDAP sync (exposed for the API endpoint).
func (m *Manager) Sync() error {
	return m.sync()
}

func (m *Manager) sync() error {
	m.logger.Info("identity: starting LDAP sync", zap.String("url", m.cfg.URL))

	conn, err := m.connect()
	if err != nil {
		m.logger.Error("identity: LDAP connect failed", zap.Error(err))
		return err
	}
	defer conn.Close()

	users, err := m.fetchUsers(conn)
	if err != nil {
		m.logger.Error("identity: LDAP user fetch failed", zap.Error(err))
		return err
	}

	upserted := 0
	for _, u := range users {
		if err := m.store.UpsertIdentityUser(u); err != nil {
			m.logger.Warn("identity: upsert failed", zap.String("user", u.SamAccount), zap.Error(err))
		} else {
			upserted++
		}
	}

	m.logger.Info("identity: LDAP sync complete",
		zap.Int("users_fetched", len(users)),
		zap.Int("upserted", upserted),
	)
	return nil
}

func (m *Manager) connect() (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	if strings.HasPrefix(m.cfg.URL, "ldaps://") {
		conn, err = ldap.DialURL(m.cfg.URL, ldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: true, //nolint:gosec — dev/internal use
		}))
	} else {
		conn, err = ldap.DialURL(m.cfg.URL)
	}
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	if m.cfg.BindDN != "" {
		if err := conn.Bind(m.cfg.BindDN, m.cfg.BindPassword); err != nil {
			conn.Close()
			return nil, fmt.Errorf("bind: %w", err)
		}
	}
	return conn, nil
}

func (m *Manager) fetchUsers(conn *ldap.Conn) ([]*models.IdentityUser, error) {
	filter := m.cfg.UserFilter
	if filter == "" {
		filter = "(&(objectClass=person)(sAMAccountName=*))"
	}

	req := ldap.NewSearchRequest(
		m.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{
			"sAMAccountName", "displayName", "mail",
			"department", "title", "manager",
			"memberOf", "userAccountControl",
			"lastLogon", "badPwdCount",
		},
		nil,
	)

	result, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}

	users := make([]*models.IdentityUser, 0, len(result.Entries))
	for _, entry := range result.Entries {
		u := &models.IdentityUser{
			SamAccount:  entry.GetAttributeValue("sAMAccountName"),
			DisplayName: entry.GetAttributeValue("displayName"),
			Email:       entry.GetAttributeValue("mail"),
			Department:  entry.GetAttributeValue("department"),
			Title:       entry.GetAttributeValue("title"),
			Manager:     dnToCN(entry.GetAttributeValue("manager")),
			Source:      "ldap",
		}
		if u.SamAccount == "" {
			continue
		}

		// memberOf → group CNs
		for _, dn := range entry.GetAttributeValues("memberOf") {
			if cn := dnToCN(dn); cn != "" {
				u.Groups = append(u.Groups, cn)
			}
		}

		// userAccountControl bit 2 = disabled
		uac := entry.GetAttributeValue("userAccountControl")
		u.Enabled = true
		if uac != "" {
			var v int
			fmt.Sscanf(uac, "%d", &v)
			u.Enabled = (v & 2) == 0
		}

		// lastLogon (Windows FILETIME → Unix ms)
		if ll := entry.GetAttributeValue("lastLogon"); ll != "" {
			var ft int64
			fmt.Sscanf(ll, "%d", &ft)
			if ft > 0 {
				// Windows FILETIME: 100ns intervals since 1601-01-01
				u.LastLogon = (ft - 116444736000000000) / 10000
			}
		}

		fmt.Sscanf(entry.GetAttributeValue("badPwdCount"), "%d", &u.BadPwdCount)

		users = append(users, u)
	}
	return users, nil
}

// dnToCN extracts the CN from a Distinguished Name.
func dnToCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && strings.EqualFold(kv[0], "CN") {
			return kv[1]
		}
	}
	return dn
}
