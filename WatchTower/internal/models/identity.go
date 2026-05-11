package models

// IdentityUser represents a user account synced from LDAP/AD or added manually.
type IdentityUser struct {
	ID          int64             `json:"id"`
	SamAccount  string            `json:"sam_account"`  // login name / sAMAccountName
	DisplayName string            `json:"display_name"`
	Email       string            `json:"email"`
	Department  string            `json:"department"`
	Title       string            `json:"title"`
	Manager     string            `json:"manager"`
	Groups      []string          `json:"groups"`
	Enabled     bool              `json:"enabled"`
	LastLogon   int64             `json:"last_logon"`
	BadPwdCount int               `json:"bad_pwd_count"`
	RawAttrs    map[string]string `json:"raw_attrs,omitempty"`
	SyncedAt    int64             `json:"synced_at"`
	Source      string            `json:"source"` // ldap, manual
	// Computed fields (not stored — set at query time)
	AlertCount    int `json:"alert_count,omitempty"`
	CriticalCount int `json:"critical_count,omitempty"`
	RiskScore     int `json:"risk_score,omitempty"`
}
