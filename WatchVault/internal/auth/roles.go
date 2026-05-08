package auth

var (
	AdminRole = &Role{
		Name:        "admin",
		Permissions: []string{"*"},
	}

	ReadOnlyRole = &Role{
		Name:        "readonly",
		Permissions: []string{"search", "indices:list", "health", "stats"},
	}

	IngestRole = &Role{
		Name:        "ingest",
		Permissions: []string{"ingest:events", "ingest:alerts", "health"},
	}
)
