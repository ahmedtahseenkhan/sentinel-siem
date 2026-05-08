package models

type IndexInfo struct {
	Name      string `json:"name"`
	Health    string `json:"health"`
	Status    string `json:"status"`
	DocsCount int64  `json:"docs_count"`
	StoreSize string `json:"store_size"`
}

type ClusterHealth struct {
	Status              string `json:"status"`
	NumberOfNodes       int    `json:"number_of_nodes"`
	ActiveShards        int    `json:"active_shards"`
	ActivePrimaryShards int    `json:"active_primary_shards"`
}
